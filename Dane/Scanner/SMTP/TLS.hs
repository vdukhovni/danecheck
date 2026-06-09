{-# LANGUAGE OverloadedStrings #-}

module Dane.Scanner.SMTP.TLS
  ( tlsSource
  , tlsSink
  , tlsParams
  , connTLS
  , hasTLS
  , endTLS
  , startTLS
  , tlsInfo
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.List as L
import qualified Data.X509.CertificateStore as X509
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLS
import qualified Network.TLS.Extra.CipherCBC as TLS
import qualified Streaming.ByteString as Q
import           Control.Applicative ((<|>))
import           Control.Exception (Handler(..), catches, toException)
import           Control.Monad ((>=>))
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.State.Strict (gets, modify')
import           Data.Default.Class
import           Data.Function ((&))
import           Data.IORef (IORef)
import           Data.Maybe (isJust)
import           Network.Socket (Socket)
import           Network.TLS (Version(TLS12, TLS13))
import           System.Timeout (timeout)

import           Dane.Scanner.Opts (SigAlgs(..), SigAlgGroup(..))
import           Dane.Scanner.SMTP.Certs
import           Dane.Scanner.SMTP.Internal

-- callback args: serviceid fingerprint certificate
nullCache :: TLS.ValidationCache
nullCache = TLS.ValidationCache
  { TLS.cacheQuery = \_ _ _ -> return TLS.ValidationCacheUnknown
  , TLS.cacheAdd   = \_ _ _ -> return ()
  }

tlsParams :: SigAlgs
          -> String
          -> IORef ChainInfo
          -> X509.CertificateStore
          -> TLS.ClientParams
tlsParams sigAlgs host cref store =
  (TLS.defaultParamsClient host "smtp")
      { TLS.clientUseServerNameIndication = True
      , TLS.clientHooks = def
          { TLS.onCertificateRequest = \ _ -> return Nothing
          , TLS.onServerCertificate  = genChainInfo cref
          , TLS.onSuggestALPN        = return Nothing
          , TLS.onSelectKeyShareGroups = chooseKS
          }
      , TLS.clientShared    = def
          { TLS.sharedCAStore            = store
          , TLS.sharedCredentials        = mempty
          , TLS.sharedValidationCache    = nullCache
          , TLS.sharedSessionManager     = TLS.noSessionManager
          }
      , TLS.clientSupported = def & \ d -> d
          { TLS.supportedCiphers = chooseCS
          , TLS.supportedVersions = [TLS13, TLS12]
          , TLS.supportedCompressions = [TLS.nullCompression]
          , TLS.supportedSecureRenegotiation = True
          , TLS.supportedSession = False
          , TLS.supportedFallbackScsv = False
          , TLS.supportedEmptyPacket = True
          , TLS.supportedGroups = chooseGS (TLS.supportedGroups d)
          , TLS.supportedHashSignatures = case sigAlgs of
                SigAlgs [] -> TLS.supportedHashSignatures d
                SigAlgs gs -> concatMap sigAlgsFor gs
          }
      , TLS.clientWantSessionResume = Nothing    -- no session to resume
      , TLS.clientDebug = def                    -- Can override DRBG seed
      , TLS.clientWantTicket = False
      }
  where
    -- Expand a named group to its (HashAlgorithm, SignatureAlgorithm)
    -- pairs.  RSA covers both TLS 1.3 (RSA-PSS-RSAE) and TLS 1.2
    -- (RSA-PKCS#1) variants; ECDSA covers the three NIST P-curves;
    -- EdDSA covers Ed25519 and Ed448.  Within each group the pairs
    -- are listed in the conventional SHA-256\/384\/512 order; the
    -- caller controls the group-level order via the @--sigalgs@
    -- option, and the TLS library honours that order when offering
    -- algorithms to the server.
    sigAlgsFor :: SigAlgGroup -> [(TLS.HashAlgorithm, TLS.SignatureAlgorithm)]
    sigAlgsFor SigEcdsa = (,) <$> [ TLS.HashSHA256
                                  , TLS.HashSHA384
                                  , TLS.HashSHA512 ]
                              <*> [ TLS.SignatureECDSA ]
    sigAlgsFor SigRsa   = -- TLS 1.3 RSA-PSS-RSAE
                          ((,) TLS.HashIntrinsic <$>
                              [ TLS.SignatureRSApssRSAeSHA256
                              , TLS.SignatureRSApssRSAeSHA384
                              , TLS.SignatureRSApssRSAeSHA512 ])
                          ++
                          -- TLS 1.2 RSA-PKCS#1
                          ((,) <$> [ TLS.HashSHA256
                                   , TLS.HashSHA384
                                   , TLS.HashSHA512 ]
                               <*> [ TLS.SignatureRSA ])
    sigAlgsFor SigEdDsa = (,) TLS.HashIntrinsic <$>
                              [ TLS.SignatureEd25519
                              , TLS.SignatureEd448 ]

    -- Add some DHE TLS 1.2 ciphers, with the AES128 choice first
    chooseCS :: [TLS.Cipher]
    chooseCS =
        TLS.ciphersuite_strong ++
        case L.uncons $ reverse TLS.ciphersuite_dhe_rsa of
            Just (l, cs) -> l : reverse cs
            Nothing       -> []
        ++ TLS.ciphersuite_pfs_sha2_cbc

    chooseGS :: [TLS.Group] -> [TLS.Group]
    chooseGS = go False
      where
        go _ [] = []
        go dheSeen (g@(TLS.Group n) : gs)
            -- No P521 or SecP384r1MLKEM1024
            | n == 25 || n == 4589 = go dheSeen gs
            -- All other EC curves
            | n < 256
            = g : go dheSeen gs
            -- Replace FFDHE list with just ffdhe2048 and ffdhe3072
            | n >= 256 && n < 512
            = if dheSeen
              then go dheSeen gs
              else TLS.FFDHE2048 : TLS.FFDHE3072 : go True gs
            | otherwise
            = g : go dheSeen gs

    chooseKS :: [TLS.Group] -> [TLS.Group]
    chooseKS = go Nothing Nothing
      where
        go g2 g3 (g@(TLS.Group n) : gs)
            -- EC, if possible
            | n < 256   = [g]
            -- else FFDHE, if possible
            | n < 512   = go (g2 <|> Just g) g3 gs
            -- else anything goes
            | otherwise = go g2 (g3 <|> Just g) gs
        go (Just g) _ _ = [g]
        go _ (Just g) _ = [g]
        go _ _ _        = []

-- | Read decrypted records off the TLS context and produce a
-- 'ByteStream' for downstream consumers.  Errors, EOF and
-- timeouts are recorded in 'smtpErr' and terminate the stream.
tlsSource :: Q.ByteStream SmtpM ()
tlsSource = lift (gets smtpConn) >>= \ case
    SmtpTLS ctx -> go ctx
    _           -> error "Non-TLS channel"
  where
    go ctx = do
        tm <- lift timeLeft
        liftIO (timeout tm (doRecv ctx)) >>= \ case
            Just (Right bs)
                | B.length bs > 0 -> Q.chunk bs >> go ctx
                | otherwise
                  -> lift $ modify' \s -> s { smtpErr = DataErr $ eofErr "TLS read" }
            Just (Left e)
                  -> lift $ modify' \s -> s { smtpErr = e }
            _     -> lift $ modify' \s -> s { smtpErr = DataErr $ timeErr "TLS read" }

    doRecv ctx = (Right <$> TLS.recvData ctx) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.Terminated _ _ _ -> return $ Left TlsRecvError
        _                    -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

-- | Consume a 'ByteStream' and write each chunk through the TLS
-- context.  Errors and timeouts are recorded in 'smtpErr' and
-- stop the loop.
tlsSink :: Q.ByteStream SmtpM () -> SmtpM ()
tlsSink str = gets smtpConn >>= \ case
    SmtpTLS ctx -> go ctx str
    _           -> fail "Non-TLS channel"
  where
    go ctx = Q.unconsChunk >=> \ case
        Right (bs, bss) -> do
            tm <- timeLeft
            liftIO (timeout tm (doSend ctx bs)) >>= \ case
                Just (Right _) -> go ctx bss
                Just (Left e)  -> modify' \s -> s { smtpErr = e }
                _              -> modify' \s -> s { smtpErr = DataErr $ timeErr "TLS write" }
        Left () -> pure ()

    doSend ctx bs = (Right <$> TLS.sendData ctx (LB.fromStrict bs)) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.Terminated _ _ _ -> return $ Left TlsSendError
        _                    -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

endTLS :: SmtpM ()
endTLS = gets smtpConn >>= \ case
    SmtpTLS ctx -> go ctx
    _           -> error "Non-TLS channel"
  where
    go ctx = do
        tm <- timeLeft
        liftIO (timeout tm (doBye ctx)) >>= \ case
            Just (Right _) -> pure ()
            Just (Left  e) -> modify' \s -> s { smtpErr = e }
            _              -> modify' \s -> s { smtpErr = DataErr $ timeErr "shutdown" }

    doBye ctx = (Right <$> TLS.bye ctx) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.Terminated _ _ _ -> return $ Left TlsSendError
        _                    -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

connTLS :: SmtpConn -> Maybe TLS.Context
connTLS (SmtpTLS ctx) = Just ctx
connTLS _             = Nothing

hasTLS :: ProtoState -> Bool
hasTLS = isJust . connTLS . smtpConn

startTLS :: SmtpM ()
startTLS = gets smtpConn >>= \ case
    SmtpPlain sock -> go sock
    _              -> error "Non-plaintext channel"
  where
    go :: Socket -> SmtpM ()
    go sock = do
      servername <- gets serverName
      cref <- gets chainRef
      sigAlgs <- gets tlsSigAlgs
      store <- getStore Nothing
      ctx <- TLS.contextNew sock $ tlsParams sigAlgs servername cref store
      tmout <- gets smtpTimeout
      liftIO (timeout tmout (doHandshake ctx)) >>= \ case
          Just (Right _) -> do
              deadline <- liftIO $ timeLimit tmout
              modify' \s -> s { smtpConn = SmtpTLS ctx, ioDeadline = deadline }
          Just (Left e)  -> modify' \s -> s { smtpErr = e }
          _              -> modify' \s -> s { smtpErr = DataErr $ timeErr "handshake" }

    getStore :: Maybe FilePath -> SmtpM X509.CertificateStore
    getStore cafp =
        maybe (return Nothing)
              (\fp -> liftIO $ X509.readCertificateStore fp) cafp >>=
        return . maybe (X509.makeCertificateStore []) id

    doHandshake ctx = (Right <$> TLS.handshake ctx) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.HandshakeFailed t -> return $ Left $ TlsHandError t
        TLS.Terminated _ _ t  -> return $ Left $ TlsHandError t
        _                     -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

tlsInfo :: TLS.Context -> IO (TLS.Version, TLS.Cipher, Maybe TLS.Group)
tlsInfo ctx = do
  ~(Just i) <- TLS.contextGetInformation ctx
  return $ (,,) <$> TLS.infoVersion
                <*> TLS.infoCipher
                <*> TLS.infoSupportedGroup
                 $! i
