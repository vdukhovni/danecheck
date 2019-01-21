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

import           System.Timeout.Lifted (timeout)

import           Control.Exception.Safe (Handler(..), catches, toException)
import           Control.Monad.Base (liftBase)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.State.Strict (gets, modify)
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as LB
import           Data.Conduit (ConduitM, await, yield)
import           Data.Default.Class
import           Data.IORef (IORef)
import           Data.Maybe (isJust, fromJust)
import           Data.Void (Void)
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import           Network.Socket (Socket)
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLS

import           Dane.Scanner.SMTP.Internal
import           Dane.Scanner.SMTP.Certs

-- callback args: serviceid fingerprint certificate
nullCache :: X509.ValidationCache
nullCache = TLS.ValidationCache
  { TLS.cacheQuery = \_ _ _ -> return TLS.ValidationCacheUnknown
  , TLS.cacheAdd   = \_ _ _ -> return ()
  }

tlsParams :: String
          -> IORef ChainInfo
          -> X509.CertificateStore
          -> TLS.ClientParams
tlsParams host cref store =
  (TLS.defaultParamsClient host "smtp")
      { TLS.clientUseServerNameIndication = True
      , TLS.clientHooks = def
          { TLS.onCertificateRequest = \ _ -> return Nothing
          , TLS.onServerCertificate  = genChainInfo cref
          , TLS.onSuggestALPN        = return Nothing
          }
      , TLS.clientShared    = def
          { TLS.sharedCAStore            = store
          , TLS.sharedCredentials        = mempty
          , TLS.sharedValidationCache    = nullCache
          , TLS.sharedSessionManager     = TLS.noSessionManager
          }
      , TLS.clientSupported = def
          { TLS.supportedCiphers = TLS.ciphersuite_strong
          , TLS.supportedVersions = [TLS.TLS12, TLS.TLS11, TLS.TLS10] -- XXX: Floor?
          , TLS.supportedCompressions = [TLS.nullCompression]
          , TLS.supportedHashSignatures =
              (,) <$> [ TLS.HashSHA384
                      , TLS.HashSHA256
                      , TLS.HashSHA1
                      ]
                  <*> [ TLS.SignatureECDSA
                      , TLS.SignatureRSA
                      ]
          , TLS.supportedSecureRenegotiation = True
          , TLS.supportedSession = False
          , TLS.supportedFallbackScsv = False
          , TLS.supportedEmptyPacket = True
          }
      , TLS.clientWantSessionResume = Nothing    -- no session to resume
      , TLS.clientUseMaxFragmentLength = Nothing -- not space constrained
      , TLS.clientDebug = def                    -- Can override DRBG seed
      }

tlsSource :: ConduitM () ByteString SmtpM ()
tlsSource = do
  conn <- lift $ gets smtpConn
  case conn of
    SmtpTLS ctx -> go ctx
    _           -> error "Non-TLS channel"
  where
    go ctx = do
      res <- lift $ timeLeft >>= flip timeout (doRecv ctx)
      case res of
        Just x
          | Right bs <- x
          -> if (BC.length bs > 0)
             then yield bs >> go ctx
             else lift $ modify $
               \s -> s { smtpErr = DataErr $ eofErr "TLS read" }
          | Left e  <- x
          -> lift $ modify $ \s -> s { smtpErr = e }
        _ -> lift $ modify $
               \s -> s { smtpErr = DataErr $ timeErr "TLS read" }

    doRecv ctx = (Right <$> TLS.recvData ctx) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.Terminated _ _ _ -> return $ Left TlsRecvError
        _                    -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

tlsSink :: ConduitM ByteString Void SmtpM ()
tlsSink = do
  conn <- lift $ gets smtpConn
  case conn of
    SmtpTLS ctx -> go ctx
    _           -> error "Non-TLS channel"
  where
    go ctx = await >>= ( maybe (return ()) $ \bs -> do
      res <- lift $ timeLeft >>= flip timeout (doSend ctx bs)
      case res of
        Just x
          | Right _ <- x -> go ctx
          | Left e  <- x
          -> lift $ modify $ \s -> s { smtpErr = e}
        _ -> lift $ modify $
               \s -> s { smtpErr = DataErr $ timeErr "TLS write" }
      )

    doSend ctx bs = (Right <$> TLS.sendData ctx (LB.fromStrict bs)) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.Terminated _ _ _ -> return $ Left TlsSendError
        _                    -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

endTLS :: SmtpM ()
endTLS = do
  conn <- gets smtpConn
  case conn of
    SmtpTLS ctx -> go ctx
    _           -> error "Non-TLS channel"
  where
    go ctx = do
      res <- timeLeft >>= flip timeout (doBye ctx)
      case res of
        Just x
          | Right _ <- x -> return ()
          | Left  e <- x -> modify $ \s -> s { smtpErr = e }
        _ -> modify $ \s -> s { smtpErr = DataErr $ timeErr "shutdown" }

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
startTLS = do
  conn <- gets smtpConn
  case conn of
    SmtpPlain sock -> go sock
    _              -> error "Non-plaintext channel"
  where
    go :: Socket -> SmtpM ()
    go sock = do
      servername <- gets serverName
      cref <- gets chainRef
      store <- getStore Nothing
      ctx <- TLS.contextNew sock $ tlsParams servername cref store
      tmout <- gets smtpTimeout
      res <- timeout tmout (doHandshake ctx)
      case res of
        Just x
          | Right _ <- x
          -> do
             deadline <- liftBase $ timeLimit tmout
             modify $ \s -> s { smtpConn = SmtpTLS ctx, ioDeadline = deadline }
          | Left e  <- x
          -> modify $ \s -> s { smtpErr = e }
        _ -> modify $ \s -> s { smtpErr = DataErr $ timeErr "handshake" }

    getStore :: Maybe FilePath -> SmtpM X509.CertificateStore
    getStore cafp =
        maybe (return Nothing)
              (\fp -> liftBase $ X509.readCertificateStore fp) cafp >>=
        return . maybe (X509.makeCertificateStore []) id

    doHandshake ctx = (Right <$> TLS.handshake ctx) `catches`
        [ Handler handleTLS, Handler handleIO ]

    handleTLS e = case e of
        TLS.HandshakeFailed t -> return $ Left $ TlsHandError t
        TLS.Terminated _ _ t  -> return $ Left $ TlsHandError t
        _                     -> return $ Left $ OtherErr $ toException e

    handleIO e = return $ Left $ DataErr e

tlsInfo :: TLS.Context -> IO (TLS.Version, TLS.Cipher)
tlsInfo ctx = do
  i <- TLS.contextGetInformation ctx
  return $ (,) <$> TLS.infoVersion <*> TLS.infoCipher $ fromJust i
