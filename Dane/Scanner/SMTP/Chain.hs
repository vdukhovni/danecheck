{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Dane.Scanner.SMTP.Chain
    ( getAddrChains
    , AddrChain(..)
    , PeerChain(..)
    , SmtpState(..)
    )
  where

import           Control.Concurrent.MVar (takeMVar)
import           Control.Exception (Exception, SomeException, toException)
import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.State.Strict (gets)

import qualified Data.ByteString.Char8 as BC (map, unpack, unsnoc)
import           Data.Char (toLower)
import           Data.Int (Int64)
import           Data.IP (AddrRange, IPv4, IPv6, isMatchedTo, makeAddrRange, toIPv4, toIPv6)
import           Data.List (find)
import           Network.DNS (Domain, RData(..))
import           Network.HostName (getHostName)
import qualified Network.TLS as TLS

import           GHC.IO.Exception (IOException(..), IOErrorType(TimeExpired))

import qualified Dane.Scanner.Opts as Opts
import           Dane.Scanner.State
import           Dane.Scanner.Util
import           Dane.Scanner.SMTP.Addr
import           Dane.Scanner.SMTP.Certs
import           Dane.Scanner.SMTP.Internal
import           Dane.Scanner.SMTP.Proto
import           Dane.Scanner.SMTP.TLS

data AddrChain = AddrChain
    { peerAddr  :: !RData
    , peerChain :: PeerChain
    }

data MatchStatus = Pass
                 | Notlsa
                 | Nousable
                 | Nomatch
                 | Noname
                 | Notime
    deriving (Eq)

instance Show MatchStatus where
    show Pass = "pass"
    show Notlsa = "tlsa-absent"
    show Nousable = "tlsa-unusable"
    show Nomatch = "tlsa-mismatch"
    show Noname = "name-mismatch"
    show Notime = "cert-expired"

data PeerChain =
    PeerChain
        { peerNames      :: [TLS.HostName]
        , peerCerts      :: [CertInfo]
        , matchName      :: Maybe TLS.HostName
        , matchDepth     :: Maybe Int
        , matchStatus    :: !MatchStatus
        , peerTime       :: !Int64
        , peerTlsVersion :: !TLS.Version
        , peerTlsCipher  :: !TLS.Cipher
        }
  | SmtpError SmtpState Int String
  | ChainException SomeException

-- | https://www.iana.org/assignments/iana-ipv4-special-registry
--
reserved4 :: [ AddrRange IPv4 ]
reserved4 = map (makeAddrRange <$> toIPv4 . fst <*> snd)
    [ ( [0,0,0,0], 8 )       -- RFC1122
    , ( [10,0,0,0], 8 )      -- RFC1918
    , ( [100,64,0,0], 10 )   -- RFC6598
    , ( [127,0,0,0], 8 )     -- RFC1122
    , ( [169,254,0,0], 16 )  -- RFC3927
    , ( [172,16,0,0], 12 )   -- RFC1918
    , ( [192,0,0,0], 24 )    -- RFC6890
    , ( [192,0,2,0], 24 )    -- RFC5737
    , ( [192,31,196,0], 24 ) -- RFC7535
    , ( [192,52,193,0], 24 ) -- RFC7450
    , ( [192,88,99,0], 24 )  -- RFC3068
    , ( [192,168,0,0], 16 )  -- RFC1918
    , ( [192,175,48,0], 24 ) -- RFC7534
    , ( [198,18,0,0], 15 )   -- RFC2544
    , ( [198,51,100,0], 24 ) -- RFC5737
    , ( [203,0,113,0], 24 )  -- RFC5737
    , ( [224,0,0,0], 4 )     -- RFC1112
    , ( [240,0,0,0], 4 )     -- RFC1112
    ]

-- | https://www.iana.org/assignments/iana-ipv6-special-registry
--
reserved6 :: [ AddrRange IPv6 ]
reserved6 = map (makeAddrRange <$> toIPv6 . fst <*> snd)
    [ ( [0,0,0,0,0,0,0,0], 128 )             -- RFC4291
    , ( [0,0,0,0,0,0,0,1], 128 )             -- RFC4291
    , ( [0,0,0,0,0,0,0xffff,0], 96 )         -- RFC4291
    , ( [0x64,0xff9b,0,0,0,0,0,0], 96 )      -- RFC6052
    , ( [0x100,0,0,0,0,0,0,0], 64 )          -- RFC6666
    , ( [0x2001,0,0,0,0,0,0,0], 23 )         -- RFC2928
    , ( [0x2620,0x4f,0x8000,0,0,0,0,0], 48 ) -- RFC7534
    , ( [0xfc00,0,0,0,0,0,0,0], 7 )          -- RFC4193
    , ( [0xfe80,0,0,0,0,0,0,0], 10 )         -- RFC4291
    ]

getAddrChains :: Domain   -- MX hostname
              -> Domain   -- TLSA base domain
              -> [Domain] -- DNS reference identifiers
              -> [RData]  -- Host TLSA rdata
              -> [RData]  -- host address rdata
              -> Scanner [AddrChain]
getAddrChains mx base names tlsards addrs = do
    down <- gets $ Opts.downMX . scannerOpts
    case find (== (d2s mx)) down of
      Nothing -> mapM perAddr addrs
      Just  _ -> return []
  where
    perAddr :: RData -> Scanner AddrChain
    perAddr a = do
        allow <- gets $ Opts.useReserved . scannerOpts
        case a of
            (RD_A ipaddr)
                | not allow && any (isMatchedTo ipaddr) reserved4
                -> scannerFail $ AddrChain a $ SmtpError CONNECT (-1) ""
                | otherwise -> doAddr base names tlsards a
            (RD_AAAA ipaddr)
                | not allow && any (isMatchedTo ipaddr) reserved6
                -> scannerFail $ AddrChain a $ SmtpError CONNECT (-1) ""
                | otherwise -> doAddr base names tlsards a
            _   -> return $ AddrChain a $ ChainException unsupported
    unsupported = toException $ userError "Unsupported address family"

doAddr :: Domain        -- TLSA base domain
       -> [Domain]      -- DNS reference identifiers
       -> [RData]       -- TLSA RRset data
       -> RData         -- address record RDATA
       -> Scanner AddrChain
doAddr base refnames tlsards peerAddr = do
  opts <- gets scannerOpts
  helo <- maybe (liftIO getHostName) return $ Opts.smtpHelo opts
  let basenm = d2s base
      tout = Opts.smtpTimeout opts * 1000
      llen = Opts.smtpLineLen opts
  ipConn peerAddr 25 tout $ \conn ->
    case conn of
      Left IOError{..} -> case ioe_type of
        TimeExpired -> notime
        _           -> noconn
      Right sock -> do
        st <- liftIO $ dosmtp =<< startState helo basenm tout llen sock
        peerChain <- case (smtpErr st) of
          DataErr err     -> scannerFail $ mkex $ errLoc err st
          OtherErr e      -> scannerFail $ ChainException e
          ProtoErr code m -> scannerFail $ SmtpError (smtpState st) code $ b2s m
          TlsHandError t  -> scannerFail $ SmtpError (smtpState st) (-1) $ show t
          TlsRecvError    -> scannerFail $ SmtpError (smtpState st) (-2) ""
          TlsSendError    -> scannerFail $ SmtpError (smtpState st) (-3) ""
          SmtpOK
            | SmtpTLS ctx <- smtpConn st
            -> do
              (peerNames, peerCerts, peerTime) <- liftIO $ takeMVar (mvCerts st)
              (peerTlsVersion, peerTlsCipher) <- liftIO $ tlsInfo ctx
              let Opts.Opts { Opts.addDays = off
                            , Opts.eeChecks = eechecks
                            } = opts
                  matchName = namecheck refnames peerNames
                  vtime = peerTime + (fromIntegral off) * 86400
                  (d, s) = tlsamatch eechecks matchName vtime tlsards peerCerts
              when (s /= Pass) $ scannerFail ()
              return PeerChain{matchDepth = d, matchStatus = s, ..}
            | otherwise
            -> scannerFail $ SmtpError STARTTLS 0 ""
        return AddrChain{..}
  where
    mkex :: Exception e => e -> PeerChain
    mkex = ChainException . toException

    notime = let peerChain = SmtpError CONNECT 0 "" in return AddrChain{..}

    noconn = let peerChain = SmtpError CONNECT 500 "" in return AddrChain{..}

    b2s = BC.unpack

    namecheck :: [Domain] -> [String] -> Maybe String
    namecheck [] _ = Nothing
    namecheck (d:ds) names =
        let dom = BC.unpack $ BC.map toLower $ case BC.unsnoc d of
                Just (i, l) | l == '.' -> i
                _           -> d
            match = find ((== dom) . map toLower) names
        in case match of
           Just  _ -> match
           Nothing | p <- dropWhile (/= '.') dom
                   , (_:t) <- p
                   , '.' `elem` t
                   , wild <- find (== ('*' : p)) names
                   , Just _ <- wild
                   -> wild
                   | otherwise -> namecheck ds names

    cinfomatch depth rds CertInfo{..} =
        let u = if depth == 0 then 3 else 2
         in (RD_TLSA u 1 1 (_spki256 _hashes)) `elem` rds ||
            (RD_TLSA u 0 1 (_cert256 _hashes)) `elem` rds ||
            (RD_TLSA u 1 2 (_spki512 _hashes)) `elem` rds ||
            (RD_TLSA u 0 2 (_cert512 _hashes)) `elem` rds ||
            (RD_TLSA u 1 0 (_spki)) `elem` rds ||
            (RD_TLSA u 0 0 (_cert)) `elem` rds

    tlsamatch :: Bool
              -> Maybe String
              -> Int64
              -> [RData]
              -> [CertInfo]
              -> (Maybe Int, MatchStatus)
    tlsamatch _ _ _ [] _ = (Nothing, Notlsa)
    tlsamatch _ _ _ (usable -> []) _ = (Nothing, Nousable)
    tlsamatch eechecks nm tm rds certinfos = go False 0 certinfos
      where
        -- | If we never find a matching TLSA record, report that!
        -- Namecheck failure or expiration are only reported if we
        -- at least find a TLSA match.
        go _ _ [] = (Nothing, Nomatch)
        go expired depth (c@CertInfo{..}:cs) =
            let matched = cinfomatch depth rds c
                e = expired || fst _life > tm || snd _life < tm
            in case depth == 0 && not eechecks of
                 True  | matched -> (Just 0, Pass)
                       | null [u | RD_TLSA u _ _ _ <- rds, u /= 3]
                       -> (Nothing, Nomatch)
                       | otherwise
                       -> go e (depth+1) cs
                 False | matched
                       -> case () of
                            _ | Nothing <- nm -> (Nothing, Noname)
                              | e             -> (Nothing, Notime)
                              | otherwise     -> (Just depth, Pass)
                       | otherwise
                       -> go e (depth+1) cs

    usable rds = [ u | RD_TLSA u s m _ <- rds
                 , u `elem` [2,3]
                 , s `elem` [0,1]
                 , m `elem` [0,1,2] ]
