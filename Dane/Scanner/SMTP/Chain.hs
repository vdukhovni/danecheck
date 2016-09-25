{-# LANGUAGE RecordWildCards #-}

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
                 | Nomatch
                 | Noname
                 | Notime
    deriving (Eq)

instance Show MatchStatus where
    show Pass = "pass"
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

reserved4 :: [ AddrRange IPv4 ]
reserved4  =
    [ (makeAddrRange (toIPv4 [127,0,0,0]) 8)     -- loopback
    , (makeAddrRange (toIPv4 [10,0,0,0]) 8)      -- RFC1918
    , (makeAddrRange (toIPv4 [172,16,0,0]) 12)   -- RFC1918
    , (makeAddrRange (toIPv4 [192,168,0,0]) 16)  -- RFC1918
    , (makeAddrRange (toIPv4 [192,0,2,0]) 24)    -- doc
    , (makeAddrRange (toIPv4 [224,0,0,0]) 4)     -- multicast
    , (makeAddrRange (toIPv4 [240,0,0,0]) 4)     -- reserved
    ]
reserved6 :: [ AddrRange IPv6 ]
reserved6 =
    [ (makeAddrRange (toIPv6 [0,0,0,0,0,0,0,1]) 128)     -- loopback
    , (makeAddrRange (toIPv6 [0,0,0,0,0,0,0xffff,0]) 96) -- mapped IPv4
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
                -> return $ AddrChain a $ SmtpError CONNECT (-1) ""
                | otherwise -> doAddr base names tlsards a
            (RD_AAAA ipaddr)
                | not allow && any (isMatchedTo ipaddr) reserved6
                -> return $ AddrChain a $ SmtpError CONNECT (-1) ""
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
              off <- gets $ Opts.addDays . scannerOpts
              let matchName = namecheck refnames peerNames
                  vtime = peerTime + (fromIntegral off) * 86400

              -- When the user wants to check names and for the EE cert, we
              -- start the chain at depth 1 instead, and then decrement the
              -- reported match depth if any.
              eechecks <- gets $ Opts.eeChecks . scannerOpts
              let depth = if_ eechecks 1 0
                  (d, s) = tlsamatch depth matchName vtime tlsards peerCerts
                  matchDepth = (if_ eechecks pred id) <$> d
                  matchStatus = s

              when (s /= Pass) $ scannerFail ()
              return PeerChain{..}
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
           Nothing | p <- takeWhile (/= '.') dom
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

    tlsamatch :: Int
              -> Maybe String
              -> Int64
              -> [RData]
              -> [CertInfo]
              -> (Maybe Int, MatchStatus)
    tlsamatch _ _ _ _ [] = (Nothing, Nomatch)
    tlsamatch depth nm tm rds (c@CertInfo{..}:cs) =
        let match = cinfomatch depth rds c
        in case depth of
          0 | match -> (Just depth, Pass)
            | not $ (fst _life < tm && snd _life > tm) -> (Nothing, Notime)
            | otherwise -> tlsamatch (depth+1) nm tm rds cs
          _ | Nothing <- nm -> (Nothing, Noname)
            | not $ (fst _life < tm && snd _life > tm) -> (Nothing, Notime)
            | match -> (Just depth, Pass)
            | otherwise -> tlsamatch (depth+1) nm tm rds cs
