{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Dane.Scanner.SMTP.Chain
    ( getAddrChains
    , AddrChain(..)
    , PeerChain(..)
    , PeerProbe(..)
    , SmtpState(..)
    )
  where

import           Control.Exception (displayException)
import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.State.Strict (gets)

import qualified Data.ByteString.Char8 as BC (unpack)
import qualified Data.ByteString.Short as SB
import           Data.Char (toLower)
import           Data.IORef (readIORef)
import           Data.IP ( AddrRange, IP(IPv4, IPv6), IPv4, IPv6
                          , isMatchedTo, makeAddrRange, toIPv4, toIPv6 )
import           Data.Int (Int64)
import           Data.List (find)
import           Data.Maybe (isJust, isNothing)
import           Net.DNSBase ( Domain, T_tlsa, X_tlsa(..) )
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
    { peerAddr  :: !IP
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

-- | Outcome of an SMTP probe at one IP address.
data PeerChain
    = Probed PeerProbe
      -- ^ TLS handshake completed.  Carries the per-probe details
      -- (TLS info, presented names, cert chain, TLSA-match result,
      -- time observed) in a separate 'PeerProbe' record so the
      -- error variants stay flat and the printer can destructure
      -- the success case in one step.
    | SmtpError SmtpState Int String
      -- ^ SMTP protocol or TLS handshake error.  The 'Int' is the
      -- SMTP response code or one of the negative sentinels: @-1@
      -- for handshake failure or connection reset, @-2@ for
      -- EOF\/recv error, @-3@ for send error.  The 'String' carries
      -- whatever message the server or stack provided (often empty
      -- for the negative-code paths).
    | ChainException String
      -- ^ Unhandled exception during the probe.  Pre-rendered to a
      -- 'String' via 'displayException' at capture time so the
      -- 'PeerChain' value carries no existential dictionary.

-- | Probe-success details captured after a successful STARTTLS
-- handshake.
data PeerProbe = PeerProbe
    { peerNames      :: [TLS.HostName]
    , peerCerts      :: [CertInfo]
    , matchName      :: Maybe TLS.HostName
    , matchDepth     :: Maybe Int
    , matchStatus    :: !MatchStatus
    , peerTime       :: !Int64
    , peerTlsVersion :: !TLS.Version
    , peerTlsCipher  :: !TLS.Cipher
    , peerTlsGroup   :: !(Maybe TLS.Group)
    }

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
    , ( [0,0,0,0,0,0xffff,0,0], 96 )         -- RFC4291
    , ( [0x64,0xff9b,0,0,0,0,0,0], 96 )      -- RFC6052
    , ( [0x100,0,0,0,0,0,0,0], 64 )          -- RFC6666
    , ( [0x2001,0,0,0,0,0,0,0], 23 )         -- RFC2928
    , ( [0x2620,0x4f,0x8000,0,0,0,0,0], 48 ) -- RFC7534
    , ( [0xfc00,0,0,0,0,0,0,0], 7 )          -- RFC4193
    , ( [0xfe80,0,0,0,0,0,0,0], 10 )         -- RFC4291
    -- 6to4 versions of IPv4 reserved addresses
    , ( [0x2002,0,0,0,0,0,0,0], 24 )           -- RFC1122
    , ( [0x2002,0x0a00,0,0,0,0,0,0], 24 )      -- RFC1918
    , ( [0x2002,0x6440,0,0,0,0,0,0], 26 )      -- RFC6598
    , ( [0x2002,0x7f00,0,0,0,0,0,0], 24 )      -- RFC1122
    , ( [0x2002,0xa9fe,0,0,0,0,0,0], 32 )      -- RFC3927
    , ( [0x2002,0xac10,0,0,0,0,0,0], 28 )      -- RFC1918
    , ( [0x2002,0xc000,0,0,0,0,0,0], 40 )      -- RFC6890
    , ( [0x2002,0xc000,0x0200,0,0,0,0,0], 40 ) -- RFC5737
    , ( [0x2002,0xc01f,0xc200,0,0,0,0,0], 40 ) -- RFC7535
    , ( [0x2002,0xc034,0xc100,0,0,0,0,0], 40 ) -- RFC7450
    , ( [0x2002,0xc058,0x6300,0,0,0,0,0], 40 ) -- RFC3068
    , ( [0x2002,0xc0a8,0,0,0,0,0,0], 32 )      -- RFC1918
    , ( [0x2002,0xc0af,0x3000,0,0,0,0,0], 40 ) -- RFC7534
    , ( [0x2002,0xc612,0,0,0,0,0,0], 31 )      -- RFC2544
    , ( [0x2002,0xc633,0x6400,0,0,0,0,0], 40 ) -- RFC5737
    , ( [0x2002,0xcb00,0x7100,0,0,0,0,0], 40 ) -- RFC5737
    , ( [0x2002,0xe000,0,0,0,0,0,0], 20 )      -- RFC1112
    , ( [0x2002,0xf000,0,0,0,0,0,0], 20 )      -- RFC1112
    ]

getAddrChains :: Domain    -- MX hostname
              -> Domain    -- TLSA base domain
              -> [Domain]  -- DNS reference identifiers
              -> [T_tlsa]  -- Host TLSA rdata, typed
              -> [IP]      -- Host addresses (already converted from T_a/T_aaaa)
              -> Scanner [AddrChain]
getAddrChains mx base names tlsards addrs = do
    opts <- gets scannerOpts
    let down = find (== (d2s mx)) (Opts.downMX opts)
        skip = if_ (Opts.upsideDown opts) isNothing isJust
    if skip down
    then return []
    else mapM perAddr addrs
  where
    perAddr :: IP -> Scanner AddrChain
    perAddr a = do
        allow <- gets $ Opts.useReserved . scannerOpts
        case a of
            IPv4 ip4
                | not allow && any (isMatchedTo ip4) reserved4
                -> scannerFail $ AddrChain a $ SmtpError CONNECT (-1) ""
                | otherwise -> doAddr base names tlsards a
            IPv6 ip6
                | not allow && any (isMatchedTo ip6) reserved6
                -> scannerFail $ AddrChain a $ SmtpError CONNECT (-1) ""
                | otherwise -> doAddr base names tlsards a

doAddr :: Domain        -- TLSA base domain
       -> [Domain]      -- DNS reference identifiers
       -> [T_tlsa]      -- TLSA RRset data, typed
       -> IP            -- peer address
       -> Scanner AddrChain
doAddr base refnames tlsards peerAddr = do
  opts <- gets scannerOpts
  helo <- maybe (liftIO getHostName) return $ Opts.smtpHelo opts
  let basenm   = d2s base
      tout     = Opts.smtpTimeout opts * 1000
      llen     = Opts.smtpLineLen opts
      eechecks = Opts.eeChecks opts
      addOff   = Opts.addDays opts
      sigAlgs  = Opts.sigAlgs opts
  -- Run the connect + SMTP + TLS + cert capture as a pure 'IO'
  -- action inside the 'ipConn' bracket; the 'Scanner' state
  -- update is then a single 'scannerFail' driven by the @isOK@
  -- flag returned from the closure.
  (peerChain, isOK) <- liftIO $ ipConn peerAddr 25 tout \case
    Left IOError{..} -> case ioe_type of
      TimeExpired -> pure (SmtpError CONNECT   0 "", False)
      _           -> pure (SmtpError CONNECT 500 "", False)
    Right sock -> do
      st <- dosmtp =<< startState sigAlgs helo basenm tout llen sock
      case smtpErr st of
        DataErr err     -> pure ( ChainException $ displayException $ errLoc err st
                                , False )
        OtherErr e      -> pure ( ChainException $ displayException e
                                , False )
        ProtoErr code m -> pure ( SmtpError (smtpState st) code $ b2s m
                                , False )
        TlsHandError t  -> pure ( SmtpError (smtpState st) (-1) $ show t
                                , False )
        TlsRecvError    -> pure ( SmtpError (smtpState st) (-2) ""
                                , False )
        TlsSendError    -> pure ( SmtpError (smtpState st) (-3) ""
                                , False )
        SmtpOK
          | SmtpTLS ctx <- smtpConn st -> do
              (peerNames, peerCerts, peerTime) <- readIORef (chainRef st)
              (peerTlsVersion, peerTlsCipher, peerTlsGroup) <- tlsInfo ctx
              let matchName = namecheck refnames peerNames
                  vtime     = peerTime + fromIntegral addOff * 86400
                  (d, s)    = tlsamatch eechecks matchName vtime tlsards peerCerts
              pure ( Probed PeerProbe{matchDepth = d, matchStatus = s, ..}
                   , s == Pass )
          | otherwise
              -> pure (SmtpError STARTTLS 0 "", False)
  when (not isOK) $ scannerFail ()
  return AddrChain { peerAddr = peerAddr, peerChain = peerChain }
  where
    b2s = BC.unpack

    -- Match a TLS peer-presented name (already a 'String') against
    -- the DNS reference identifiers (canonicalised through 'd2s').
    -- Wildcard handling follows RFC 6125: '*' matches at the first
    -- label only, and only when the remainder has at least two
    -- labels (so '*.example' doesn't match the apex).
    namecheck :: [Domain] -> [String] -> Maybe String
    namecheck [] _ = Nothing
    namecheck (d:ds) names =
        let dom = d2s d
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

    -- Compare the cert's precomputed hash/SPKI bytes against the
    -- typed TLSA RRset.  The 'ByteString' fields on 'CertHashes'
    -- are converted to 'ShortByteString' for the 'T_TLSA' equality
    -- check (T_TLSA's data field is short-bytestring-shaped).
    cinfomatch depth rds CertInfo{..} =
        let u = if depth == 0 then 3 else 2
            short = SB.toShort
         in T_TLSA u 1 1 (short (_spki256 _hashes)) `elem` rds ||
            T_TLSA u 0 1 (short (_cert256 _hashes)) `elem` rds ||
            T_TLSA u 1 2 (short (_spki512 _hashes)) `elem` rds ||
            T_TLSA u 0 2 (short (_cert512 _hashes)) `elem` rds ||
            T_TLSA u 1 0 (short _spki)               `elem` rds ||
            T_TLSA u 0 0 (short _cert)               `elem` rds

    tlsamatch :: Bool
              -> Maybe String
              -> Int64
              -> [T_tlsa]
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
                       | null [u | T_TLSA u _ _ _ <- rds, u /= 3]
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

    -- A TLSA RRset is "usable" if any record has a usage from
    -- {DANE-TA, DANE-EE} = {2, 3}, a selector from {Cert, SPKI} =
    -- {0, 1}, and a matching type from {Full, SHA-256, SHA-512} =
    -- {0, 1, 2}.  Now pattern-matches on typed 'T_TLSA' record
    -- syntax instead of the old 'RD_TLSA' constructor.
    usable rds = [ u | T_TLSA u s m _ <- rds
                 , u `elem` [2,3]
                 , s `elem` [0,1]
                 , m `elem` [0,1,2] ]
