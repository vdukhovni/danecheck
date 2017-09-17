{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Dane.Scanner.DNS.Response
    ( RC(.., NoErrorRC, NXDomainRC)
    , Validity(..)
    , AD
    , Response(..)
    , RespTLSA(..)
    , AddrChain(..)
    , nodata
    , respFailed
    , respQname
    , respValidity
    , respValidated
    ) where

import qualified Data.ByteString.Char8 as BC
import           Data.UnixTime (formatUnixTimeGMT, UnixTime(..))
import           Foreign.C.Types (CTime(..))
import           Network.DNS (Domain, RCODE(..), TYPE(AAAA, CNAME))
import           Network.DNS (RData(RD_A, RD_AAAA, RD_TLSA))

import           Dane.Scanner.Util
import           Dane.Scanner.SMTP.Certs
import           Dane.Scanner.SMTP.Chain


-- | DNSSEC validation status of a query response.  A lookup might
-- fail, return insecure results, or return a secure NXDomain,
-- NODATA or an answer.
--
data Validity = Indeterminate  -- ^ Lookup failed
              | Insecure       -- ^ Lookup done, insecure answer or DoE
              | Nodomain       -- ^ Lookup done, secure NXDomain
              | Nodata         -- ^ Lookup done, secure NODATA
              | Secure         -- ^ Lookup done, host secure
    deriving (Eq)


-- | Display cached lookup status, using the correspoding
-- DNS RCODE format for the secure variants.
--
instance Show Validity where
    show Indeterminate = "Indeterminate"
    show Insecure      = "Insecure"
    show Nodomain      = "NXDomain"
    show Nodata        = "NODATA"
    show Secure        = "NoError"


-- | Raw DNS query response response code, or an  error condition.
--
data RC = DnsRC RCODE
        | DnsTimeout
        | TldMX
        | ErrRC String
        deriving (Eq)

pattern NoErrorRC  :: RC
pattern NXDomainRC :: RC
pattern NoErrorRC   = DnsRC NoErr
pattern NXDomainRC  = DnsRC NameErr

instance Show RC where
    show NoErrorRC     = "NoError"
    show NXDomainRC    = "NXDomain"
    show (DnsRC ServFail)  = "ServFail"
    show (DnsRC FormatErr) = "FormErr"
    show (DnsRC NotImpl)   = "NotImp"
    show (DnsRC Refused)   = "Refused"
    show (DnsRC rc)        = show rc
    show DnsTimeout        = "timeout"
    show TldMX             = "TldMXHost"
    show (ErrRC err)       = err


-- | DNSSEC Authentication indication from the trusted validating resolver
--
type AD = Bool


-- | Per TCP endpoint DANE TLSA-related information from DNS and an SMTP
-- connection to the server.
--
data RespTLSA =
    RespTLSA { tlsaBase   :: !Domain
             , tlsaRRset  :: !Response
             , addrChains :: [ AddrChain ]
             }

-- The essential data from a DNS lookup, RCODE, AD bit, name chain,
-- and answer RRDATA.  If not empty, the name chain starts with the
-- qname, and may include additional intermediate aliases.
--
data Response = Response
    { respRC     :: !RC              -- DNS rcode or other status
    , respAD     :: !AD              -- AD bit for answer RRset
    , respCnAD   :: !AD              -- AD bit for initial CNAME
    , respCnames :: [ Domain ]       -- CNAME chain, possibly empty
    , respBadCNs :: Maybe [Domain]   -- Invalid multi-CNAME RRset?
    , respOwner  :: !Domain          -- qname or final cname
    , respType   :: !TYPE            -- RRtype
    , respRD     :: [RData]          -- empty if no answer
    , respTLSA   :: Maybe RespTLSA   -- TLSA base and live server chains
    }

-- | If the query response entails a CNAME chain, then the qname is
-- different from the ultimate owner domain of the anwer RRset, and
-- the 'respCnames' element of the response is a non-empty list whose
-- first element is the qname.
--
respQname :: Response -- ^ Query response
          -> Domain   -- ^ Qname, usually same as owner
respQname Response{..} = headDef respOwner respCnames
{-# INLINE respQname #-}


-- | Compute the validation status of a query response.
--
respValidity :: Response -> Validity
respValidity Response{..} = case respRC of
    NoErrorRC  | not respAD  -> Insecure
               | null respRD -> Nodata
               | otherwise   -> Secure
    NXDomainRC | not respAD  -> Insecure
               | otherwise   -> Nodomain
    _                        -> Indeterminate
{-# INLINE respValidity #-}


-- | Is the response a DNSSEC-validated NoError response?
--
respValidated :: Response -> Bool
respValidated r = case respValidity r of
    Secure -> True
    Nodata -> True
    _      -> False
{-# INLINE respValidated #-}


-- | Did the lookup fail?
--
respFailed :: Response -> Bool
respFailed (respRC -> NoErrorRC)  = False
respFailed (respRC -> NXDomainRC) = False
respFailed _                      = True
{-# INLINE respFailed #-}


-- | Synthesize an empty response
--
nodata :: RC -> AD -> Domain -> TYPE -> Response
nodata rc ad owner typ = Response
    { respRC = rc
    , respAD = ad
    , respCnAD = ad
    , respCnames = []
    , respBadCNs = Nothing
    , respOwner = owner
    , respType = typ
    , respRD = []
    , respTLSA = Nothing
    }


-- | Complete hex encoding of a short-enough ByteString
--
fullhex :: BC.ByteString -> String
fullhex = BC.unpack . bs2hex


-- | Truncated in the middle hex encoding of all but the shortest ByteStrings
--
shorthex :: BC.ByteString -> String
shorthex b
    | BC.length b < 14
    = fullhex b
    | otherwise
    = fullhex (BC.take 6 b) ++ "..." ++ fullhex (BC.drop (BC.length b - 6) b)


-- | Show a response as a concatenation of a set of newline-terminated records
-- with "; trailing comments".  Certificate data from SMTP is inserted indented
-- by two spaces, with additional indentation for clarity as appropriate.
--
instance Show Response where
  show Response{..} =
      showResp respRC respAD respCnAD respCnames respBadCNs respOwner respType
          respRD ++ showTLSA respType respTLSA
    where
      sAns :: String -> AD -> Domain -> TYPE -> String -> String
      sAns rcstr ad owner typ rdstr =
            ( ++ "\n") $ unwords $
                [ BC.unpack owner
                , "IN"
                , show typ
                , rdstr
                , ";"
                , rcstr
                , if (ad) then "AD=1" else "AD=0"
                ]

      showTLSA AAAA (Just (t@RespTLSA{..})) =
          show tlsaRRset ++
          concatMap (showChain t) addrChains
      showTLSA _ _ = ""

      showChain t (AddrChain{..}) =
          let addr = case peerAddr of
                  RD_A a -> show a
                  RD_AAAA a -> show a
                  _ -> error "showChain: peerAddr not A or AAAA RData"
          in showChainInfo t addr peerChain

      showChainInfo RespTLSA{..} addr chain =
        let base = case BC.unsnoc tlsaBase of
                Just (i, l) | l == '.' -> BC.unpack i
                _           -> BC.unpack tlsaBase
        in case chain of
          SmtpError CONNECT (-1) _
              -> "  " ++ base ++ "[" ++ addr ++ "]: address reserved\n"
          SmtpError CONNECT 0 _
              -> "  " ++ base ++ "[" ++ addr ++ "]: connection timeout\n"
          SmtpError CONNECT _ _
              -> "  " ++ base ++ "[" ++ addr ++ "]: connection refused\n"
          SmtpError STARTTLS (-1) _
              -> "  " ++ base ++ "[" ++ addr ++ "]: STARTTLS failure\n"
          SmtpError STARTTLS 0 _
              -> "  " ++ base ++ "[" ++ addr ++ "]: STARTTLS not offered\n"
          SmtpError state code m
              -> "  " ++ base ++ "[" ++ addr ++ "]: " ++
                  (show state) ++ " " ++ (show code) ++ " " ++ m ++ "\n"
          ChainException ex
              -> "  " ++ base ++ "[" ++ addr ++ "]: " ++ show ex ++ "\n"
          PeerChain{..}
              -> let auth = case matchDepth of
                         Nothing -> show matchStatus
                         Just  d | Just n <- matchName
                                 -> "pass: TLSA match: depth = " ++
                                    (show d) ++ ", name = " ++ n
                                 | otherwise
                                 -> "pass: TLSA match: depth = " ++ (show d)
                  in "  " ++ base ++ "[" ++ addr ++ "]: " ++ auth ++ "\n" ++
                     showTLS peerTlsVersion peerTlsCipher ++
                     concatMap showName peerNames ++
                     concatMap showCert peerCerts
          where
              showTLS v c  = "    TLS = " ++ (show v) ++ " with " ++ (show c) ++ "\n"
              showName n = "    name = " ++ n ++ "\n"
              showCert CertInfo{..} =
                  showDepth _depth ++
                  maybe "" (showDN "Issuer" "CommonName") (cnOf _idn) ++
                  maybe "" (showDN "Issuer" "Organization") (orgOf _idn) ++
                  showLife _life ++
                  maybe "" (showDN "Subject" "CommonName") (cnOf _sdn) ++
                  maybe "" (showDN "Subject" "Organization") (orgOf _sdn) ++
                  showHashes (if_ (_depth == 0) 3 2) _hashes _cert _spki
              showDepth depth = "    depth = " ++ (show depth) ++ "\n"
              showDN which what val =
                  let indent = replicate 6 ' '
                   in indent ++ unwords [which, what, "=", val] ++ "\n"
              showLife (before, after) =
                showTime "Before" before ++
                showTime "After"  after
              showTime n t =
                  let ut = UnixTime (CTime t) 0
                      st = BC.unpack $ formatUnixTimeGMT (BC.pack "%FT%TZ") ut
                  in "      not" ++ n ++ " = " ++ st ++ "\n"
              showHashes u CertHashes{..} _cert _spki =
                  showHash tlsaRRset "cert sha256" u 0 1 _cert256 ++
                  showHash tlsaRRset "pkey sha256" u 1 1 _spki256 ++
                  showHash tlsaRRset "cert sha512" u 0 2 _cert512 ++
                  showHash tlsaRRset "pkey sha512" u 1 2 _spki512 ++
                  showHash tlsaRRset "full cert" u 0 0 _cert ++
                  showHash tlsaRRset "full spki" u 1 0 _spki

              -- | Show all matching data, and data with the same selector and
              -- matching type as present in some TLSA record, and always show
              -- the SPKI(1) SHA2-256 hashes.  Full(0) data may be abbreviated
              --
              showHash t l u s m bs =
                  if matched t
                  then if m /= 0
                       then "      " ++ l ++ " [matched] <- " ++
                              (show $ RD_TLSA u s m bs) ++ "\n"
                       else "      " ++ l ++ " [matched] <- " ++
                              unwords [ show u
                                      , show s
                                      , show m
                                      , shorthex bs ]
                  else if (s == 1 && m == 1) || wanted t
                       then "      " ++ l ++ " [nomatch] <- " ++
                              (show $ RD_TLSA u s m bs) ++ "\n"
                       else ""
                  where
                      wantsm (RD_TLSA _ s' m' _) = (s' == s && m' == m)
                      wantsm _ = False
                      wanted Response{respRD=rd} = any wantsm rd
                      matched Response{respRD=rd} = RD_TLSA u s m bs `elem` rd

      -- | Convert the result of a DNS query to String form.  We prepend any
      -- CNAME RRs leading to the answer RRset, and then all the answers.
      --
      -- Even if the final RRset carries an NXDOMAIN RCODE, any intermediate
      -- CNAME values are of necessity NOERROR.
      --
      showResp :: RC
               -> AD             -- AD of final answer
               -> AD             -- AD of first CNAME
               -> [Domain]       -- CNAME chain
               -> Maybe [Domain] -- Bad CNAME RRset
               -> Domain         -- Final owner domain
               -> TYPE
               -> [RData]
               -> String

            -- No answer, e.g. NODATA, NXDOMAIN.
      showResp NoErrorRC ad _ [] Nothing owner typ [] =
        sAns "NODATA" ad owner typ "?"
      showResp rc ad _ [] Nothing owner typ [] =
        sAns (show rc) ad owner typ "?"

      -- One or more answers:
      showResp rc ad _ [] Nothing owner typ rds =
        concatMap (sAns (show rc) ad owner typ . show) rds

      -- Invalid final CNAME:
      showResp _ _ ad' [] (Just bad) owner _ _ =
        concatMap (sAns "CnameErr" ad' owner CNAME) $ map BC.unpack bad

      -- | Final valid CNAME.  Consumes ad', with ad used for subsequent
      -- RData output.
      --
      showResp rc ad ad' (alias:[]) bad cname typ rds =
        sAns (show NoErrorRC) ad' alias CNAME (BC.unpack cname) ++
          showResp rc ad ad [] bad cname typ rds

      -- Two or more valid CNAMEs.  Only the first one gets tagged with the
      -- ad' security status.
      --
      showResp rc ad ad' (alias:aliases@(cname:_)) bad owner typ rds =
        let out = sAns (show NoErr) ad' alias CNAME $ BC.unpack cname
        in out ++ showResp rc ad ad aliases bad owner typ rds
