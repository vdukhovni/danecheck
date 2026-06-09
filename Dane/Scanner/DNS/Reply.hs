{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Dane.Scanner.DNS.Reply
-- Description : Typed DNS-reply data + per-RRtype printing
-- Copyright   : (c) Viktor Dukhovni, 2018-2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
--
-- The 'Reply a' type carries the per-RRtype query result: the
-- 'RC' rcode\/error, the AD bit, optional CNAME\/DNAME chain
-- bookkeeping, the final-owner name, and the answer RRset as a
-- typed @[a]@ list.  Because @a@ is a concrete dnsbase RR data
-- type (e.g. 'T_a', 'T_dnskey', 'T_tlsa'), callers can pattern
-- match on record fields directly instead of unwrapping an
-- existential 'RData'.
--
-- The 'put*' family produces continuation-style 'Builder' output
-- for streaming results to stdout as they become available
-- (danecheck prints each MX-host's results as soon as that host's
-- A\/AAAA\/TLSA\/chain probes are done).
--
module Dane.Scanner.DNS.Reply
    ( AD
    , Dname(..)
    , NameChain(..)
    , RC( DnsRC, DnsTimeout, DnsXprtErr, TldMX, BadName, CnameErr, ErrRC
        , NoErrorRC, NXDomainRC
        )
    , Reply(..)
    , TlsaInfo(..)
    , Validity(..)
    , chainOf
    , noReply
    , putReplyA
    , putReplyAaaa
    , putReplyAny
    , putReplyDnskey
    , putReplyDs
    , putReplyMx
    , repCnAD
    , repCnames
    , repQname
    , repValidated
    , repValidity
    , showXprtErr
    ) where

import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Short as SB
import qualified Data.Text as T
import qualified Data.Text.Encoding as E
import Control.Exception (IOException)
import Data.ByteString (ByteString)
import Data.Char (isControl, ord)
import Data.UnixTime (formatUnixTimeGMT, UnixTime(..))
import Data.Word (Word8)
import Foreign.C.Types (CTime(..))
import GHC.IO.Exception (ioe_description, ioe_filename, ioe_location)
import Text.Printf (printf)

import Data.IP (IP(IPv4, IPv6))
import Net.DNSBase ( Domain, RCODE(NOERROR, NXDOMAIN, SERVFAIL, FORMERR, NOTIMP, REFUSED)
                   , RRCLASS(IN)
                   , RRTYPE(A, AAAA, CNAME, DNAME, DS, DNSKEY, MX, TLSA)
                   , T_a(T_A), T_aaaa(T_AAAA)
                   , T_dnskey, T_ds, T_mx, T_tlsa, X_tlsa(..)
                   , toHost
                   )
import Net.DNSBase.Present
import qualified Network.TLS as TLS

import Dane.Scanner.Util
import Dane.Scanner.SMTP.Certs (CertInfo(..), CertHashes(..), cnOf, orgOf)
import Dane.Scanner.SMTP.Chain
    ( AddrChain(..), PeerChain(..), PeerProbe(..), SmtpState(..)
    )


----------------------------------------------------------------------
-- Validity and RC
----------------------------------------------------------------------

-- | DNSSEC validation status of a query response.  A lookup might
-- fail, return insecure results, or return a secure NXDomain,
-- NODATA, or a regular answer.
data Validity
    = Indeterminate  -- ^ Lookup failed
    | Insecure       -- ^ Lookup done, insecure answer or DoE
    | Nodomain       -- ^ Lookup done, secure NXDomain
    | Nodata         -- ^ Lookup done, secure NODATA
    | Secure         -- ^ Lookup done, host secure
    deriving (Eq)

instance Show Validity where
    show Indeterminate = "Indeterminate"
    show Insecure      = "Insecure"
    show Nodomain      = "NXDomain"
    show Nodata        = "NODATA"
    show Secure        = "NoError"

instance Presentable Validity where
    present v = present (show v :: String)


-- | DNS query response code or error condition.
data RC = DnsRC RCODE
        | DnsTimeout
        | DnsXprtErr String      -- ^ Pre-rendered network/transport error
        | TldMX                  -- ^ MX host is at TLD or root level
        | BadName                -- ^ MX hostname has a disallowed
                                 --   label shape (e.g. ATTRLEAF, ULABEL,
                                 --   WILDLABEL, OCTET) — kept in the
                                 --   output but not looked up
        | CnameErr [Domain]      -- ^ Invalid multi-CNAME RRset; the targets
                                 --   are recorded for display
        | ErrRC String
        deriving (Eq)

pattern NoErrorRC :: RC
pattern NoErrorRC = DnsRC NOERROR

pattern NXDomainRC :: RC
pattern NXDomainRC = DnsRC NXDOMAIN

instance Show RC where
    show NoErrorRC         = "NoError"
    show NXDomainRC        = "NXDomain"
    show (DnsRC SERVFAIL)  = "ServFail"
    show (DnsRC FORMERR)   = "FormErr"
    show (DnsRC NOTIMP)    = "NotImp"
    show (DnsRC REFUSED)   = "Refused"
    show (DnsRC rc)        = presentString rc mempty
    show DnsTimeout        = "timeout"
    show (DnsXprtErr s)    = s
    show TldMX             = "TldMXHost"
    show BadName           = "Invalid MX hostname"
    show (CnameErr _)      = "CnameErr"
    show (ErrRC err)       = err

instance Presentable RC where
    present rc = present (show rc :: String)


-- | The DNS library sets the 'ioe_filename' field of network I/O
-- errors to the protocol (@UDP@ or @TCP@) and the 'ioe_location'
-- to the address and port of the peer nameserver.  We render
-- those into a single string at error-capture time so 'RC' can
-- stay 'Eq'-derivable and survive any future serialisation.
showXprtErr :: IOException -> String
showXprtErr = (\a b c -> a ++ b ++ c)
    <$> maybe "" (++ ": ") . ioe_filename
    <*> ( ++ "; ") . ioe_location
    <*> ioe_description


----------------------------------------------------------------------
-- AD bit and chain bookkeeping
----------------------------------------------------------------------

-- | DNSSEC authentication-data bit from the response header.
type AD = Bool

-- | DNAME source/target pair recorded during answer-section parsing.
data Dname = Dname
    { dnameOwner  :: Domain
    , dnameTarget :: Domain
    }

-- | CNAME / DNAME chain bookkeeping.  Present only when the answer
-- was reached via aliasing (or DNAMEs were observed); 'ncCnames'
-- is non-empty in the common chain case and starts with the qname,
-- followed by any intermediate aliases.
data NameChain = NameChain
    { ncCnames :: [Domain]   -- ^ qname : intermediates; empty if
                             --   only DNAMEs were seen
    , ncDnames :: [Dname]    -- ^ DNAME source/target pairs
    , ncCnAD   :: AD         -- ^ AD bit of the initial CNAME RRset
    }


----------------------------------------------------------------------
-- Reply
----------------------------------------------------------------------

-- | Per-RRtype-specialized reply.  Carries the typed answer RRset
-- @[a]@, the rcode, the AD bit, and optional chain provenance.
data Reply a = Reply
    { repRC    :: RC
    , repAD    :: AD
    , repChain :: Maybe NameChain
    , repOwner :: Domain
    , repRD    :: [a]
    }

-- | AD bit of the initial CNAME RRset, falling back to 'repAD'
-- when the response was reached without aliasing.
repCnAD :: Reply a -> AD
repCnAD r = maybe (repAD r) ncCnAD (repChain r)
{-# INLINE repCnAD #-}

-- | Intermediate alias names from qname to (just before) the
-- final owner.  Empty when the response was reached without
-- CNAMEs.
repCnames :: Reply a -> [Domain]
repCnames r = maybe [] ncCnames (repChain r)
{-# INLINE repCnames #-}

-- | DNAME source/target pairs observed in the answer section.
repDnames :: Reply a -> [Dname]
repDnames r = maybe [] ncDnames (repChain r)
{-# INLINE repDnames #-}

-- | Qname of the original query (first element of the CNAME
-- chain when present); falls back to the ultimate owner domain
-- when no aliasing was involved.
repQname :: Reply a -> Domain
repQname r = headDef (repOwner r) (repCnames r)
{-# INLINE repQname #-}

-- | DNSSEC validation status of a query response.
repValidity :: Reply a -> Validity
repValidity Reply{..} = case repRC of
    NoErrorRC  | not repAD  -> Insecure
               | null repRD -> Nodata
               | otherwise  -> Secure
    NXDomainRC | not repAD  -> Insecure
               | otherwise  -> Nodomain
    _                       -> Indeterminate
{-# INLINE repValidity #-}

-- | Is the response a DNSSEC-validated NoError response?
repValidated :: Reply a -> Bool
repValidated r = case repValidity r of
    Secure -> True
    Nodata -> True
    _      -> False
{-# INLINE repValidated #-}

-- | Build a 'Maybe NameChain' from possibly-empty alias and DNAME
-- lists.  Returns 'Nothing' when neither list contributes anything.
chainOf :: [Domain] -> [Dname] -> AD -> Maybe NameChain
chainOf [] [] _    = Nothing
chainOf cs ds cnAD = Just NameChain
    { ncCnames = cs
    , ncDnames = ds
    , ncCnAD   = cnAD
    }

-- | Synthetic empty 'Reply'.  The RR type is implicit in the type
-- parameter @a@.
noReply :: RC -> AD -> Domain -> Reply a
noReply rc ad owner = Reply
    { repRC    = rc
    , repAD    = ad
    , repChain = Nothing
    , repOwner = owner
    , repRD    = []
    }


----------------------------------------------------------------------
-- TLSA bundle
----------------------------------------------------------------------

-- | Per-host DNS-side TLSA information.  Holds the TLSA base
-- domain and the typed TLSA RRset reply.  The cert-chain probes
-- (one 'AddrChain' per scanned IP) are passed separately to
-- 'putReplyAaaa' rather than packaged here, so the print-as-you-go
-- driver can attach them at the right moment without buffering
-- the chains alongside the TLSA bundle.
data TlsaInfo = TlsaInfo
    { tlsaBase  :: !Domain        -- ^ TLSA base (host name, the prefix
                                  --   @_25._tcp.@ is added at query time)
    , tlsaRRset :: !(Reply T_tlsa)
    }


----------------------------------------------------------------------
-- Per-RRtype Builder rendering
----------------------------------------------------------------------

-- | Render a 'Reply' for any concrete RR-data type.  The 'RRTYPE'
-- parameter pins down the slot's nominal type for the
-- owner\/IN\/type lines (and for the AD-suppression test on
-- validated DS\/DNSKEY answers).  'CnameErr' is dispatched at the
-- top: DNAMEs print as usual, then the offending CNAME targets
-- emit as failed CNAME records.  All other RC values delegate to
-- 'putRespBody' for the CNAME-chain prefix + answer RRset.
putReplyAny :: Presentable a => RRTYPE -> Reply a -> Builder -> Builder
putReplyAny typ r@Reply{..} = case repRC of
    CnameErr bad ->
        putDnames repAD (repDnames r)
        . putBadCNames (repCnAD r) repOwner bad
    _ ->
        putRespBody repRC repAD (repCnAD r) (repDnames r) (repCnames r)
                    repOwner typ repRD

-- Per-slot renderers — wrap 'putReplyAny' with the slot's RR type.
putReplyDs :: Reply T_ds -> Builder -> Builder
putReplyDs = putReplyAny DS

putReplyDnskey :: Reply T_dnskey -> Builder -> Builder
putReplyDnskey = putReplyAny DNSKEY

putReplyMx :: Reply T_mx -> Builder -> Builder
putReplyMx = putReplyAny MX

putReplyA :: Reply T_a -> Builder -> Builder
putReplyA = putReplyAny A

-- | AAAA reply renderer; also emits the per-host TLSA bundle and
-- SMTP cert-chain output appended after the AAAA records.
putReplyAaaa :: Maybe TlsaInfo -> [AddrChain] -> Reply T_aaaa
             -> Builder -> Builder
putReplyAaaa mtlsa chains r = putReplyAny AAAA r . putHostTlsa mtlsa chains


-- | Render an answer RRset to a CPS builder.  Prepends any CNAME
-- RRs leading to the answer RRset, then all the answers.  Even if
-- the final RRset carries an NXDOMAIN RCODE, any intermediate
-- CNAME values are necessarily NOERROR.
putRespBody :: Presentable a
            => RC
            -> AD             -- AD of final answer
            -> AD             -- AD of first CNAME
            -> [Dname]        -- DNAME chain
            -> [Domain]       -- CNAME chain
            -> Domain         -- Final owner domain
            -> RRTYPE
            -> [a]
            -> Builder
            -> Builder

-- No answer, e.g. NODATA, NXDOMAIN.
putRespBody (DnsRC NOERROR) ad _ [] [] owner typ [] =
    putAns "NODATA" ad owner (presentSp typ . presentSp '?')
putRespBody rc ad _ [] [] owner typ [] =
    putAns rc ad owner (presentSp typ . presentSp '?')

-- One or more answers.  Validated DS\/DNSKEY answer RRs are
-- suppressed (the rcode-comment line is sufficient context).
-- The RR-type label is emitted explicitly because the typed
-- 'T_*' 'Presentable' instances render only the record fields,
-- so the @owner IN TYPE rdata@ line shape needs the @TYPE@
-- prepended here.
putRespBody rc ad _ [] [] owner typ rds =
    if ad && typ `elem` [DS, DNSKEY] && nonempty rds
    then id
    else flip (foldr f) rds
  where
    f rd = putAns rc ad owner (presentSp typ . presentSp rd)

-- Final valid CNAME.  Consumes ad'; ad is used for subsequent RData.
putRespBody rc ad ad' [] (alias:[]) cname typ rds =
    putAns NOERROR ad' alias (presentSp CNAME . presentSp cname)
    . putRespBody rc ad ad [] [] cname typ rds

-- Two or more valid CNAMEs.  Only the first gets the ad' security tag.
putRespBody rc ad ad' [] (alias:aliases@(cname:_)) owner typ rds =
    putAns NOERROR ad' alias (presentSp CNAME . presentSp cname)
    . putRespBody rc ad ad [] aliases owner typ rds

-- One or more DNAMEs.  The security status of even the first DNAME
-- record cannot be reliably inferred from the first CNAME's, so
-- 'ad' is used for all of them.
putRespBody rc ad ad' (dname:dnames) aliases owner typ rds =
    putAns NOERROR ad q (presentSp DNAME . presentSp d)
    . putRespBody rc ad ad' dnames aliases owner typ rds
  where
    q = dnameOwner dname
    d = dnameTarget dname


-- | Generic record-line emitter:  @owner IN <rdata> ; <rcode> AD=<n>@.
putAns :: Presentable rc
       => rc -> AD -> Domain -> (Builder -> Builder) -> Builder -> Builder
putAns rc ad owner rdbuilder =
    present owner
    . presentSp IN
    . rdbuilder
    . presentSp ';'
    . presentSp rc
    . presentSpLn @String (if_ ad "AD=1" "AD=0")

-- | Print the DNAME chain.  The security status of even the first
-- DNAME record cannot be reliably inferred from the security
-- status of the first CNAME, so 'ad' applies to all of them.
putDnames :: AD -> [Dname] -> Builder -> Builder
putDnames ad = flip (foldr f)
  where
    f (Dname q d) =
        putAns NOERROR ad q (presentSp DNAME . presentSp d)

-- | Emit the targets of a multi-CNAME RRset as failed CNAME
-- records under a "CnameErr" rcode comment.
putBadCNames :: AD -> Domain -> [Domain] -> Builder -> Builder
putBadCNames ad' owner = flip (foldr f)
  where
    f rd = putAns "CnameErr" ad' owner b
      where
        b = presentSp CNAME . presentSp rd


----------------------------------------------------------------------
-- TLSA + per-IP SMTP chain rendering
----------------------------------------------------------------------

-- | TLSA RRset display + per-IP SMTP chain output, appended after
-- the AAAA reply for an MX host.  No-op when the host has no
-- TLSA bundle attached.
putHostTlsa :: Maybe TlsaInfo -> [AddrChain] -> Builder -> Builder
putHostTlsa Nothing _ k = k
putHostTlsa (Just t@TlsaInfo{..}) cs k =
    putReplyAny TLSA tlsaRRset (foldr f k cs)
  where
    f AddrChain{..} = putChainInfo t peerAddr peerChain


-- | Per-IP chain info: TLSA-base header line, the 'AddrChain'
-- outcome, and (for the success case) the per-cert chain display.
putChainInfo :: TlsaInfo -> IP -> PeerChain -> Builder -> Builder
putChainInfo TlsaInfo{..} addr chain =
    indent2
    . present (toHost tlsaBase)
    . case addr of
        IPv4 ip4 -> presentCharSep '[' (T_A ip4)
        IPv6 ip6 -> presentCharSep '[' (T_AAAA ip6)
    . present @String "]:"
    . case chain of
         ChainException msg
             -> presentSpLn msg
         SmtpError CONNECT (-1) _
             -> presentSpLn @String "address reserved"
         SmtpError CONNECT 0 _
             -> presentSpLn @String "connection timeout"
         SmtpError CONNECT _ _
             -> presentSpLn @String "connection refused"
         SmtpError STARTTLS (-1) _
             -> presentSpLn @String "STARTTLS failure"
         SmtpError STARTTLS 0 _
             -> presentSpLn @String "STARTTLS not offered"
         SmtpError state code m
             -> presentSp (show state :: String)
                . presentSp code
                . presentSpLn m
         Probed PeerProbe{..}
             -> let auth = case matchDepth of
                        Nothing -> show matchStatus
                        Just d | Just n <- matchName
                               -> "pass: TLSA match: depth = " ++ show d
                                  ++ ", name = " ++ n
                               | otherwise
                               -> "pass: TLSA match: depth = " ++ show d
                in presentSpLn auth
                   . putTLS peerTlsVersion peerTlsCipher peerTlsGroup peerCerts
                   . flip (foldr putName) peerNames
                   . flip (foldr putCert) peerCerts
  where
    putTLS v c g cs =
        indent4
        . present @String "TLS ="
        . presentSp (show v :: String)
        . case g of
            Nothing  -> presentSp @String "with"
                        . presentSpLn (show c :: String)
            Just grp -> presentSp @String "with"
                        . presentSp (show c :: String)
                        . present ','
                        . present (show grp :: String)
                        . leafAlg v cs
                        . present '\n'
    leafAlg :: TLS.Version -> [CertInfo] -> Builder -> Builder
    leafAlg v (CertInfo{..}:_) | v > TLS.TLS12 =
        present ',' . present (show _alg :: String)
    leafAlg _ _ = id

    putName n =
        indent4
        . present @String "name ="
        . presentSp n
        . present '\n'

    putCert ci@CertInfo{..} =
        putDepth _depth
        . maybe id (putDN "Issuer"  "CommonName")   (DnDisplay <$> cnOf _idn)
        . maybe id (putDN "Issuer"  "Organization") (DnDisplay <$> orgOf _idn)
        . putLife _life
        . maybe id (putDN "Subject" "CommonName")   (DnDisplay <$> cnOf _sdn)
        . maybe id (putDN "Subject" "Organization") (DnDisplay <$> orgOf _sdn)
        . putHashes (if_ (_depth == 0) 3 2) ci

    putDepth depth =
        indent4
        . present @String "depth ="
        . presentSpLn depth

    putDN which what val =
        indent6
        . present @String which
        . presentSp @String what
        . presentSp '='
        . presentSpLn val

    putLife (before, after) =
        putTime "notBefore" before
        . putTime "notAfter"  after

    putTime n t =
        indent6
        . present @String n
        . presentSp '='
        . presentSpLn gmtime
      where
        gmtime = formatUnixTimeGMT (BC.pack "%FT%TZ") (UnixTime (CTime t) 0)

    -- Print policy: show all hashes that match a TLSA RR, show all
    -- hashes whose (selector, matching-type) pair appears in the
    -- RRset, and always show the SPKI SHA2-256 entry.  Full(0)
    -- payloads are truncated by 'shorthex'.
    putHashes u ci =
        putHash tlsaRRset "cert sha256" u 0 1 (_cert256 (_hashes ci))
        . putHash tlsaRRset "pkey sha256" u 1 1 (_spki256 (_hashes ci))
        . putHash tlsaRRset "cert sha512" u 0 2 (_cert512 (_hashes ci))
        . putHash tlsaRRset "pkey sha512" u 1 2 (_spki512 (_hashes ci))
        . putHash tlsaRRset "full cert"   u 0 0 (_cert ci)
        . putHash tlsaRRset "full spki"   u 1 0 (_spki ci)

    putHash :: Reply T_tlsa
            -> String -> Word8 -> Word8 -> Word8 -> ByteString
            -> Builder -> Builder
    putHash t l u s m hash
        | matched || (s == 1 && m == 1) || wanted
            = indent6
              . present l
              . presentSp matchstr
              . presentSp @String "<- "
              . fmtHash
        | otherwise = id
      where
        rd       = repRD t
        sbHash   = SB.toShort hash
        matched  = T_TLSA u s m sbHash `elem` rd
        wanted   = any (\(T_TLSA _ s' m' _) -> s' == s && m' == m) rd
        matchstr | matched   = "[matched]" :: String
                 | otherwise = "[nomatch]"
        fmtHash =
            present u
            . presentSp s
            . presentSp m
            . presentSpLn (shorthex hash)


indent2, indent4, indent6 :: Builder -> Builder
indent2 = present @String "  "
indent4 = present @String "    "
indent6 = present @String "      "


-- | Wrapper for a certificate Distinguished-Name field
-- ('cnOf'\/'orgOf' result) that should be rendered as Unicode
-- display text rather than DNS wire-form bytes.  Use at sites
-- that print human-readable cert fields:
--
-- > presentSpLn (DnDisplay orgString)
--
-- The 'Presentable' instance emits the UTF-8 bytes of the
-- underlying 'String' verbatim, matching the on-disk byte form
-- the certificate carried (for modern UTF8String certs).
-- Unicode control characters (Cc category — C0 + DEL + C1) are
-- escaped as @\\xNN@; everything else passes through.
--
-- The output shape mirrors a (sufficiently recent) OpenSSL
-- @x509 -nameopt utf8,-esc_msb@ rendering.  Distinct from the
-- byte-per-'Char' 'Presentable' 'String' instance dnsbase
-- provides (correct for DNS wire-form labels but wrong for
-- arbitrary Unicode text) and from 'Net.DNSBase.DnsUtf8Text'
-- (which escapes every non-printable byte as @\\NNN@ decimal).
newtype DnDisplay = DnDisplay String

instance Presentable DnDisplay where
    present (DnDisplay s) = present (utf8Bytes s)
      where
        -- Pre-encode the input as UTF-8 bytes carried in a
        -- 'String' whose 'Char's all have code values < 256, then
        -- feed it through the existing byte-per-'Char' 'String'
        -- presentation path.
        utf8Bytes :: String -> String
        utf8Bytes = BC.unpack . E.encodeUtf8 . T.pack . concatMap escChar

        -- Escape control characters (Cc: C0 + DEL + C1) as the
        -- DNS-style @\\DDD@ three-decimal-digit byte escape used
        -- throughout the rest of the output for domain labels.
        -- This is the safety-critical category: it includes LF,
        -- CR, BS, ESC, etc., any of which could otherwise break
        -- the per-record one-line shape, drive the terminal
        -- off-screen, or smuggle ANSI escape sequences out of a
        -- malicious certificate.  The fixed three-digit width is
        -- unambiguous regardless of what follows.  The backslash
        -- itself is escaped as @\\\\@ so a literal @\\DDD@
        -- sequence in a cert stays distinguishable from an
        -- actually-escaped control byte.
        escChar c | isControl c = printf "\\%03d" (ord c)
                  | c == '\\'   = "\\\\"
                  | otherwise   = [c]

-- | Truncated in the middle hex encoding of all but the shortest
-- ByteStrings.
shorthex :: ByteString -> ByteString
shorthex b
    | BC.length b < 65 = bs2hex b
    | otherwise        = bs2hex (BC.take 31 b)
                         <> BC.pack "..."
                         <> bs2hex (BC.drop (BC.length b - 31) b)
