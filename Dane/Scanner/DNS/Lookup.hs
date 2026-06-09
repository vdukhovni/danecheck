{-# LANGUAGE RecordWildCards        #-}
{-# LANGUAGE RequiredTypeArguments  #-}

-- |
-- Module      : Dane.Scanner.DNS.Lookup
-- Description : DNS lookup layer for the scanner.
--
-- Issues a DNS query at the slot's RR type (derived from the
-- caller's type parameter via 'rdType') and packages the result
-- as a typed 'Reply a' carrying the answer RRset narrowed to
-- @[a]@, the AD bit, and any CNAME or DNAME chain provenance
-- that led to the final owner.  'rawReply' \/ 'rawReplyCD' are
-- the two public entry points; both share an implementation
-- parameterised over 'QueryControls'.
--
-- The CNAME walk uses 'Net.DNSBase.RRSet.rrSetsFromList' to group
-- the answer section by RRset and 'Data.Map.Strict' to look up
-- the chain; 'M.alterF (, Just []) (CNAME, owner)' fetches the
-- CNAME RRset and replaces it with @[]@ in a single pass, so a
-- malicious CNAME loop cannot be traversed twice.  When the chain
-- as a whole is not secure and the query is for A/AAAA,
-- 'cnameAdProbe' issues a separate CNAME query to recover the
-- source-zone signedness (see RFC 7672, section 2.1.3).
--
module Dane.Scanner.DNS.Lookup
    ( dnsConf
    , rawReply
    , rawReplyCD
    ) where

import qualified Data.Map.Strict as M
import           Control.Monad.Trans.Except (ExceptT(ExceptT))
import           Data.List (partition, sort)
import           Data.List.NonEmpty (NonEmpty(..))
import           Data.Maybe (mapMaybe)

import qualified Net.DNSBase as DNS
import           Net.DNSBase ( Domain, DNSFlags(..), KnownRData, QueryControls
                             , RR(..), RRTYPE(..), RRCLASS(..)
                             , T_dname(..), X_domain(..)
                             , canonicalise, rdType, rrDataCast )
import           Net.DNSBase.Lookup (lookupRawCtl)
import           Net.DNSBase.RRSet (RRSet(..), rrSetsFromList)
import           Net.DNSBase.Resolver (DNSIO, Resolver, ResolvSeed)

import qualified Dane.Scanner.Opts as Opts
import           Dane.Scanner.DNS.Reply


-- | Single low-level DNS query.  CD-bit selection is via the
-- 'QueryControls' argument; see 'rawReply' / 'rawReplyCD'.
rawDnsLookup :: Resolver
             -> QueryControls
             -> Domain
             -> RRTYPE
             -> IO (RC, AD, [RR])
rawDnsLookup rv qctls qname typ = do
    reply <- lookupRawCtl rv qctls qname IN typ
    pure $ case reply of
        Left (DNS.NetworkError n)
            | DNS.TimeoutExpired     <- n -> (DnsTimeout,    False, [])
            | DNS.RetryLimitExceeded <- n -> (DnsTimeout,    False, [])
            | DNS.NetworkFailure e   <- n -> (DnsXprtErr (showXprtErr e), False, [])
        Left e   -> (ErrRC (show e),  False, [])
        Right msg -> let !fl = DNS.dnsMsgFl msg
                         !ad = DNS.maskDNSFlags fl ADflag /= mempty
                         !rc = DNS.dnsMsgRC msg
                         !an = DNS.dnsMsgAn msg
                      in (DnsRC rc, ad, an)


-- | Probe the source-zone signedness of a CNAMEd MX host name
-- (RFC 7672, section 2.1.3).
--
-- When an A/AAAA reply is reached via a CNAME and the answer
-- chain as a whole is not secure, the A/AAAA RRsets sit on the
-- /target/ side of the CNAME and so reflect the target zone's
-- signedness; they say nothing about whether the source zone
-- (the MX host's own zone) is signed.  The source zone may still
-- publish authentic TLSA records at @_25._tcp.\<mx-host\>@ even
-- when the target zone is unsigned.  Querying TLSA directly is
-- unsafe in that case because out-of-spec name servers serving
-- the target may @SERVFAIL@\/@NOTIMP@ on TLSA, so we issue this
-- CNAME query at the MX host name and consult only the AD bit
-- of the result.
cnameAdProbe :: Resolver -> Domain -> IO (RC, AD)
cnameAdProbe rv qname = do
    (rc, ad, _) <- rawDnsLookup rv mempty qname CNAME
    pure (rc, ad)


-- | Issue a DNS query at the slot's RR type and return the typed
-- 'Reply a' directly.  The RR type is supplied as a required
-- visible type argument (no @\@@ needed at the call site).  The
-- CnAD probe for A\/AAAA replies that arrive over an insecure
-- CNAME chain happens inside 'buildReply'.
rawReply :: forall a -> KnownRData a => Resolver -> Domain -> IO (Reply a)
rawReply a = rawReply' a mempty
{-# INLINE rawReply #-}

-- | 'rawReply' with the CD bit set.  Used to probe a name that
-- returned bogus / SERVFAIL: if the same query with the CD bit
-- set succeeds, the upstream zone is signed but at least one
-- record is bogus.
rawReplyCD :: forall a -> KnownRData a => Resolver -> Domain -> IO (Reply a)
rawReplyCD a = rawReply' a (DNS.QctlFlags (DNS.setFlagBits CDflag))
{-# INLINE rawReplyCD #-}


-- | Shared implementation of 'rawReply' / 'rawReplyCD'.
rawReply' :: forall a -> KnownRData a
          => QueryControls -> Resolver -> Domain -> IO (Reply a)
rawReply' a qctls rv qname = do
    let typ = rdType a
    (rc, ad, an) <- rawDnsLookup rv qctls qname typ
    case rc of
        NoErrorRC  -> buildReply rv rc ad qname typ an
        NXDomainRC -> buildReply rv rc ad qname typ an
        _          -> pure (noReply rc ad qname)


-- | Process the answer section of a NOERROR / NXDOMAIN response
-- into a typed 'Reply a'.  Extracts DNAMEs separately
-- (informational), groups the CNAME and qtype RRs into an RRset
-- map keyed by @(RRTYPE, canonical-owner)@, then walks the CNAME
-- chain via 'M.alterF'-with-deletion so that pathological cycles
-- cannot be re-traversed.  A multi-CNAME RRset at any owner
-- along the chain yields a 'Reply' with 'repRC' set to
-- 'CnameErr' carrying the offending targets; otherwise the chain
-- walk sets 'repOwner' and 'repChain' (when any CNAMEs or DNAMEs
-- were observed), and the answer-section RRset at the final
-- owner is narrowed to @[a]@ via 'rrDataCast' to populate
-- 'repRD'.
buildReply :: forall a. KnownRData a
           => Resolver -> RC -> AD -> Domain -> RRTYPE -> [RR]
           -> IO (Reply a)
buildReply rv rc ad qname typ rs = do
    let -- DNAMEs are pulled out separately: they are informational
        -- and not part of the CNAME walk.
        (dnameRRs, others) = partition ((== DNAME) . DNS.rrType) rs
        ds = [ Dname (rrOwner rr) target
             | rr <- dnameRRs
             , Just (T_DNAME target) <- [rrDataCast rr]
             ]
        -- Filter to IN-class records that can participate in the
        -- chain walk: the CNAMEs that drive it and the qtype that
        -- terminates it.  Group into RRsets, then key the map by
        -- (RRTYPE, canonical-owner) so that lookups don't depend
        -- on the wire-form casing of owner names.
        relevant = [ rr | rr <- others
                        , rrClass rr == IN
                        , let t = DNS.rrType rr
                        , t == typ || t == CNAME ]
        sm0 :: M.Map (RRTYPE, Domain) [RR]
        sm0 = M.fromList
                [ ((rrSetType s, canonicalise (rrSetOwner s)), rrSetRecs s)
                | s <- rrSetsFromList relevant
                ]
    case walkChain qname sm0 [] of
        BadCNames bad ->
            pure Reply
                { repRC    = CnameErr bad
                , repAD    = ad
                , repChain = chainOf [] ds ad
                , repOwner = qname
                , repRD    = []
                }
        Walked owner aliases -> do
            let ans :: [a]
                ans = case M.lookup (typ, canonicalise owner) sm0 of
                        Nothing  -> []
                        Just rrs -> sort (mapMaybe rrDataCast rrs)
            cnAD <-
                if rc == NoErrorRC
                   && not ad
                   && typ `elem` [A, AAAA]
                   && not (null aliases)
                  then do
                    (rc', ad') <- cnameAdProbe rv qname
                    -- If the probe didn't return NoError, fall
                    -- back to the chain's AD bit (which is False
                    -- here).
                    pure $ case rc' of
                        NoErrorRC -> ad'
                        _         -> ad
                  else
                    pure ad
            pure Reply
                { repRC    = rc
                , repAD    = ad
                , repChain = chainOf aliases ds cnAD
                , repOwner = owner
                , repRD    = ans
                }


-- | Result of walking a CNAME chain.
data ChainResult
    = BadCNames [Domain]
      -- ^ Multi-CNAME RRset detected; the offending targets are
      -- recorded for the 'CnameErr' RC.
    | Walked    !Domain   ![Domain]
      -- ^ Final owner reached, plus the alias list with @qname@
      -- at the head and the name whose CNAME terminated the walk
      -- at the tail.  Empty alias list means no chain was
      -- followed.


-- | Walk a CNAME chain starting at @owner@.  At each step at most
-- one CNAME may match the current owner; multiple matches abort
-- the walk via 'BadCNames'.  The CNAME entry under each visited
-- owner is removed from the map as we traverse it
-- ('M.alterF (, Just []) (CNAME, owner)' fetches and replaces in
-- one pass), so a malicious CNAME loop cannot be walked twice.
walkChain :: Domain
          -> M.Map (RRTYPE, Domain) [RR]
          -> [Domain]    -- ^ aliases accumulated so far, in reverse
          -> ChainResult
walkChain owner sm acc =
    let key = (CNAME, canonicalise owner)
        (cnameRRs, sm') = M.alterF (, Just []) key sm
    in case cnameRRs of
        Just rrs
            | length rrs > 1 ->
                BadCNames
                  [ t | r <- rrs
                      , Just (T_CNAME t) <- [rrDataCast r]
                  ]
            | [r] <- rrs
            , Just (T_CNAME target) <- rrDataCast r ->
                walkChain target sm' (owner : acc)
        _ ->
            -- No CNAME at this owner.  Walk terminates; if we
            -- accumulated aliases, the final 'repOwner' is
            -- 'owner' and 'repCnames' is the reversed accumulator.
            Walked owner (reverse acc)


-- | Seed the DNS resolver from dc-main's flat 'Opts.Opts'.  AD
-- bit is requested by default; CD is selected per-query via the
-- 'QueryControls' argument on 'rawReplyCD'.
dnsConf :: Opts.Opts -> DNSIO ResolvSeed
dnsConf opts = ExceptT $ DNS.makeResolvSeed
    $ DNS.setResolverConfRetries (Opts.dnsTries opts)
    . DNS.setResolverConfTimeout (1000 * Opts.dnsTimeout opts)
    . DNS.setResolverConfQueryControls qctls
    . case Opts.dnsServer opts of
        Nothing -> id
        Just ns
            | servers <- DNS.NameserverSpec ns Nothing :| []
              ->  DNS.setResolverConfSource $ DNS.HostList servers
    $ DNS.defaultResolvConf
  where
    qctls = DNS.QctlFlags (DNS.setFlagBits ADflag)
          <> DNS.EdnsUdpSize (Opts.dnsUdpSize opts)
