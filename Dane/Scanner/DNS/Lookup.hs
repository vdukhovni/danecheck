module Dane.Scanner.DNS.Lookup
    ( getResponse )
    where

import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.State.Strict (gets)
import           Data.List (partition, sort)
import qualified Network.DNS as DNS
import           Network.DNS (Domain, ResourceRecord(..))
import           Network.DNS (RCODE(..), RData(..), TYPE(..))
import           Network.DNS (withResolver, lookupRawAD)

import           Dane.Scanner.State
import           Dane.Scanner.Util
import           Dane.Scanner.DNS.Response


-- | Partition the CNAMEs into those matching the desired owner, and the rest.
-- If none of the CNAMEs are pertinent, ignore them.
--
-- If exactly one matches the current qname, recurse changing the qname to its
-- target.  Since we remove the matching CNAMEs from the RR list, we're sure to
-- be loop free.
--
-- Otherwise, we have illegal multiple CNAMEs for the same owner.
--
-- Finally, return the alias chain and ultimate owner name of any answer RRset.
-- If the CNAME chain runs into an invalid multi-name RRset, the final "Maybe"
-- list will contain those names.
--
doCnames :: Domain -> [ResourceRecord] -> (Domain, [Domain], Maybe [Domain])
doCnames owner cnameRRs =
  case directs of
    []      -> (owner, [], Nothing)
    rr:[] | RD_CNAME cname <- rdata rr
            -> (\(o, cs, m) -> (o, owner:cs, m)) $ doCnames cname rest
    _       -> (owner, [], Just [c | RD_CNAME c <- map rdata directs])
  where
    (directs, rest) = partition ((== owner) . rrname) cnameRRs


-- | Process all answer RRs, extracting, the CNAME alias chain, final owner
-- name and answer RData.  All this, plus the RCODE and AD bit are packaged up
-- into a Response object.
--
-- If, for an A/AAAA response, we have a non-empty CNAME chain, and the AD bit
-- is not set, we issue another query for just the initial CNAME RRset, and
-- note its AD bit.
--
-- XXX: Here, we might in the future add recursion, if our iterative resolver
-- can't be relied upon to complete the recursion for us.  Except when an SOA
-- record is also included in the authority section (not currently provided)
-- covers the target of the CNAME, and no NS records in the authority section
-- signal a delegation of the target to a sub-domain.
--
response :: RC -> AD -> Domain -> TYPE -> [ResourceRecord] -> Scanner Response
response rc ad qname typ rs = do
  let (owner, aliases, badCnames) =
        doCnames qname $ [r | r <- rs, rrtype r == CNAME]
  case badCnames of
    Just _  -> return $ Response
                 { respRC = ErrRC "CnameErr"
                 , respAD = ad
                 , respCnAD = ad
                 , respCnames = aliases
                 , respBadCNs = badCnames
                 , respOwner = owner
                 , respType = typ
                 , respRD = []
                 , respTLSA = Nothing
                 }
    Nothing -> do
               -- Check status of first CNAME if full chain is not secure.
               (rc', ad', _) <-
                 case () of
                   _ | rc == NoErrorRC && not ad &&
                       not (null aliases) && typ `elem` [A, AAAA]
                       -> dnsLookup qname CNAME
                     | otherwise -> return $ (rc, ad, [])
               let ans = [rdata r | r <- rs, rrtype r == typ, rrname r == owner]
               return $ Response
                 { respRC = rc
                 , respAD = ad
                 , respCnAD = if_ (rc' == NoErrorRC) ad' ad
                 , respCnames = aliases
                 , respBadCNs = Nothing
                 , respOwner = owner
                 , respType = typ
                 , respRD = sort ans
                 , respTLSA = Nothing
                 }


-- | Perform generic DNS lookup from which we'll extract our RC, AD, CNAMEs,
-- owner and answer RData.
--
dnsLookup :: Domain -> TYPE -> Scanner (RC, AD, [ResourceRecord])
dnsLookup qname typ = do
    seed <- gets scannerDnsSeed
    reply <- liftIO $ withResolver seed $ \rv -> lookupRawAD rv qname typ
    case reply of
      Left DNS.TimeoutExpired -> return (DnsTimeout, False, [])
      Left (DNS.NetworkFailure e)  -> return (DnsXprtErr e, False, [])
      Left e -> return $ (ErrRC $ show e, False, [])
      Right msg -> do
        let fl = DNS.flags $ DNS.header msg
            ad = DNS.authenData fl
            rc = DnsRC $ DNS.rcode fl
            answers = DNS.answer msg
        return (rc, ad, answers)


-- | Package up a DNS lookup result in a Response object.
--
getResponse :: Domain -> TYPE -> Scanner Response
getResponse qname typ = do
  (rc, ad, answers) <- dnsLookup qname typ
  case rc of
    DnsRC NoErr   -> response rc ad qname typ answers
    DnsRC NameErr -> response rc ad qname typ answers
    _             -> return $ nodata rc ad qname typ
