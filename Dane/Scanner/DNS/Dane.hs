{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Dane.Scanner.DNS.Dane (daneCheck) where

import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.State.Strict (gets)

import qualified Data.ByteString.Char8 as BC
import           Data.List (nub, sortOn)

import qualified Network.DNS as DNS
import           Network.DNS
                   ( Domain
                   , RCODE(NoErr, NameErr)
                   , RData(RD_MX)
                   , TYPE(A, AAAA, DNSKEY, DS, MX, SOA, TLSA)
                   )

import qualified Dane.Scanner.Opts as Opts
import           Dane.Scanner.State
import           Dane.Scanner.Util
import           Dane.Scanner.DNS.Lookup
import           Dane.Scanner.DNS.Response
import           Dane.Scanner.DNS.Toascii
import           Dane.Scanner.SMTP.Chain


-- | Prefix prepended to TLSA base domain to obtain the TLSA qname
--
tlsaPrefix :: BC.ByteString
tlsaPrefix = BC.pack "_25._tcp."


-- | Skip hosts that securely don't exist
--
skipHost :: RC -> Bool
skipHost (DnsRC NameErr) = True
skipHost (DnsRC NoErr)   = False
skipHost (DnsRC _)       = False
skipHost DnsTimeout      = False
skipHost (DnsXprtErr _)  = False
skipHost TldMX           = False
skipHost (ErrRC _)       = False


-- | Given a non-empty A or AAAA response, try to find TLSA records at the
-- CNAME-expanded name if the entire chain is secure.  If no TLSA records are
-- found there, and the CNAME chain is non-empty try at the initial name if
-- secure.
--
getTLSA :: Response -- ^ MX Host address response
        -> Scanner (Maybe (Domain, Response))
getTLSA a = case respValidity a of
    Secure -> do
        cnamebt <- baseTLSA $ respOwner a
        case cnamebt of
            Just (_, t) | done t  -> return cnamebt
            _                     -> baseTLSA $ respQname a
    Insecure
        | respCnAD a
        , nonempty (respRD a)
        , nonempty (respCnames a) -> baseTLSA $ respQname a
    _                             -> return Nothing
  where
    -- Is the initial qname a candidate base domain?
    --
    done :: Response -- ^ TLSA response at expanded name
         -> Bool
    done t = case respValidity t of
        Indeterminate           -> True
        Secure                  -> True
        _ | not (respCnAD a)    -> True
          | null (respCnames a) -> True
          | otherwise           -> False

    baseTLSA :: Domain -> Scanner (Maybe (Domain, Response))
    baseTLSA b = (\t -> Just (b, t)) <$> getResponse (tlsaPrefix <> b) TLSA


-- | For each MX host display the corresponding per-host information.  This
-- includes any A/AAAA records and also the TLSA records if the MX RRset is
-- dnssec signed, and either the A or AAAA records are present and also signed.
--
doMXHost :: Domain -- ^ Qname of MX RRset
         -> Domain -- ^ MX RRset owner
         -> Domain -- ^ MX host to process
         -> Scanner ()
doMXHost qname owner mx = do
  if rootOrTLD mx /= Nothing
  then displayFail $ nodata TldMX False mx A
  else do
    a <- getResponse mx A
    noteInsecure a
    if (skipHost $ respRC a)
    then display $ a
    else do
      aaaa <- getResponse mx AAAA
      noteInsecure aaaa
      opts <- gets scannerOpts
      let doV4 = Opts.enableV4 opts
          doV6 = Opts.enableV6 opts
          connaddrs = if_ doV4 [a] [] ++ if_ doV6 [aaaa] []
      bt <- getTLSA a
      case bt of
        Just (b, t) -> do
            chains <- getchains t b connaddrs
            display $ a
            display $ addbase b t chains aaaa
        Nothing     -> do
            bt' <- getTLSA aaaa
            case bt' of
              Just (b, t) -> do
                chains <- getchains t b connaddrs
                display $ a
                display $ addbase b t chains aaaa
              Nothing
                  | Opts.useAll opts -> do
                      let b = mx
                          n = tlsaPrefix <> b
                          t = nodata NoErrorRC False n TLSA
                      chains <- getchains t b connaddrs
                      display $ a
                      display $ addbase b t chains aaaa
                  | otherwise -> do
                      displayFail $ a
                      displayFail $ aaaa
  where
    noteInsecure Response{..} = case respRC of
        NoErrorRC  | respCnAD -> return ()
        NXDomainRC | respCnAD -> return ()
        _                     -> scannerFail ()

    display :: Response -> Scanner ()
    display r = liftIO $ putStr $ show r

    displayFail :: Response -> Scanner ()
    displayFail r = do
        liftIO $ putStr $ show r
        scannerFail ()

    addbase base tlsa chains r =
        r { respTLSA = Just $ RespTLSA { tlsaBase = base
                                       , tlsaRRset = tlsa
                                       , addrChains = chains } }

    getchains :: Response -> Domain -> [Response] -> Scanner [AddrChain]
    getchains tlsa@(respValidity -> Secure) base rs =
        let addrs = concatMap respRD rs
            refnames = nub [base, qname, owner]
         in getAddrChains mx base refnames (respRD tlsa) addrs
    getchains _ base rs = gets scannerOpts >>= \opts ->
        let addrs = concatMap respRD rs
         in if Opts.useAll opts
            then scannerFail () >> getAddrChains mx base [] [] addrs
            else scannerFail []


-- | If the MX RRset is secure (AD==True), for each MX host perform A/AAAA
-- lookups and then TLSA lookups if those are in turn secure.
--
chaseMX :: RC
        -> AD
        -> Domain  -- MX qname
        -> Domain  -- owner of MX answer RRset
        -> [RData] -- MX RDATA
        -> Scanner ()

chaseMX _             False _     _         _          =
    return ()

chaseMX (DnsRC NoErr) True  qname owner     []         =
    doMXHost qname owner owner

chaseMX _             _     qname owner     mxs        =
    mapM_ (doMXHost qname owner) $ gethosts mxs
  where
    mxpref (RD_MX p _) = p
    mxpref _           = error "unexpected non-MX RDATA"
    gethosts rds =
        nub [exch | (RD_MX _ exch) <- sortOn mxpref rds, exch /= "."]


-- | For all other domains check DS, DNSKEY, MX, A, AAAA and TLSA records as
-- appropriate.
--
checkDomain :: String -> Scanner Bool
checkDomain domain =
    let q = BC.pack domain <> BC.pack "."
    in go q [DS, DNSKEY, MX]
  where

    -- | MX is assumed last and recurses as needed for the per-host records.
    --
    go q (MX:_) = do
      m <- getResponse q MX
      liftIO $ putStr $ show m
      when (not $ respValidated m) $ scannerFail ()
      let Response { respRC = rc
                   , respAD = ad
                   , respOwner = owner
                   , respRD = rd
                   } = m
      chaseMX rc ad (respQname m) owner rd
      gets scannerOK

    -- | The DS and DNSKEY RRs are more straightforward
    --
    go q (t:ts) = do
      r <- getResponse q t
      liftIO $ putStr $ show r
      if respValidated r
      then go q ts
      else return False

    -- | We should never get here with the MX last
    --
    go _ [] = return False


-- | For the root and TLDs, check a fixed list of types
--
checkTld :: String -> [TYPE] -> Scanner Bool
checkTld domain types =
    let tld = BC.pack domain <> BC.pack "."
    in go tld types
  where

    -- | Try each lookup in turn stopping at the first failed, insecure or
    -- empty answer
    --
    go q (t:ts) = do
      r <- getResponse q t
      liftIO $ putStr $ show r
      if respValidity r == Secure
      then go q ts
      else return False

    -- | All's well if we got through all the lookups
    --
    go _ [] = return True


-- | For the root domain and TLDs simply check for working DNSSEC.
-- For sub-domains attempt to verify MX host DANE TLSA.
--
check :: String -> Scanner Bool
check domain = do
  case toascii domain of
    Just "."               -> checkTld "" [DNSKEY, SOA]
    Just a | '.' `elem` a  -> checkDomain a
           | otherwise     -> checkTld a [DS, DNSKEY, SOA]
    _                      -> invalid
  where
    invalid = do
        liftIO $ putStrLn $ domain ++ " IN MX ? ; Invalid AD=0"
        return False


-- | Seed the DNS resolver
--
dnsSeed :: Opts.Opts -> IO DNS.ResolvSeed
dnsSeed opts =
    let seed = DNS.defaultResolvConf
            { DNS.resolvRetry = Opts.dnsTries opts
            , DNS.resolvTimeout = 1000 * Opts.dnsTimeout opts
            , DNS.resolvQueryControls =
                  DNS.adFlag DNS.FlagSet <>
                  DNS.ednsSetUdpSize (Just $ Opts.dnsUdpSize opts)
            }
     in DNS.makeResolvSeed $ case Opts.dnsServer opts of
            Nothing -> seed
            Just ns -> seed { DNS.resolvInfo = DNS.RCHostName ns }


-- | Scan requested domain after seeding the DNS resolver
daneCheck :: Opts.Opts -> IO Bool
daneCheck opts = do
    seed <- dnsSeed opts
    evalScanner (check $ Opts.dnsDomain opts) $
        ScannerSt { scannerOpts = opts
                  , scannerDnsSeed = seed
                  , scannerOK = True
                  }
