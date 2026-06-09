{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE TemplateHaskell    #-}

module Dane.Scanner.DNS.Dane (daneCheck) where

import qualified Data.Text as T
import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.Except (runExceptT)
import           Control.Monad.Trans.State.Strict (gets)
import           Data.List (nub, sortOn)

import           Data.IP (IP(IPv4, IPv6))
import           Net.DNSBase ( Domain(RootDomain)
                             , T_a(T_A), T_aaaa(T_AAAA)
                             , T_dnskey, T_ds, T_mx(..), T_soa, T_tlsa
                             , RRTYPE(SOA)
                             , appendDomain, dnLit8, shortBytes
                             )
import           Net.DNSBase.Present (putBuilder)
import           Net.DNSBase.Resolver (withResolver)

import qualified Text.IDNA2008 as I
import qualified Text.IDNA2008.Wire as IW

import qualified Dane.Scanner.Opts as Opts
import           Dane.Scanner.State
import           Dane.Scanner.Util
import           Dane.Scanner.DNS.Lookup
import           Dane.Scanner.DNS.Reply
import           Dane.Scanner.DNS.Toascii
import           Dane.Scanner.SMTP.Chain


-- | Prefix prepended to a TLSA base domain to form the TLSA
-- query name (e.g. @_25._tcp.mx1.example.com@).  Built once at
-- compile-time via 'DNS.dnLit8'; combined with the per-host base
-- via 'DNS.appendDomain', which returns 'Nothing' when the
-- result would overflow the 255-octet wire-form name limit.
tlsaPrefix :: Domain
tlsaPrefix = $$(dnLit8 "_25._tcp.")


-- | Skip hosts that securely don't exist.
skipHost :: RC -> Bool
skipHost NXDomainRC = True
skipHost _          = False


-- | Label-form set acceptable for an MX hostname received from
-- DNS: LDH + ALABEL + RLDH + FAKEA.  Excludes ATTRLEAF
-- (leading-underscore service labels are not MX exchanger
-- names), ULABEL (wire form is never UTF-8 here), WILDLABEL,
-- OCTET, BLANK, LAXULABEL.  xn-- labels are accepted whether or
-- not they decode as valid Punycode — FAKEA admission means we
-- don't reject names whose Punycode happens not to decode.
mxHostForms :: I.LabelFormSet
mxHostForms = mempty I.<+> I.LDH I.<+> I.ALABEL I.<+> I.RLDH I.<+> I.FAKEA

-- | Validate an MX hostname's label shape.  Classifies the
-- wire-form bytes directly via 'IW.unparseOpts' (no 'Text'
-- round-trip) against 'mxHostForms'.  Flags are 'mempty' —
-- pure shape classification, with ALABELCHECK / NFCCHECK /
-- BIDICHECK / character mappings all off, since none of them
-- are meaningful constraints on data received off the wire.
validMXHost :: Domain -> Bool
validMXHost dom =
    case IW.unparseOpts mxHostForms mempty (shortBytes dom) of
        Right _ -> True
        Left _  -> False


-- | Given a non-empty A or AAAA response, try to find TLSA
-- records at the CNAME-expanded name if the entire chain is
-- secure.  If no TLSA records are found there, and the CNAME
-- chain is non-empty, try at the initial name if secure.
--
getTLSA :: Reply a       -- ^ MX-host address reply
        -> Scanner (Maybe (Domain, Reply T_tlsa))
getTLSA a = case repValidity a of
    Secure -> do
        cnamebt <- baseTLSA (repOwner a)
        case cnamebt of
            Just (_, t) | done t -> return cnamebt
            _                    -> baseTLSA (repQname a)
    Insecure
        | repCnAD a
        , nonempty (repRD a)
        , nonempty (repCnames a) -> baseTLSA (repQname a)
    _                            -> return Nothing
  where
    -- Is the initial qname a candidate base domain?
    done :: Reply T_tlsa -> Bool
    done t = case repValidity t of
        Indeterminate         -> True
        Secure                -> True
        _ | not (repCnAD a)   -> True
          | null (repCnames a) -> True
          | otherwise          -> False

    baseTLSA :: Domain -> Scanner (Maybe (Domain, Reply T_tlsa))
    baseTLSA b = case appendDomain tlsaPrefix b of
        Nothing -> return Nothing       -- host name too long for TLSA prefix
        Just q  -> do
            rv <- gets scannerResolver
            t <- liftIO $ rawReply T_tlsa rv q
            return (Just (b, t))


-- | For each MX host display the corresponding per-host
-- information.  This includes the A\/AAAA records and, when
-- DNSSEC-secure, the TLSA records and per-IP SMTP chain probes.
doMXHost :: Domain  -- ^ Qname of MX RRset
         -> Domain  -- ^ MX RRset owner
         -> Domain  -- ^ MX host to process
         -> Scanner ()
doMXHost qname owner mx
  | Just _ <- rootOrTLD mx
  = displayFailA (noReply TldMX False mx)
  | not (validMXHost mx)
  = displayFailA (noReply BadName False mx)
  | otherwise = do
    rv <- gets scannerResolver
    a  <- liftIO $ rawReply T_a rv mx
    noteInsecure a
    if skipHost (repRC a)
    then liftIO $ putBuilder $ putReplyA a mempty
    else do
        aaaa <- liftIO $ rawReply T_aaaa rv mx
        noteInsecure aaaa
        opts <- gets scannerOpts
        let doV4 = Opts.enableV4 opts
            doV6 = Opts.enableV6 opts
            v4addrs = if_ doV4 [ IPv4 ip | T_A    ip <- repRD a    ] []
            v6addrs = if_ doV6 [ IPv6 ip | T_AAAA ip <- repRD aaaa ] []
            connaddrs = v4addrs ++ v6addrs
        bt <- getTLSA a
        case bt of
            Just (b, t) -> renderHost a aaaa (Just (b, t)) connaddrs
            Nothing     -> do
                bt' <- getTLSA aaaa
                case bt' of
                    Just (b, t) -> renderHost a aaaa (Just (b, t)) connaddrs
                    Nothing
                        | Opts.useAll opts -> do
                            let synth = case appendDomain tlsaPrefix mx of
                                    Just n  -> noReply NoErrorRC False n
                                    Nothing -> noReply NoErrorRC False mx
                            renderHost a aaaa (Just (mx, synth)) connaddrs
                        | otherwise -> do
                            displayFailA a
                            displayFailAaaa aaaa
  where
    noteInsecure r = case repRC r of
        NoErrorRC  | repCnAD r -> return ()
        NXDomainRC | repCnAD r -> return ()
        _                      -> scannerFail ()

    displayFailA r = do
        liftIO $ putBuilder $ putReplyA r mempty
        scannerFail ()

    displayFailAaaa r = do
        liftIO $ putBuilder $ putReplyAaaa Nothing [] r mempty
        scannerFail ()

    renderHost :: Reply T_a -> Reply T_aaaa
               -> Maybe (Domain, Reply T_tlsa)
               -> [IP]
               -> Scanner ()
    renderHost a aaaa (Just (b, t)) connaddrs = do
        chains <- getchains t b connaddrs
        let tlsa = TlsaInfo { tlsaBase = b, tlsaRRset = t }
        liftIO $ putBuilder $
            putReplyA a . putReplyAaaa (Just tlsa) chains aaaa $ mempty
    renderHost a aaaa Nothing _ =
        liftIO $ putBuilder $
            putReplyA a . putReplyAaaa Nothing [] aaaa $ mempty

    getchains :: Reply T_tlsa -> Domain -> [IP] -> Scanner [AddrChain]
    getchains tlsa base addrs = case repValidity tlsa of
        Secure ->
            let refnames = nub [base, qname, owner]
             in getAddrChains mx base refnames (repRD tlsa) addrs
        _ -> gets scannerOpts >>= \opts ->
            if Opts.useAll opts
            then scannerFail () >> getAddrChains mx base [] [] addrs
            else scannerFail []


-- | If the MX RRset is secure (AD==True), for each MX host
-- perform A\/AAAA lookups and then TLSA lookups if those are in
-- turn secure.
chaseMX :: Reply T_mx -> Scanner ()
chaseMX m = case repAD m of
    False -> return ()
    True
      | NoErrorRC <- repRC m, null (repRD m)
          -> doMXHost (repQname m) (repOwner m) (repOwner m)
      | otherwise
          -> mapM_ (doMXHost (repQname m) (repOwner m)) (gethosts (repRD m))
  where
    gethosts mxs = nub [ exch | T_MX _ exch <- sortOn mxPref mxs
                              , exch /= RootDomain ]


-- | For sub-domains, check DS, DNSKEY, MX and then recurse over
-- the MX hosts for A\/AAAA and TLSA.
checkDomain :: Domain -> Scanner Bool
checkDomain dom = do
    rv <- gets scannerResolver
    ds <- liftIO $ rawReply T_ds rv dom
    liftIO $ putBuilder $ putReplyDs ds mempty
    if not (repValidated ds)
    then return False
    else do
        dk <- liftIO $ rawReply T_dnskey rv dom
        liftIO $ putBuilder $ putReplyDnskey dk mempty
        if not (repValidated dk)
        then return False
        else do
            m <- liftIO $ rawReply T_mx rv dom
            liftIO $ putBuilder $ putReplyMx m mempty
            when (not (repValidated m)) (scannerFail ())
            chaseMX m
            gets scannerOK


-- | For the root and TLDs, check DS (if applicable), DNSKEY, and
-- SOA in turn.  Each step requires a secure validated answer; the
-- first failure stops the chain.  DS is skipped at the root, which
-- has no parent zone and therefore no DS RRset to look up.
checkTld :: Domain -> Scanner Bool
checkTld tld = do
    rv <- gets scannerResolver
    dsOK <- case tld of
        RootDomain -> return True
        _ -> do
            ds <- liftIO $ rawReply T_ds rv tld
            liftIO $ putBuilder $ putReplyDs ds mempty
            return (repValidity ds == Secure)
    if not dsOK
    then return False
    else do
        dk <- liftIO $ rawReply T_dnskey rv tld
        liftIO $ putBuilder $ putReplyDnskey dk mempty
        if repValidity dk /= Secure
        then return False
        else do
            soa <- liftIO $ rawReply T_soa rv tld
            liftIO $ putBuilder $ putReplyAny SOA soa mempty
            return (repValidity soa == Secure)


-- | For the root domain and TLDs simply check for working
-- DNSSEC.  For sub-domains attempt to verify MX host DANE TLSA.
check :: String -> Scanner Bool
check domain = case todomain forms flags (T.pack domain) of
    Just dom
      | Just _ <- rootOrTLD dom -> checkTld dom
      | otherwise               -> checkDomain dom
    Nothing -> do
        liftIO $ putStrLn $ domain ++ " IN MX ? ; Invalid AD=0"
        return False
  where
    -- Hostname-shaped label set: LDH + ALABEL + ULABEL + RLDH +
    -- FAKEA.  Excludes ATTRLEAF (leading-underscore service
    -- labels like @_dmarc@, @_25@), WILDLABEL, OCTET, BLANK,
    -- LAXULABEL — none of which a user-typed mail domain has
    -- any legitimate use for.  Tighter than the pre-port
    -- Toascii.hs, which short-circuited any all-ASCII input
    -- through without validation and accepted ATTRLEAF and
    -- worse by accident.
    forms = I.hostnameLabelForms
    flags = I.defaultIdnaFlags <> I.allIdnaMappings


-- | Scan the requested domain after seeding the DNS resolver.
daneCheck :: Opts.Opts -> IO Bool
daneCheck opts = do
    seedRes <- runExceptT (dnsConf opts)
    case seedRes of
        Left e -> do
            putStrLn $ "Resolver configuration error: " ++ show e
            return False
        Right seed -> withResolver seed $ \rv ->
            evalScanner (check (Opts.dnsDomain opts))
                        ScannerSt { scannerOpts     = opts
                                  , scannerResolver = rv
                                  , scannerOK       = True }
