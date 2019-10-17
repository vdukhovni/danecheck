{-# LANGUAGE RecordWildCards #-}

module Dane.Scanner.SMTP.Certs
    ( cnOf
    , orgOf
    , encodeDER
    , genChainInfo
    , ChainInfo
    , CertInfo(..)
    , CertHashes(..)
    , HostName
    ) where

import           Crypto.Hash                      (hashWith)
import           Crypto.Hash.Algorithms           (SHA256(..), SHA512(..))
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteArray as BA
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LB
import           Data.Hourglass (timeConvert, DateTime)
import           Data.IORef (IORef, writeIORef)
import           Data.Int (Int64)
import           Data.List (find)
import           Data.Maybe (catMaybes)
import           Data.X509
import           Data.X509.CertificateStore
import           Data.X509.Validation
import           Foreign.C.Types (CTime(..))

import           Dane.Scanner.Util

data CertHashes =
     CertHashes
         { _cert256, _spki256, _cert512, _spki512 :: ByteString }

type Timestamp = Int64

type LifeSpan = (Timestamp, Timestamp)

data CertInfo = CertInfo { _depth :: !Int -- chain depth
                         , _idn :: !DistinguishedName -- issuer
                         , _life :: !LifeSpan         -- dates
                         , _sdn :: !DistinguishedName -- subject
                         , _hashes :: !CertHashes
                         , _cert :: !ByteString -- Cert as DER ByteString
                         , _spki :: !ByteString -- Cert as DER ByteString
                         , _alg :: !PubKeyALG
                         }

cnOf :: DistinguishedName -> Maybe String
cnOf dn = getDnElement DnCommonName dn >>= asn1CharacterToString

orgOf :: DistinguishedName -> Maybe String
orgOf dn = getDnElement DnOrganization dn >>= asn1CharacterToString

type ChainInfo = ( [HostName] -- DNS-IDs or CN-ID from leaf cert
                 , [CertInfo] -- Constructed chain
                 , Int64      -- Time observed
                 )

genChainInfo :: IORef ChainInfo
             -> CertificateStore
             -> ValidationCache
             -> ServiceID
             -> CertificateChain
             -> IO [FailedReason]
genChainInfo cref _ _ _ chain = do
    now <- gettime
    writeIORef cref $ buildChain now chain
    return [] -- Always succeed

buildChain :: Int64 -> CertificateChain -> ChainInfo
buildChain now (CertificateChain xs) =
    case xs of
      [] -> error "Empty certificate chain"
      top:chain ->
          let names = getNames top
              topinfo = certInfo 0 top
              (issuer, rest) = getIssuer 0 chain top
              infos = maybe [topinfo] ((topinfo:). getChainInfo 1 rest) issuer
          in (names, infos, now)
    where
        certInfo _depth scert =
            let cert = getCertificate scert
                _cert = encodeSignedObject scert
                _spki = encodeDER $ certPubKey cert
                _hashes = getHashes _cert _spki
                _idn = certIssuerDN cert
                _life = getDates cert
                _sdn = certSubjectDN cert
                _alg = pubkeyToAlg $ certPubKey cert
             in CertInfo{..}

        getDates :: Certificate -> LifeSpan
        getDates = toTimestampTuple . certValidity
            where
                toTimestampTuple :: (DateTime, DateTime) -> LifeSpan
                toTimestampTuple = (,) <$> toTimestamp . fst <*> toTimestamp . snd
                    where
                        toTimestamp :: DateTime -> Timestamp
                        toTimestamp = (\(CTime x) -> x) . timeConvert

        getChainInfo :: Int
                     -> [SignedCertificate]
                     -> SignedCertificate
                     -> [CertInfo]
        getChainInfo depth cc cert =
            let info = certInfo depth cert
                (issuer, rest) = getIssuer depth cc cert
            in maybe [info] ((info:). getChainInfo (depth + 1) rest) issuer

getIssuer :: Int
          -> [SignedCertificate]
          ->  SignedCertificate
          -> ( Maybe (SignedCertificate)
             ,       [SignedCertificate]
             )
getIssuer dep cc cert =
    let iss = (certIssuerDN . getCertificate $ cert)
        isMatch = (==iss) . certSubjectDN . getCertificate
        isCA c = case certVersion c of
                     0 -> True
                     2 -> checkV3CA dep c
                     _ -> False
        isSigner = checkSignature cert
     in nulled $ (\x -> (x, filter (/= x) cc)) <$>
                 find (\s -> isMatch s && isCA (getCertificate s)
                                       && isSigner s) cc
    where
        nulled :: Maybe (a,[b]) -> (Maybe a, [b])
        nulled Nothing = (Nothing, [])
        nulled (Just (x,ys)) = (Just x, ys)

getHashes :: ByteString -> ByteString -> CertHashes
getHashes cert spki =
    let _cert256 =  BS.pack $ BA.unpack $ hashWith SHA256 cert
        _spki256 =  BS.pack $ BA.unpack $ hashWith SHA256 spki
        _cert512 =  BS.pack $ BA.unpack $ hashWith SHA512 cert
        _spki512 =  BS.pack $ BA.unpack $ hashWith SHA512 spki
     in CertHashes{..}

encodeDER :: ASN1Object a => a -> ByteString
encodeDER = LB.toStrict . encodeASN1 DER . flip toASN1 []

getNames :: SignedCertificate -> [HostName]
getNames scert =
    let cert = getCertificate scert
        sdn = certSubjectDN cert
        altNames = maybe [] toAltName $ extensionGet $ certExtensions cert
     in case altNames of
          [] -> case cnOf sdn of
                    Just s -> [s]
                    Nothing -> []
          x -> x
    where
        unAltName :: AltName -> Maybe HostName
        unAltName (AltNameDNS s) = Just s
        unAltName _              = Nothing

        toAltName :: ExtSubjectAltName -> [HostName]
        toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names

checkV3CA :: Int -> Certificate -> Bool
checkV3CA level cert = allowedSign && allowedCA && allowedDepth
    where extensions  = certExtensions cert
          allowedSign = case extensionGet extensions of
                          Just (ExtKeyUsage flags) -> KeyUsage_keyCertSign `elem` flags
                          Nothing                  -> True
          (allowedCA,pathLen) = case extensionGet extensions of
                                  Just (ExtBasicConstraints True pl) -> (True, pl)
                                  _                                  -> (False, Nothing)
          allowedDepth = case pathLen of
                           Nothing                            -> True
                           Just pl | fromIntegral pl >= level -> True
                                   | otherwise                -> False

checkSignature :: SignedCertificate -> SignedCertificate -> Bool
checkSignature signedCert signingCert =
    case verifySignedSignature signedCert (certPubKey $ getCertificate signingCert) of
      SignaturePass     -> True
      SignatureFailed _ -> False
