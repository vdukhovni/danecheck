{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}

module Dane.Scanner.Opts
    ( Opts(..)
    , SigAlgs(..)
    , SigAlgGroup(..)
    , getOpts
    ) where

import           Options.Applicative
import           Data.Char (isSpace, toLower)
import           Data.List (intercalate)
import           Data.Word (Word16)

-- | Named signature-algorithm groups offered to the server.
-- Each group expands at TLS-config time to a list of
-- @(HashAlgorithm, SignatureAlgorithm)@ pairs covering the
-- common SHA-256\/384\/512 variants within the family.  The
-- friendly group names give users a stable handle to refer to a
-- family without having to spell out (or remember) the individual
-- sig-alg codepoint names.  Future post-quantum families (e.g. an
-- @mldsa@ group covering ML-DSA-44\/65\/87) would slot in here
-- as additional constructors.
data SigAlgGroup = SigEcdsa  -- ^ ECDSA over P-256, P-384, P-521
                 | SigRsa    -- ^ RSA-PSS (TLS 1.3) + RSA-PKCS#1 (TLS 1.2)
                 | SigEdDsa  -- ^ Ed25519 and Ed448
    deriving (Eq, Show)

-- | An ordered list of 'SigAlgGroup's, expressing the relative
-- preference offered to the server.  The empty list means \"use
-- the TLS library default\", i.e. no override.  A non-empty list
-- both restricts the offered algorithms to the named groups and
-- pins their relative order.  Hosts that publish certificates of
-- multiple kinds can therefore be probed independently by passing
-- a single group, or with a chosen preference order by passing
-- two or more groups.
newtype SigAlgs = SigAlgs { sigAlgsList :: [SigAlgGroup] }
    deriving (Eq, Show)

data Opts = Opts
  { dnsServer   :: !(Maybe String)
  , dnsTimeout  :: !Int
  , dnsTries    :: !Int
  , dnsUdpSize  :: !Word16
  , smtpHelo    :: !(Maybe String)
  , smtpTimeout :: !Int
  , smtpLineLen :: !Int
  , useReserved :: !Bool
  , downMX      :: !([String])
  , upsideDown  :: !Bool
  , enableV4    :: !Bool
  , enableV6    :: !Bool
  , useAll      :: !Bool
  , addDays     :: !Int
  , eeChecks    :: !Bool
  , sigAlgs     :: !SigAlgs
  , dnsDomain   :: !String
  }

parseN :: Parser (Maybe String)
parseN = flag' Nothing
    ( short 'N'
   <> help "Use /etc/resolv.conf nameserver list" )

parsen :: Parser (Maybe String)
parsen = Just <$> strOption
    ( long "nameserver"
   <> short 'n'
   <> value "127.0.0.1"
   <> showDefault
   <> metavar "ADDRESS"
   <> help "Use nameserver at ADDRESS" )

parser :: Parser Opts
parser = do
    dnsServer <- parseN <|> parsen

    dnsTimeout <- option auto
      ( long "timeout"
     <> short 't'
     <> metavar "TIMEOUT"
     <> value 5000
     <> showDefaultWith (\t -> show t ++ " ms")
     <> help "DNS request TIMEOUT" )

    dnsTries <- option auto
      ( long "tries"
     <> short 'r'
     <> metavar "NUMTRIES"
     <> value 3
     <> showDefault
     <> help "at most NUMTRIES requests per lookup" )

    dnsUdpSize <- option auto
      ( long "udpsize"
     <> short 'u'
     <> metavar "SIZE"
     <> value 1400
     <> showDefault
     <> help "set EDNS UDP buffer SIZE" )

    smtpHelo <- optional ( strOption
      ( long "helo"
     <> short 'H'
     <> metavar "HELO"
     <> help "send specified client HELO name" ) )

    smtpTimeout <- option auto
      ( long "smtptimeout"
     <> short 's'
     <> metavar "TIMEOUT"
     <> value 30000
     <> showDefaultWith (\t -> show t ++ " ms")
     <> help "SMTP TIMEOUT" )

    smtpLineLen <- option auto
      ( long "linelimit"
     <> short 'l'
     <> metavar "LENGTH"
     <> value 4096
     <> showDefault
     <> help "Maximum server SMTP response LENGTH" )

    useReserved <- switch
      ( long "reserved"
     <> short 'R'
     <> help "connect to reserved IP addresses" )

    downMX <- many
      ( (map toLower) <$> strOption
        ( long "down"
       <> short 'D'
       <> metavar "HOSTNAME"
       <> help "Specify one or more HOSTNAMEs that are down" ) )

    upsideDown <- switch
      ( long "down-only"
     <> short 'U'
     <> help "Limit connections to just the '-D' option hosts" )

    enableV4 <- not <$> switch
      ( long "noipv4"
     <> short '4'
     <> help "disable SMTP via IPv4" )

    enableV6 <- not <$> switch
      ( long "noipv6"
     <> short '6'
     <> help "disable SMTP via IPv6" )

    useAll <- switch
      ( long "all"
     <> short 'A'
     <> help "scan all MX hosts, not just those with TLSA RRs" )

    addDays <- option auto
      ( long "days"
     <> short 'd'
     <> metavar "DAYS"
     <> value 0
     <> help "check validity at DAYS in the future" )

    eeChecks <- switch
      ( long "eechecks"
     <> short 'e'
     <> help "check end-entity (leaf) certificate dates and names" )

    sigAlgs <- option (eitherReader parseSigAlgs)
      ( long "sigalgs"
     <> metavar "GROUPS"
     <> value (SigAlgs [])
     <> showDefaultWith showSigAlgs
     <> help "Comma-separated ordered list of TLS signature-algorithm \
             \groups, drawn from 'rsa', 'ecdsa' and 'eddsa'; restricts \
             \the offered algorithms and pins their relative order.  \
             \Use 'any' or the empty string for the TLS library \
             \defaults (the default)." )

    dnsDomain <- strArgument
      ( metavar "DOMAIN"
     <> value "."
     <> showDefault
     <> help "check the specified DOMAIN" )

    return Opts{..}

-- | Parse the @--sigalgs@ argument:  a comma-separated, case-
-- insensitive list of named groups, with whitespace tolerated.
-- The literal string @any@ (or an empty string) yields
-- @SigAlgs []@, meaning \"no override\".
parseSigAlgs :: String -> Either String SigAlgs
parseSigAlgs s
    | null trimmed                    = Right (SigAlgs [])
    | map toLower trimmed == "any"    = Right (SigAlgs [])
    | otherwise = SigAlgs <$> traverse parseOne (splitComma trimmed)
  where
    trimmed = dropWhile isSpace $ reverse $ dropWhile isSpace $ reverse s
    splitComma xs = case break (== ',') xs of
        (h, ',':t) -> trim h : splitComma t
        (h, _)     -> [trim h]
    trim = dropWhile isSpace . reverse . dropWhile isSpace . reverse
    parseOne g = case map toLower g of
        "rsa"   -> Right SigRsa
        "ecdsa" -> Right SigEcdsa
        "eddsa" -> Right SigEdDsa
        ""      -> Left "empty sig-alg group name"
        _       -> Left $ "unknown sig-alg group: " ++ show g
                       ++ " (expected one of rsa, ecdsa, eddsa)"

-- | Pretty-print a 'SigAlgs' value for the @--help@ default
-- display.
showSigAlgs :: SigAlgs -> String
showSigAlgs (SigAlgs []) = "any"
showSigAlgs (SigAlgs gs) = intercalate "," (map groupName gs)
  where
    groupName SigRsa   = "rsa"
    groupName SigEcdsa = "ecdsa"
    groupName SigEdDsa = "eddsa"

-- | Parse command-line switches
--
getOpts :: IO Opts
getOpts =
  execParser
    $ info (helper <*> parser)
    $ noIntersperse
    <> fullDesc
    <> header "danecheck - check for and validate SMTP TLSA records"
    <> footer
       ("When scanning the root domain, what's checked is secure retrieval of \
       \ the root DNSKEY and SOA RRSets. Similarly, when scanning a top-level \
       \ domain, what's checked is secure retrieval of its DS, DNSKEY and SOA \
       \ records. For all other domains, MX records, address records and TLSA \
       \ records are retrieved and must be DNSSEC signed. Each MX host is     \
       \ expected to have TLSA records, an SMTP connection is made to each    \
       \ address of each such MX host (with the '-A' option connections are   \
       \ made to all MX hosts). A TLS handshake is performed to retrieve the  \
       \ hosts's certificate chain which is verified against the DNS TLSA RRs \
       \ If anything is unavailable, insecure or wrong, a non-zero exit code  \
       \ is returned. The '-D' option can be used multiple times to skip SMTP \
       \ connections to MX hosts that are expected to be down. The '-U' option\
       \ inverts the action of the '-D' option, and connects to only those MX \
       \ hosts that are specified via the '-D' option (none if no such hosts  \
       \ are specified)."
       )
