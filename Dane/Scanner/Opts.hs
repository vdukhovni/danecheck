{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}

module Dane.Scanner.Opts (Opts(..), getOpts) where

import           Options.Applicative
import           Data.Char (toLower)
import           Data.Word (Word16)

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
     <> value 3000
     <> showDefaultWith (\t -> show t ++ " ms")
     <> help "DNS request TIMEOUT" )

    dnsTries <- option auto
      ( long "tries"
     <> short 'r'
     <> metavar "NUMTRIES"
     <> value 6
     <> showDefault
     <> help "at most NUMTRIES requests per lookup" )

    dnsUdpSize <- option auto
      ( long "udpsize"
     <> short 'u'
     <> metavar "SIZE"
     <> value 1216
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

    dnsDomain <- strArgument
      ( metavar "DOMAIN"
     <> value "."
     <> showDefault
     <> help "check the specified DOMAIN" )

    return Opts{..}

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
