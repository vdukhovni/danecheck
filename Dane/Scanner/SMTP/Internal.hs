module Dane.Scanner.SMTP.Internal
  ( ProtoState(..)
  , SmtpM
  , SmtpState(..)
  , SmtpReply(..)
  , SmtpErr(..)
  , SmtpConn(..)
  , SmtpFeature(..)
  , timeLimit
  , timeLeft
  , startState
  , ioErr
  , eofErr
  , timeErr
  , errLoc
  ) where

import qualified System.Clock as Sys
import           System.IO.Error as Sys

import           GHC.IO.Exception (IOErrorType(EOF, TimeExpired))

import           Control.Exception (SomeException, IOException)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.State.Strict (StateT, gets)
import           Data.ByteString.Char8 (ByteString, pack)
import           Data.IORef (IORef, newIORef)
import           Data.Int (Int64)
import           Network.Socket (Socket)
import qualified Network.TLS as TLS
import           Text.Show (showString, showChar)
import           Dane.Scanner.SMTP.Certs (ChainInfo)

data ProtoState = ProtoState
  { smtpState   :: ! SmtpState
  , smtpErr     :: ! SmtpErr
  , clientName  :: ! ByteString
  , serverName  :: ! String
  , smtpConn    :: ! SmtpConn
  , smtpTimeout :: ! Int
  , llenLimit   :: ! Int
  , ioDeadline  :: ! Sys.TimeSpec
  , features    :: ! [SmtpFeature]
  , chainRef    :: ! (IORef ChainInfo)
  }

type SmtpM = StateT ProtoState IO

data SmtpConn = SmtpPlain Socket
              | SmtpTLS TLS.Context

data SmtpFeature = FeatureTLS
                 | FeatureSIZE Int64
                 | FeatureUTF8
  deriving (Eq)

data SmtpState = CONNECT
               | GREETING
               | EHLO
               | STARTTLS
               | DOTLS
               | QUIT
               | DONE
  deriving (Eq, Enum, Show, Ord)

data SmtpReply = SmtpReply
  { replyCode :: ! Int
  , replyCont :: ! Bool
  , replyText :: ! ByteString
  }
  deriving (Show)

data SmtpErr = SmtpOK
             | TlsHandError TLS.TLSError
             | TlsRecvError
             | TlsSendError
             | DataErr IOException
             | ProtoErr Int ByteString
             | OtherErr SomeException

timeLimit :: Int -> IO Sys.TimeSpec
timeLimit tmout = do
  now <- Sys.getTime Sys.Monotonic
  return $! Sys.fromNanoSecs
         $ (fromIntegral tmout * 1000) + Sys.toNanoSecs now

timeLeft :: SmtpM Int
timeLeft = do
  deadline <- gets ioDeadline
  now <- liftIO $ Sys.getTime Sys.Monotonic
  return $! fromIntegral
         $ flip div 1000
         $ Sys.toNanoSecs
         $ Sys.diffTimeSpec deadline now

-- | Initialize the client SMTP protocol state
--
startState :: String     -- ^ SMTP client EHLO name
           -> String     -- ^ SMTP server name
           -> Int        -- ^ SMTP command timeout (us)
           -> Int        -- ^ SMTP response line length limit
           -> Socket     -- ^ Socket connected to the SMTP server
           -> IO ProtoState
startState helo peer tout llen sock = do
  cref <- newIORef undefined
  deadline <- timeLimit tout
  return ProtoState
    { smtpState = GREETING
    , clientName = pack helo
    , serverName = peer
    , smtpConn   = SmtpPlain sock
    , smtpTimeout = tout
    , ioDeadline = deadline
    , smtpErr    = SmtpOK
    , llenLimit  = llen
    , features   = []
    , chainRef   = cref
    }

ioErr :: String -> IOException -> IOException
ioErr loc err = Sys.ioeSetLocation err loc

eofErr :: String -> IOException
eofErr loc = Sys.mkIOError EOF loc Nothing Nothing

timeErr :: String -> IOException
timeErr loc = Sys.mkIOError TimeExpired loc Nothing Nothing

errLoc :: IOException -> ProtoState -> IOException
errLoc err st =
  let loc = Sys.ioeGetLocation err
  in if (loc /= "")
  then Sys.ioeSetLocation err $
    (showString. show $ smtpState st).
    showChar ' '.
    showString loc $ ""
  else Sys.ioeSetLocation err $ show $ smtpState st
