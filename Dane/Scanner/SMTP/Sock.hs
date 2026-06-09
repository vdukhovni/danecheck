module Dane.Scanner.SMTP.Sock
  ( sockSource
  , sockSink
  ) where

import qualified Data.ByteString as B
import qualified Streaming.ByteString as Q
import           Control.Monad ((>=>))
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.State.Strict (gets, modify')
import           Network.Socket (Socket)
import           Network.Socket.ByteString (recv, send)
import           System.Timeout (timeout)

import           Dane.Scanner.SMTP.Internal

-- | Write the whole bytestring to the socket, looping if 'send'
-- only consumes a prefix.  Returns once every byte has been sent
-- or the underlying 'send' has thrown.
sockWrite :: Socket -> B.ByteString -> IO ()
sockWrite sock bs = send sock bs >>= \ case
    n | n < B.length bs -> sockWrite sock $ B.drop n bs
      | otherwise       -> pure ()

-- | Consume a 'ByteStream' and push each chunk down the plaintext
-- socket.  Errors and timeouts are recorded in 'smtpErr' and
-- stop the loop.
sockSink :: Q.ByteStream SmtpM () -> SmtpM ()
sockSink str = gets smtpConn >>= \ case
    SmtpPlain sock -> go sock str
    _              -> fail "Non-plaintext channel"
  where
    go sock = Q.unconsChunk >=> \ case
        Right (bs, bss) -> do
            tm <- timeLeft
            liftIO (timeout tm $ tryIO $ sockWrite sock bs) >>= \ case
                Just (Right _) -> go sock bss
                Just (Left e)
                    -> modify' \s -> s { smtpErr = DataErr $ ioErr "write" e }
                _   -> modify' \s -> s { smtpErr = DataErr $ timeErr "write" }
        Left ()        -> pure ()

-- | Read chunks off the plaintext socket and produce a
-- 'ByteStream' for downstream consumers.  EOF, errors and
-- timeouts are recorded in 'smtpErr' and terminate the stream.
sockSource :: Q.ByteStream SmtpM ()
sockSource = lift (gets smtpConn) >>= \ case
    SmtpPlain sock -> go sock
    _              -> error "Non-plaintext channel"
  where
    go sock = do
        tm <- lift timeLeft
        liftIO (timeout tm $ tryIO $ recv sock 65536) >>= \ case
            Just (Right bs)
                | B.length bs > 0 -> Q.chunk bs >> go sock
                | otherwise
                  -> lift $ modify' \s -> s { smtpErr = DataErr $ eofErr "read" }
            Just (Left e)
                  -> lift $ modify' \s -> s { smtpErr = DataErr $ ioErr "read" e }
            _     -> lift $ modify' \s -> s { smtpErr = DataErr $ timeErr "read" }
