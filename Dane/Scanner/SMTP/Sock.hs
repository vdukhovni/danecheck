{-# LANGUAGE FlexibleContexts #-}

module Dane.Scanner.SMTP.Sock
  ( sockSource
  , sockSink
  ) where

import           System.Timeout.Lifted (timeout)

import           Control.Exception.Safe (tryIO)
import           Control.Monad (when)
import           Control.Monad.Base (liftBase)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.Control (MonadBaseControl)
import           Control.Monad.Trans.State.Strict (gets, modify)
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BS
import           Data.Conduit (Source, Sink, yield, await)
import           Network.Socket (Socket)
import           Network.Socket.ByteString (recv, send)

import           Dane.Scanner.SMTP.Internal

sockWrite :: MonadBaseControl IO m => Socket -> ByteString -> m ()
sockWrite sock bs = do
  n <- liftBase $ send sock bs
  when (n < BS.length bs) $ sockWrite sock $ BS.drop n bs

sockSink :: Sink ByteString SmtpM ()
sockSink = do
  conn <- lift $ gets smtpConn
  case conn of
      SmtpPlain sock -> go sock
      _              -> error "Non-plaintext channel"
  where
    go sock = await >>= ( maybe (return ()) $ \bs -> do
      res <- lift $ timeLeft >>= flip timeout (tryIO $ sockWrite sock bs)
      case res of
        Just x
          | Right _ <- x -> go sock
          | Left e  <- x
          -> lift $ modify $
               \s -> s { smtpErr = DataErr $ ioErr "write" e }
        _ -> lift $ modify $
               \s -> s { smtpErr = DataErr $ timeErr "write" }
      )

sockRead :: MonadBaseControl IO m => Socket -> Int -> m ByteString
sockRead sock n = liftBase $ recv sock n

sockSource :: Source SmtpM ByteString
sockSource = do
  conn <- lift $ gets smtpConn
  case conn of
      SmtpPlain sock -> go sock
      _              -> error "Non-plaintext channel"
  where
    go sock = do
      res <- lift $ timeLeft >>= flip timeout (tryIO $ sockRead sock 65536)
      case res of
        Just x
          | Right bs <- x
          -> if (BS.length bs > 0)
             then yield bs >> go sock
             else lift $ modify $
               \s -> s { smtpErr = DataErr $ eofErr "read" }
          | Left e  <- x
          -> lift $ modify $
               \s -> s { smtpErr = DataErr $ ioErr "read" e }
        _ -> lift $ modify $
               \s -> s { smtpErr = DataErr $ timeErr "read" }
