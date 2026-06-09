{-# LANGUAGE OverloadedStrings #-}

module Dane.Scanner.SMTP.Proto (dosmtp) where

import qualified Control.Monad.Trans.State.Strict as ST
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.Text as T
import qualified Data.Text.Encoding as E
import qualified Streaming.ByteString as Q
import qualified Streaming.Prelude as Streaming
import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.State.Strict (get, gets, modify')
import           Data.Function ((&))

import           Dane.Scanner.Source (strictLines)
import           Dane.Scanner.SMTP.Sock
import           Dane.Scanner.SMTP.Parse
import           Dane.Scanner.SMTP.Internal
import           Dane.Scanner.SMTP.TLS

crlf :: B.ByteString
crlf = "\r\n"

ok :: SmtpErr -> Bool
ok SmtpOK = True
ok _      = False

smtpSendHello :: SmtpM B.ByteString
smtpSendHello = do
  deadline <- liftIO . timeLimit =<< gets smtpTimeout
  modify' \s -> s { smtpState = EHLO, ioDeadline = deadline }
  name <- gets clientName
  pure $ "EHLO " <> name <> crlf

smtpGreeting :: Int -> SmtpReply -> SmtpM B.ByteString
smtpGreeting _ r
    | replyCont r = pure B.empty
    | code <- replyCode r
    , code `div` 100 /= 2
    = do modify' \s -> s { smtpErr = ProtoErr code $ replyText r }
         pure B.empty
    | otherwise = smtpSendHello

smtpHello :: Int -> SmtpReply -> SmtpM B.ByteString
smtpHello count r = do
    when (count > 0
          && "STARTTLS" == T.toUpper (E.decodeLatin1 (replyText r))) do
        modify' \s -> s { features = FeatureTLS:features s }
    if | replyCont r -> pure B.empty
       | code <- replyCode r
       , code `div` 100 /= 2
       -> do modify' \s -> s { smtpErr = ProtoErr code $ replyText r }
             pure B.empty
       | otherwise -> do
           deadline <- liftIO . timeLimit =<< gets smtpTimeout
           modify' \s -> s { ioDeadline = deadline }
           st <- get
           if | FeatureTLS `elem` features st
              , not (hasTLS st)
              -> "STARTTLS\r\n" <$ modify' \s -> s { smtpState = STARTTLS }
              | otherwise
              -> "QUIT\r\n" <$ modify' \s -> s { smtpState = QUIT }

smtpStartTLS :: Int -> SmtpReply -> SmtpM B.ByteString
smtpStartTLS _ r = do
    when (not $ replyCont r) do
        let code = replyCode r
        if | code `div` 100 == 2
           -> modify' \s -> s { smtpState = DOTLS }
           | otherwise
           -> modify' \s -> s { smtpErr = ProtoErr code $ replyText r }
    pure B.empty

smtpQuit :: Int -> SmtpReply -> SmtpM B.ByteString
smtpQuit _ r = do
    when (not $ replyCont r) do
        let code = replyCode r
        if | code `div` 100 == 2 -> do
               get >>= \st -> when (hasTLS st) endTLS
               modify' \s -> s { smtpState = DONE }
           | otherwise
           -> modify' \s -> s { smtpErr = ProtoErr code $ replyText r }
    pure B.empty

-- | SMTP state machine over a 'ByteStream' input.  Reads lines via
-- 'strictLines' (so the per-reply length cap from 'llenLimit' is
-- enforced on every line), dispatches them on 'smtpState', and
-- writes the resulting client commands back out as a 'ByteStream'
-- that the caller pipes to 'sockSink' (for plaintext) or 'tlsSink'
-- (for the post-STARTTLS phase).
proto :: Q.ByteStream SmtpM () -> Q.ByteStream SmtpM ()
proto src = lift get >>= \ st -> do
    when (smtpState st == DOTLS) do        -- Redo EHLO after TLS
        lift smtpSendHello >>= Q.chunk
    loop 0 $ strictLines (fromIntegral $ llenLimit st) src
  where
    loop count str = do
      st <- lift get
      if | DONE  <- smtpState st -> pure ()
         | DOTLS <- smtpState st -> pure ()
         | not $ ok $ smtpErr st -> pure ()
         | otherwise -> lift (Streaming.uncons str) >>= \ case
               Nothing
                   -> lift $ gets smtpErr >>= \e -> when (ok e) do
                          modify' \s -> s { smtpErr = DataErr $ eofErr "read" }
               Just (bs, bss)
                   | B.null bs
                   -> lift $ gets smtpErr >>= \e -> when (ok e) do
                          modify' \s -> s { smtpErr = DataErr $ eofErr "read" }
                   | B.length bs >= llenLimit st
                   -> lift $ gets smtpErr >>= \e -> when (ok e) do
                          modify' \s -> s { smtpErr = ProtoErr 401 $
                                            "Reply too long: " <> bs <> "..." }
                   | otherwise -> case parseReply bs of
                         Nothing -> pure ()
                         Just  r -> do
                             let count' = if replyCont r then count + 1 else 0
                             cmd <- case smtpState st of
                                 GREETING -> lift $ smtpGreeting count r
                                 EHLO     -> lift $ smtpHello count r
                                 STARTTLS -> lift $ smtpStartTLS count r
                                 QUIT     -> lift $ smtpQuit count r
                                 _        -> lift $ fail $
                                             "Unexpected SMTP state "
                                             ++ show (smtpState st)
                             when (not $ BC.null cmd) do
                                 Q.chunk cmd
                             loop count' bss

dosmtp :: ProtoState -> IO ProtoState
dosmtp start = do
  st <- ST.execStateT (sockSource & proto & sockSink) start
  case smtpErr st of
    SmtpOK
      | smtpState st == DOTLS
      -> do
         tlsst <- ST.execStateT startTLS st
         case smtpErr tlsst of
           SmtpOK -> ST.execStateT (tlsSource & proto & tlsSink) tlsst
           _      -> return tlsst
    _ -> return st
