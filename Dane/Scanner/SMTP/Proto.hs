{-# LANGUAGE OverloadedStrings #-}

module Dane.Scanner.SMTP.Proto (dosmtp) where

import           Conduit (sinkNull, takeCE, foldC)
import           Control.Monad (unless, when)
import           Control.Monad.Base (liftBase)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.State.Strict (get, gets, modify)
import qualified Control.Monad.Trans.State.Strict as ST
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BS
import           Data.Conduit (ConduitM, runConduit)
import           Data.Conduit (await, leftover, yield, (.|))
import qualified Data.Text as T
import qualified Data.Text.Encoding as E

import           Dane.Scanner.SMTP.Sock
import           Dane.Scanner.SMTP.Parse
import           Dane.Scanner.SMTP.Internal
import           Dane.Scanner.SMTP.TLS

ok :: SmtpErr -> Bool
ok SmtpOK = True
ok _      = False

data SmtpLine = FullLine ByteString
              | LongLine ByteString
              | SmtpEOF
              deriving (Show)

-- crlf :: ByteString
-- crlf = "\r\n"

-- | Used
--
takeLine :: ConduitM ByteString ByteString SmtpM ()
         -> ConduitM ByteString ByteString SmtpM SmtpLine
takeLine inner =
  loop .| do
      b <- inner .| foldC
      rest <- await
      e <- lift $ gets smtpErr
      case (rest) of
          Nothing | BS.null b || ok e /= True
                              -> return $ SmtpEOF
                  | otherwise -> return $ FullLine b
          Just _  -> sinkNull >> (return $ LongLine b)
  where
    loop = await >>= mapM_ go
    go bs = do
      let (lineFragment, rest) = BS.break (== '\n') bs
      if BS.null rest
          then yield lineFragment >> loop
          else do
              let t = BS.tail rest
              yield $ lineFragment <> BS.singleton '\n'
              unless (BS.null t) $ leftover t

smtpSendHello :: SmtpM ByteString
smtpSendHello = do
  cmd <- gets clientName >>= \name -> return $ "EHLO " <> name <> "\r\n"
  -- liftBase $ BS.putStr $ "\r\n"<> "C: " <> cmd
  deadline <- liftBase . timeLimit =<< gets smtpTimeout
  modify $ \s -> s { smtpState = EHLO, ioDeadline  = deadline }
  return cmd

smtpGreeting :: Int -> SmtpReply -> SmtpM ByteString
smtpGreeting _ r = do
  case () of
    _ | replyCont r -> return BS.empty
      | code <- replyCode r
      , code `div` 100 /= 2
      -> do
          modify $ \s -> s { smtpErr = ProtoErr code $ replyText r }
          return BS.empty
      | otherwise
      -> smtpSendHello

smtpHello :: Int -> SmtpReply -> SmtpM ByteString
smtpHello count r = do
  when (count > 0 && "STARTTLS" == T.toUpper (E.decodeLatin1 (replyText r))) $
    modify $ \s -> s { features = FeatureTLS:features s}
  case () of
    _ | replyCont r
      -> return BS.empty
      | code <- replyCode r
      , code `div` 100 /= 2
      -> do
          modify $ \s -> s { smtpErr = ProtoErr code $ replyText r }
          return BS.empty
      | otherwise
      -> do
          st <- get
          cmd <- if (FeatureTLS `elem` features st && (not $ hasTLS st))
            then do
              modify $ \s -> s { smtpState = STARTTLS }
              return $ "STARTTLS\r\n"
            else do
              modify $ \s -> s { smtpState = QUIT }
              return $ "QUIT\r\n"
          -- liftBase $ BS.putStr $ "\r\n" <> "C: " <> cmd
          deadline <- liftBase . timeLimit =<< gets smtpTimeout
          modify $ \s -> s { ioDeadline  = deadline }
          return cmd

smtpStartTLS :: Int -> SmtpReply -> SmtpM ByteString
smtpStartTLS _ r = do
  when (not $ replyCont r) $ do
    let code = replyCode r
    if (code `div` 100 == 2)
    then modify $ \s -> s { smtpState = DOTLS }
    else modify $ \s -> s { smtpErr = ProtoErr code $ replyText r }
  return BS.empty

smtpQuit :: Int -> SmtpReply -> SmtpM ByteString
smtpQuit _ r = do
  when (not $ replyCont r) $ do
    let code = replyCode r
    if (code `div` 100 == 2)
    then do
      get >>= \st -> when (hasTLS st) $ endTLS
      modify $ \s -> s { smtpState = DONE }
    else
      modify $ \s -> s { smtpErr = ProtoErr code $ replyText r }
  return BS.empty

proto :: ConduitM ByteString ByteString SmtpM ()
proto = do
  -- Redo EHLO after TLS handshake
  st <- lift $ gets smtpState
  when (st == DOTLS) $ lift smtpSendHello >>= yield
  loop 0
  where
    loop count = do
      st <- lift get
      when (ok (smtpErr st) &&
            not (smtpState st `elem` [DONE, DOTLS])) $
        (takeLine $ takeCE $ llenLimit st) >>= go count

    go count (FullLine bs) = do
      -- liftBase $ BS.putStr $ "S: " <> bs
      st <- lift get
      case (parseReply bs) of
        Nothing -> return ()
        Just  r -> do
          let count' = if (replyCont r) then count + 1 else 0
          cmd <- case smtpState st of
            GREETING -> lift $ smtpGreeting count r
            EHLO     -> lift $ smtpHello count r
            STARTTLS -> lift $ smtpStartTLS count r
            QUIT     -> lift $ smtpQuit count r
            _        -> error $ "Unexpected SMTP state" ++
                        (show $ smtpState st)
          when (not $ BS.null cmd) $ yield cmd
          loop count'
    go _ SmtpEOF = lift $
      gets smtpErr >>= \e -> when (ok e) $
        modify $
          \s -> s { smtpErr = DataErr $ eofErr "read" }
    go _ (LongLine bs) = do
      -- liftBase $ BS.putStr $ "S...: " <> bs <> crlf
      lift $ modify $ \s -> s { smtpErr = ProtoErr 401 $
                                "Reply too long: " <> bs <> "..." }

dosmtp :: ProtoState -> IO ProtoState
dosmtp start = do
  st <- ST.execStateT (runConduit $ sockSource .| proto .| sockSink) start
  case smtpErr st of
    SmtpOK
      | smtpState st == DOTLS
      -> do
         tlsst <- ST.execStateT(startTLS) st
         case smtpErr tlsst of
           SmtpOK -> flip ST.execStateT tlsst $ runConduit $
                        tlsSource .| proto .| tlsSink
           _      -> return tlsst
    _ -> return st
