{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Dane.Scanner.SMTP.Parse (SmtpReply(..), parseReply)
  where

import           Control.Applicative ( (<|>), (*>) )
import           Control.Monad (mzero)
import           Data.Attoparsec.ByteString.Char8 (Parser, parseOnly)
import qualified Data.Attoparsec.ByteString.Char8 as AP
import qualified Data.ByteString.Char8 as BC
import           Data.Char (ord)
import           Data.Either (isLeft)
import           Data.Monoid (mconcat)

import           Dane.Scanner.SMTP.Internal

digit :: Parser Int
digit = do
  c <- AP.satisfy AP.isDigit
  return $ ord(c) - ord('0')

space :: Parser Char
space = AP.char ' '

hyphen :: Parser Char
hyphen = AP.char '-'

textchar :: Parser BC.ByteString
textchar = do
  c <- AP.satisfy $ (&&) <$> (/= '\r') <*> (/= '\n')
  return $ BC.singleton c

barecr :: Parser BC.ByteString
barecr = do
  c <- AP.char '\r' *> AP.peekChar
  case c of
    Just '\n' -> mzero
    _ -> return $ BC.singleton '\r'

text :: Parser BC.ByteString
text = do
  chunks <- AP.many' $ (textchar <|> barecr)
  return $ mconcat chunks

parser :: Parser SmtpReply
parser = do
  digits <- AP.count 3 digit
  let replyCode = foldl (\acc x -> 10 * acc + x) 0 digits
  replyCont <- isLeft <$> AP.eitherP hyphen space
  replyText <- text
  AP.endOfLine
  AP.endOfInput
  return $! SmtpReply{..}

parseReply :: BC.ByteString -> Maybe SmtpReply
parseReply reply =
  case (parseOnly parser reply) of
  Right x -> Just x
  Left _  -> Nothing
