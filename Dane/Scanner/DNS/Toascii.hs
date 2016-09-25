module Dane.Scanner.DNS.Toascii (toascii) where

import           Data.Char (chr)
import qualified Data.Text as T
import qualified Text.IDNA as IDNA

-- Besides U+002E (full stop) IDNA2003 allows DNS labels to be
-- separated by any of the Unicode variants U+3002 (ideographic
-- full stop), U+FF0E (fullwidth full stop), and U+FF61
-- (halfwidth ideographic full stop).

dots :: [Char]
dots = map chr [0x002E, 0x3002, 0xFF0E, 0xFF61]

encode :: T.Text -> Maybe T.Text
encode label
  | (label == T.empty) = Nothing
  | otherwise = IDNA.toASCII True True label

convert_labels :: [T.Text] -> Maybe String
convert_labels labels =
  ascii_labels |$> reverse
               |$> T.intercalate (T.singleton '.')
               |$> T.toLower
               |$> T.unpack
  where ascii_labels = sequence $ map encode labels

infixl 1 |$>
(|$>) :: (Functor f) => f a -> (a -> b) -> f b
(|$>) = flip fmap

toascii :: String -> Maybe String
toascii s =
  case janet of
  [] -> Nothing
  x:xs | (x == T.empty &&
          length xs == 1 &&
          (T.null $ head xs)) -> Just "."
       | (x == T.empty) -> convert_labels xs
       | otherwise -> convert_labels janet
  where janet = reverse $ T.split (`elem` dots) $ T.pack s
