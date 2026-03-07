{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ViewPatterns #-}
module Dane.Scanner.DNS.Toascii (toascii) where

import qualified Data.List as L
import qualified Data.Text as T
import Data.Char (chr, toLower)
import Data.Text.IDN (toASCII, IDNError(EmptyLabel))

-- Besides U+002E (full stop) IDNA2003 allows DNS labels to be
-- separated by any of the Unicode variants U+3002 (ideographic
-- full stop), U+FF0E (fullwidth full stop), and U+FF61
-- (halfwidth ideographic full stop).

dots :: [Char]
dots = map chr [0x002E, 0x3002, 0xFF0E, 0xFF61]

brk :: String -> (String, String)
brk = L.break (`elem` dots)

toascii :: String -> Either IDNError [T.Text]
toascii (brk -> (l0, ls0)) = reverse <$> go [] l0 ls0
  where
    go acc l@(_:_) = \ case
        (_ : (brk -> (m, ms))) -> convert acc l >>= \a -> go a m ms
        _                      -> convert acc l
    go acc _ = \ case
        ""   | _:_ <- acc -> Right acc
             | otherwise  -> Left EmptyLabel
        _:[] | [] <- acc  -> Right acc
        _                 -> Left EmptyLabel

    convert acc (T.pack . map toLower -> label)
        | T.all (<= '\x7f') label = Right (label : acc)
        | otherwise             = (: acc) <$> toASCII label
