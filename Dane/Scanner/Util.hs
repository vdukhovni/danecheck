{-# LANGUAGE OverloadedStrings #-}

module Dane.Scanner.Util
  ( bs2hex
  , d2s
  , gettime
  , headDef
  , if_
  , nonempty
  , rootOrTLD
  ) where

import qualified System.Posix.Time as Sys
import           Foreign.C.Types (CTime(..))

import qualified Data.ByteString.Builder as LB
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Lazy as LB
import           Data.Int (Int64)

import           Net.DNSBase (Domain, canonicalise, labelCount, toHost)
import           Net.DNSBase.Present (presentString)


-- | Hexadecimal representation of the input ByteString as a new ByteString
--
bs2hex :: ByteString -> ByteString
bs2hex = LB.toStrict . LB.toLazyByteString . LB.byteStringHex
{-# INLINE bs2hex #-}


-- | Render a 'Domain' as its canonical lowercase 'String' form,
-- with no trailing dot.  Calls 'canonicalise' to lowercase the
-- domain, then 'toHost' to drop the trailing root label, then
-- 'presentString' to materialise the bytes.  Not valid on the
-- root domain; callers know they're working with host names.
d2s :: Domain -> String
d2s d = presentString (toHost (canonicalise d)) mempty


-- | Get POSIX time (in a more usable form)
--
gettime :: IO Int64
gettime = Sys.epochTime >>= \(CTime t) -> return t


-- | Safe @head@ that returns a default value for empty lists
--
headDef :: a -> [a] -> a
headDef z [] = z
headDef _ (h:_) = h
{-# INLINE headDef #-}


-- | de-sugared pure ternary
--
if_ :: Bool -> a -> a -> a
if_ True  x _ = x
if_ False _ y = y
{-# INLINE if_ #-}


-- | Macro for not @null@
--
nonempty :: [a] -> Bool
nonempty [] = False
nonempty _ = True
{-# INLINE nonempty #-}


-- | Test whether a domain is either the root domain ".", or is
-- a TLD and therefore has only one label.
--
rootOrTLD :: Domain -> Maybe Domain
rootOrTLD d
    | labelCount d <= 1 = Just d
    | otherwise         = Nothing
{-# INLINE rootOrTLD #-}
