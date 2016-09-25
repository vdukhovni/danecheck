{-# LANGUAGE OverloadedStrings #-}

module Dane.Scanner.Util
  ( bs2hex
  , cons2
  , d2s
  , gettime
  , headDef
  , if_
  , justHead
  , nonempty
  , pair
  , rootOrTLD
  ) where

import qualified System.Posix.Time as Sys
import           Foreign.C.Types (CTime(..))

import qualified Data.ByteString.Builder as LB
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as LB
import           Data.Char (toLower)
import           Data.Int (Int64)


-- | Hexadecimal representation of the input ByteString as a new ByteString
--
bs2hex :: ByteString -> ByteString
bs2hex = LB.toStrict . LB.toLazyByteString . LB.byteStringHex
{-# INLINE bs2hex #-}


-- | Convert mixed-case ByteString domains that typically end in a trailing '.'
--   to lower-case strings with no trailing '.'.
d2s :: ByteString -> String
d2s d = BC.unpack $ BC.map toLower $ case BC.unsnoc d of
    Just (i, l) | l == '.'
                -> i
    _           -> d


-- | Prepend two elements to a list
--
cons2 :: a -> a -> [a] -> [a]
cons2 a1 a2 as = a1 : a2 : as


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


-- | Wrap the head of a list in the Maybe monad, defaulting to Nothing for
-- empty lists
--
justHead :: [a] -> Maybe a
justHead [] = Nothing
justHead (h:_) = Just h
{-# INLINE justHead #-}


-- | Macro for not @null@
--
nonempty :: [a] -> Bool
nonempty [] = False
nonempty _ = True
{-# INLINE nonempty #-}


-- | Make a two element list
--
pair :: a -> a -> [a]
pair x y = [x, y]
{-# INLINE pair #-}


-- | Test whether a domain is either the root domain ".", or is a TLD and
-- therefore has no nonfinal "."
--
rootOrTLD :: ByteString -> Maybe ByteString
rootOrTLD b =
    if (BC.null b) then Just "."
    else if (BC.notElem '.' $ BC.init b) then Just b
    else Nothing
{-# INLINE rootOrTLD #-}
