module Dane.Scanner.Source
    ( strictLines
    ) where

import qualified Data.ByteString as B
import qualified Streaming.ByteString.Char8 as Q
import Control.Monad ((>=>))
import Data.Bitraversable (bitraverse)
import Data.Int (Int64)
import Streaming (Stream, Of, inspect, unfold)

-- | Stream lines as strict 'B.ByteString' values truncated to
-- @limit@ bytes.  Newline characters are retained on lines that
-- fit within the limit (so a non-empty chunk that does not end in
-- @\\n@ signals a long line that was cut off mid-content); an
-- empty chunk signals end-of-input.
--
strictLines :: Monad m
            => Int64                -- ^ Line length limit
            -> Q.ByteStream m r     -- ^ Input 'Q.ByteStream'
            -> Stream (Of B.ByteString) m r
strictLines limit = unfold (inspect >=> bitraverse pure trim) . Q.lineSplit 1
  where
    trim = Q.toStrict . Q.drained . Q.splitAt limit
