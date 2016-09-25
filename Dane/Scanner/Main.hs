module Main (main) where

import           System.Exit (ExitCode(ExitFailure), exitWith)
import           Control.Monad (when)

import           Dane.Scanner.DNS.Dane
import qualified Dane.Scanner.Opts as Opts


-- | Parse JCL and check the requested domain
--
main :: IO ()
main = do
  ok <- daneCheck =<< Opts.getOpts
  when (not ok) $ exitWith $ ExitFailure 1
