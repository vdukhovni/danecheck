module Dane.Scanner.State
    ( Scanner
    , ScannerSt(..)
    , evalScanner
    , scannerFail
    ) where

import qualified Control.Monad.Trans.State.Strict as ST
import qualified Network.DNS as DNS

import Dane.Scanner.Opts

data ScannerSt = ScannerSt
    { scannerOpts    :: ! Opts
    , scannerDnsSeed :: ! DNS.ResolvSeed
    , scannerOK      :: ! Bool
    }

type Scanner = ST.StateT ScannerSt IO

evalScanner :: Scanner a -> ScannerSt -> IO a
evalScanner = ST.evalStateT

scannerFail :: a -> Scanner a
scannerFail x = do
    ST.modify $ \s -> s { scannerOK = False }
    return x
