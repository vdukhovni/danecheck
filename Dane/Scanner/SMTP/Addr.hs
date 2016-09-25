{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}

module Dane.Scanner.SMTP.Addr ( ipConn ) where

import           System.Timeout.Lifted (timeout)

import           Control.Exception.Lifted (IOException, try, bracket)
import           Control.Monad.Base (liftBase)
import           Control.Monad.Trans.Control (MonadBaseControl)
import           Network.Socket (SockAddr(..), AddrInfo(..), Socket, SocketType(Stream))
import           Network.Socket (Family(AF_INET, AF_INET6), defaultProtocol, PortNumber)
import           Network.Socket (connect, close, socket)

import           Network.DNS (RData(RD_A, RD_AAAA))
import           Data.IP (toHostAddress, toHostAddress6)
import           Dane.Scanner.SMTP.Internal

connectIP :: MonadBaseControl IO m
          => Int
          -> (Either IOException Socket -> m a)
          -> AddrInfo
          -> m a
connectIP tmout action ~(AddrInfo{..}) =
  let addr = addrAddress
   in bracket (liftBase $ socket addrFamily addrSocketType addrProtocol)
              (liftBase . close)
              (\sock -> do
                res <- timeout tmout $ try $ liftBase $ connect sock addr
                case res of
                  Just (Right _) -> action . Right $ sock
                  Just (Left e)  -> action . Left $ ioErr "connect" e
                  Nothing        -> action . Left $ timeErr "connect"
              )

-- | ipConn
--   Connect to the specified SMTP server (default "localhost")
--   on the specified port (default "smtp"), with the specified
--   timeout.  The return value is either a connected socket or
--   or IOException.
--
ipConn :: MonadBaseControl IO m
       => RData
       -> PortNumber
       -> Int
       -> (Either IOException Socket -> m a)
       -> m a
ipConn rd port tmout action =
  let ai = case rd of
             RD_A ip4 ->  AddrInfo { addrFlags = []
                                   , addrFamily = AF_INET
                                   , addrSocketType = Stream
                                   , addrProtocol = defaultProtocol
                                   , addrAddress = SockAddrInet port (toHostAddress ip4)
                                   , addrCanonName = Nothing
                                   }
             RD_AAAA ip6 -> AddrInfo { addrFlags = []
                                     , addrFamily = AF_INET6
                                     , addrSocketType = Stream
                                     , addrProtocol = defaultProtocol
                                     , addrAddress = SockAddrInet6 port 0 (toHostAddress6 ip6) 0 -- 0 for FlowInfo, ScopeID
                                     , addrCanonName = Nothing
                                     }
             _ -> error "Dane.Scanner.SMTP.Addr.ipConn: rd must be A or AAAA RData"
   in do connectIP tmout action ai
