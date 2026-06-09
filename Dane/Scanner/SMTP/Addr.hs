{-# LANGUAGE RecordWildCards #-}

module Dane.Scanner.SMTP.Addr ( ipConn ) where

import           Control.Exception (IOException, bracket, try)
import           Data.IP (IP(IPv4, IPv6), toHostAddress, toHostAddress6)
import           Network.Socket (SockAddr(..), AddrInfo(..), Socket, SocketType(Stream))
import           Network.Socket (Family(AF_INET, AF_INET6), defaultProtocol, PortNumber)
import           Network.Socket (connect, close, socket)
import           System.Timeout (timeout)

import           Dane.Scanner.SMTP.Internal

connectIP :: Int
          -> (Either IOException Socket -> IO a)
          -> AddrInfo
          -> IO a
connectIP tmout action ~(AddrInfo{..}) =
    bracket (socket addrFamily addrSocketType addrProtocol) close \sock -> do
        res <- timeout tmout $ try $ connect sock addrAddress
        case res of
            Just (Right _) -> action . Right $ sock
            Just (Left e)  -> action . Left $ ioErr "connect" e
            Nothing        -> action . Left $ timeErr "connect"

-- | Connect to the specified peer on the given TCP port with the
-- given timeout (in microseconds).  The callback receives either
-- a connected 'Socket' or the 'IOException' describing the
-- failure to connect; the socket is always closed when the
-- callback returns, regardless of how it returns.
ipConn :: IP
       -> PortNumber
       -> Int
       -> (Either IOException Socket -> IO a)
       -> IO a
ipConn (IPv4 ip4) port tmout action = connectIP tmout action AddrInfo
    { addrFlags      = []
    , addrFamily     = AF_INET
    , addrSocketType = Stream
    , addrProtocol   = defaultProtocol
    , addrAddress    = SockAddrInet port (toHostAddress ip4)
    , addrCanonName  = Nothing
    }
ipConn (IPv6 ip6) port tmout action = connectIP tmout action AddrInfo
    { addrFlags      = []
    , addrFamily     = AF_INET6
    , addrSocketType = Stream
    , addrProtocol   = defaultProtocol
    , addrAddress    = SockAddrInet6 port 0 (toHostAddress6 ip6) 0
                       -- 0 for FlowInfo, ScopeID
    , addrCanonName  = Nothing
    }
