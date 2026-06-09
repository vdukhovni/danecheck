-- | Module      : Dane.Scanner.DNS.Toascii
-- Description   : IDNA2008 input parser for a one-shot DANE check
-- Copyright     : (c) Viktor Dukhovni, 2018
-- License       : BSD-3-Clause
-- Maintainer    : ietf-dane@dukhovni.org
-- Stability     : experimental
-- Portability   : POSIX
--
-- Convert input domains that may contain U-labels to A-label form.
-- Optionally allow leading underscores in labels.
--
module Dane.Scanner.DNS.Toascii (todomain) where

import qualified Text.IDNA2008 as I
import Data.Text (Text)
import Net.DNSBase (Domain, wireToDomain)

-- | Attempt to convert all the labels of a 'Text' domainname to IDNA ASCII.
-- Returns 'Nothing' on failure.
--
todomain :: I.LabelFormSet -- ^ Accepted label forms
         -> I.IdnaFlags    -- ^ IDNA parser options
         -> Text           -- ^ Input domain name
         -> Maybe Domain
todomain forms opts name = case I.parseDomainOpts forms opts name of
    Right (I.Domain sbs, _) -> wireToDomain sbs
    Left _                  -> Nothing
