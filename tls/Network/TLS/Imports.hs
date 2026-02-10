{-# LANGUAGE NoImplicitPrelude #-}

module Network.TLS.Imports (
    -- generic exports
    ByteString,
    (<&>),
    module Control.Applicative,
    module Control.Monad,
    module Data.Bits,
    module Data.List,
    module Data.Maybe,
    module Data.Semigroup,
    module Data.Ord,
    module Data.Word,
    -- project definition
    showBytesHex,
) where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as Base16
import Data.ByteString.Char8 ()
import Data.Functor
import Data.List
import Data.Maybe
import Data.Ord
import Data.Semigroup
import Data.Word
import qualified Prelude as P

showBytesHex :: ByteString -> P.String
showBytesHex bs = P.show (Base16.encode bs)
