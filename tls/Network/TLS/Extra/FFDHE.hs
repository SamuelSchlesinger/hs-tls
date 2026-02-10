-- |
-- Module      : Network.TLS.Extra
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- Finite Field Diffie-Hellman Ephemeral Parameters defined in RFC 7919.
--
-- DEPRECATED: DHE cipher suites have been removed for security reasons
-- (timing-vulnerable modular exponentiation). These stubs are retained
-- only for API compatibility.
module Network.TLS.Extra.FFDHE where

import Network.TLS.Struct (DHParams, dhParams)

-- | DEPRECATED: DHE is no longer supported.
ffdhe2048 :: DHParams
ffdhe2048 = dhParams 0 0

-- | DEPRECATED: DHE is no longer supported.
ffdhe3072 :: DHParams
ffdhe3072 = dhParams 0 0

-- | DEPRECATED: DHE is no longer supported.
ffdhe4096 :: DHParams
ffdhe4096 = dhParams 0 0

-- | DEPRECATED: DHE is no longer supported.
ffdhe6144 :: DHParams
ffdhe6144 = dhParams 0 0

-- | DEPRECATED: DHE is no longer supported.
ffdhe8192 :: DHParams
ffdhe8192 = dhParams 0 0
