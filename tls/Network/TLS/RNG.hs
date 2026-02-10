{-# LANGUAGE BangPatterns #-}

-- | HMAC-DRBG based random number generator (NIST SP 800-90A)
-- using HMAC-SHA256 via boringssl.
module Network.TLS.RNG (
    StateRNG,
    Seed,
    seedNew,
    seedToInteger,
    seedFromInteger,
    newStateRNG,
    hmacDrbgGenerate,
) where

import qualified Crypto.BoringSSL.Digest as Digest
import qualified Crypto.BoringSSL.HMAC as HMAC
import qualified Crypto.BoringSSL.Random as Random
import qualified Data.ByteString as B
import Data.ByteString (ByteString)

import Network.TLS.Crypto.BoringCompat (i2ospOf_, os2ip)

-- | Seed for initializing the DRBG.
newtype Seed = Seed ByteString

-- | Generate a fresh random seed using the OS CSPRNG.
seedNew :: IO Seed
seedNew = Seed <$> Random.randomBytes 48

-- | Convert a seed to an integer.
seedToInteger :: Seed -> Integer
seedToInteger (Seed bs) = os2ip bs

-- | Create a seed from an integer (padded to 48 bytes).
seedFromInteger :: Integer -> Seed
seedFromInteger n = Seed (i2ospOf_ 48 n)

-- | HMAC-DRBG state: (Key, V) both 32 bytes (SHA-256).
data StateRNG = StateRNG !ByteString !ByteString

instance Show StateRNG where
    show _ = "rng[..]"

-- | Instantiate HMAC-DRBG from a seed.
newStateRNG :: Seed -> StateRNG
newStateRNG (Seed seedBytes) = hmacDrbgUpdate seedBytes k0 v0
  where
    k0 = B.replicate 32 0x00
    v0 = B.replicate 32 0x01

-- | HMAC-DRBG Update function (NIST SP 800-90A Section 10.1.2.2).
hmacDrbgUpdate :: ByteString -> ByteString -> ByteString -> StateRNG
hmacDrbgUpdate provided !k !v =
    let !k1 = hmac256 k (v <> B.singleton 0x00 <> provided)
        !v1 = hmac256 k1 v
     in if B.null provided
            then StateRNG k1 v1
            else
                let !k2 = hmac256 k1 (v1 <> B.singleton 0x01 <> provided)
                    !v2 = hmac256 k2 v1
                 in StateRNG k2 v2

-- | HMAC-DRBG Generate function (NIST SP 800-90A Section 10.1.2.5).
-- Returns @n@ pseudorandom bytes and the updated RNG state.
hmacDrbgGenerate :: Int -> StateRNG -> (ByteString, StateRNG)
hmacDrbgGenerate n (StateRNG k v0) =
    let (!chunks, !vLast) = go v0 0 []
        !temp = B.concat (reverse chunks)
        !result = B.take n temp
        -- Reseed step (update with no additional input)
        !k' = hmac256 k (vLast <> B.singleton 0x00)
        !v' = hmac256 k' vLast
     in (result, StateRNG k' v')
  where
    go !v !generated !acc
        | generated >= n = (acc, v)
        | otherwise =
            let !v' = hmac256 k v
             in go v' (generated + 32) (v' : acc)

-- | Pure HMAC-SHA256 wrapper.
hmac256 :: ByteString -> ByteString -> ByteString
hmac256 key msg = case HMAC.hmac Digest.SHA256 key msg of
    Right bs -> bs
    Left _ -> error "hmac256: HMAC-SHA256 failed unexpectedly"
