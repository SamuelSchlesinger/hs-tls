-- | Compatibility utilities providing functions equivalent to those from
-- the @memory@ package (Data.ByteArray) and @crypton@ package
-- (Crypto.Number.Serialize, Crypto.Number.Basic), implemented without
-- those dependencies.
module Network.TLS.Crypto.BoringCompat (
    -- * ByteString XOR
    bsXor,

    -- * Integer / ByteString conversion
    os2ip,
    i2osp,
    i2ospOf_,

    -- * Integer utilities
    numBits,
) where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

-- | XOR two ByteStrings of equal length. If lengths differ, the result
-- is truncated to the shorter length.
bsXor :: ByteString -> ByteString -> ByteString
bsXor a b = BS.pack $ BS.zipWith xor a b

-- | Octet String to Integer Primitive.
-- Convert a big-endian ByteString to a non-negative Integer.
os2ip :: ByteString -> Integer
os2ip = BS.foldl' (\acc w -> acc `shiftL` 8 .|. fromIntegral w) 0

-- | Integer to Octet String Primitive.
-- Convert a non-negative Integer to a minimal big-endian ByteString.
-- Returns a single zero byte for input 0.
i2osp :: Integer -> ByteString
i2osp 0 = BS.singleton 0
i2osp n = BS.pack $ reverse $ unfoldr n
  where
    unfoldr 0 = []
    unfoldr i =
        let (q, r) = i `divMod` 256
         in fromIntegral r : unfoldr q

-- | Integer to Octet String Primitive with fixed output length.
-- Zero-pads on the left to the requested length. If the integer
-- requires more bytes than @len@, the output is truncated (takes
-- the least-significant @len@ bytes).
i2ospOf_ :: Int -> Integer -> ByteString
i2ospOf_ len n =
    let bs = i2osp n
        bsLen = BS.length bs
     in if bsLen >= len
            then BS.drop (bsLen - len) bs
            else BS.append (BS.replicate (len - bsLen) 0) bs

-- | Number of bits needed to represent a non-negative Integer.
-- Returns 0 for input 0.
numBits :: Integer -> Int
numBits 0 = 0
numBits n = go n 0
  where
    go :: Integer -> Int -> Int
    go 0 acc = acc
    go i acc = go (i `shiftR` 1) (acc + 1)
