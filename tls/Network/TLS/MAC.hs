module Network.TLS.MAC (
    hmac,
    prf_MD5,
    prf_SHA1,
    prf_SHA256,
    prf_TLS,
    prf_MD5SHA1,
) where

import qualified Crypto.BoringSSL.HMAC as BHMAC
import qualified Data.ByteString as B

import Network.TLS.Crypto (Hash (..), hashAlgorithm)
import Network.TLS.Crypto.BoringCompat (bsXor)
import Network.TLS.Imports
import Network.TLS.Types

type HMAC = ByteString -> ByteString -> ByteString

-- | HMAC using BoringSSL's constant-time implementation.
hmac :: Hash -> HMAC
hmac alg secret msg =
    case BHMAC.hmac (hashAlgorithm alg) secret msg of
        Right result -> result
        Left err -> error ("hmac: internal error: " ++ show err)

hmacIter
    :: HMAC -> ByteString -> ByteString -> ByteString -> Int -> [ByteString]
hmacIter f secret seed aprev len =
    let an = f secret aprev
     in let out = f secret (B.concat [an, seed])
         in let digestsize = B.length out
             in if digestsize >= len
                    then [B.take (fromIntegral len) out]
                    else out : hmacIter f secret seed an (len - digestsize)

prf_SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_SHA1 secret seed len = B.concat $ hmacIter (hmac SHA1) secret seed seed len

prf_MD5 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5 secret seed len = B.concat $ hmacIter (hmac MD5) secret seed seed len

prf_MD5SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5SHA1 secret seed len =
    bsXor (prf_MD5 s1 seed len) (prf_SHA1 s2 seed len)
  where
    slen = B.length secret
    s1 = B.take (slen `div` 2 + slen `mod` 2) secret
    s2 = B.drop (slen `div` 2) secret

prf_SHA256 :: ByteString -> ByteString -> Int -> ByteString
prf_SHA256 secret seed len = B.concat $ hmacIter (hmac SHA256) secret seed seed len

-- | For now we ignore the version, but perhaps some day the PRF will depend
-- not only on the cipher PRF algorithm, but also on the protocol version.
prf_TLS :: Version -> Hash -> ByteString -> ByteString -> Int -> ByteString
prf_TLS _ halg secret seed len =
    B.concat $ hmacIter (hmac halg) secret seed seed len
