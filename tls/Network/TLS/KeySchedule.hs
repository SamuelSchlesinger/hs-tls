{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.KeySchedule (
    hkdfExtract,
    hkdfExpandLabel,
    deriveSecret,
) where

import qualified Control.Exception as E
import qualified Crypto.BoringSSL.HKDF as BHKDF
import qualified Data.ByteString as BS

import Network.TLS.Crypto
import Network.TLS.Error
import Network.TLS.Imports
import Network.TLS.Types
import Network.TLS.Wire

----------------------------------------------------------------

-- | @HKDF-Extract@ function.  Returns the pseudorandom key (PRK) from salt and
-- input keying material (IKM).
hkdfExtract :: Hash -> ByteString -> ByteString -> ByteString
hkdfExtract h salt ikm =
    case BHKDF.hkdfExtract (hashAlgorithm h) ikm salt of
        Right prk -> BHKDF.secureBytesToByteString prk
        Left err -> E.throw $ Uncontextualized $ Error_Protocol ("hkdfExtract: " ++ show err) InternalError

----------------------------------------------------------------

deriveSecret :: Hash -> ByteString -> ByteString -> TranscriptHash -> ByteString
deriveSecret h secret label (TranscriptHash hashedMsgs) =
    hkdfExpandLabel h secret label hashedMsgs outlen
  where
    outlen = hashDigestSize h

----------------------------------------------------------------

-- | @HKDF-Expand-Label@ function.  Returns output keying material of the
-- specified length from the PRK, customized for a TLS label and context.
hkdfExpandLabel
    :: Hash
    -> ByteString
    -> ByteString
    -> ByteString
    -> Int
    -> ByteString
hkdfExpandLabel h secret label ctx outlen = expand' h secret hkdfLabel outlen
  where
    hkdfLabel = runPut $ do
        putWord16 $ fromIntegral outlen
        putOpaque8 ("tls13 " `BS.append` label)
        putOpaque8 ctx

expand' :: Hash -> ByteString -> ByteString -> Int -> ByteString
expand' h secret label len =
    case BHKDF.hkdfExpand (hashAlgorithm h) secret label len of
        Right okm -> BHKDF.secureBytesToByteString okm
        Left err -> E.throw $ Uncontextualized $ Error_Protocol ("hkdfExpandLabel: " ++ show err) InternalError

----------------------------------------------------------------
