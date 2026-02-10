{-# LANGUAGE RankNTypes #-}
{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Crypto (
    HashContext,
    HashCtx,
    hashInit,
    hashUpdate,
    hashUpdates,
    hashUpdateSSL,
    hashFinal,
    module Network.TLS.Crypto.IES,
    module Network.TLS.Crypto.Types,

    -- * Hash
    hash,
    hashChunks,
    Hash (..),
    hashAlgorithm,
    hashName,
    hashDigestSize,
    hashBlockSize,

    -- * key exchange generic interface
    PubKey (..),
    PrivKey (..),
    PublicKey,
    PrivateKey,
    SignatureParams (..),
    isKeyExchangeSignatureKey,
    findKeyExchangeSignatureAlg,
    findEllipticCurveGroup,
    kxEncrypt,
    kxDecrypt,
    kxSign,
    kxVerify,
    kxCanUseRSApkcs1,
    kxCanUseRSApss,
    kxSupportedPrivKeyEC,
    KxError (..),
    RSAEncoding (..),
    pubkeyType,
) where

import qualified Control.Exception as E
import qualified Crypto.BoringSSL.Digest as Digest
import qualified Crypto.BoringSSL.ECDSA as BECDSA
import qualified Crypto.BoringSSL.Ed25519 as BEd25519
import qualified Crypto.BoringSSL.RSA as BRSA
import qualified Data.ByteString as B
import System.IO.Unsafe (unsafePerformIO)

import Network.TLS.Crypto.IES
import Network.TLS.Crypto.Types
import Network.TLS.Error
import Network.TLS.Imports

{-# DEPRECATED PublicKey "use PubKey" #-}
type PublicKey = PubKey
{-# DEPRECATED PrivateKey "use PrivKey" #-}
type PrivateKey = PrivKey

-- | Public key types backed by boringssl.
data PubKey
    = PubKeyRSA BRSA.RSAPublicKey
    | PubKeyEC BECDSA.ECCurve BECDSA.ECPublicKey
    | PubKeyEd25519 BEd25519.PublicKey

instance Show PubKey where
    show (PubKeyRSA _) = "PubKeyRSA"
    show (PubKeyEC c _) = "PubKeyEC " ++ show c
    show (PubKeyEd25519 _) = "PubKeyEd25519"

-- | Private key types backed by boringssl.
data PrivKey
    = PrivKeyRSA BRSA.RSAKeyPair
    | PrivKeyEC BECDSA.ECCurve BECDSA.ECKeyPair
    | PrivKeyEd25519 BEd25519.PrivateKey

instance Show PrivKey where
    show (PrivKeyRSA _) = "PrivKeyRSA"
    show (PrivKeyEC c _) = "PrivKeyEC " ++ show c
    show (PrivKeyEd25519 _) = "PrivKeyEd25519"

data KxError
    = RSAError String
    | KxUnsupported
    deriving (Show)

-- | Return a human-readable name for a public key type.
pubkeyType :: PubKey -> String
pubkeyType (PubKeyRSA _) = "RSA"
pubkeyType (PubKeyEC _ _) = "ECDSA"
pubkeyType (PubKeyEd25519 _) = "Ed25519"

isKeyExchangeSignatureKey :: KeyExchangeSignatureAlg -> PubKey -> Bool
isKeyExchangeSignatureKey KX_RSA (PubKeyRSA _) = True
isKeyExchangeSignatureKey KX_ECDSA (PubKeyEC _ _) = True
isKeyExchangeSignatureKey KX_ECDSA (PubKeyEd25519 _) = True
isKeyExchangeSignatureKey _ _ = False

findKeyExchangeSignatureAlg
    :: (PubKey, PrivKey) -> Maybe KeyExchangeSignatureAlg
findKeyExchangeSignatureAlg keyPair =
    case keyPair of
        (PubKeyRSA _, PrivKeyRSA _) -> Just KX_RSA
        (PubKeyEC _ _, PrivKeyEC _ _) -> Just KX_ECDSA
        (PubKeyEd25519 _, PrivKeyEd25519 _) -> Just KX_ECDSA
        _ -> Nothing

findEllipticCurveGroup :: BECDSA.ECCurve -> Maybe Group
findEllipticCurveGroup BECDSA.P256 = Just P256
findEllipticCurveGroup BECDSA.P384 = Just P384
findEllipticCurveGroup BECDSA.P521 = Just P521

-- Map our Hash type to boringssl's Algorithm type.
hashAlgorithm :: Hash -> Digest.Algorithm
hashAlgorithm MD5 = Digest.MD5
hashAlgorithm SHA1 = Digest.SHA1
hashAlgorithm SHA224 = Digest.SHA224
hashAlgorithm SHA256 = Digest.SHA256
hashAlgorithm SHA384 = Digest.SHA384
hashAlgorithm SHA512 = Digest.SHA512
hashAlgorithm SHA1_MD5 = E.throw $ Uncontextualized $ Error_Protocol "hashAlgorithm: SHA1_MD5 has no single algorithm" InternalError

hashInit :: Hash -> HashContext
hashInit SHA1_MD5 = unsafePerformIO $ do
    sha1Ctx <- Digest.digestInit Digest.SHA1
    md5Ctx <- Digest.digestInit Digest.MD5
    return (HashContextSSL sha1Ctx md5Ctx)
hashInit h = unsafePerformIO $ do
    ctx <- Digest.digestInit (hashAlgorithm h)
    return (HashContext ctx)

hashUpdate :: HashContext -> ByteString -> HashCtx
hashUpdate (HashContext ctx) b = unsafePerformIO $ do
    ctx' <- Digest.digestCopy ctx
    Digest.digestUpdate ctx' b
    return (HashContext ctx')
hashUpdate (HashContextSSL sha1Ctx md5Ctx) b = unsafePerformIO $ do
    sha1Ctx' <- Digest.digestCopy sha1Ctx
    md5Ctx' <- Digest.digestCopy md5Ctx
    Digest.digestUpdate sha1Ctx' b
    Digest.digestUpdate md5Ctx' b
    return (HashContextSSL sha1Ctx' md5Ctx')

hashUpdates :: HashContext -> [ByteString] -> HashCtx
hashUpdates ctx xs = foldl' hashUpdate ctx xs

hashChunks :: Hash -> [ByteString] -> ByteString
hashChunks h xs = hashFinal $ hashUpdates (hashInit h) xs

hashUpdateSSL
    :: HashCtx
    -> (ByteString, ByteString)
    -- ^ (for the md5 context, for the sha1 context)
    -> HashCtx
hashUpdateSSL (HashContext _) _ = E.throw $ Uncontextualized $ Error_Protocol "internal error: update SSL without a SSL Context" InternalError
hashUpdateSSL (HashContextSSL sha1Ctx md5Ctx) (b1, b2) = unsafePerformIO $ do
    sha1Ctx' <- Digest.digestCopy sha1Ctx
    md5Ctx' <- Digest.digestCopy md5Ctx
    Digest.digestUpdate sha1Ctx' b2
    Digest.digestUpdate md5Ctx' b1
    return (HashContextSSL sha1Ctx' md5Ctx')

hashFinal :: HashCtx -> ByteString
hashFinal (HashContext ctx) = unsafePerformIO $ do
    ctx' <- Digest.digestCopy ctx
    Digest.digestFinalize ctx'
hashFinal (HashContextSSL sha1Ctx md5Ctx) = unsafePerformIO $ do
    sha1Ctx' <- Digest.digestCopy sha1Ctx
    md5Ctx' <- Digest.digestCopy md5Ctx
    md5Digest <- Digest.digestFinalize md5Ctx'
    sha1Digest <- Digest.digestFinalize sha1Ctx'
    return $ B.concat [md5Digest, sha1Digest]

data Hash = MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | SHA1_MD5
    deriving (Show, Eq)

data HashContext
    = HashContext Digest.DigestCtx
    | HashContextSSL Digest.DigestCtx Digest.DigestCtx -- SHA1, MD5

instance Show HashContext where
    show _ = "hash-context"

type HashCtx = HashContext

hash :: Hash -> ByteString -> ByteString
hash SHA1_MD5 b =
    B.concat [Digest.hash Digest.MD5 b, Digest.hash Digest.SHA1 b]
hash h b = Digest.hash (hashAlgorithm h) b

hashName :: Hash -> String
hashName = show

-- | Digest size in bytes.
hashDigestSize :: Hash -> Int
hashDigestSize MD5 = 16
hashDigestSize SHA1 = 20
hashDigestSize SHA224 = 28
hashDigestSize SHA256 = 32
hashDigestSize SHA384 = 48
hashDigestSize SHA512 = 64
hashDigestSize SHA1_MD5 = 36

hashBlockSize :: Hash -> Int
hashBlockSize MD5 = 64
hashBlockSize SHA1 = 64
hashBlockSize SHA224 = 64
hashBlockSize SHA256 = 64
hashBlockSize SHA384 = 128
hashBlockSize SHA512 = 128
hashBlockSize SHA1_MD5 = 64

{- key exchange methods encrypt and decrypt for each supported algorithm -}

data RSAEncoding = RSApkcs1 | RSApss deriving (Show, Eq)

-- Signature algorithm and associated parameters.
data SignatureParams
    = RSAParams Hash RSAEncoding
    | ECDSAParams Hash
    | Ed25519Params
    deriving (Show, Eq)

-- | Test the RSASSA-PKCS1 length condition described in RFC 8017 section 9.2,
-- i.e. @emLen >= tLen + 11@.  Lengths are in bytes.
kxCanUseRSApkcs1 :: BRSA.RSAPublicKey -> Hash -> Bool
kxCanUseRSApkcs1 pk h = unsafePerformIO $ do
    size <- BRSA.rsaPublicSize pk
    return $ size >= tLen + 11
  where
    tLen = prefixSize h + hashDigestSize h

    prefixSize MD5 = 18
    prefixSize SHA1 = 15
    prefixSize SHA224 = 19
    prefixSize SHA256 = 19
    prefixSize SHA384 = 19
    prefixSize SHA512 = 19
    prefixSize _ = E.throw $ Uncontextualized $ Error_Protocol (show h ++ " is not supported for RSASSA-PKCS1") InternalError

-- | Test the RSASSA-PSS length condition described in RFC 8017 section 9.1.1,
-- i.e. @emBits >= 8hLen + 8sLen + 9@.  Lengths are in bits.
kxCanUseRSApss :: BRSA.RSAPublicKey -> Hash -> Bool
kxCanUseRSApss pk h = unsafePerformIO $ do
    bits <- BRSA.rsaPublicBits pk
    return $ bits >= 16 * hashDigestSize h + 10

-- | All EC curves supported by boringssl are supported.
kxSupportedPrivKeyEC :: BECDSA.ECCurve -> Bool
kxSupportedPrivKeyEC _ = True

-- | Encrypt using RSA PKCS#1 v1.5 (for TLS 1.2 RSA key exchange).
kxEncrypt :: PubKey -> ByteString -> IO (Either KxError ByteString)
kxEncrypt (PubKeyRSA pk) b = mapErr <$> BRSA.rsaEncryptPKCS1 pk b
kxEncrypt _ _ = return (Left KxUnsupported)

-- | Decrypt using RSA PKCS#1 v1.5 (for TLS 1.2 RSA key exchange).
kxDecrypt :: PrivKey -> ByteString -> IO (Either KxError ByteString)
kxDecrypt (PrivKeyRSA pk) b = mapErr <$> BRSA.rsaDecryptPKCS1 pk b
kxDecrypt _ _ = return (Left KxUnsupported)

-- | Sign the given message using the private key.
-- The message is hashed internally using the appropriate hash algorithm.
kxSign
    :: PrivKey
    -> PubKey
    -> SignatureParams
    -> ByteString
    -> IO (Either KxError ByteString)
kxSign (PrivKeyRSA pk) (PubKeyRSA _) (RSAParams SHA1_MD5 RSApkcs1) _msg =
    -- SHA1_MD5 is used for TLS < 1.2 raw RSA signing. Not supported with boringssl.
    return (Left (RSAError "SHA1_MD5 RSA signing not supported"))
kxSign (PrivKeyRSA pk) (PubKeyRSA _) (RSAParams hashAlg RSApkcs1) msg = do
    let alg = hashAlgorithm hashAlg
        digest = Digest.hash alg msg
    mapErr <$> BRSA.rsaSign pk alg digest
kxSign (PrivKeyRSA pk) (PubKeyRSA _) (RSAParams hashAlg RSApss) msg = do
    let alg = hashAlgorithm hashAlg
        digest = Digest.hash alg msg
    mapErr <$> BRSA.rsaSignPSS pk alg digest
kxSign (PrivKeyEC _ kp) (PubKeyEC _ _) (ECDSAParams hashAlg) msg = do
    let digest = Digest.hash (hashAlgorithm hashAlg) msg
    mapErr <$> BECDSA.ecdsaSign kp digest
kxSign (PrivKeyEd25519 pk) (PubKeyEd25519 _) Ed25519Params msg =
    case BEd25519.sign pk msg of
        Right sig -> return $ Right $ BEd25519.signatureToBytes sig
        Left err -> return $ Left $ RSAError (show err)
kxSign _ _ _ _ =
    return (Left KxUnsupported)

-- | Verify that the signature matches the given message, using the public key.
-- The message is hashed internally using the appropriate hash algorithm.
kxVerify :: PubKey -> SignatureParams -> ByteString -> ByteString -> IO Bool
kxVerify (PubKeyRSA pk) (RSAParams SHA1_MD5 RSApkcs1) _msg _sig =
    -- SHA1_MD5 is used for TLS < 1.2. Not supported with boringssl.
    return False
kxVerify (PubKeyRSA pk) (RSAParams hashAlg RSApkcs1) msg sig = do
    let alg = hashAlgorithm hashAlg
        digest = Digest.hash alg msg
    result <- BRSA.rsaVerify pk alg digest sig
    return $ either (const False) id result
kxVerify (PubKeyRSA pk) (RSAParams hashAlg RSApss) msg sig = do
    let alg = hashAlgorithm hashAlg
        digest = Digest.hash alg msg
    result <- BRSA.rsaVerifyPSS pk alg digest sig
    return $ either (const False) id result
kxVerify (PubKeyEC _ pubKey) (ECDSAParams hashAlg) msg sig = do
    let digest = Digest.hash (hashAlgorithm hashAlg) msg
    result <- BECDSA.ecdsaVerify pubKey digest sig
    return $ either (const False) id result
kxVerify (PubKeyEd25519 pk) Ed25519Params msg sigBS =
    case BEd25519.signatureFromBytes sigBS of
        Just sig -> return $ BEd25519.verify pk msg sig
        Nothing -> return False
kxVerify _ _ _ _ = return False

-- | Map CryptoError to KxError
mapErr :: Either BRSA.CryptoError a -> Either KxError a
mapErr (Left e) = Left (RSAError (show e))
mapErr (Right x) = Right x
