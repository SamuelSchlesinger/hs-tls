-- | (Elliptic Curve) Integrated Encryption Scheme
--
-- Module      : Network.TLS.Crypto.IES
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Crypto.IES (
    GroupPublic,
    GroupPrivate,
    GroupKey,

    -- * Group methods
    groupGenerateKeyPair,
    groupGetPubShared,
    groupGetShared,
    encodeGroupPublic,
    decodeGroupPublic,
) where

import qualified Control.Exception as E
import qualified Crypto.BoringSSL.ECDH as ECDH
import qualified Crypto.BoringSSL.X25519 as X25519
import System.IO.Unsafe (unsafePerformIO)

import Network.TLS.Crypto.Types
import Network.TLS.Error
import Network.TLS.Imports

-- | Private key for a named group.
data GroupPrivate
    = GroupPri_P256 ECDH.ECKeyPair
    | GroupPri_P384 ECDH.ECKeyPair
    | GroupPri_P521 ECDH.ECKeyPair
    | GroupPri_X255 X25519.PrivateKey

instance Show GroupPrivate where
    show (GroupPri_P256 _) = "GroupPri_P256"
    show (GroupPri_P384 _) = "GroupPri_P384"
    show (GroupPri_P521 _) = "GroupPri_P521"
    show (GroupPri_X255 _) = "GroupPri_X255"

instance Eq GroupPrivate where
    _ == _ = False

-- | Public key for a named group.
data GroupPublic
    = GroupPub_P256 ByteString
    | GroupPub_P384 ByteString
    | GroupPub_P521 ByteString
    | GroupPub_X255 X25519.PublicKey
    deriving (Eq, Show)

-- | Shared secret result of key exchange.
type GroupKey = ByteString

groupCurve :: Group -> Maybe ECDH.ECCurve
groupCurve P256 = Just ECDH.P256
groupCurve P384 = Just ECDH.P384
groupCurve P521 = Just ECDH.P521
groupCurve _ = Nothing

-- | Generate a key pair for the given group.
groupGenerateKeyPair :: Group -> IO (GroupPrivate, GroupPublic)
groupGenerateKeyPair P256 = ecGenerateKeyPair ECDH.P256 GroupPri_P256 GroupPub_P256
groupGenerateKeyPair P384 = ecGenerateKeyPair ECDH.P384 GroupPri_P384 GroupPub_P384
groupGenerateKeyPair P521 = ecGenerateKeyPair ECDH.P521 GroupPri_P521 GroupPub_P521
groupGenerateKeyPair X25519 = do
    (pub, pri) <- X25519.generateKeyPair
    return (GroupPri_X255 pri, GroupPub_X255 pub)
groupGenerateKeyPair grp = E.throwIO $ Uncontextualized $ Error_Protocol ("groupGenerateKeyPair: unsupported group " ++ show grp) InternalError

ecGenerateKeyPair
    :: ECDH.ECCurve
    -> (ECDH.ECKeyPair -> GroupPrivate)
    -> (ByteString -> GroupPublic)
    -> IO (GroupPrivate, GroupPublic)
ecGenerateKeyPair curve priTag pubTag = do
    ekp <- ECDH.generateECKeyPair curve
    case ekp of
        Left err -> E.throwIO $ Uncontextualized $ Error_Protocol ("EC key generation failed: " ++ show err) InternalError
        Right kp -> do
            epub <- ECDH.ecPublicKeyBytes kp
            case epub of
                Left err -> E.throwIO $ Uncontextualized $ Error_Protocol ("EC public key encoding failed: " ++ show err) InternalError
                Right pubBytes -> return (priTag kp, pubTag pubBytes)

-- | Generate a new key pair and compute a shared secret with the given
-- peer public key.  Used by client for one-shot ECDHE.
groupGetPubShared :: GroupPublic -> IO (Maybe (GroupPublic, GroupKey))
groupGetPubShared (GroupPub_P256 peerPubBytes) = ecGetPubShared ECDH.P256 peerPubBytes GroupPub_P256
groupGetPubShared (GroupPub_P384 peerPubBytes) = ecGetPubShared ECDH.P384 peerPubBytes GroupPub_P384
groupGetPubShared (GroupPub_P521 peerPubBytes) = ecGetPubShared ECDH.P521 peerPubBytes GroupPub_P521
groupGetPubShared (GroupPub_X255 peerPub) = do
    (myPub, myPri) <- X25519.generateKeyPair
    case X25519.computeSharedSecret myPri peerPub of
        Left _ -> return Nothing
        Right shared -> return $ Just (GroupPub_X255 myPub, X25519.secureBytesToByteString shared)

ecGetPubShared
    :: ECDH.ECCurve
    -> ByteString
    -> (ByteString -> GroupPublic)
    -> IO (Maybe (GroupPublic, GroupKey))
ecGetPubShared curve peerPubBytes pubTag = do
    epeerPub <- ECDH.ecPublicKeyFromBytes curve peerPubBytes
    case epeerPub of
        Left _ -> return Nothing
        Right peerPub -> do
            ekp <- ECDH.generateECKeyPair curve
            case ekp of
                Left _ -> return Nothing
                Right myKp -> do
                    emyPubBytes <- ECDH.ecPublicKeyBytes myKp
                    case emyPubBytes of
                        Left _ -> return Nothing
                        Right myPubBytes -> do
                            eshared <- ECDH.ecdhComputeRawSecret myKp peerPub
                            case eshared of
                                Left _ -> return Nothing
                                Right shared -> return $ Just (pubTag myPubBytes, ECDH.secureBytesToByteString shared)

-- | Compute a shared secret given a peer's public key and our private key.
groupGetShared :: GroupPublic -> GroupPrivate -> Maybe GroupKey
groupGetShared (GroupPub_P256 peerPubBytes) (GroupPri_P256 myKp) = ecGetShared ECDH.P256 peerPubBytes myKp
groupGetShared (GroupPub_P384 peerPubBytes) (GroupPri_P384 myKp) = ecGetShared ECDH.P384 peerPubBytes myKp
groupGetShared (GroupPub_P521 peerPubBytes) (GroupPri_P521 myKp) = ecGetShared ECDH.P521 peerPubBytes myKp
groupGetShared (GroupPub_X255 peerPub) (GroupPri_X255 myPri) =
    case X25519.computeSharedSecret myPri peerPub of
        Left _ -> Nothing
        Right shared -> Just (X25519.secureBytesToByteString shared)
groupGetShared _ _ = Nothing

ecGetShared :: ECDH.ECCurve -> ByteString -> ECDH.ECKeyPair -> Maybe ByteString
ecGetShared curve peerPubBytes myKp = unsafePerformIO $ do
    epeerPub <- ECDH.ecPublicKeyFromBytes curve peerPubBytes
    case epeerPub of
        Left _ -> return Nothing
        Right peerPub -> do
            eshared <- ECDH.ecdhComputeRawSecret myKp peerPub
            case eshared of
                Left _ -> return Nothing
                Right shared -> return $ Just (ECDH.secureBytesToByteString shared)

-- | Encode a group public key to wire format.
encodeGroupPublic :: GroupPublic -> ByteString
encodeGroupPublic (GroupPub_P256 bs) = bs
encodeGroupPublic (GroupPub_P384 bs) = bs
encodeGroupPublic (GroupPub_P521 bs) = bs
encodeGroupPublic (GroupPub_X255 pub) = X25519.publicKeyToBytes pub

-- | Decode a group public key from wire format.
decodeGroupPublic :: Group -> ByteString -> Either String GroupPublic
decodeGroupPublic P256 bs = Right $ GroupPub_P256 bs
decodeGroupPublic P384 bs = Right $ GroupPub_P384 bs
decodeGroupPublic P521 bs = Right $ GroupPub_P521 bs
decodeGroupPublic X25519 bs =
    case X25519.publicKeyFromBytes bs of
        Just pub -> Right $ GroupPub_X255 pub
        Nothing -> Left "invalid X25519 public key"
decodeGroupPublic grp _ = Left $ "decodeGroupPublic: unsupported group " ++ show grp
