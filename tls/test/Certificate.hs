{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Certificate (
    arbitraryX509,
    arbitraryX509WithKey,
    arbitraryX509WithKeyAndUsage,
    simpleX509,
) where

import Data.Bits (shiftL, shiftR, (.|.))
import qualified Data.Bits as Bits
import qualified Crypto.BoringSSL.ECDSA as BECDSA
import qualified Crypto.BoringSSL.Ed25519 as BEd25519
import qualified Crypto.BoringSSL.RSA as BRSA
import qualified Crypto.BoringSSL.X509 as BX509
import qualified Data.ByteString as B
import Data.Word
import Network.TLS (PrivKey (..))
import Network.TLS.Internal (SignedCertificate (..), ExtKeyUsageFlag (..))
import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck

import PubKey

----------------------------------------------------------------
-- Test certificate generation
----------------------------------------------------------------

-- | Build a self-signed DER X.509 certificate with the given private key
-- and key usage flags. The certificate is not cryptographically valid
-- (signature is dummy) but is structurally parseable by BoringSSL.
buildTestCertDER :: PrivKey -> Maybe [ExtKeyUsageFlag] -> B.ByteString
buildTestCertDER privKey musageFlags =
    let spki = encodeSubjectPublicKeyInfo privKey
        sigAlgOID = sigAlgForKey privKey
        sigAlgSeq = derSequence (derOID sigAlgOID <> sigAlgParams privKey)
        tbs = derSequence $ mconcat
            [ derExplicit 0 (derInteger 2)  -- version v3
            , derInteger 1                  -- serial
            , sigAlgSeq                     -- sig algorithm
            , derSequence (derSet (derSequence (derOID [2,5,4,3] <> derUTF8String "Test CA")))  -- issuer (different from subject)
            , derSequence (derUTCTime "200101000000Z" <> derUTCTime "300101000000Z")  -- validity
            , derSequence (derSet (derSequence (derOID [2,5,4,3] <> derUTF8String "Test")))  -- subject
            , spki
            , case musageFlags of
                Nothing -> mempty  -- no key usage extension = unrestricted
                Just flags -> derExplicit 3 (derSequence (encodeKeyUsageExt flags))
            ]
        sig = derBitString (B.replicate 64 0x01)  -- dummy signature
     in derSequence (tbs <> sigAlgSeq <> sig)

sigAlgForKey :: PrivKey -> [Word32]
sigAlgForKey (PrivKeyRSA _) = [1,2,840,113549,1,1,5]   -- sha1WithRSAEncryption
sigAlgForKey (PrivKeyEC _ _) = [1,2,840,10045,4,3,2]    -- ecdsa-with-SHA256
sigAlgForKey (PrivKeyEd25519 _) = [1,3,101,112]          -- Ed25519

sigAlgParams :: PrivKey -> B.ByteString
sigAlgParams (PrivKeyEd25519 _) = mempty  -- Ed25519 has no params
sigAlgParams _ = derNull

-- | Encode SPKI (SubjectPublicKeyInfo) from a private key.
-- Uses the key pair to extract the public key bytes, since boringssl-hs
-- serialization functions work on key pair types, not public key types.
encodeSubjectPublicKeyInfo :: PrivKey -> B.ByteString
encodeSubjectPublicKeyInfo (PrivKeyRSA kp) = unsafePerformIO $ do
    result <- BRSA.publicKeyToBytes kp
    case result of
        Left err -> error $ "encodeSubjectPublicKeyInfo RSA: " ++ show err
        Right pkcs1DER -> return $ derSequence $
            derSequence (derOID [1,2,840,113549,1,1,1] <> derNull)
            <> derBitString pkcs1DER
encodeSubjectPublicKeyInfo (PrivKeyEC curve kp) = unsafePerformIO $ do
    result <- BECDSA.ecPublicKeyBytes kp
    case result of
        Left err -> error $ "encodeSubjectPublicKeyInfo EC: " ++ show err
        Right pubBytes -> return $ derSequence $
            derSequence (derOID [1,2,840,10045,2,1] <> derOID (curveOID curve))
            <> derBitString pubBytes
encodeSubjectPublicKeyInfo (PrivKeyEd25519 priv) =
    -- Ed25519 private key is 64 bytes: 32-byte seed ++ 32-byte public key
    let pubBytes = B.drop 32 (BEd25519.privateKeyToBytes priv)
     in derSequence $
            derSequence (derOID [1,3,101,112])
            <> derBitString pubBytes

curveOID :: BECDSA.ECCurve -> [Word32]
curveOID BECDSA.P256 = [1,2,840,10045,3,1,7]
curveOID BECDSA.P384 = [1,3,132,0,34]
curveOID BECDSA.P521 = [1,3,132,0,35]

encodeKeyUsageExt :: [ExtKeyUsageFlag] -> B.ByteString
encodeKeyUsageExt flags =
    derSequence $
        derOID [2,5,29,15]  -- id-ce-keyUsage
        <> derBool True      -- critical
        <> derOctetString (derBitStringBits (keyUsageBits flags))

keyUsageBits :: [ExtKeyUsageFlag] -> Word16
keyUsageBits = foldl (\acc f -> acc .|. (1 `shiftL` (15 - flagBit f))) 0
  where
    flagBit :: ExtKeyUsageFlag -> Int
    flagBit KeyUsage_digitalSignature = 0
    flagBit KeyUsage_nonRepudiation = 1
    flagBit KeyUsage_keyEncipherment = 2
    flagBit KeyUsage_dataEncipherment = 3
    flagBit KeyUsage_keyAgreement = 4
    flagBit KeyUsage_keyCertSign = 5
    flagBit KeyUsage_cRLSign = 6
    flagBit KeyUsage_encipherOnly = 7
    flagBit KeyUsage_decipherOnly = 8

-- | Parse a DER cert into our SignedCertificate type
parseDERCert :: B.ByteString -> SignedCertificate
parseDERCert der =
    case BX509.parseDER der of
        Left err -> error $ "parseDERCert: " ++ show err
        Right cert -> SignedCertificate der cert

mkTestCert :: PrivKey -> Maybe [ExtKeyUsageFlag] -> SignedCertificate
mkTestCert privKey flags = parseDERCert (buildTestCertDER privKey flags)

simpleX509 :: PrivKey -> SignedCertificate
simpleX509 privKey = mkTestCert privKey Nothing

arbitraryX509WithKey :: PrivKey -> Gen SignedCertificate
arbitraryX509WithKey privKey = return $ mkTestCert privKey Nothing

arbitraryX509WithKeyAndUsage
    :: [ExtKeyUsageFlag] -> PrivKey -> Gen SignedCertificate
arbitraryX509WithKeyAndUsage usageFlags privKey =
    return $ mkTestCert privKey (Just usageFlags)

arbitraryX509 :: Gen SignedCertificate
arbitraryX509 = arbitraryX509WithKey (PrivKeyRSA getGlobalRSAPair)

instance {-# OVERLAPS #-} Arbitrary [ExtKeyUsageFlag] where
    arbitrary = sublistOf knownKeyUsage

knownKeyUsage :: [ExtKeyUsageFlag]
knownKeyUsage =
    [ KeyUsage_digitalSignature
    , KeyUsage_keyEncipherment
    , KeyUsage_keyAgreement
    ]

----------------------------------------------------------------
-- Minimal DER encoding helpers
----------------------------------------------------------------

derTag :: Word8 -> B.ByteString -> B.ByteString
derTag t content =
    let len = B.length content
        lenBytes
            | len < 128 = B.singleton (fromIntegral len)
            | len < 256 = B.pack [0x81, fromIntegral len]
            | len < 65536 = B.pack [0x82, fromIntegral (len `shiftR` 8), fromIntegral (len Bits..&. 0xFF)]
            | otherwise = error "derTag: length too large"
     in B.singleton t <> lenBytes <> content

derSequence :: B.ByteString -> B.ByteString
derSequence = derTag 0x30

derSet :: B.ByteString -> B.ByteString
derSet = derTag 0x31

derInteger :: Integer -> B.ByteString
derInteger n
    | n >= 0 && n < 128 = derTag 0x02 (B.singleton (fromIntegral n))
    | otherwise =
        let bs = integerToBytes n
            -- Add leading zero if high bit set
            bs' = if B.null bs || B.index bs 0 >= 128
                  then B.cons 0 bs
                  else bs
         in derTag 0x02 bs'

integerToBytes :: Integer -> B.ByteString
integerToBytes 0 = B.singleton 0
integerToBytes n = B.pack (go n [])
  where
    go 0 acc = acc
    go x acc = go (x `div` 256) (fromIntegral (x `mod` 256) : acc)

derOID :: [Word32] -> B.ByteString
derOID [] = error "derOID: empty OID"
derOID [_] = error "derOID: OID too short"
derOID (a:b:rest) =
    let first = fromIntegral a * 40 + fromIntegral b :: Word8
        encoded = B.singleton first <> B.concat (map encodeOIDComponent rest)
     in derTag 0x06 encoded

encodeOIDComponent :: Word32 -> B.ByteString
encodeOIDComponent n
    | n < 128 = B.singleton (fromIntegral n)
    | otherwise =
        let bytes = go n []
            go 0 acc = acc
            go x acc = go (x `shiftR` 7) (fromIntegral (x Bits..&. 0x7F) : acc)
            -- Set high bit on all but last byte
            setHigh [] = []
            setHigh [x] = [x]
            setHigh (x:xs) = (x .|. 0x80) : setHigh xs
         in B.pack (setHigh bytes)

derNull :: B.ByteString
derNull = B.pack [0x05, 0x00]

derBool :: Bool -> B.ByteString
derBool True = derTag 0x01 (B.singleton 0xFF)
derBool False = derTag 0x01 (B.singleton 0x00)

derOctetString :: B.ByteString -> B.ByteString
derOctetString = derTag 0x04

derBitString :: B.ByteString -> B.ByteString
derBitString bs = derTag 0x03 (B.cons 0x00 bs)  -- 0 unused bits

derBitStringBits :: Word16 -> B.ByteString
derBitStringBits 0 = derTag 0x03 (B.pack [0x00, 0x00])  -- 0 unused bits, 1 data byte of 0x00
derBitStringBits w =
    let hi = fromIntegral (w `shiftR` 8) :: Word8
        lo = fromIntegral (w Bits..&. 0xFF) :: Word8
     in if lo == 0
        then derTag 0x03 (B.pack [countTrailing hi, hi])
        else derTag 0x03 (B.pack [countTrailing lo, hi, lo])
  where
    countTrailing :: Word8 -> Word8
    countTrailing 0 = 8
    countTrailing x
        | x Bits..&. 1 /= 0 = 0
        | otherwise = 1 + countTrailing (x `shiftR` 1)

derUTF8String :: B.ByteString -> B.ByteString
derUTF8String = derTag 0x0C

derUTCTime :: B.ByteString -> B.ByteString
derUTCTime = derTag 0x17

derExplicit :: Word8 -> B.ByteString -> B.ByteString
derExplicit n = derTag (0xA0 .|. n)
