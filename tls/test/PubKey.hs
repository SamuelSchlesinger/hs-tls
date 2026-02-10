module PubKey (
    arbitraryRSAPair,
    arbitraryECDSAPair,
    arbitraryEd25519Pair,
    globalRSAPair,
    getGlobalRSAPair,
    knownECCurves,
    defaultECCurve,
) where

import Control.Concurrent.MVar
import qualified Crypto.BoringSSL.ECDSA as BECDSA
import qualified Crypto.BoringSSL.Ed25519 as BEd25519
import qualified Crypto.BoringSSL.RSA as BRSA
import System.IO.Unsafe
import Test.QuickCheck

arbitraryRSAPair :: Gen BRSA.RSAKeyPair
arbitraryRSAPair = return $ unsafePerformIO $ do
    result <- BRSA.generateRSAKeyPair 2048
    case result of
        Left err -> error $ "arbitraryRSAPair: " ++ show err
        Right kp -> return kp

{-# NOINLINE globalRSAPair #-}
globalRSAPair :: MVar BRSA.RSAKeyPair
globalRSAPair = unsafePerformIO $ do
    result <- BRSA.generateRSAKeyPair 2048
    case result of
        Left err -> error $ "globalRSAPair: " ++ show err
        Right kp -> newMVar kp

{-# NOINLINE getGlobalRSAPair #-}
getGlobalRSAPair :: BRSA.RSAKeyPair
getGlobalRSAPair = unsafePerformIO (readMVar globalRSAPair)

knownECCurves :: [BECDSA.ECCurve]
knownECCurves =
    [ BECDSA.P256
    , BECDSA.P384
    , BECDSA.P521
    ]

defaultECCurve :: BECDSA.ECCurve
defaultECCurve = BECDSA.P256

arbitraryECDSAPair :: BECDSA.ECCurve -> Gen BECDSA.ECKeyPair
arbitraryECDSAPair curve = return $ unsafePerformIO $ do
    result <- BECDSA.generateKeyPair curve
    case result of
        Left err -> error $ "arbitraryECDSAPair: " ++ show err
        Right kp -> return kp

arbitraryEd25519Pair :: Gen (BEd25519.PublicKey, BEd25519.PrivateKey)
arbitraryEd25519Pair = return $ unsafePerformIO BEd25519.generateKeyPair
