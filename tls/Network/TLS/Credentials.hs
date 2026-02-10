{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Network.TLS.Credentials (
    Credential,
    Credentials (..),
    credentialLoadX509,
    credentialLoadX509FromMemory,
    credentialLoadX509Chain,
    credentialLoadX509ChainFromMemory,
    credentialsFindForSigning,
    credentialsFindForDecrypting,
    credentialsListSigningAlgorithms,
    credentialPublicPrivateKeys,
    credentialMatchesHashSignatures,
) where

import qualified Crypto.BoringSSL.PEM as PEM
import qualified Crypto.BoringSSL.PrivateKey as BPK
import qualified Crypto.BoringSSL.X509 as BX509
import qualified Data.ByteString as B
import System.IO.Unsafe (unsafePerformIO)

import Network.TLS.Crypto
import Network.TLS.Imports
import qualified Network.TLS.Struct as TLS
import Network.TLS.X509

type Credential = (CertificateChain, PrivKey)

newtype Credentials = Credentials [Credential] deriving (Show)

instance Semigroup Credentials where
    Credentials l1 <> Credentials l2 = Credentials (l1 ++ l2)

instance Monoid Credentials where
    mempty = Credentials []
#if !(MIN_VERSION_base(4,11,0))
    mappend (Credentials l1) (Credentials l2) = Credentials (l1 ++ l2)
#endif

-- | try to create a new credential object from a public certificate
-- and the associated private key that are stored on the filesystem
-- in PEM format.
credentialLoadX509
    :: FilePath
    -- ^ public certificate (X.509 format)
    -> FilePath
    -- ^ private key associated
    -> IO (Either String Credential)
credentialLoadX509 certFile = credentialLoadX509Chain certFile []

-- | similar to 'credentialLoadX509' but take the certificate
-- and private key from memory instead of from the filesystem.
credentialLoadX509FromMemory
    :: ByteString
    -> ByteString
    -> Either String Credential
credentialLoadX509FromMemory certData =
    credentialLoadX509ChainFromMemory certData []

-- | similar to 'credentialLoadX509' but also allow specifying chain
-- certificates.
credentialLoadX509Chain
    :: FilePath
    -- ^ public certificate (X.509 format)
    -> [FilePath]
    -- ^ chain certificates (X.509 format)
    -> FilePath
    -- ^ private key associated
    -> IO (Either String Credential)
credentialLoadX509Chain certFile chainFiles privateFile = do
    certData <- B.readFile certFile
    chainDatas <- mapM B.readFile chainFiles
    keyData <- B.readFile privateFile
    return $ credentialLoadX509ChainFromMemory certData chainDatas keyData

-- | similar to 'credentialLoadX509FromMemory' but also allow
-- specifying chain certificates.
credentialLoadX509ChainFromMemory
    :: ByteString
    -> [ByteString]
    -> ByteString
    -> Either String Credential
credentialLoadX509ChainFromMemory certData chainData privateData =
    let certs = readSignedObjectFromMemory certData
        chains = concatMap readSignedObjectFromMemory chainData
        mkey = readKeyFromMemory privateData
     in case mkey of
            Left err -> Left err
            Right k -> Right (CertificateChain (certs ++ chains), k)

-- | Read signed certificates from a PEM-encoded ByteString.
readSignedObjectFromMemory :: ByteString -> [SignedCertificate]
readSignedObjectFromMemory pem =
    case PEM.pemDecodeMany pem of
        Left _ -> []
        Right blocks ->
            [ sc
            | ("CERTIFICATE", der) <- blocks
            , Right x509 <- [BX509.parseDER der]
            , let sc = SignedCertificate der x509
            ]

-- | Read a private key from a PEM-encoded ByteString.
readKeyFromMemory :: ByteString -> Either String PrivKey
readKeyFromMemory pem = unsafePerformIO $ do
    result <- BPK.loadPrivateKeyPEM pem
    return $ case result of
        Left err -> Left ("failed to load private key: " ++ show err)
        Right (BPK.SomeRSAKey kp) -> Right (PrivKeyRSA kp)
        Right (BPK.SomeECKey curve kp) -> Right (PrivKeyEC curve kp)
        Right (BPK.SomeEd25519Key pk) -> Right (PrivKeyEd25519 pk)
        Right (BPK.SomeX25519Key _) -> Left "X25519 keys are not supported for TLS credentials"

credentialsListSigningAlgorithms :: Credentials -> [KeyExchangeSignatureAlg]
credentialsListSigningAlgorithms (Credentials l) = mapMaybe credentialCanSign l

credentialsFindForSigning
    :: KeyExchangeSignatureAlg -> Credentials -> Maybe Credential
credentialsFindForSigning kxsAlg (Credentials l) = find forSigning l
  where
    forSigning cred = case credentialCanSign cred of
        Nothing -> False
        Just kxs -> kxs == kxsAlg

credentialsFindForDecrypting :: Credentials -> Maybe Credential
credentialsFindForDecrypting (Credentials l) = find forEncrypting l
  where
    forEncrypting cred = Just () == credentialCanDecrypt cred

-- here we assume that only RSA is supported for key encipherment (encryption/decryption)
-- we keep the same construction as 'credentialCanSign', returning a Maybe of () in case
-- this change in future.
credentialCanDecrypt :: Credential -> Maybe ()
credentialCanDecrypt (chain, priv) =
    case (pub, priv) of
        (PubKeyRSA _, PrivKeyRSA _) ->
            case certKeyUsageFlags cert of
                Nothing -> Just ()
                Just flags
                    | KeyUsage_keyEncipherment `elem` flags -> Just ()
                    | otherwise -> Nothing
        _ -> Nothing
  where
    cert = getCertificate signed
    pub = certPubKey cert
    signed = getCertificateChainLeaf chain

credentialCanSign :: Credential -> Maybe KeyExchangeSignatureAlg
credentialCanSign (chain, priv) =
    case certKeyUsageFlags cert of
        Nothing -> findKeyExchangeSignatureAlg (pub, priv)
        Just flags
            | KeyUsage_digitalSignature `elem` flags ->
                findKeyExchangeSignatureAlg (pub, priv)
            | otherwise -> Nothing
  where
    cert = getCertificate signed
    pub = certPubKey cert
    signed = getCertificateChainLeaf chain

credentialPublicPrivateKeys :: Credential -> (PubKey, PrivKey)
credentialPublicPrivateKeys (chain, priv) = pub `seq` (pub, priv)
  where
    cert = getCertificate signed
    pub = certPubKey cert
    signed = getCertificateChainLeaf chain

getHashSignature :: SignedCertificate -> Maybe TLS.HashAndSignatureAlgorithm
getHashSignature signed = unsafePerformIO $ do
    mAlgInfo <- BX509.certSignatureAlgorithm (scCert signed)
    return $ case mAlgInfo of
        Nothing -> Nothing
        Just info -> convertSigAlg (BX509.sigAlgShortName info)
  where
    convertSigAlg name = case name of
        "RSA-SHA1" -> Just (TLS.HashSHA1, TLS.SignatureRSA)
        "RSA-SHA224" -> Just (TLS.HashSHA224, TLS.SignatureRSA)
        "RSA-SHA256" -> Just (TLS.HashSHA256, TLS.SignatureRSA)
        "RSA-SHA384" -> Just (TLS.HashSHA384, TLS.SignatureRSA)
        "RSA-SHA512" -> Just (TLS.HashSHA512, TLS.SignatureRSA)
        "sha256WithRSAEncryption" -> Just (TLS.HashSHA256, TLS.SignatureRSA)
        "sha384WithRSAEncryption" -> Just (TLS.HashSHA384, TLS.SignatureRSA)
        "sha512WithRSAEncryption" -> Just (TLS.HashSHA512, TLS.SignatureRSA)
        "RSA-PSS" -> Nothing -- can't determine hash from short name alone
        "rsassaPss" -> Nothing
        "ecdsa-with-SHA1" -> Just (TLS.HashSHA1, TLS.SignatureECDSA)
        "ecdsa-with-SHA224" -> Just (TLS.HashSHA224, TLS.SignatureECDSA)
        "ecdsa-with-SHA256" -> Just (TLS.HashSHA256, TLS.SignatureECDSA)
        "ecdsa-with-SHA384" -> Just (TLS.HashSHA384, TLS.SignatureECDSA)
        "ecdsa-with-SHA512" -> Just (TLS.HashSHA512, TLS.SignatureECDSA)
        "ED25519" -> Just (TLS.HashIntrinsic, TLS.SignatureEd25519)
        _ -> Nothing

-- | Checks whether certificate signatures in the chain comply with a list of
-- hash/signature algorithm pairs.  Currently the verification applies only to
-- the signature of the leaf certificate, and when not self-signed.  This may
-- be extended to additional chain elements in the future.
credentialMatchesHashSignatures
    :: [TLS.HashAndSignatureAlgorithm] -> Credential -> Bool
credentialMatchesHashSignatures hashSigs (chain, _) =
    case chain of
        CertificateChain [] -> True
        CertificateChain (leaf : _) -> isSelfSigned leaf || matchHashSig leaf
  where
    matchHashSig signed = case getHashSignature signed of
        Nothing -> False
        Just hs -> hs `elem` hashSigs

    isSelfSigned signed =
        let cert = getCertificate signed
         in certSubjectDN cert == certIssuerDN cert
