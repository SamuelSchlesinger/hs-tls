-- | X509 helpers using boringssl
module Network.TLS.X509 (
    CertificateChain (..),
    SignedCertificate (..),
    Certificate (..),
    DistinguishedName (..),
    ExtKeyUsageFlag (..),
    getCertificate,
    isNullCertificateChain,
    getCertificateChainLeaf,
    CertificateRejectReason (..),
    CertificateUsage (..),
    CertificateStore (..),
    emptyCertificateStore,
    ValidationCache,
    defaultValidationCache,
    exceptionValidationCache,
    validateDefault,
    FailedReason (..),
    ServiceID,
    wrapCertificateChecks,
    pubkeyType,
    validateClientCertificate,
    signedCertSubjectName,
    -- * Certificate store operations
    readCertificateStore,
    readCertificateStoreFromFiles,
    getSystemCertificateStore,
    -- * Wire encoding/decoding
    encodeCertificateChain,
    decodeCertificateChain,
) where

import qualified Control.Exception as E
import Control.Monad (foldM)
import qualified Crypto.BoringSSL.ECDSA as BECDSA
import qualified Crypto.BoringSSL.Ed25519 as BEd25519
import qualified Crypto.BoringSSL.RSA as BRSA
import qualified Crypto.BoringSSL.X509 as BX509
import qualified Data.ByteString as B
import Data.Char (toLower)

import Network.TLS.Error
import qualified Data.ByteString.Char8 as C8
import Data.ByteString (ByteString)
import Data.List (isPrefixOf, isSuffixOf)
import System.Directory (doesFileExist)
import System.IO.Unsafe (unsafePerformIO)

import Network.TLS.Crypto (PubKey (..), pubkeyType)

-- | A signed certificate wrapping DER bytes and a parsed boringssl X509Cert.
data SignedCertificate = SignedCertificate
    { scDER :: ByteString
    , scCert :: BX509.X509Cert
    }

instance Show SignedCertificate where
    show sc = "SignedCertificate " ++ show (B.length (scDER sc)) ++ " bytes"

instance Eq SignedCertificate where
    a == b = scDER a == scDER b

-- | A chain of certificates.
newtype CertificateChain = CertificateChain [SignedCertificate]
    deriving (Eq)

instance Show CertificateChain where
    show (CertificateChain certs) = "CertificateChain[" ++ show (length certs) ++ "]"

-- | A distinguished name as DER-encoded bytes.
newtype DistinguishedName = DistinguishedName ByteString
    deriving (Eq, Show)

-- | Key usage flags (matching Data.X509.ExtKeyUsageFlag names for compatibility).
data ExtKeyUsageFlag
    = KeyUsage_digitalSignature
    | KeyUsage_nonRepudiation
    | KeyUsage_keyEncipherment
    | KeyUsage_dataEncipherment
    | KeyUsage_keyAgreement
    | KeyUsage_keyCertSign
    | KeyUsage_cRLSign
    | KeyUsage_encipherOnly
    | KeyUsage_decipherOnly
    deriving (Show, Eq, Ord, Enum, Bounded)

-- | Certificate information extracted from a SignedCertificate.
data Certificate = Certificate
    { certPubKey :: PubKey
    , certSubjectDN :: DistinguishedName
    , certIssuerDN :: DistinguishedName
    , certKeyUsageFlags :: Maybe [ExtKeyUsageFlag]
    }

-- | Extract certificate information from a signed certificate.
-- Throws a 'TLSException' if the certificate contains an unsupported
-- or invalid public key type.
getCertificate :: SignedCertificate -> Certificate
getCertificate sc = unsafePerformIO $ do
    let cert = scCert sc
    pubKeyResult <- BX509.certPublicKey cert
    pubKey <- case pubKeyResult of
        Right (BX509.CertPubKeyRSA pk) -> return $ PubKeyRSA pk
        Right (BX509.CertPubKeyEC curve pk) -> return $ PubKeyEC curve pk
        Right (BX509.CertPubKeyEd25519 bs) ->
            case BEd25519.publicKeyFromBytes bs of
                Just pk -> return $ PubKeyEd25519 pk
                Nothing -> certError "invalid Ed25519 public key"
        Right (BX509.CertPubKeyUnknown n) ->
            certError ("unsupported public key type " ++ show n)
        Left err ->
            certError ("failed to extract public key: " ++ show err)
    subjectDER <- BX509.certSubjectDER cert
    issuerDER <- BX509.certIssuerDER cert
    let keyUsage = fmap (map fromBoringKeyUsage) (BX509.certKeyUsage cert)
    return Certificate
        { certPubKey = pubKey
        , certSubjectDN = DistinguishedName subjectDER
        , certIssuerDN = DistinguishedName issuerDER
        , certKeyUsageFlags = keyUsage
        }
  where
    certError msg = E.throwIO $ Uncontextualized $ Error_Protocol msg DecodeError
{-# NOINLINE getCertificate #-}

-- | Map boringssl KeyUsageFlag to our ExtKeyUsageFlag.
fromBoringKeyUsage :: BX509.KeyUsageFlag -> ExtKeyUsageFlag
fromBoringKeyUsage BX509.DigitalSignature = KeyUsage_digitalSignature
fromBoringKeyUsage BX509.ContentCommitment = KeyUsage_nonRepudiation
fromBoringKeyUsage BX509.KeyEncipherment = KeyUsage_keyEncipherment
fromBoringKeyUsage BX509.DataEncipherment = KeyUsage_dataEncipherment
fromBoringKeyUsage BX509.KeyAgreement = KeyUsage_keyAgreement
fromBoringKeyUsage BX509.KeyCertSign = KeyUsage_keyCertSign
fromBoringKeyUsage BX509.CRLSign = KeyUsage_cRLSign
fromBoringKeyUsage BX509.EncipherOnly = KeyUsage_encipherOnly
fromBoringKeyUsage BX509.DecipherOnly = KeyUsage_decipherOnly

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = null l

getCertificateChainLeaf :: CertificateChain -> SignedCertificate
getCertificateChainLeaf (CertificateChain []) = error "empty certificate chain"
getCertificateChainLeaf (CertificateChain (x : _)) = x

-- | Certificate and Chain rejection reason
data CertificateRejectReason
    = CertificateRejectExpired
    | CertificateRejectRevoked
    | CertificateRejectUnknownCA
    | CertificateRejectAbsent
    | CertificateRejectOther String
    deriving (Show, Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage
    = -- | usage of certificate accepted
      CertificateUsageAccept
    | -- | usage of certificate rejected
      CertificateUsageReject CertificateRejectReason
    deriving (Show, Eq)

-- | Reasons a certificate chain validation can fail.
data FailedReason
    = Expired
    | InFuture
    | UnknownCA
    | SelfSigned
    | EmptyChain
    | NameMismatch
    | InvalidSignature String
    | OtherFailure String
    deriving (Show, Eq)

-- | A trust store containing CA certificates.
newtype CertificateStore = CertificateStore BX509.X509Store

-- | An empty certificate store with no trusted CA certificates.
-- TODO: unsafePerformIO here is safe only because nobody mutates the default
-- store. Consider changing sharedCAStore to Maybe CertificateStore instead.
emptyCertificateStore :: CertificateStore
emptyCertificateStore = CertificateStore $ unsafePerformIO BX509.newX509Store
{-# NOINLINE emptyCertificateStore #-}

type ServiceID = (String, ByteString)

type ValidationCache = ()

defaultValidationCache :: ValidationCache
defaultValidationCache = ()

exceptionValidationCache :: [(ServiceID, ByteString)] -> ValidationCache
exceptionValidationCache _ = ()

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l = CertificateUsageReject CertificateRejectExpired
    | InFuture `elem` l = CertificateUsageReject CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | SelfSigned `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | EmptyChain `elem` l = CertificateUsageReject CertificateRejectAbsent
    | NameMismatch `elem` l = CertificateUsageReject $ CertificateRejectOther "hostname mismatch"
    | otherwise = CertificateUsageReject $ CertificateRejectOther (show l)

-- | Validate a certificate chain against a trust store.
validateDefault
    :: CertificateStore
    -> ValidationCache
    -> ServiceID
    -> CertificateChain
    -> IO [FailedReason]
validateDefault (CertificateStore store) _cache _serviceID (CertificateChain []) =
    return [EmptyChain]
validateDefault (CertificateStore store) _cache serviceID (CertificateChain (leaf : intermediates)) = do
    let leafCert = scCert leaf
        intermediateCerts = map scCert intermediates
    result <- BX509.verifyCertChain store leafCert intermediateCerts
    let chainErrors = case result of
            BX509.VerifyOK -> []
            BX509.VerifyFailed code msg -> [OtherFailure (show code ++ ": " ++ msg)]
        nameErrors = validateHostname serviceID leafCert
    return (chainErrors ++ nameErrors)

-- | Check whether the hostname from ServiceID matches the leaf certificate's
-- DNS names (SANs or CN fallback).
validateHostname :: ServiceID -> BX509.X509Cert -> [FailedReason]
validateHostname (hostname, _) cert
    | null hostname = [] -- no hostname to check (e.g. client cert validation)
    | not (null dnsSANs) = if any (matchHostname hostname) dnsSANs
                           then []
                           else [NameMismatch]
    | otherwise = -- no DNS SANs, fall back to CN
        let cn = BX509.subjectName cert
        in if matchHostname hostname cn then [] else [NameMismatch]
  where
    sans = BX509.certSubjectAltNames cert
    dnsSANs = [name | BX509.GNDNS name <- sans]

-- | Match a hostname against a reference identifier (from a certificate).
-- Supports basic wildcard matching per RFC 6125: a leading @*.@ matches
-- exactly one label (not the base domain itself, not sub-sub-domains).
matchHostname :: String -> String -> Bool
matchHostname hostname pattern'
    | "*." `isPrefixOf` lPattern =
        let suffix = drop 2 lPattern
        in case break (== '.') lHostname of
            (_, []) -> False -- hostname has no dot, can't match *.x
            (_, rest) -> drop 1 rest == suffix && not (null (takeWhile (/= '.') lHostname))
    | otherwise = lHostname == lPattern
  where
    lHostname = map toLower hostname
    lPattern = map toLower pattern'

-- | Validate a client certificate chain.
validateClientCertificate
    :: CertificateStore
    -> ValidationCache
    -> CertificateChain
    -> IO CertificateUsage
validateClientCertificate store cache cc =
    wrapCertificateChecks <$> validateDefault store cache ("", mempty) cc

-- | Get the subject name of a signed certificate as a string.
signedCertSubjectName :: SignedCertificate -> String
signedCertSubjectName sc = BX509.subjectName (scCert sc)

-- | Encode a CertificateChain as a list of DER-encoded certificate bytes.
encodeCertificateChain :: CertificateChain -> [ByteString]
encodeCertificateChain (CertificateChain certs) = map scDER certs

-- | Decode a list of DER-encoded certificate bytes into a CertificateChain.
decodeCertificateChain :: [ByteString] -> Either String CertificateChain
decodeCertificateChain derCerts =
    case mapM parseCert derCerts of
        Left err -> Left err
        Right certs -> Right (CertificateChain certs)
  where
    parseCert der = case BX509.parseDER der of
        Left err -> Left ("failed to parse certificate: " ++ show err)
        Right x509 -> Right (SignedCertificate der x509)

-- | Read PEM-encoded certificates from a file and return a CertificateStore.
-- Returns 'Nothing' if the file doesn't exist or contains no valid certificates.
readCertificateStore :: FilePath -> IO (Maybe CertificateStore)
readCertificateStore path = do
    exists <- doesFileExist path
    if not exists
        then return Nothing
        else do
            content <- B.readFile path
            let pemBlocks = splitPEMCerts content
            if null pemBlocks
                then return Nothing
                else do
                    store <- BX509.newX509Store
                    added <- addPEMCertsToStore store pemBlocks
                    if added
                        then return $ Just $ CertificateStore store
                        else return Nothing

-- | Add PEM-encoded certificates to an X509Store. Returns True if any certs were added.
addPEMCertsToStore :: BX509.X509Store -> [ByteString] -> IO Bool
addPEMCertsToStore store pems = go False pems
  where
    go added [] = return added
    go added (pem : rest) =
        case BX509.parsePEM pem of
            Right cert -> do
                BX509.addTrustAnchor store cert
                go True rest
            Left _ -> go added rest

-- | Read PEM-encoded certificates from multiple files into a single CertificateStore.
-- Returns 'Nothing' if no valid certificates were found in any file.
-- Throws an error if a file doesn't exist.
readCertificateStoreFromFiles :: [FilePath] -> IO (Maybe CertificateStore)
readCertificateStoreFromFiles [] = return Nothing
readCertificateStoreFromFiles paths = do
    store <- BX509.newX509Store
    anyAdded <- foldM (addFromFile store) False paths
    if anyAdded
        then return $ Just $ CertificateStore store
        else return Nothing
  where
    addFromFile store added path = do
        content <- B.readFile path
        let pemBlocks = splitPEMCerts content
        result <- addPEMCertsToStore store pemBlocks
        return (added || result)

-- | Load the system certificate store.
-- Tries common system certificate locations on macOS and Linux.
getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore = do
    let paths =
            [ "/etc/ssl/cert.pem"                        -- macOS, some Linux
            , "/etc/ssl/certs/ca-certificates.crt"       -- Debian/Ubuntu
            , "/etc/pki/tls/certs/ca-bundle.crt"         -- RHEL/CentOS/Fedora
            , "/etc/ssl/ca-bundle.pem"                   -- openSUSE
            , "/usr/local/share/certs/ca-root-nss.crt"   -- FreeBSD
            ]
    tryPaths paths
  where
    tryPaths [] = return $ emptyCertificateStore
    tryPaths (p : ps) = do
        mstore <- E.try (readCertificateStore p) :: IO (Either E.SomeException (Maybe CertificateStore))
        case mstore of
            Right (Just store) -> return store
            _ -> tryPaths ps

-- | Split a PEM file into individual PEM blocks for certificates only.
splitPEMCerts :: ByteString -> [ByteString]
splitPEMCerts bs = go (C8.lines bs) []
  where
    beginMarker :: ByteString
    beginMarker = C8.pack "-----BEGIN CERTIFICATE-----"
    endMarker :: ByteString
    endMarker = C8.pack "-----END CERTIFICATE-----"

    go :: [ByteString] -> [ByteString] -> [ByteString]
    go [] acc = reverse acc
    go (line : rest) acc
        | beginMarker `B.isPrefixOf` line =
            let (certBlock, remaining) = collectCert rest []
             in go remaining (certBlock : acc)
        | otherwise = go rest acc

    collectCert :: [ByteString] -> [ByteString] -> (ByteString, [ByteString])
    collectCert [] _ = (B.empty, [])
    collectCert (line : rest) certAcc
        | endMarker `B.isPrefixOf` line =
            let pemBlock = B.intercalate (C8.singleton '\n') $
                    [beginMarker] ++ reverse certAcc ++ [endMarker]
             in (pemBlock, rest)
        | otherwise = collectCert rest (line : certAcc)
