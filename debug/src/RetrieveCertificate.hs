{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

import Control.Exception
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as BS16
import Data.Default (def)
import Data.IORef
import Network.Socket
import System.Console.GetOpt
import System.Environment
import System.Exit
import Text.Printf

import qualified Crypto.BoringSSL.Digest as Digest
import qualified Crypto.BoringSSL.PEM as PEM
import qualified Crypto.BoringSSL.X509 as BX509

import Network.TLS
import Network.TLS.Extra.Cipher

import Imports

openConnection :: String -> String -> IO CertificateChain
openConnection s p = do
    ref <- newIORef Nothing
    let hooks =
            def{onServerCertificate = \_ _ _ _ -> return []}
    let params =
            (defaultParamsClient s (B8.pack p))
                { clientSupported = def{supportedCiphers = ciphersuite_all}
                , clientShared = def
                , clientHooks = hooks
                }

    let hints = defaultHints{addrSocketType = Stream}
    addr : _ <- getAddrInfo (Just hints) (Just s) (Just p)

    sock <- bracketOnError
        (socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr))
        close
        $ \sock -> do
            connect sock $ addrAddress addr
            return sock
    ctx <- contextNew sock params

    contextHookSetCertificateRecv ctx $ \l -> writeIORef ref (Just l)

    _ <- handshake ctx
    bye ctx
    r <- readIORef ref
    case r of
        Nothing -> error "cannot retrieve any certificate"
        Just certs -> return certs

data Flag
    = PrintChain
    | Format String
    | Verify
    | GetFingerprint
    | VerifyFQDN String
    | Help
    deriving (Show, Eq)

options :: [OptDescr Flag]
options =
    [ Option
        []
        ["chain"]
        (NoArg PrintChain)
        "output the chain of certificate used"
    , Option
        []
        ["format"]
        (ReqArg Format "format")
        "define the output format (full, pem, default: simple)"
    , Option
        []
        ["verify"]
        (NoArg Verify)
        "verify the chain received with the trusted system certificate"
    , Option [] ["fingerprint"] (NoArg GetFingerprint) "show fingerprint (SHA1)"
    , Option
        []
        ["verify-domain-name"]
        (ReqArg VerifyFQDN "fqdn")
        "verify the chain against a specific FQDN"
    , Option ['h'] ["help"] (NoArg Help) "request help"
    ]

showCert :: String -> SignedCertificate -> IO ()
showCert "pem" sc = case PEM.pemEncode "CERTIFICATE" (scDER sc) of
    Right pemBS -> B8.putStrLn pemBS
    Left err -> putStrLn ("error encoding PEM: " ++ show err)
showCert "full" sc = do
    let cert = scCert sc
    putStrLn ("serial:   " ++ BX509.serialNumberHex cert)
    putStrLn ("issuer:   " ++ BX509.issuerName cert)
    putStrLn ("subject:  " ++ BX509.subjectName cert)
    putStrLn ("validity: " ++ showValidity cert)
    putStrLn ("DER size: " ++ show (B.length (scDER sc)) ++ " bytes")
showCert _ sc = do
    let cert = scCert sc
    putStrLn ("serial:   " ++ BX509.serialNumberHex cert)
    putStrLn ("issuer:   " ++ show (certIssuerDN (getCertificate sc)))
    putStrLn ("subject:  " ++ show (certSubjectDN (getCertificate sc)))
    putStrLn ("validity: " ++ showValidity cert)

showValidity :: BX509.X509Cert -> String
showValidity cert =
    showTime (BX509.notBefore cert) ++ " to " ++ showTime (BX509.notAfter cert)
  where
    showTime (Right t) = show t
    showTime (Left _) = "(unknown)"

printUsage :: IO ()
printUsage =
    putStrLn $
        usageInfo
            "usage: retrieve-certificate [opts] <hostname> [port]\n\n\t(port default to: 443)\noptions:\n"
            options

fingerprintHex :: ByteString -> String
fingerprintHex bs = B8.unpack (BS16.encode bs)

main :: IO ()
main = do
    args <- getArgs
    let (opts, other, errs) = getOpt Permute options args
    when (not $ null errs) $ do
        print errs
        exitFailure

    when (Help `elem` opts) $ do
        printUsage
        exitSuccess

    case other of
        [destination, port] -> doMain destination port opts
        [destination] -> doMain destination "443" opts
        _ -> printUsage >> exitFailure
  where
    outputFormat [] = "simple"
    outputFormat (Format s : _) = s
    outputFormat (_ : xs) = outputFormat xs

    getFQDN [] = Nothing
    getFQDN (VerifyFQDN fqdn : _) = Just fqdn
    getFQDN (_ : xs) = getFQDN xs

    doMain destination port opts = do
        _ <- printf "connecting to %s on port %s ...\n" destination port

        chain <- openConnection destination port
        let (CertificateChain certs) = chain
            format = outputFormat opts
            fqdn = getFQDN opts
        if PrintChain `elem` opts
            then forM_ (zip [0 ..] certs) $ \(n, cert) -> do
                putStrLn ("###### Certificate " ++ show (n + 1 :: Int) ++ " ######")
                showCert format cert
            else showCert format $ head certs

        let fingerprints = foldl (doFingerprint (head certs)) [] opts
        unless (null fingerprints) $ putStrLn "Fingerprints:"
        mapM_ (\(alg, fprint) -> putStrLn ("  " ++ alg ++ " = " ++ fprint)) $
            concat fingerprints

        when (Verify `elem` opts) $ do
            store <- getSystemCertificateStore
            putStrLn "### certificate chain trust"
            let servId = (fromMaybe "" fqdn, B.empty)
            reasons <- validateDefault store () servId chain
            if null reasons
                then putStrLn "chain is valid"
                else do
                    putStrLn "fail validation:"
                    print reasons

    doFingerprint sc acc GetFingerprint =
        let der = scDER sc
        in  [ ("SHA1", fingerprintHex (Digest.hashSHA1 der))
            , ("SHA256", fingerprintHex (Digest.hashSHA256 der))
            , ("SHA512", fingerprintHex (Digest.hashSHA512 der))
            ]
                : acc
    doFingerprint _ acc _ = acc
