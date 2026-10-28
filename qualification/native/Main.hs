{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- This program is for disposable qualification material only.  The pure KES
-- interface deliberately copies secret bytes and must never handle live keys.
module Main (main) where

import qualified Cardano.Api.Key as API
import qualified Cardano.Api.Serialise.Cbor as API
import qualified Cardano.Api.Serialise.Raw as API
import qualified Cardano.Api.Serialise.TextEnvelope as API
import Cardano.Binary (decodeFull', serialize')
import Cardano.Crypto.DSIGN.Class (rawSerialiseVerKeyDSIGN)
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Libsodium (sodiumInit)
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.KESAgent.KES.Bundle (Bundle (..), Timestamp (..))
import Cardano.KESAgent.KES.Crypto (KES)
import Cardano.KESAgent.KES.OCert
import Cardano.KESAgent.Serialization.CBOR (OpCert (..))
import Cardano.KESAgent.Protocols.StandardCrypto (StandardCrypto)
import Cardano.KESAgent.Protocols.Service.V2.Driver (KeyMessageTypeID (..))
import Cardano.KESAgent.Protocols.Service.V2.Protocol (ServiceProtocol)
import Cardano.KESAgent.Protocols.VersionedProtocol (VersionIdentifier (..), VersionedProtocol (..))
import Cardano.KESAgent.Serialization.DirectCodec (sendItem)
import Cardano.KESAgent.Serialization.RawUtil (ReadResult (..), receiveRecvResult, sendBS)
import Cardano.KESAgent.Util.RefCounting (newCRef, releaseCRef)
import Control.Applicative ((<|>))
import Control.Exception (SomeException, bracket, try)
import Control.Monad (foldM, unless, when)
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as BA
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Attoparsec.ByteString.Char8 as P
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as LBS
import Data.List (sort)
import Data.IORef (newIORef, readIORef, modifyIORef')
import Data.Proxy (Proxy (..))
import qualified Data.Text as T
import qualified Data.Text.Encoding as Text
import Data.Word (Word64)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (castPtr)
import Ouroboros.Network.RawBearer (RawBearer (..))
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hClose, stdout)
import System.Posix.IO (fdToHandle)
import System.Posix.Types (Fd (..))
import Text.Read (readMaybe)

type Algorithm = KES StandardCrypto

data Field = HexField BS.ByteString | NumberField Integer

-- A deliberately restricted JSON object grammar: only unescaped ASCII keys,
-- lowercase hexadecimal strings, and nonnegative integer values are accepted.
-- Keeping pairs before validation ensures duplicate keys cannot be discarded.
request :: P.Parser [(BS.ByteString, Field)]
request = P.skipSpace *> P.char '{' *> P.skipSpace *> fields <* P.skipSpace <* P.char '}' <* P.skipSpace <* P.endOfInput
  where
    fields = pair `P.sepBy` (P.skipSpace *> P.char ',' *> P.skipSpace)
    pair = do
      key <- quoted (P.takeWhile1 (\c -> c >= 'a' && c <= 'z' || c == '_'))
      P.skipSpace *> P.char ':' *> P.skipSpace
      value <- (HexField <$> quoted (P.takeWhile (\c -> c >= '0' && c <= '9' || c >= 'a' && c <= 'f'))) <|> (NumberField <$> number)
      pure (key, value)
    quoted p = P.char '"' *> p <* P.char '"'
    number = do
      digits <- P.takeWhile1 (\c -> c >= '0' && c <= '9')
      when (BS.length digits > 20 || (BS.length digits > 1 && BS.head digits == 48)) (fail "invalid integer")
      pure (C.foldl' (\n c -> n * 10 + toInteger (fromEnum c - fromEnum '0')) 0 digits)

hexField :: BS.ByteString -> [(BS.ByteString, Field)] -> IO BS.ByteString
hexField key fields = case lookup key fields of
  Just (HexField s) -> either (const failRequest) pure (Hex.decode s)
  _ -> failRequest

failRequest :: IO a
failRequest = ioError (userError "invalid request")

runKES :: BS.ByteString -> IO BS.ByteString
runKES input = do
  fields <- either (const failRequest) pure (P.parseOnly request input)
  unless (sort (map fst fields) == ["expected_state", "message", "period", "seed"]) failRequest
  seed <- hexField "seed" fields
  message <- hexField "message" fields
  expected <- hexField "expected_state" fields
  period <- case lookup "period" fields of
    Just (NumberField n) | n >= 0 && n < 64 -> pure (fromInteger n)
    _ -> failRequest
  unless (BS.length seed == 32 && BS.length message <= 4096 && BS.length expected == 608) failRequest
  let initial = unsoundPureGenKeyKES @Algorithm (mkSeedFromBytes seed)
      vkey = unsoundPureDeriveVerKeyKES @Algorithm initial
  evolved <- foldM (\key t -> maybe failRequest pure (unsoundPureUpdateKES @Algorithm () key t)) initial (take (fromIntegral period) [0 ..])
  let state = rawSerialiseUnsoundPureSignKeyKES @Algorithm evolved
      signature = unsoundPureSignKES @Algorithm () period message evolved
      valid = either (const False) (const True) (verifyKES @Algorithm () vkey period message signature)
      encoded = C.unpack . Hex.encode
  pure . LBS.toStrict . Aeson.encode $ Aeson.object
    [ "vkey" Aeson..= encoded (rawSerialiseVerKeyKES @Algorithm vkey)
    , "state" Aeson..= encoded state
    , "signature" Aeson..= encoded (rawSerialiseSigKES @Algorithm signature)
    , "verified" Aeson..= valid
    , "state_matches" Aeson..= (state == expected)
    ]

runVerify :: BS.ByteString -> IO BS.ByteString
runVerify input = do
  fields <- either (const failRequest) pure (P.parseOnly request input)
  unless (sort (map fst fields) == ["message", "period", "signature", "vkey"]) failRequest
  message <- hexField "message" fields
  vkBytes <- hexField "vkey" fields
  sigBytes <- hexField "signature" fields
  period <- case lookup "period" fields of
    Just (NumberField n) | n >= 0 && n < 64 -> pure (fromInteger n)
    _ -> failRequest
  unless (BS.length message <= 4096) failRequest
  vk <- maybe failRequest pure (rawDeserialiseVerKeyKES @Algorithm vkBytes)
  signature <- maybe failRequest pure (rawDeserialiseSigKES @Algorithm sigBytes)
  let valid = either (const False) (const True) (verifyKES @Algorithm () vk period message signature)
  pure . LBS.toStrict . Aeson.encode $ Aeson.object ["verified" Aeson..= valid]

-- OpCert is the agent library's node-compatible envelope payload wrapper,
-- distinct from its deliberately incompatible wire-protocol OCert instance.
runOpCert :: BS.ByteString -> IO BS.ByteString
runOpCert input = do
  fields <- either (const failRequest) pure (P.parseOnly request input)
  unless (map fst fields == ["cbor"]) failRequest
  bytes <- hexField "cbor" fields
  cert <- either (const failRequest) pure (decodeFull' @(OpCert StandardCrypto) bytes)
  unless (serialize' cert == bytes) failRequest
  let oc = opCert cert
      cold = opCertColdKey cert
      hot = ocertVkHot oc
      valid = either (const False) (const True) (validateOCert cold hot oc)
      encoded = C.unpack . Hex.encode
  pure . LBS.toStrict . Aeson.encode $ Aeson.object
    [ "hot_vkey" Aeson..= encoded (rawSerialiseVerKeyKES hot)
    , "cold_vkey" Aeson..= encoded (rawSerialiseVerKeyDSIGN cold)
    , "counter" Aeson..= ocertN oc
    , "start_period" Aeson..= unKESPeriod (ocertKESPeriod oc)
    , "verified" Aeson..= valid
    ]

-- Use the same DirectCodec primitives and ordering as the V2 service driver.
-- The in-memory bearer is confined to this disposable protected invocation.
runService :: BS.ByteString -> IO BS.ByteString
runService input = do
  fields <- either (const failRequest) pure (P.parseOnly request input)
  unless (sort (map fst fields) == ["cbor", "confirmation", "expected_wire", "period", "state", "timestamp"]) failRequest
  state <- hexField "state" fields
  cbor <- hexField "cbor" fields
  confirmation <- hexField "confirmation" fields
  expected <- hexField "expected_wire" fields
  let integer key = case lookup key fields of
        Just (NumberField n) | n >= 0 && n <= toInteger (maxBound :: Word64) -> pure n
        _ -> failRequest
  period <- integer "period"
  timestamp <- integer "timestamp"
  unless (BS.length state == 608 && period < 64 && BS.length confirmation == 4 && BS.length expected <= 4096) failRequest
  cert <- either (const failRequest) pure (decodeFull' @(OpCert StandardCrypto) cbor)
  unless (serialize' cert == cbor) failRequest
  key <- rawDeserialiseSignKeyKES @Algorithm state >>= maybe failRequest pure
  incoming <- newIORef confirmation
  outgoing <- newIORef []
  let bearer = RawBearer
        { send = \ptr size -> do
            chunk <- BS.packCStringLen (castPtr ptr, size)
            modifyIORef' outgoing (chunk :)
            pure size
        , recv = \ptr size -> do
            remaining <- readIORef incoming
            let (chunk, rest) = BS.splitAt size remaining
            BS.useAsCString chunk $ \src -> copyBytes ptr (castPtr src) (BS.length chunk)
            modifyIORef' incoming (const rest)
            pure (BS.length chunk)
        }
  result <- bracket (newCRef (forgetSignKeyKES . skWithoutPeriodKES) (SignKeyWithPeriodKES key (fromInteger period))) releaseCRef $ \ref -> do
    let version = versionIdentifier (Proxy @(ServiceProtocol IO))
    _ <- sendBS bearer (unVersionIdentifier version)
    sendItem bearer KeyMessageID
    sendItem bearer (Timestamp (fromInteger timestamp))
    sendItem bearer (Bundle ref (opCert cert))
    receiveRecvResult bearer
  rest <- readIORef incoming
  unless (BS.null rest) failRequest
  confirmationResult <- case result of
    ReadOK value -> pure (show value)
    _ -> failRequest
  wire <- BS.concat . reverse <$> readIORef outgoing
  pure . LBS.toStrict . Aeson.encode $ Aeson.object
    [ "wire" Aeson..= C.unpack (Hex.encode wire)
    , "wire_matches" Aeson..= (wire == expected)
    , "confirmation" Aeson..= confirmationResult
    ]

-- Preserve duplicate object names until after parsing rather than relying on
-- Aeson's map representation, which discards duplicates.
envelopeFields :: P.Parser [(String, String)]
envelopeFields = P.skipSpace *> P.char '{' *> P.skipSpace *> pairs <* P.skipSpace <* P.char '}' <* P.skipSpace <* P.endOfInput
  where
    pairs = pair `P.sepBy` (P.skipSpace *> P.char ',' *> P.skipSpace)
    pair = do
      key <- jsonString
      P.skipSpace *> P.char ':' *> P.skipSpace
      value <- jsonString
      pure (key, value)
    jsonString = do
      _ <- P.char '"'
      body <- P.scan False $ \escaped c ->
        if escaped then Just False
        else if c == '\\' then Just True
        else if c == '"' then Nothing
        else Just False
      _ <- P.char '"'
      either fail pure (Aeson.eitherDecodeStrict' ("\"" <> body <> "\""))

runEnvelope :: BS.ByteString -> IO BS.ByteString
runEnvelope input = do
  fields <- either (const failRequest) pure (P.parseOnly request input)
  unless (sort (map fst fields) == ["envelope", "expected_state"]) failRequest
  envelope <- hexField "envelope" fields
  expected <- hexField "expected_state" fields
  unless (BS.length expected == 608) failRequest
  members <- either (const failRequest) pure (P.parseOnly envelopeFields envelope)
  unless (sort (map fst members) == ["cborHex", "description", "type"]) failRequest
  decoded <- either (const failRequest) pure (API.decodeTextEnvelopeJSON envelope)
  key <- either (const failRequest) pure (API.deserialiseFromTextEnvelope decoded :: Either API.TextEnvelopeError (API.SigningKey API.KesKey))
  unless (API.serialiseToCBOR key == API.textEnvelopeRawCBOR decoded) failRequest
  let state = API.serialiseToRawBytes key
      vkey = API.serialiseToRawBytes (API.getVerificationKey key)
  pure . LBS.toStrict . Aeson.encode $ Aeson.object
    [ "state" Aeson..= C.unpack (Hex.encode state)
    , "vkey" Aeson..= C.unpack (Hex.encode vkey)
    , "state_matches" Aeson..= (state == expected)
    ]

-- Public mode emits hashes and lengths instead of protected bytes.
publicResponse :: BS.ByteString -> IO BS.ByteString
publicResponse response = do
  value <- either (const failRequest) pure (Aeson.eitherDecodeStrict' response)
  case value of
    Aeson.Object obj -> do
      sanitized <- foldM hide obj ["state", "wire", "signature"]
      pure . LBS.toStrict . Aeson.encode . Aeson.Object $
        KeyMap.insert "status" (Aeson.String "ok") sanitized
    _ -> failRequest
  where
    hide obj name = case KeyMap.lookup (Key.fromText (T.pack name)) obj of
      Nothing -> pure obj
      Just (Aeson.String hex) -> do
        bytes <- either (const failRequest) pure (Hex.decode (Text.encodeUtf8 hex))
        let digest = BA.convert (Hash.hash bytes :: Hash.Digest Hash.SHA256) :: BS.ByteString
        pure $ KeyMap.insert (Key.fromText (T.pack (name ++ "_length"))) (Aeson.toJSON (BS.length bytes))
             $ KeyMap.insert (Key.fromText (T.pack (name ++ "_sha256"))) (Aeson.toJSON (C.unpack (Hex.encode digest)))
             $ KeyMap.delete (Key.fromText (T.pack name)) obj
      _ -> failRequest

run :: IO ()
run = do
  args <- getArgs
  (public, operation, inputFd, outputFd) <- case args of
    ["public", op, a, b] -> invocation True op a b
    ["protected", op, a, b] -> invocation False op a b
    _ -> failRequest
  sodiumInit
  input <- fdToHandle (Fd inputFd)
  output <- fdToHandle (Fd outputFd)
  bytes <- BS.hGet input 16385
  when (BS.length bytes > 16384) failRequest
  response <- case operation of
    "kes" -> runKES bytes
    "verify" -> runVerify bytes
    "opcert" -> runOpCert bytes
    "service" -> runService bytes
    "envelope" -> runEnvelope bytes
    _ -> failRequest
  outputBytes <- if public then publicResponse response else pure response
  BS.hPut output outputBytes
  when public (BS.hPut stdout outputBytes)
  hClose output
  hClose input
  where
    invocation public op a b
      | op `elem` ["kes", "verify", "opcert", "service", "envelope"] =
          case (readMaybe a, readMaybe b) of
            (Just i, Just o) | i >= 3 && o >= 3 && i /= o -> pure (public, op, i, o)
            _ -> failRequest
      | otherwise = failRequest

main :: IO ()
main = do
  result <- try run :: IO (Either SomeException ())
  case result of
    Left _ -> exitFailure
    Right () -> pure ()
