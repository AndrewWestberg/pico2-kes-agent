{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- These deliberately public synthetic keys must never be used for funds.
module Main (main) where

import qualified Cardano.Api.Key as API
import qualified Cardano.Api.Serialise.Raw as API
import qualified Cardano.Api.Serialise.TextEnvelope as API
import Cardano.Binary (decodeFull', serialize')
import Cardano.Crypto.DSIGN.Class (deriveVerKeyDSIGN, genKeyDSIGN, rawSerialiseVerKeyDSIGN)
import Cardano.Crypto.DSIGN.Ed25519 (Ed25519DSIGN)
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Libsodium (sodiumInit)
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.KESAgent.KES.Crypto (KES)
import Cardano.KESAgent.KES.OCert
import Cardano.KESAgent.Protocols.StandardCrypto (StandardCrypto)
import Cardano.KESAgent.Serialization.CBOR (OpCert (..))
import Control.Exception (evaluate)
import Control.Monad (unless)
import qualified Data.Aeson as Aeson
import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as LBS
import System.Environment (getArgs)

type Algorithm = KES StandardCrypto

hex :: BS.ByteString -> String
hex = C.unpack . Hex.encode

check :: Bool -> String -> IO ()
check condition message = unless condition (ioError (userError message))

main :: IO ()
main = do
  args <- getArgs
  check (null args) "this generator accepts no arguments"
  sodiumInit
  let seed = BS.pack [0 .. 31]
      message = "disposable Sum6KES interoperability"
      initial = unsoundPureGenKeyKES @Algorithm (mkSeedFromBytes seed)
      vkey = unsoundPureDeriveVerKeyKES @Algorithm initial
      vkeyBytes = rawSerialiseVerKeyKES @Algorithm vkey
      coldKey = genKeyDSIGN @Ed25519DSIGN (mkSeedFromBytes (BS.pack [32 .. 63]))
      coldVkey = deriveVerKeyDSIGN @Ed25519DSIGN coldKey
      coldBytes = rawSerialiseVerKeyDSIGN @Ed25519DSIGN coldVkey
      envelopeKey = API.deterministicSigningKey (API.asType @API.KesKey) (mkSeedFromBytes seed)
      envelope = API.serialiseToTextEnvelope Nothing envelopeKey
  check (BS.length vkeyBytes == 32 && BS.length coldBytes == 32) "invalid verification key length"
  periods <- generatePeriods message vkey vkeyBytes 0 initial
  certificates <- mapM (generateCertificate vkey coldKey coldVkey) [(3, 10), (4, 10), (4, 11), (5, 10)]
  decoded <- either (ioError . userError . show) pure
    (API.deserialiseFromTextEnvelope envelope :: Either API.TextEnvelopeError (API.SigningKey API.KesKey))
  check (API.serialiseToRawBytes decoded == rawSerialiseUnsoundPureSignKeyKES @Algorithm initial)
    "envelope state mismatch"
  check (API.serialiseToRawBytes (API.getVerificationKey decoded) == vkeyBytes)
    "envelope verification key mismatch"
  output <- evaluate . LBS.toStrict . Aeson.encode $ Aeson.object
    [ "schema_version" Aeson..= (1 :: Int)
    , "warning" Aeson..= ("PUBLIC SYNTHETIC TEST KEYS - NEVER USE FOR FUNDS" :: String)
    , "seed_hex" Aeson..= hex seed
    , "message_hex" Aeson..= hex message
    , "vkey_hex" Aeson..= hex vkeyBytes
    , "periods" Aeson..= periods
    , "cold_vkey_hex" Aeson..= hex coldBytes
    , "certificates" Aeson..= certificates
    , "envelope" Aeson..= Aeson.object
        [ "type" Aeson..= API.teType envelope
        , "cborHex" Aeson..= hex (API.textEnvelopeRawCBOR envelope)
        ]
    ]
  BS.putStr output

generatePeriods message vkey vkeyBytes period key = do
  let state = rawSerialiseUnsoundPureSignKeyKES @Algorithm key
      signature = unsoundPureSignKES @Algorithm () period message key
      signatureBytes = rawSerialiseSigKES @Algorithm signature
      altered = BS.cons (BS.head signatureBytes `xor` 1) (BS.tail signatureBytes)
      valid sig = either (const False) (const True) (verifyKES @Algorithm () vkey period message sig)
  check (BS.length state == 608 && BS.length signatureBytes == 448) "invalid KES output length"
  check (rawSerialiseVerKeyKES @Algorithm (unsoundPureDeriveVerKeyKES @Algorithm key) == vkeyBytes)
    "KES verification key changed"
  check (valid signature) "KES signature verification failed"
  check (maybe True (not . valid) (rawDeserialiseSigKES @Algorithm altered))
    "altered KES signature verified"
  let row = Aeson.object
        [ "period" Aeson..= period
        , "state_hex" Aeson..= hex state
        , "signature_hex" Aeson..= hex signatureBytes
        ]
  case unsoundPureUpdateKES @Algorithm () key period of
    Nothing -> do
      check (period == 63) "KES expired early"
      pure [row]
    Just next -> do
      check (period < 63) "KES did not expire"
      rest <- generatePeriods message vkey vkeyBytes (period + 1) next
      pure (row : rest)

generateCertificate vkey coldKey coldVkey (counter, startPeriod) = do
  let cert = OpCert (makeOCert @StandardCrypto vkey counter (KESPeriod startPeriod) coldKey) coldVkey
      bytes = serialize' cert
  decoded <- either (ioError . userError . show) pure (decodeFull' @(OpCert StandardCrypto) bytes)
  check (decoded == cert && serialize' decoded == bytes) "certificate CBOR round-trip failed"
  check (either (const False) (const True) (validateOCert coldVkey vkey (opCert decoded)))
    "certificate signature verification failed"
  pure $ Aeson.object
    [ "counter" Aeson..= counter
    , "start_period" Aeson..= startPeriod
    , "cbor_hex" Aeson..= hex bytes
    ]
