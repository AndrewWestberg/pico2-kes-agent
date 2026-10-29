use super::{
    cbor::{Encoder, Map, Value},
    recipient::RecipientKeyFile,
};
use crate::{
    files::{open_owner_controlled_file, publish_no_clobber},
    memory::SecretBuffer,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR,
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    setup_receiver,
};
use kes_core::{
    backup::{CIPHERTEXT_BYTES, MAGIC, MAX_BACKUP_BYTES},
    kes::{STATE_BYTES, verification_key_from_state},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{io::Read, os::unix::fs::PermissionsExt, path::Path};
use zeroize::Zeroizing;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;

#[derive(Clone, Copy)]
pub struct Expectations {
    pub device: [u8; 16],
    pub pool: [u8; 28],
    pub incarnation: [u8; 16],
    pub generation: [u8; 16],
    pub verification_key: [u8; 32],
    pub identity_public_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArtifact,
    WrongBinding,
    InvalidSignature,
    WrongRecipient,
    WrongPassword,
    Decryption,
    InvalidState,
    MemoryProtection,
    InvalidInput,
    Publication,
}

pub fn recover(
    artifact_bytes: &[u8],
    recipient: &RecipientKeyFile,
    passphrase: &[u8],
    expected: Expectations,
) -> Result<SecretBuffer, Error> {
    let map = parse_artifact(artifact_bytes)?;
    for (field, binding) in [
        ("device", expected.device.as_slice()),
        ("pool", expected.pool.as_slice()),
        ("incarnation", expected.incarnation.as_slice()),
        ("generation", expected.generation.as_slice()),
        ("verification_key", expected.verification_key.as_slice()),
    ] {
        require_binding(map, field, binding)?;
    }
    verify_signature(map, expected.identity_public_key)?;

    let public = recipient.public().map_err(|_| Error::WrongRecipient)?;
    require_binding(map, "recipient_public_key", &public.public_key)
        .map_err(|_| Error::WrongRecipient)?;
    require_binding(map, "recipient_id", &public.recipient_id)
        .map_err(|_| Error::WrongRecipient)?;
    if Sha256::digest(public.public_key).as_slice() != public.recipient_id {
        return Err(Error::WrongRecipient);
    }
    let private = recipient.unlock(passphrase).map_err(|error| match error {
        super::recipient::Error::Authentication => Error::WrongPassword,
        super::recipient::Error::MemoryProtection => Error::MemoryProtection,
        _ => Error::InvalidInput,
    })?;
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(private.as_slice())
        .map_err(|_| Error::WrongRecipient)?;
    let encapsulation = map
        .required("encapsulation")
        .and_then(Value::bytes)
        .map_err(|_| Error::InvalidArtifact)?;
    let encapsulation = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulation)
        .map_err(|_| Error::InvalidArtifact)?;
    let header = artifact_header(map)?;
    let mut info = Vec::with_capacity(32 + header.len());
    info.extend_from_slice(b"cardano-kes-forge/backup/v1");
    info.extend_from_slice(&header);
    let mut aad = Vec::with_capacity(MAGIC.len() + header.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&header);
    let mut receiver =
        setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private_key, &encapsulation, &info)
            .map_err(|_| Error::Decryption)?;
    let ciphertext = map
        .required("ciphertext")
        .and_then(Value::bytes)
        .map_err(|_| Error::InvalidArtifact)?;
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(Error::InvalidArtifact);
    }
    let mut state = SecretBuffer::new(STATE_BYTES).map_err(|_| Error::MemoryProtection)?;
    state
        .as_mut_slice()
        .copy_from_slice(&ciphertext[..STATE_BYTES]);
    let tag = AeadTag::<Aead>::from_bytes(&ciphertext[STATE_BYTES..])
        .map_err(|_| Error::InvalidArtifact)?;
    receiver
        .open_in_place_detached(state.as_mut_slice(), &aad, &tag)
        .map_err(|_| Error::Decryption)?;
    let state_array: &[u8; STATE_BYTES] = state
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidState)?;
    let verification_key =
        verification_key_from_state(state_array, 0).map_err(|_| Error::InvalidState)?;
    if verification_key != expected.verification_key {
        return Err(Error::InvalidState);
    }
    Ok(state)
}

pub fn restore_to_file(
    artifact_bytes: &[u8],
    recipient: &RecipientKeyFile,
    passphrase: &[u8],
    expected: Expectations,
    output: &Path,
) -> Result<(), Error> {
    let state = recover(artifact_bytes, recipient, passphrase, expected)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(1_360));
    envelope.extend_from_slice(
        br#"{"type":"KesSigningKey_ed25519_kes_2^6","description":"Pico2 KES agent restored signing key","cborHex":"590260"#,
    );
    append_hex(&mut envelope, state.as_slice());
    envelope.extend_from_slice(br#""}"#);
    publish_no_clobber(output, &envelope, 0o600).map_err(|_| Error::Publication)
}

pub fn read_file(path: &Path, private: bool, maximum: u64) -> Result<Vec<u8>, Error> {
    let mut file = open_owner_controlled_file(path).map_err(|_| Error::InvalidInput)?;
    let metadata = file.metadata().map_err(|_| Error::InvalidInput)?;
    if metadata.len() > maximum || (private && metadata.permissions().mode() & 0o777 != 0o600) {
        return Err(Error::InvalidInput);
    }
    let mut output = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut output)
        .map_err(|_| Error::InvalidInput)?;
    Ok(output)
}

#[derive(Deserialize)]
struct DeviceIdentity {
    device_id: String,
    identity_public_key: String,
}

pub fn load_identity(path: &Path, expected_device: [u8; 16]) -> Result<[u8; 32], Error> {
    let bytes = read_file(path, false, 16_384)?;
    let identity: DeviceIdentity =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
    if decode_hex::<16>(&identity.device_id).ok_or(Error::InvalidInput)? != expected_device {
        return Err(Error::WrongBinding);
    }
    decode_hex(&identity.identity_public_key).ok_or(Error::InvalidInput)
}

pub fn parse_verification_key_file(path: &Path) -> Result<[u8; 32], Error> {
    let bytes = read_file(path, false, 16_384)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Envelope {
        #[serde(rename = "type")]
        kind: String,
        description: String,
        cbor_hex: String,
    }
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
    if envelope.kind != "KesVerificationKey_ed25519_kes_2^6"
        || envelope.description.is_empty()
        || !envelope.cbor_hex.starts_with("5820")
        || envelope.cbor_hex.len() != 68
    {
        return Err(Error::InvalidInput);
    }
    decode_hex(&envelope.cbor_hex[4..]).ok_or(Error::InvalidInput)
}

fn parse_artifact(bytes: &[u8]) -> Result<Map<'_>, Error> {
    if bytes.len() > MAX_BACKUP_BYTES || bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(Error::InvalidArtifact);
    }
    let map = Value::parse(&bytes[MAGIC.len()..])
        .and_then(Value::map)
        .map_err(|_| Error::InvalidArtifact)?;
    const FIELDS: [(&str, Option<usize>); 16] = [
        ("version", None),
        ("kem", None),
        ("kdf", None),
        ("aead", None),
        ("device", Some(16)),
        ("incarnation", Some(16)),
        ("generation", Some(16)),
        ("pool", Some(28)),
        ("generation_number", None),
        ("verification_key", Some(32)),
        ("recipient_public_key", Some(32)),
        ("recipient_id", Some(32)),
        ("period", None),
        ("encapsulation", Some(32)),
        ("ciphertext", Some(CIPHERTEXT_BYTES)),
        ("device_signature", Some(64)),
    ];
    let mut count = 0;
    for field in map {
        let (key, value) = field.map_err(|_| Error::InvalidArtifact)?;
        let (_, length) = FIELDS
            .iter()
            .find(|(known, _)| *known == key)
            .ok_or(Error::InvalidArtifact)?;
        match length {
            Some(length) if value.bytes().map_err(|_| Error::InvalidArtifact)?.len() == *length => {
            }
            Some(_) => return Err(Error::InvalidArtifact),
            None => {
                value.uint().map_err(|_| Error::InvalidArtifact)?;
            }
        }
        count += 1;
    }
    if count != FIELDS.len()
        || map
            .required("version")
            .and_then(Value::uint)
            .map_err(|_| Error::InvalidArtifact)?
            != 1
        || map
            .required("kem")
            .and_then(Value::uint)
            .map_err(|_| Error::InvalidArtifact)?
            != 32
        || map
            .required("kdf")
            .and_then(Value::uint)
            .map_err(|_| Error::InvalidArtifact)?
            != 1
        || map
            .required("aead")
            .and_then(Value::uint)
            .map_err(|_| Error::InvalidArtifact)?
            != 3
        || map
            .required("period")
            .and_then(Value::uint)
            .map_err(|_| Error::InvalidArtifact)?
            != 0
    {
        return Err(Error::InvalidArtifact);
    }
    Ok(map)
}

fn verify_signature(map: Map<'_>, identity_public_key: [u8; 32]) -> Result<(), Error> {
    let signature: [u8; 64] = map
        .required("device_signature")
        .and_then(Value::bytes)
        .map_err(|_| Error::InvalidArtifact)?
        .try_into()
        .map_err(|_| Error::InvalidArtifact)?;
    let mut storage = [0; MAX_BACKUP_BYTES];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(15).map_err(|_| Error::InvalidArtifact)?;
    for field in map {
        let (key, value) = field.map_err(|_| Error::InvalidArtifact)?;
        if key != "device_signature" {
            encoder.text(key).map_err(|_| Error::InvalidArtifact)?;
            encoder.value(value).map_err(|_| Error::InvalidArtifact)?;
        }
    }
    let unsigned = encoder.finish().map_err(|_| Error::InvalidArtifact)?;
    let mut message = Vec::with_capacity(48 + unsigned.encoded().len());
    message.extend_from_slice(b"cardano-kes-forge/backup-signature/v1");
    message.extend_from_slice(MAGIC);
    message.extend_from_slice(unsigned.encoded());
    VerifyingKey::from_bytes(&identity_public_key)
        .map_err(|_| Error::InvalidSignature)?
        .verify(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::InvalidSignature)
}

fn artifact_header(map: Map<'_>) -> Result<Vec<u8>, Error> {
    let mut storage = [0; 512];
    let mut encoder = Encoder::new(&mut storage);
    encoder.map(13).map_err(|_| Error::InvalidArtifact)?;
    for key in [
        "kdf",
        "kem",
        "aead",
        "pool",
        "device",
        "period",
        "version",
        "generation",
        "incarnation",
        "recipient_id",
        "verification_key",
        "generation_number",
        "recipient_public_key",
    ] {
        encoder.text(key).map_err(|_| Error::InvalidArtifact)?;
        encoder
            .value(map.required(key).map_err(|_| Error::InvalidArtifact)?)
            .map_err(|_| Error::InvalidArtifact)?;
    }
    encoder
        .finish()
        .map(|value| value.encoded().to_vec())
        .map_err(|_| Error::InvalidArtifact)
}

fn require_binding(map: Map<'_>, field: &str, expected: &[u8]) -> Result<(), Error> {
    let actual = map
        .required(field)
        .and_then(Value::bytes)
        .map_err(|_| Error::InvalidArtifact)?;
    (actual == expected)
        .then_some(())
        .ok_or(Error::WrongBinding)
}

pub fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(output)
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn append_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    output.reserve(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize]);
        output.push(DIGITS[(byte & 15) as usize]);
    }
}
