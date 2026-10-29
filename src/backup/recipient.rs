use super::cbor::{Encoder, Map, Value};
use crate::memory::SecretBuffer;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"KESRCP01";
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 4;
const ARGON_VERSION: u64 = 19;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPassphrase,
    Entropy,
    InvalidFormat,
    UnsupportedParameters,
    Authentication,
    TerminalUnavailable,
    ConfirmationMismatch,
    MemoryProtection,
}

pub trait Entropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}

pub struct OsEntropy(File);

impl OsEntropy {
    pub fn new() -> Result<Self, Error> {
        File::open("/dev/urandom")
            .map(Self)
            .map_err(|_| Error::Entropy)
    }
}

impl Entropy for OsEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.0.read_exact(output).map_err(|_| Error::Entropy)
    }
}

struct EchoGuard {
    terminal: File,
    original: rustix::termios::Termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            &self.terminal,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}

fn prompt(label: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::TerminalUnavailable)?;
    let original = rustix::termios::tcgetattr(&terminal).map_err(|_| Error::TerminalUnavailable)?;
    let restore = terminal
        .try_clone()
        .map_err(|_| Error::TerminalUnavailable)?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(
        rustix::termios::LocalModes::ECHO
            | rustix::termios::LocalModes::ECHOE
            | rustix::termios::LocalModes::ECHOK
            | rustix::termios::LocalModes::ECHONL,
    );
    rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &hidden)
        .map_err(|_| Error::TerminalUnavailable)?;
    let _guard = EchoGuard {
        terminal: restore,
        original,
    };
    terminal
        .write_all(label)
        .and_then(|()| terminal.flush())
        .map_err(|_| Error::TerminalUnavailable)?;
    let mut output = Zeroizing::new(Vec::with_capacity(64));
    let mut byte = [0];
    while output.len() <= 4096 {
        if terminal
            .read(&mut byte)
            .map_err(|_| Error::TerminalUnavailable)?
            != 1
        {
            return Err(Error::TerminalUnavailable);
        }
        if byte[0] == b'\n' {
            if output.last() == Some(&b'\r') {
                output.pop();
            }
            terminal
                .write_all(b"\n")
                .map_err(|_| Error::TerminalUnavailable)?;
            validate_passphrase(&output)?;
            return Ok(output);
        }
        output.push(byte[0]);
    }
    Err(Error::InvalidPassphrase)
}

pub fn prompt_new_passphrase() -> Result<Zeroizing<Vec<u8>>, Error> {
    let first = prompt(b"Recipient passphrase: ")?;
    let second = prompt(b"Confirm recipient passphrase: ")?;
    if first.as_slice() == second.as_slice() {
        Ok(first)
    } else {
        Err(Error::ConfirmationMismatch)
    }
}

pub fn prompt_existing_passphrase() -> Result<Zeroizing<Vec<u8>>, Error> {
    prompt(b"Recipient passphrase: ")
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecipientPublic {
    pub public_key: [u8; 32],
    pub recipient_id: [u8; 32],
}

impl RecipientPublic {
    pub fn json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "algorithm": "X25519",
            "publicKey": hex(&self.public_key),
            "recipientId": hex(&self.recipient_id),
        }))
        .map_err(|_| Error::InvalidFormat)
    }

    pub fn public_key_hex(&self) -> String {
        hex(&self.public_key)
    }

    pub fn recipient_id_hex(&self) -> String {
        hex(&self.recipient_id)
    }
}

pub fn parse_public_json(encoded: &[u8]) -> Result<RecipientPublic, Error> {
    let value: serde_json::Value =
        serde_json::from_slice(encoded).map_err(|_| Error::InvalidFormat)?;
    let object = value.as_object().ok_or(Error::InvalidFormat)?;
    if object.len() != 4
        || object.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || object.get("algorithm").and_then(serde_json::Value::as_str) != Some("X25519")
    {
        return Err(Error::InvalidFormat);
    }
    let public_key = json_hex(
        object
            .get("publicKey")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidFormat)?,
    )?;
    let recipient_id = json_hex(
        object
            .get("recipientId")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidFormat)?,
    )?;
    if Sha256::digest(public_key).as_slice() != recipient_id {
        return Err(Error::InvalidFormat);
    }
    Ok(RecipientPublic {
        public_key,
        recipient_id,
    })
}

pub struct RecipientKeyFile {
    encoded: Vec<u8>,
}

impl RecipientKeyFile {
    pub fn parse(encoded: Vec<u8>) -> Result<Self, Error> {
        parse_fields(&encoded)?;
        Ok(Self { encoded })
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub fn public(&self) -> Result<RecipientPublic, Error> {
        let fields = parse_fields(&self.encoded)?;
        Ok(RecipientPublic {
            public_key: fields.public_key,
            recipient_id: fields.recipient_id,
        })
    }

    pub fn unlock(&self, passphrase: &[u8]) -> Result<SecretBuffer, Error> {
        validate_passphrase(passphrase)?;
        let fields = parse_fields(&self.encoded)?;
        let aad = header(
            &fields.salt,
            &fields.nonce,
            &fields.public_key,
            &fields.recipient_id,
        )?;
        let mut key = derive_key(passphrase, &fields.salt)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| Error::InvalidFormat)?;
        let mut private = SecretBuffer::new(32).map_err(|_| Error::MemoryProtection)?;
        private
            .as_mut_slice()
            .copy_from_slice(fields.ciphertext.get(..32).ok_or(Error::InvalidFormat)?);
        let tag: [u8; 16] = fields.ciphertext[32..]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        cipher
            .decrypt_in_place_detached(
                &XNonce::from(fields.nonce),
                &aad,
                private.as_mut_slice(),
                &Tag::from(tag),
            )
            .map_err(|_| Error::Authentication)?;
        key.zeroize();
        let actual: [u8; 32] = private.as_slice().try_into().expect("fixed secret buffer");
        verify_private(&actual, fields.public_key, fields.recipient_id)?;
        Ok(private)
    }
}

pub fn create_interactive() -> Result<(RecipientPublic, RecipientKeyFile), Error> {
    let passphrase = prompt_new_passphrase()?;
    create(&passphrase, &mut OsEntropy::new()?)
}

pub fn create(
    passphrase: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(RecipientPublic, RecipientKeyFile), Error> {
    validate_passphrase(passphrase)?;
    let mut private = SecretBuffer::new(32).map_err(|_| Error::MemoryProtection)?;
    entropy.fill(private.as_mut_slice())?;
    let private_bytes: [u8; 32] = private.as_slice().try_into().expect("fixed secret buffer");
    let public_key = PublicKey::from(&StaticSecret::from(private_bytes)).to_bytes();
    let public = RecipientPublic {
        public_key,
        recipient_id: Sha256::digest(public_key).into(),
    };
    let protected = encode_private(&private_bytes, public, passphrase, entropy)?;
    protected.unlock(passphrase)?;
    Ok((public, protected))
}

fn encode_private(
    private: &[u8; 32],
    public: RecipientPublic,
    passphrase: &[u8],
    entropy: &mut impl Entropy,
) -> Result<RecipientKeyFile, Error> {
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    entropy.fill(&mut salt)?;
    entropy.fill(&mut nonce)?;
    let aad = header(&salt, &nonce, &public.public_key, &public.recipient_id)?;
    let mut key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| Error::InvalidFormat)?;
    let mut ciphertext = Zeroizing::new(Vec::from(private.as_slice()));
    let tag = cipher
        .encrypt_in_place_detached(&XNonce::from(nonce), &aad, &mut ciphertext)
        .map_err(|_| Error::Authentication)?;
    ciphertext.extend_from_slice(&tag);
    key.zeroize();
    let mut storage = [0; 512];
    let mut encoder = Encoder::new(&mut storage);
    encode_fields(
        &mut encoder,
        &salt,
        &nonce,
        &public.public_key,
        &public.recipient_id,
        Some(&ciphertext),
    )?;
    let encoded_map = encoder.finish().map_err(|_| Error::InvalidFormat)?;
    let mut encoded = Vec::with_capacity(MAGIC.len() + encoded_map.encoded().len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(encoded_map.encoded());
    Ok(RecipientKeyFile { encoded })
}

fn header(
    salt: &[u8; 16],
    nonce: &[u8; 24],
    public_key: &[u8; 32],
    recipient_id: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut storage = [0; 512];
    let mut encoder = Encoder::new(&mut storage);
    encode_fields(&mut encoder, salt, nonce, public_key, recipient_id, None)?;
    let value = encoder.finish().map_err(|_| Error::InvalidFormat)?;
    let mut output = Vec::with_capacity(MAGIC.len() + value.encoded().len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(value.encoded());
    Ok(output)
}

fn encode_fields(
    encoder: &mut Encoder<'_>,
    salt: &[u8; 16],
    nonce: &[u8; 24],
    public_key: &[u8; 32],
    recipient_id: &[u8; 32],
    ciphertext: Option<&[u8]>,
) -> Result<(), Error> {
    encoder
        .map(if ciphertext.is_some() { 12 } else { 11 })
        .map_err(|_| Error::InvalidFormat)?;
    for (key, value) in [("kdf", "argon2id"), ("aead", "XChaCha20Poly1305")] {
        encoder.text(key).map_err(|_| Error::InvalidFormat)?;
        encoder.text(value).map_err(|_| Error::InvalidFormat)?;
    }
    for (key, value) in [("salt", salt.as_slice()), ("nonce", nonce.as_slice())] {
        encoder.text(key).map_err(|_| Error::InvalidFormat)?;
        encoder.bytes(value).map_err(|_| Error::InvalidFormat)?;
    }
    encoder.text("version").map_err(|_| Error::InvalidFormat)?;
    encoder.uint(1).map_err(|_| Error::InvalidFormat)?;
    if let Some(ciphertext) = ciphertext {
        encoder
            .text("ciphertext")
            .map_err(|_| Error::InvalidFormat)?;
        encoder
            .bytes(ciphertext)
            .map_err(|_| Error::InvalidFormat)?;
    }
    for (key, value) in [("iterations", ITERATIONS), ("memory_kib", MEMORY_KIB)] {
        encoder.text(key).map_err(|_| Error::InvalidFormat)?;
        encoder
            .uint(u64::from(value))
            .map_err(|_| Error::InvalidFormat)?;
    }
    encoder
        .text("public_key")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .bytes(public_key)
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("parallelism")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .uint(u64::from(PARALLELISM))
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("recipient_id")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .bytes(recipient_id)
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .text("argon_version")
        .map_err(|_| Error::InvalidFormat)?;
    encoder
        .uint(ARGON_VERSION)
        .map_err(|_| Error::InvalidFormat)
}

struct Fields<'a> {
    salt: [u8; 16],
    nonce: [u8; 24],
    public_key: [u8; 32],
    recipient_id: [u8; 32],
    ciphertext: &'a [u8],
}

fn parse_fields(encoded: &[u8]) -> Result<Fields<'_>, Error> {
    if encoded.get(..8) != Some(MAGIC) {
        return Err(Error::InvalidFormat);
    }
    let map = Value::parse(&encoded[8..])
        .and_then(Value::map)
        .map_err(|_| Error::InvalidFormat)?;
    require_keys(map)?;
    if uint(map, "version")? != 1
        || text(map, "kdf")? != "argon2id"
        || text(map, "aead")? != "XChaCha20Poly1305"
    {
        return Err(Error::InvalidFormat);
    }
    if uint(map, "argon_version")? != ARGON_VERSION
        || uint(map, "memory_kib")? != u64::from(MEMORY_KIB)
        || uint(map, "iterations")? != u64::from(ITERATIONS)
        || uint(map, "parallelism")? != u64::from(PARALLELISM)
    {
        return Err(Error::UnsupportedParameters);
    }
    let fields = Fields {
        salt: fixed(map, "salt")?,
        nonce: fixed(map, "nonce")?,
        public_key: fixed(map, "public_key")?,
        recipient_id: fixed(map, "recipient_id")?,
        ciphertext: map
            .required("ciphertext")
            .and_then(Value::bytes)
            .map_err(|_| Error::InvalidFormat)?,
    };
    if fields.ciphertext.len() != 48
        || fields.recipient_id != Sha256::digest(fields.public_key).as_slice()
    {
        return Err(Error::InvalidFormat);
    }
    Ok(fields)
}

fn require_keys(map: Map<'_>) -> Result<(), Error> {
    const KEYS: [&str; 12] = [
        "kdf",
        "aead",
        "salt",
        "nonce",
        "version",
        "ciphertext",
        "iterations",
        "memory_kib",
        "public_key",
        "parallelism",
        "recipient_id",
        "argon_version",
    ];
    let mut count = 0;
    for field in map {
        let (key, _) = field.map_err(|_| Error::InvalidFormat)?;
        if !KEYS.contains(&key) {
            return Err(Error::InvalidFormat);
        }
        count += 1;
    }
    (count == KEYS.len())
        .then_some(())
        .ok_or(Error::InvalidFormat)
}

struct KdfMemory(Vec<argon2::Block>);

impl Drop for KdfMemory {
    fn drop(&mut self) {
        let length = self.0.len() * core::mem::size_of::<argon2::Block>();
        // SAFETY: the vector uniquely owns this initialized byte range until
        // drop returns. Zeroize uses volatile writes and a compiler fence.
        unsafe {
            core::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast::<u8>(), length).zeroize();
        }
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        .map_err(|_| Error::UnsupportedParameters)?;
    let blocks = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    let mut blocks_memory = Vec::new();
    blocks_memory
        .try_reserve_exact(blocks)
        .map_err(|_| Error::MemoryProtection)?;
    blocks_memory.resize(blocks, argon2::Block::default());
    let mut memory = KdfMemory(blocks_memory);
    argon
        .hash_password_into_with_memory(passphrase, salt, &mut key[..], &mut memory.0)
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), Error> {
    if passphrase.is_empty() || std::str::from_utf8(passphrase).is_err() {
        Err(Error::InvalidPassphrase)
    } else {
        Ok(())
    }
}

fn verify_private(
    private: &[u8; 32],
    public: [u8; 32],
    recipient_id: [u8; 32],
) -> Result<(), Error> {
    let actual = PublicKey::from(&StaticSecret::from(*private)).to_bytes();
    if actual == public && Sha256::digest(actual).as_slice() == recipient_id {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

fn fixed<const N: usize>(map: Map<'_>, field: &str) -> Result<[u8; N], Error> {
    map.required(field)
        .and_then(Value::bytes)
        .map_err(|_| Error::InvalidFormat)?
        .try_into()
        .map_err(|_| Error::InvalidFormat)
}

fn uint(map: Map<'_>, field: &str) -> Result<u64, Error> {
    map.required(field)
        .and_then(Value::uint)
        .map_err(|_| Error::InvalidFormat)
}

fn text<'a>(map: Map<'a>, field: &str) -> Result<&'a str, Error> {
    map.required(field)
        .and_then(Value::text)
        .map_err(|_| Error::InvalidFormat)
}

fn json_hex(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 {
        return Err(Error::InvalidFormat);
    }
    let mut output = [0; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        output[index] = (nibble(pair[0]).ok_or(Error::InvalidFormat)? << 4)
            | nibble(pair[1]).ok_or(Error::InvalidFormat)?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
