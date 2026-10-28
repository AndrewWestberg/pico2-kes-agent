use crate::identity::{DeviceId, Digest32, GenerationId, IncarnationId, PoolId};
use crate::kes::{KesError, STATE_BYTES, Sum6Kes};
use crate::platform::{Entropy, fill_secret};
use crate::recipient::RecipientPolicy;
use ed25519_dalek::{Signer, SigningKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_sender,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"KESBKP01";
pub const MAX_BACKUP_BYTES: usize = 2_048;
pub const CIPHERTEXT_BYTES: usize = STATE_BYTES + 16;
const INFO_DOMAIN: &[u8] = b"cardano-kes-forge/backup/v1";
const SIGNATURE_DOMAIN: &[u8] = b"cardano-kes-forge/backup-signature/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupError {
    Kes(KesError),
    Entropy,
    InvalidPeriod,
    InvalidGenerationNumber,
    VerificationKeyMismatch,
    InvalidRecipient,
    Hpke,
    Encoding,
}

impl From<KesError> for BackupError {
    fn from(error: KesError) -> Self {
        Self::Kes(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupBindings {
    pub device: DeviceId,
    pub pool: PoolId,
    pub incarnation: IncarnationId,
    pub generation: GenerationId,
    pub generation_number: u64,
    pub verification_key: [u8; 32],
}

pub struct BackupArtifact {
    bytes: [u8; MAX_BACKUP_BYTES],
    len: u16,
}

impl BackupArtifact {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn digest(&self) -> Digest32 {
        Digest32::from_bytes(Sha256::digest(self.as_bytes()).into())
    }
}

pub fn create<E: Entropy>(
    key: &Sum6Kes,
    bindings: &BackupBindings,
    recipient: &RecipientPolicy,
    identity: &SigningKey,
    entropy: &mut E,
) -> Result<BackupArtifact, BackupError> {
    if key.period() != 0 {
        return Err(BackupError::InvalidPeriod);
    }
    if bindings.generation_number == 0 {
        return Err(BackupError::InvalidGenerationNumber);
    }
    if key.verification_key() != bindings.verification_key {
        return Err(BackupError::VerificationKeyMismatch);
    }

    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;
    type Kem = X25519HkdfSha256;
    let recipient_key = <Kem as KemTrait>::PublicKey::from_bytes(recipient.public_key())
        .map_err(|_| BackupError::InvalidRecipient)?;

    let mut header_storage = [0; 512];
    let header_len = encode_header(&mut header_storage, bindings, recipient)?;
    let header = &header_storage[..header_len];
    let mut info = [0; 512];
    let info_len = INFO_DOMAIN.len() + header.len();
    info[..INFO_DOMAIN.len()].copy_from_slice(INFO_DOMAIN);
    info[INFO_DOMAIN.len()..info_len].copy_from_slice(header);
    let mut aad = [0; 512];
    let aad_len = MAGIC.len() + header.len();
    aad[..MAGIC.len()].copy_from_slice(MAGIC);
    aad[MAGIC.len()..aad_len].copy_from_slice(header);

    let mut rng_seed = Zeroizing::new([0; 32]);
    fill_secret(entropy, &mut *rng_seed).map_err(|_| BackupError::Entropy)?;
    let mut rng = ChaCha20Rng::from_seed(*rng_seed);
    let (encapsulation, mut sender) = setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &recipient_key,
        &info[..info_len],
        &mut rng,
    )
    .map_err(|_| BackupError::Hpke)?;

    let mut ciphertext = Zeroizing::new([0; CIPHERTEXT_BYTES]);
    ciphertext[..STATE_BYTES].copy_from_slice(&key.canonical_state());
    let tag = sender
        .seal_in_place_detached(&mut ciphertext[..STATE_BYTES], &aad[..aad_len])
        .map_err(|_| BackupError::Hpke)?;
    ciphertext[STATE_BYTES..].copy_from_slice(&tag.to_bytes());
    let encapsulation: [u8; 32] = encapsulation.to_bytes().into();

    let mut unsigned_storage = [0; MAX_BACKUP_BYTES];
    let unsigned_len = encode_map(
        &mut unsigned_storage,
        bindings,
        recipient,
        &encapsulation,
        &ciphertext,
        None,
    )?;
    let mut signable = Zeroizing::new([0; MAX_BACKUP_BYTES + 64]);
    let signable_len = SIGNATURE_DOMAIN.len() + MAGIC.len() + unsigned_len;
    signable[..SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN);
    signable[SIGNATURE_DOMAIN.len()..SIGNATURE_DOMAIN.len() + MAGIC.len()].copy_from_slice(MAGIC);
    signable[SIGNATURE_DOMAIN.len() + MAGIC.len()..signable_len]
        .copy_from_slice(&unsigned_storage[..unsigned_len]);
    let signature = identity.sign(&signable[..signable_len]).to_bytes();

    let mut artifact = BackupArtifact {
        bytes: [0; MAX_BACKUP_BYTES],
        len: 0,
    };
    artifact.bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    let encoded_len = encode_map(
        &mut artifact.bytes[MAGIC.len()..],
        bindings,
        recipient,
        &encapsulation,
        &ciphertext,
        Some(&signature),
    )?;
    artifact.len = u16::try_from(MAGIC.len() + encoded_len).map_err(|_| BackupError::Encoding)?;
    Ok(artifact)
}

fn encode_header(
    storage: &mut [u8; 512],
    bindings: &BackupBindings,
    recipient: &RecipientPolicy,
) -> Result<usize, BackupError> {
    let mut encoder = Encoder::new(storage);
    encoder.map(13)?;
    encode_header_fields(&mut encoder, bindings, recipient)?;
    Ok(encoder.finish())
}

fn encode_header_fields(
    encoder: &mut Encoder<'_>,
    bindings: &BackupBindings,
    recipient: &RecipientPolicy,
) -> Result<(), BackupError> {
    encoder.text("kdf")?;
    encoder.uint(1)?;
    encoder.text("kem")?;
    encoder.uint(32)?;
    encoder.text("aead")?;
    encoder.uint(3)?;
    encoder.text("pool")?;
    encoder.bytes(bindings.pool.as_bytes())?;
    encoder.text("device")?;
    encoder.bytes(bindings.device.as_bytes())?;
    encoder.text("period")?;
    encoder.uint(0)?;
    encoder.text("version")?;
    encoder.uint(1)?;
    encoder.text("generation")?;
    encoder.bytes(bindings.generation.as_bytes())?;
    encoder.text("incarnation")?;
    encoder.bytes(bindings.incarnation.as_bytes())?;
    encoder.text("recipient_id")?;
    encoder.bytes(recipient.fingerprint().as_bytes())?;
    encoder.text("verification_key")?;
    encoder.bytes(&bindings.verification_key)?;
    encoder.text("generation_number")?;
    encoder.uint(bindings.generation_number)?;
    encoder.text("recipient_public_key")?;
    encoder.bytes(recipient.public_key())
}

fn encode_map(
    storage: &mut [u8],
    bindings: &BackupBindings,
    recipient: &RecipientPolicy,
    encapsulation: &[u8; 32],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
    signature: Option<&[u8; 64]>,
) -> Result<usize, BackupError> {
    let mut encoder = Encoder::new(storage);
    encoder.map(if signature.is_some() { 16 } else { 15 })?;
    encoder.text("kdf")?;
    encoder.uint(1)?;
    encoder.text("kem")?;
    encoder.uint(32)?;
    encoder.text("aead")?;
    encoder.uint(3)?;
    encoder.text("pool")?;
    encoder.bytes(bindings.pool.as_bytes())?;
    encoder.text("device")?;
    encoder.bytes(bindings.device.as_bytes())?;
    encoder.text("period")?;
    encoder.uint(0)?;
    encoder.text("version")?;
    encoder.uint(1)?;
    encoder.text("ciphertext")?;
    encoder.bytes(ciphertext)?;
    encoder.text("generation")?;
    encoder.bytes(bindings.generation.as_bytes())?;
    encoder.text("incarnation")?;
    encoder.bytes(bindings.incarnation.as_bytes())?;
    encoder.text("recipient_id")?;
    encoder.bytes(recipient.fingerprint().as_bytes())?;
    encoder.text("encapsulation")?;
    encoder.bytes(encapsulation)?;
    if let Some(signature) = signature {
        encoder.text("device_signature")?;
        encoder.bytes(signature)?;
    }
    encoder.text("verification_key")?;
    encoder.bytes(&bindings.verification_key)?;
    encoder.text("generation_number")?;
    encoder.uint(bindings.generation_number)?;
    encoder.text("recipient_public_key")?;
    encoder.bytes(recipient.public_key())?;
    Ok(encoder.finish())
}

struct Encoder<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Encoder<'a> {
    const fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn finish(self) -> usize {
        self.position
    }

    fn map(&mut self, len: u8) -> Result<(), BackupError> {
        self.major(5, u64::from(len))
    }

    fn uint(&mut self, value: u64) -> Result<(), BackupError> {
        self.major(0, value)
    }

    fn text(&mut self, value: &str) -> Result<(), BackupError> {
        self.major(3, value.len() as u64)?;
        self.put(value.as_bytes())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), BackupError> {
        self.major(2, value.len() as u64)?;
        self.put(value)
    }

    fn major(&mut self, major: u8, value: u64) -> Result<(), BackupError> {
        let prefix = major << 5;
        match value {
            0..=23 => self.put(&[prefix | value as u8]),
            24..=0xff => self.put(&[prefix | 24, value as u8]),
            0x100..=0xffff => {
                self.put(&[prefix | 25])?;
                self.put(&(value as u16).to_be_bytes())
            }
            0x1_0000..=0xffff_ffff => {
                self.put(&[prefix | 26])?;
                self.put(&(value as u32).to_be_bytes())
            }
            _ => {
                self.put(&[prefix | 27])?;
                self.put(&value.to_be_bytes())
            }
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(BackupError::Encoding)?;
        let target = self
            .output
            .get_mut(self.position..end)
            .ok_or(BackupError::Encoding)?;
        target.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::EntropyError;
    use x25519_dalek::{PublicKey, StaticSecret};

    struct CounterEntropy(u8);

    impl Entropy for CounterEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn artifact_has_exact_outer_contract_and_is_immutable() {
        let mut entropy = CounterEntropy(1);
        let key = Sum6Kes::generate(&mut entropy, 64).unwrap();
        let recipient_key = PublicKey::from(&StaticSecret::from([9; 32])).to_bytes();
        let recipient = RecipientPolicy::new(recipient_key, 1).unwrap();
        let bindings = BackupBindings {
            device: DeviceId::from_bytes([1; 16]),
            pool: PoolId::from_bytes([2; 28]),
            incarnation: IncarnationId::from_bytes([3; 16]),
            generation: GenerationId::from_bytes([4; 16]),
            generation_number: 1,
            verification_key: key.verification_key(),
        };
        let identity = SigningKey::from_bytes(&[5; 32]);
        let artifact = create(&key, &bindings, &recipient, &identity, &mut entropy).unwrap();
        assert!(artifact.as_bytes().starts_with(MAGIC));
        assert!(artifact.as_bytes().len() <= MAX_BACKUP_BYTES);
        assert_eq!(CIPHERTEXT_BYTES, 624);
    }

    #[test]
    fn refuses_noninitial_or_mismatched_keys() {
        let mut entropy = CounterEntropy(1);
        let mut key = Sum6Kes::generate(&mut entropy, 64).unwrap();
        let recipient_key = PublicKey::from(&StaticSecret::from([9; 32])).to_bytes();
        let recipient = RecipientPolicy::new(recipient_key, 1).unwrap();
        let mut bindings = BackupBindings {
            device: DeviceId::from_bytes([1; 16]),
            pool: PoolId::from_bytes([2; 28]),
            incarnation: IncarnationId::from_bytes([3; 16]),
            generation: GenerationId::from_bytes([4; 16]),
            generation_number: 1,
            verification_key: [0; 32],
        };
        let identity = SigningKey::from_bytes(&[5; 32]);
        assert_eq!(
            create(&key, &bindings, &recipient, &identity, &mut entropy)
                .err()
                .unwrap(),
            BackupError::VerificationKeyMismatch
        );
        bindings.verification_key = key.verification_key();
        key.evolve_to(1).unwrap();
        assert_eq!(
            create(&key, &bindings, &recipient, &identity, &mut entropy)
                .err()
                .unwrap(),
            BackupError::InvalidPeriod
        );
    }
}
