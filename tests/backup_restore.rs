use ed25519_dalek::SigningKey;
use kes_core::{
    backup::{self, BackupBindings},
    identity::{DeviceId, GenerationId, IncarnationId, PoolId},
    kes::Sum6Kes,
    platform::{Entropy as CoreEntropy, EntropyError},
    recipient::RecipientPolicy,
};
use pico2_kes_agent::backup::{
    recipient::{self, Entropy as RecipientEntropy},
    recover::{self, Error, Expectations},
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

struct TestEntropy(u8);

impl TestEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

impl CoreEntropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.fill_bytes(output);
        Ok(())
    }
}

impl RecipientEntropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), recipient::Error> {
        self.fill_bytes(output);
        Ok(())
    }
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pico2-backup-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (
    Vec<u8>,
    recipient::RecipientKeyFile,
    Expectations,
    [u8; kes_core::kes::STATE_BYTES],
) {
    let mut entropy = TestEntropy(1);
    let (recipient_public, recipient) =
        recipient::create(b"test passphrase", &mut entropy).unwrap();
    let policy = RecipientPolicy::new(recipient_public.public_key, 1).unwrap();
    let key = Sum6Kes::generate(&mut entropy, 64).unwrap();
    let state = key.canonical_state();
    let identity = SigningKey::from_bytes(&[91; 32]);
    let expected = Expectations {
        device: [1; 16],
        pool: [2; 28],
        incarnation: [3; 16],
        generation: [4; 16],
        verification_key: key.verification_key(),
        identity_public_key: identity.verifying_key().to_bytes(),
    };
    let artifact = backup::create(
        &key,
        &BackupBindings {
            device: DeviceId::from_bytes(expected.device),
            pool: PoolId::from_bytes(expected.pool),
            incarnation: IncarnationId::from_bytes(expected.incarnation),
            generation: GenerationId::from_bytes(expected.generation),
            generation_number: 1,
            verification_key: expected.verification_key,
        },
        &policy,
        &identity,
        &mut entropy,
    )
    .unwrap();
    (artifact.as_bytes().to_vec(), recipient, expected, state)
}

#[test]
fn public_recipient_inspection_authenticates_origin_and_bindings_without_decryption() {
    let (artifact, recipient, expected, _) = fixture();
    assert_eq!(
        recover::artifact_recipient(&artifact, expected).unwrap(),
        recipient.public().unwrap().public_key,
    );
    let mut wrong_identity = expected;
    wrong_identity.identity_public_key =
        SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes();
    assert_eq!(
        recover::artifact_recipient(&artifact, wrong_identity),
        Err(Error::InvalidSignature)
    );
    let mut wrong_generation = expected;
    wrong_generation.generation[0] ^= 1;
    assert_eq!(
        recover::artifact_recipient(&artifact, wrong_generation),
        Err(Error::WrongBinding)
    );
    let mut altered = artifact;
    let index = altered.len() - 80;
    altered[index] ^= 1;
    assert!(recover::artifact_recipient(&altered, expected).is_err());
}

#[test]
fn restores_exact_period_zero_state_to_owner_only_no_clobber_file() {
    let (artifact, recipient, expected, state) = fixture();
    let directory = TestDir::new();
    let output = directory.0.join("kes.skey");
    recover::restore_to_file(&artifact, &recipient, b"test passphrase", expected, &output).unwrap();
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    let encoded = envelope["cborHex"].as_str().unwrap();
    assert_eq!(&encoded[..6], "590260");
    assert_eq!(decode_hex(&encoded[6..]), state);
    assert_eq!(
        recover::restore_to_file(&artifact, &recipient, b"test passphrase", expected, &output,),
        Err(Error::Publication)
    );
}

#[test]
fn wrong_binding_recipient_password_and_tampering_publish_nothing() {
    let (artifact, recipient, expected, _) = fixture();
    let mut wrong_binding = expected;
    wrong_binding.pool[0] ^= 1;
    assert_eq!(
        recover::recover(&artifact, &recipient, b"test passphrase", wrong_binding).err(),
        Some(Error::WrongBinding)
    );
    assert_eq!(
        recover::recover(&artifact, &recipient, b"wrong", expected).err(),
        Some(Error::WrongPassword)
    );
    let mut tampered = artifact.clone();
    let index = tampered.len() - 80;
    tampered[index] ^= 1;
    let directory = TestDir::new();
    let output = directory.0.join("rejected.skey");
    assert!(
        recover::restore_to_file(&tampered, &recipient, b"test passphrase", expected, &output,)
            .is_err()
    );
    assert!(!output.exists());

    let mut entropy = TestEntropy(77);
    let (_, wrong_recipient) = recipient::create(b"test passphrase", &mut entropy).unwrap();
    assert_eq!(
        recover::recover(&artifact, &wrong_recipient, b"test passphrase", expected,).err(),
        Some(Error::WrongRecipient)
    );
}

#[test]
fn generated_recipient_public_file_round_trips_and_authenticates_its_identifier() {
    let mut entropy = TestEntropy(29);
    let (public, _) = recipient::create(b"test passphrase", &mut entropy).unwrap();
    let encoded = public.json().unwrap();
    assert!(recipient::parse_public_json(&encoded).is_ok());

    let mut tampered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    tampered["recipientId"] = serde_json::Value::String("00".repeat(32));
    assert!(recipient::parse_public_json(&serde_json::to_vec(&tampered).unwrap()).is_err());
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid hex"),
    }
}
