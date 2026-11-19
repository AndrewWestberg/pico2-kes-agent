#![cfg(feature = "qualification")]

use ed25519_dalek::SigningKey;
use kes_core::{
    certificate::{CertificateHistory, OperationalCertificate},
    identity::PoolId,
    kes::{self, SIGNATURE_BYTES, STATE_BYTES, Sum6Kes},
    platform::{Entropy, EntropyError},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    schema_version: u32,
    warning: String,
    seed_hex: String,
    message_hex: String,
    vkey_hex: String,
    periods: Vec<Period>,
    cold_vkey_hex: String,
    certificates: Vec<CertificateVector>,
    envelope: Envelope,
}

#[derive(Deserialize)]
struct Period {
    period: u64,
    state_hex: String,
    signature_hex: String,
}

#[derive(Deserialize)]
struct CertificateVector {
    counter: u64,
    start_period: u64,
    cbor_hex: String,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

// shortcut: fixed public vectors cover one seed and message, extend the corpus for new compatibility cases.
fn vectors() -> Vectors {
    let vectors: Vectors =
        serde_json::from_slice(include_bytes!("fixtures/cardano-kes.json")).unwrap();
    assert_eq!(vectors.schema_version, 1);
    assert_eq!(
        vectors.warning,
        "PUBLIC SYNTHETIC TEST KEYS - NEVER USE FOR FUNDS"
    );
    assert_eq!(
        decode_hex::<32>(&vectors.seed_hex),
        core::array::from_fn(|i| i as u8)
    );
    assert_eq!(
        decode_bytes(&vectors.message_hex),
        b"disposable Sum6KES interoperability"
    );
    assert_eq!(vectors.periods.len(), 64);
    for (index, row) in vectors.periods.iter().enumerate() {
        assert_eq!(row.period, index as u64);
        decode_hex::<STATE_BYTES>(&row.state_hex);
        decode_hex::<SIGNATURE_BYTES>(&row.signature_hex);
    }
    assert_eq!(
        vectors
            .certificates
            .iter()
            .map(|c| (c.counter, c.start_period))
            .collect::<Vec<_>>(),
        [(3, 10), (4, 10), (4, 11), (5, 10)]
    );
    decode_hex::<32>(&vectors.vkey_hex);
    decode_hex::<32>(&vectors.cold_vkey_hex);
    assert!(!vectors.envelope.kind.is_empty());
    assert!(!decode_bytes(&vectors.envelope.cbor_hex).is_empty());
    vectors
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid hex"),
    }
}

fn decode_bytes(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    assert_eq!(pairs.len(), N);
    for (index, pair) in pairs.iter().enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

struct OneSeed([u8; 32], bool);
impl Entropy for OneSeed {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        if self.1 || out.len() != 32 {
            return Err(EntropyError);
        }
        out.copy_from_slice(&self.0);
        self.1 = true;
        Ok(())
    }
}
struct BrokenEntropy;
impl Entropy for BrokenEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        if !out.is_empty() {
            out[0] = 0xa5;
        }
        Err(EntropyError)
    }
}

#[test]
fn all_periods_match_haskell_vectors() {
    let vectors = vectors();
    let mut key =
        Sum6Kes::generate(&mut OneSeed(decode_hex(&vectors.seed_hex), false), 64).unwrap();
    let public = decode_hex(&vectors.vkey_hex);
    let message = decode_bytes(&vectors.message_hex);
    let mut changed_message = message.clone();
    changed_message[0] ^= 1;
    for row in &vectors.periods {
        let period = row.period as u8;
        let signature = decode_hex(&row.signature_hex);
        assert_eq!(key.period(), row.period);
        assert_eq!(
            key.canonical_state(),
            decode_hex::<STATE_BYTES>(&row.state_hex),
            "period {period}"
        );
        assert_eq!(key.verification_key(), public);
        assert_eq!(key.sign_for_qualification(&message).unwrap(), signature);
        assert!(kes::verify(&public, period, 64, &message, &signature).is_ok());
        let mut altered = signature;
        altered[0] ^= 1;
        assert!(kes::verify(&public, period, 64, &message, &altered).is_err());
        assert!(kes::verify(&public, period, 64, &changed_message, &signature).is_err());
        assert!(kes::verify(&public, (period + 1) % 64, 64, &message, &signature).is_err());
        if period < 63 {
            key.evolve_to(u64::from(period) + 1).unwrap();
        }
    }
    let final_state = key.canonical_state();
    assert!(key.evolve_to(64).is_err());
    assert_eq!(final_state, key.canonical_state());
}

#[test]
fn short_network_lifetime_expires_before_primitive_limit() {
    let vectors = vectors();
    let mut key =
        Sum6Kes::generate(&mut OneSeed(decode_hex(&vectors.seed_hex), false), 32).unwrap();
    key.evolve_to(31).unwrap();
    let state = key.canonical_state();
    assert_eq!(
        state,
        decode_hex::<STATE_BYTES>(&vectors.periods[31].state_hex)
    );
    assert_eq!(key.verification_key(), decode_hex(&vectors.vkey_hex));
    assert_eq!(
        key.sign_for_qualification(&decode_bytes(&vectors.message_hex))
            .unwrap(),
        decode_hex::<SIGNATURE_BYTES>(&vectors.periods[31].signature_hex)
    );
    assert!(key.evolve_to(32).is_err());
    assert_eq!(state, key.canonical_state());
}

#[test]
fn certificates_bind_cold_hot_signature_and_monotonic_counter() {
    let vectors = vectors();
    let cold = decode_hex(&vectors.cold_vkey_hex);
    let hot = decode_hex(&vectors.vkey_hex);
    let pool = PoolId::from_cold_verification_key(&cold);
    let other = SigningKey::from_bytes(&[64; 32]).verifying_key().to_bytes();
    let encoded: Vec<_> = vectors
        .certificates
        .iter()
        .map(|c| decode_bytes(&c.cbor_hex))
        .collect();
    for (row, bytes) in vectors.certificates.iter().zip(&encoded) {
        let parsed = OperationalCertificate::decode(bytes).unwrap();
        assert_eq!(parsed.encoded(), bytes);
        assert_eq!(parsed.cold_verification_key(), &cold);
        assert_eq!(parsed.certificate().hot_verification_key(), &hot);
        assert_eq!(parsed.certificate().counter(), row.counter);
        assert_eq!(parsed.certificate().start_period(), row.start_period);
        parsed.certificate().verify(&cold).unwrap();
    }
    let install =
        |history: &mut CertificateHistory, bytes: &[u8], pool, cold: &[u8; 32], hot: &[u8; 32]| {
            let parsed = OperationalCertificate::decode(bytes)?;
            history.install(&parsed, pool, cold, hot, 32)
        };
    let mut history = CertificateHistory::new();
        let parsed = OperationalCertificate::decode(bytes)?;
    };
    assert!(install(&mut history, &encoded[1], pool, &cold, &hot).unwrap());
    assert!(!install(&mut history, &encoded[1], pool, &cold, &hot).unwrap());
    assert!(
        install(
            &mut history,
            &encoded[1],
            PoolId::from_cold_verification_key(&other),
            &cold,
            &hot
        )
        .is_err()
    );
    assert!(install(&mut history, &encoded[1], pool, &other, &hot).is_err());
    assert!(install(&mut history, &encoded[1], pool, &cold, &[64; 32]).is_err());
    let mut forged = encoded[1].clone();
    forged[40] ^= 1;
    assert!(install(&mut history, &forged, pool, &cold, &hot).is_err());
    assert!(install(&mut history, &encoded[0], pool, &cold, &hot).is_err());
    assert!(install(&mut history, &encoded[2], pool, &cold, &hot).is_err());
    assert!(install(&mut history, &encoded[3], pool, &cold, &hot).unwrap());
    assert!(install(&mut history, &encoded[1], pool, &cold, &hot).is_err());
}

#[test]
fn entropy_failure_never_produces_a_generation() {
    assert!(Sum6Kes::generate(&mut BrokenEntropy, 64).is_err());
}
