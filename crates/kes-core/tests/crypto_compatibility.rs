#![cfg(feature = "qualification")]

//! Disposable differential tests. The native executable and its source/build plans
//! must be the T015 pinned oracle, not a Rust-generated reference. No test vector
//! contains a persistent seed or key; a no-swap, locked-memory lab is required.
use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    backup::{self, BackupBindings},
    certificate::{CertificateHistory, OperationalCertificate},
    generation::Generation,
    identity::{DeviceId, GenerationId, IncarnationId, PoolId},
    kes::Sum6Kes,
    platform::{Entropy, EntropyError},
    recipient::RecipientPolicy,
};
use std::{env, io::Read, ops::Deref, path::PathBuf, sync::Once};
#[path = "../../../qualification/src/oracle.rs"]
mod oracle_adapter;
use oracle_adapter::{Configuration, EnvelopeRequest, KesRequest, Oracle, VerifyRequest};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// mlockall covers copies made by the independent adapter as well as the KES
// workspace. Fail closed if the runner cannot supply the required protection.
unsafe extern "C" {
    fn mlockall(flags: i32) -> i32;
    fn prctl(option: i32, ...) -> i32;
}
fn protect() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        assert_eq!(
            prctl(4, 0, 0, 0, 0),
            0,
            "inconclusive: cannot disable dumps"
        );
        assert_eq!(
            mlockall(1 | 2),
            0,
            "inconclusive: cannot lock process memory"
        );
    });
}
fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    protect();
    let mut bytes = Zeroizing::new([0; N]);
    std::fs::File::open("/dev/urandom")
        .expect("inconclusive: no OS entropy")
        .read_exact(&mut *bytes)
        .expect("inconclusive: OS entropy failed");
    bytes
}
fn path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("inconclusive: missing {name}"))
}
fn oracle() -> Oracle {
    protect();
    let c = Configuration {
        node_source: path("KES_ORACLE_NODE_SOURCE"),
        consensus_source: path("KES_ORACLE_CONSENSUS_SOURCE"),
        cli_source: path("KES_ORACLE_CLI_SOURCE"),
        oracle_source: path("KES_ORACLE_SOURCE"),
        agent_archive: path("KES_ORACLE_AGENT_ARCHIVE"),
        crypto_archive: path("KES_ORACLE_CRYPTO_ARCHIVE"),
        oracle_plan: path("KES_ORACLE_PLAN"),
        oracle_executable: path("KES_ORACLE_EXECUTABLE"),
        cli_plan: path("KES_ORACLE_CLI_PLAN"),
        cli_executable: path("KES_ORACLE_CLI_EXECUTABLE"),
        ghc: path("KES_ORACLE_GHC"),
        cabal: path("KES_ORACLE_CABAL"),
    };
    Oracle::new(&c).expect("inconclusive: T015 oracle identity or build plan unavailable")
}
struct SecretString(String);
impl SecretString {
    fn push(&mut self, value: char) {
        self.0.push(value);
    }
    fn push_str(&mut self, value: &str) {
        self.0.push_str(value);
    }
    fn as_str(&self) -> &str {
        &self.0
    }
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SecretString {
    fn drop(&mut self) {
        unsafe {
            self.0.as_mut_vec().zeroize();
        }
    }
}
fn hex(bytes: &[u8]) -> SecretString {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = SecretString(String::with_capacity(bytes.len() * 2));
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
struct OneSeed(Zeroizing<[u8; 32]>, bool);
impl Entropy for OneSeed {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        if self.1 || out.len() != 32 {
            return Err(EntropyError);
        }
        out.copy_from_slice(&*self.0);
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
fn all_periods_match_native_state_signature_and_public_key() {
    let native = oracle();
    let seed = random::<32>();
    let mut entropy = OneSeed(Zeroizing::new(*seed), false);
    let mut key = Sum6Kes::generate(&mut entropy, 64).expect("generation");
    let public = key.verification_key();
    let message = b"disposable Sum6KES interoperability";
    let seed_hex = hex(&*seed);
    let message_hex = hex(message);
    let mut executions = 0;
    for period in 0..64u64 {
        assert_eq!(key.period(), period);
        let state = Zeroizing::new(key.canonical_state());
        let state_hex = hex(&*state);
        let sig = key.sign_for_qualification(message).expect("signature");
        let result = native
            .kes(&KesRequest {
                seed: &seed_hex,
                period,
                message: &message_hex,
                expected_state: &state_hex,
            })
            .expect("native KES execution");
        executions += 1;
        assert!(result.state_matches, "canonical state mismatch at {period}");
        assert_eq!(result.state_len, 608);
        assert_eq!(result.signature_len, 448);
        assert_eq!(result.vkey, hex(&public).as_str());
        assert!(result.verified);
        assert_eq!(result.signature_sha256, hex(&Sha256::digest(sig)).as_str());
        let sig_hex = hex(&sig);
        let public_hex = hex(&public);
        assert!(
            native
                .verify(&VerifyRequest {
                    message: &message_hex,
                    period,
                    signature: &sig_hex,
                    vkey: &public_hex
                })
                .expect("native verify")
        );
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(
            !native
                .verify(&VerifyRequest {
                    message: &message_hex,
                    period,
                    signature: &hex(&bad),
                    vkey: &public_hex
                })
                .expect("native reject")
        );
        if period < 63 {
            key.evolve_to(period + 1).expect("forward evolution");
        }
    }
    assert_eq!(executions, 64, "no incomplete oracle pass");
    let final_state = Zeroizing::new(key.canonical_state());
    assert!(key.evolve_to(64).is_err());
    assert_eq!(
        &*final_state,
        &key.canonical_state(),
        "invalid evolution must not mutate key"
    );
    assert!(
        native
            .kes(&KesRequest {
                seed: &seed_hex,
                period: 64,
                message: &message_hex,
                expected_state: &hex(&*final_state)
            })
            .is_err()
    );
}

#[test]
fn short_network_lifetime_expires_before_primitive_limit() {
    let native = oracle();
    let seed = random::<32>();
    let mut e = OneSeed(Zeroizing::new(*seed), false);
    let mut key = Sum6Kes::generate(&mut e, 32).unwrap();
    key.evolve_to(31).unwrap();
    let state = Zeroizing::new(key.canonical_state());
    let result = native
        .kes(&KesRequest {
            seed: &hex(&*seed),
            period: 31,
            message: "",
            expected_state: &hex(&*state),
        })
        .expect("native execution");
    assert!(result.state_matches && result.verified);
    assert!(key.evolve_to(32).is_err());
    assert_eq!(&*state, &key.canonical_state());
}

// Construct the ledger's signed representation and CBOR independently of the
// production parser. The oracle checks that these really are Cardano OpCerts.
fn cert(cold: &SigningKey, hot: &[u8; 32], counter: u8, start: u8) -> Vec<u8> {
    assert!(counter < 24 && start < 24);
    let mut signable = [0u8; 48];
    signable[..32].copy_from_slice(hot);
    signable[32..40].copy_from_slice(&(counter as u64).to_be_bytes());
    signable[40..].copy_from_slice(&(start as u64).to_be_bytes());
    let signature = cold.sign(&signable).to_bytes();
    let mut out = vec![0x82, 0x84, 0x58, 0x20];
    out.extend_from_slice(hot);
    out.extend_from_slice(&[counter, start, 0x58, 0x40]);
    out.extend_from_slice(&signature);
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&cold.verifying_key().to_bytes());
    out
}
#[test]
fn certificates_bind_cold_hot_signature_and_monotonic_counter() {
    let native = oracle();
    let cold = SigningKey::from_bytes(&*random::<32>());
    let other = SigningKey::from_bytes(&*random::<32>());
    let hot = *random::<32>();
    let cold_key = cold.verifying_key().to_bytes();
    let pool = PoolId::from_cold_verification_key(&cold_key);
    let encoded = cert(&cold, &hot, 4, 10);
    let observed = native
        .opcert(&hex(&encoded))
        .expect("native certificate decode");
    assert!(observed.verified);
    assert_eq!((observed.counter, observed.start_period), (4, 10));
    assert_eq!(observed.hot_vkey, hex(&hot).as_str());
    assert_eq!(observed.cold_vkey, hex(&cold_key).as_str());
    let mut history = CertificateHistory::new();
    let install = |history: &mut CertificateHistory,
                   bytes: &[u8],
                   pool,
                   cold_key: &[u8; 32],
                   hot: &[u8; 32]| {
        let parsed = OperationalCertificate::decode(bytes)?;
        history.install(&parsed, pool, cold_key, hot, 32)
    };
    install(&mut history, &encoded, pool, &cold_key, &hot).unwrap();
    install(&mut history, &encoded, pool, &cold_key, &hot).unwrap(); // exact retry
    assert!(
        install(
            &mut history,
            &encoded,
            PoolId::from_cold_verification_key(&other.verifying_key().to_bytes()),
            &cold_key,
            &hot
        )
        .is_err()
    );
    assert!(
        install(
            &mut history,
            &encoded,
            pool,
            &other.verifying_key().to_bytes(),
            &hot
        )
        .is_err()
    );
    assert!(install(&mut history, &encoded, pool, &cold_key, &*random::<32>()).is_err());
    let mut forged = encoded.clone();
    forged[40] ^= 1;
    assert!(install(&mut history, &forged, pool, &cold_key, &hot).is_err());
    assert!(
        install(
            &mut history,
            &cert(&cold, &hot, 3, 10),
            pool,
            &cold_key,
            &hot
        )
        .is_err()
    );
    assert!(
        install(
            &mut history,
            &cert(&cold, &hot, 4, 11),
            pool,
            &cold_key,
            &hot
        )
        .is_err()
    );
    install(
        &mut history,
        &cert(&cold, &hot, 5, 10),
        pool,
        &cold_key,
        &hot,
    )
    .unwrap();
    assert!(install(&mut history, &encoded, pool, &cold_key, &hot).is_err());
}

#[test]
fn entropy_failure_never_produces_a_generation() {
    assert!(Sum6Kes::generate(&mut BrokenEntropy, 64).is_err());
    let identity = SigningKey::from_bytes(&*random::<32>());
    let recipient = x25519_dalek::StaticSecret::from(*random::<32>());
    let policy =
        RecipientPolicy::new(x25519_dalek::PublicKey::from(&recipient).to_bytes(), 1).unwrap();
    let pool = PoolId::from_cold_verification_key(&identity.verifying_key().to_bytes());
    assert!(
        Generation::generate(
            DeviceId::from_bytes(*random::<16>()),
            pool,
            IncarnationId::from_bytes(*random::<16>()),
            1,
            64,
            &policy,
            &identity,
            &mut BrokenEntropy,
        )
        .is_err()
    );
}
#[test]
fn generation_retains_artifact_across_certification_and_evolution() {
    let native = oracle();
    let identity = SigningKey::from_bytes(&*random::<32>());
    let cold = SigningKey::from_bytes(&*random::<32>());
    let recipient = x25519_dalek::StaticSecret::from(*random::<32>());
    let policy =
        RecipientPolicy::new(x25519_dalek::PublicKey::from(&recipient).to_bytes(), 1).unwrap();
    let pool = PoolId::from_cold_verification_key(&cold.verifying_key().to_bytes());
    let mut generation = Generation::generate(
        DeviceId::from_bytes(*random::<16>()),
        pool,
        IncarnationId::from_bytes(*random::<16>()),
        1,
        64,
        &policy,
        &identity,
        &mut OsEntropy,
    )
    .unwrap();
    let key0_artifact = generation.artifact().unwrap().to_vec();
    assert!(key0_artifact.starts_with(b"KESBKP01"));
    let cert_bytes = cert(&cold, &generation.verification_key(), 1, 0);
    assert!(
        native
            .opcert(&hex(&cert_bytes))
            .expect("native certificate")
            .verified
    );
    generation
        .install_certificate(&cert_bytes, &cold.verifying_key().to_bytes())
        .unwrap();
    generation.evolve_to(32).unwrap();
    assert_eq!(generation.artifact().unwrap(), key0_artifact);
    generation.evolve_to(63).unwrap();
    assert_eq!(generation.artifact().unwrap(), key0_artifact);
}

#[test]
fn artifact_retains_original_key0_and_all_identity_bindings() {
    let native = oracle();
    let seed = random::<32>();
    let mut entropy = OneSeed(Zeroizing::new(*seed), false);
    let mut key = Sum6Kes::generate(&mut entropy, 64).unwrap();
    let original = Zeroizing::new(key.canonical_state());
    let identity = SigningKey::from_bytes(&*random::<32>());
    let recipient_secret = x25519_dalek::StaticSecret::from(*random::<32>());
    let recipient_public = x25519_dalek::PublicKey::from(&recipient_secret).to_bytes();
    let policy = RecipientPolicy::new(recipient_public, 1).unwrap();
    let bindings = BackupBindings {
        device: DeviceId::from_bytes(*random::<16>()),
        pool: PoolId::from_cold_verification_key(
            &SigningKey::from_bytes(&*random::<32>())
                .verifying_key()
                .to_bytes(),
        ),
        incarnation: IncarnationId::from_bytes(*random::<16>()),
        generation: GenerationId::from_bytes(*random::<16>()),
        generation_number: 1,
        verification_key: key.verification_key(),
    };
    let mut os = OsEntropy;
    let artifact = backup::create(&key, &bindings, &policy, &identity, &mut os).unwrap();
    let saved = artifact.as_bytes().to_vec();
    assert!(saved.starts_with(b"KESBKP01") && saved.len() <= 2048);
    key.evolve_to(32).unwrap();
    let recovered = Zeroizing::new(
        backup::recover(
            &saved,
            &bindings,
            &identity.verifying_key().to_bytes(),
            &recipient_secret,
        )
        .unwrap(),
    );
    assert!(
        &*recovered == &*original,
        "key0 differs from generation-time state"
    );
    let mut envelope = SecretString(String::from(
        "{\"type\":\"KesSigningKey_ed25519_kes_2^6\",\"description\":\"disposable\",\"cborHex\":\"590260",
    ));
    envelope.push_str(&hex(&*recovered));
    envelope.push_str("\"}");
    let decoded = native
        .envelope(&EnvelopeRequest {
            envelope: &hex(envelope.as_bytes()),
            expected_state: &hex(&*original),
        })
        .expect("native envelope decoder");
    assert!(decoded.state_matches);
    assert_eq!(decoded.state_len, 608);
    assert_eq!(decoded.vkey, hex(&bindings.verification_key).as_str());
    let wrong_secret = x25519_dalek::StaticSecret::from(*random::<32>());
    assert!(
        backup::recover(
            &saved,
            &bindings,
            &identity.verifying_key().to_bytes(),
            &wrong_secret
        )
        .is_err()
    );
    let mut changed = bindings.clone();
    changed.device = DeviceId::from_bytes(*random::<16>());
    assert!(
        backup::recover(
            &saved,
            &changed,
            &identity.verifying_key().to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    changed = bindings.clone();
    changed.pool = PoolId::from_cold_verification_key(
        &SigningKey::from_bytes(&*random::<32>())
            .verifying_key()
            .to_bytes(),
    );
    assert!(
        backup::recover(
            &saved,
            &changed,
            &identity.verifying_key().to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    changed = bindings.clone();
    changed.incarnation = IncarnationId::from_bytes(*random::<16>());
    assert!(
        backup::recover(
            &saved,
            &changed,
            &identity.verifying_key().to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    changed = bindings.clone();
    changed.generation = GenerationId::from_bytes(*random::<16>());
    assert!(
        backup::recover(
            &saved,
            &changed,
            &identity.verifying_key().to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    changed = bindings.clone();
    changed.generation_number += 1;
    assert!(
        backup::recover(
            &saved,
            &changed,
            &identity.verifying_key().to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    changed = bindings.clone();
    changed.verification_key[0] ^= 1;
    assert!(
        backup::recover(
            &saved,
            &changed,
            &identity.verifying_key().to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    assert!(
        backup::recover(
            &saved,
            &bindings,
            &SigningKey::from_bytes(&*random::<32>())
                .verifying_key()
                .to_bytes(),
            &recipient_secret
        )
        .is_err()
    );
    for i in 0..saved.len() {
        let mut tampered = saved.clone();
        tampered[i] ^= 1;
        assert!(
            backup::recover(
                &tampered,
                &bindings,
                &identity.verifying_key().to_bytes(),
                &recipient_secret
            )
            .is_err(),
            "tamper at {i}"
        );
    }
    let mut discarded = saved;
    discarded.zeroize();
}
struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(output))
            .map_err(|_| EntropyError)
    }
}
