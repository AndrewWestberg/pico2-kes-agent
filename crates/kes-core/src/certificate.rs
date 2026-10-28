use crate::generation::Generation;
use crate::identity::{Digest32, PoolId};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const DIRECT_CERTIFICATE_LEN: usize = 112;
pub const MAX_ENCODED_CERTIFICATE_LEN: usize = 154;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    Encoding,
    TrailingData,
    ColdIdentity,
    HotIdentity,
    Signature,
    Lifetime,
    CounterRegressive,
    CounterConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Certificate {
    hot_verification_key: [u8; 32],
    counter: u64,
    start_period: u64,
    signature: [u8; 64],
}

impl Certificate {
    pub const fn new(
        hot_verification_key: [u8; 32],
        counter: u64,
        start_period: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            hot_verification_key,
            counter,
            start_period,
            signature,
        }
    }

    pub fn signing_bytes(
        hot_verification_key: &[u8; 32],
        counter: u64,
        start_period: u64,
    ) -> [u8; 48] {
        let mut bytes = [0; 48];
        bytes[..32].copy_from_slice(hot_verification_key);
        bytes[32..40].copy_from_slice(&counter.to_be_bytes());
        bytes[40..].copy_from_slice(&start_period.to_be_bytes());
        bytes
    }

    pub const fn hot_verification_key(&self) -> &[u8; 32] {
        &self.hot_verification_key
    }

    pub const fn counter(&self) -> u64 {
        self.counter
    }

    pub const fn start_period(&self) -> u64 {
        self.start_period
    }

    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn direct_bytes(&self) -> [u8; DIRECT_CERTIFICATE_LEN] {
        let mut bytes = [0; DIRECT_CERTIFICATE_LEN];
        bytes[..32].copy_from_slice(&self.hot_verification_key);
        bytes[32..40].copy_from_slice(&self.counter.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.start_period.to_be_bytes());
        bytes[48..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn digest(&self) -> Digest32 {
        Digest32::from_bytes(Sha256::digest(self.direct_bytes()).into())
    }

    pub fn verify(&self, cold_verification_key: &[u8; 32]) -> Result<(), CertificateError> {
        let cold = VerifyingKey::from_bytes(cold_verification_key)
            .map_err(|_| CertificateError::ColdIdentity)?;
        cold.verify_strict(
            &Self::signing_bytes(&self.hot_verification_key, self.counter, self.start_period),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| CertificateError::Signature)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedCertificate {
    bytes: [u8; MAX_ENCODED_CERTIFICATE_LEN],
    len: u8,
}

impl EncodedCertificate {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalCertificate {
    certificate: Certificate,
    cold_verification_key: [u8; 32],
    encoded: EncodedCertificate,
}

impl OperationalCertificate {
    pub fn from_parts(certificate: Certificate, cold_verification_key: [u8; 32]) -> Self {
        let mut bytes = [0; MAX_ENCODED_CERTIFICATE_LEN];
        let len = encode(&certificate, &cold_verification_key, &mut bytes);
        Self {
            certificate,
            cold_verification_key,
            encoded: EncodedCertificate {
                bytes,
                len: len as u8,
            },
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() > MAX_ENCODED_CERTIFICATE_LEN {
            return Err(CertificateError::Encoding);
        }
        let mut cursor = Cursor { bytes, position: 0 };
        cursor.array(2)?;
        cursor.array(4)?;
        let hot_verification_key = cursor.fixed_bytes::<32>()?;
        let counter = cursor.uint()?;
        let start_period = cursor.uint()?;
        let signature = cursor.fixed_bytes::<64>()?;
        let cold_verification_key = cursor.fixed_bytes::<32>()?;
        if cursor.position != bytes.len() {
            return Err(CertificateError::TrailingData);
        }
        let certificate = Certificate::new(hot_verification_key, counter, start_period, signature);
        let parsed = Self::from_parts(certificate, cold_verification_key);
        if parsed.encoded.as_slice() != bytes {
            return Err(CertificateError::Encoding);
        }
        Ok(parsed)
    }

    pub const fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    pub const fn cold_verification_key(&self) -> &[u8; 32] {
        &self.cold_verification_key
    }

    pub fn encoded(&self) -> &[u8] {
        self.encoded.as_slice()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateHistory {
    highest_counter: Option<u64>,
    accepted_digest: Option<Digest32>,
}

impl Default for CertificateHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateHistory {
    pub const fn new() -> Self {
        Self {
            highest_counter: None,
            accepted_digest: None,
        }
    }

    pub const fn highest_counter(&self) -> Option<u64> {
        self.highest_counter
    }

    pub fn install(
        &mut self,
        operational: &OperationalCertificate,
        pool: PoolId,
        expected_cold_key: &[u8; 32],
        expected_hot_key: &[u8; 32],
        lifetime: u8,
    ) -> Result<bool, CertificateError> {
        if !(1..=64).contains(&lifetime)
            || operational
                .certificate
                .start_period
                .checked_add(u64::from(lifetime) - 1)
                .is_none()
        {
            return Err(CertificateError::Lifetime);
        }
        if operational.cold_verification_key != *expected_cold_key
            || PoolId::from_cold_verification_key(expected_cold_key) != pool
        {
            return Err(CertificateError::ColdIdentity);
        }
        if operational.certificate.hot_verification_key != *expected_hot_key {
            return Err(CertificateError::HotIdentity);
        }
        operational.certificate.verify(expected_cold_key)?;
        let digest = Digest32::from_bytes(Sha256::digest(operational.encoded()).into());
        match self.highest_counter {
            Some(current) if operational.certificate.counter < current => {
                Err(CertificateError::CounterRegressive)
            }
            Some(current) if operational.certificate.counter == current => {
                if self.accepted_digest == Some(digest) {
                    Ok(false)
                } else {
                    Err(CertificateError::CounterConflict)
                }
            }
            _ => {
                self.highest_counter = Some(operational.certificate.counter);
                self.accepted_digest = Some(digest);
                Ok(true)
            }
        }
    }

    pub fn install_for_generation(
        &mut self,
        operational: &OperationalCertificate,
        pool: PoolId,
        expected_cold_key: &[u8; 32],
        generation: &mut Generation,
        lifetime: u8,
    ) -> Result<bool, CertificateError> {
        let changed = self.install(
            operational,
            pool,
            expected_cold_key,
            generation.verification_key(),
            lifetime,
        )?;
        generation
            .install_certificate(operational.certificate)
            .map_err(|_| CertificateError::HotIdentity)?;
        Ok(changed)
    }
}

fn put_uint(value: u64, output: &mut [u8], position: &mut usize) {
    match value {
        0..=23 => {
            output[*position] = value as u8;
            *position += 1;
        }
        24..=0xff => {
            output[*position..*position + 2].copy_from_slice(&[24, value as u8]);
            *position += 2;
        }
        0x100..=0xffff => {
            output[*position] = 25;
            output[*position + 1..*position + 3].copy_from_slice(&(value as u16).to_be_bytes());
            *position += 3;
        }
        0x1_0000..=0xffff_ffff => {
            output[*position] = 26;
            output[*position + 1..*position + 5].copy_from_slice(&(value as u32).to_be_bytes());
            *position += 5;
        }
        _ => {
            output[*position] = 27;
            output[*position + 1..*position + 9].copy_from_slice(&value.to_be_bytes());
            *position += 9;
        }
    }
}

fn put_bytes<const N: usize>(value: &[u8; N], output: &mut [u8], position: &mut usize) {
    output[*position..*position + 2].copy_from_slice(&[0x58, N as u8]);
    *position += 2;
    output[*position..*position + N].copy_from_slice(value);
    *position += N;
}

fn encode(certificate: &Certificate, cold: &[u8; 32], output: &mut [u8]) -> usize {
    let mut position = 0;
    output[position] = 0x82;
    position += 1;
    output[position] = 0x84;
    position += 1;
    put_bytes(&certificate.hot_verification_key, output, &mut position);
    put_uint(certificate.counter, output, &mut position);
    put_uint(certificate.start_period, output, &mut position);
    put_bytes(&certificate.signature, output, &mut position);
    put_bytes(cold, output, &mut position);
    position
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, CertificateError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(CertificateError::Encoding)?;
        self.position += 1;
        Ok(byte)
    }

    fn array(&mut self, len: u8) -> Result<(), CertificateError> {
        if self.byte()? == 0x80 | len {
            Ok(())
        } else {
            Err(CertificateError::Encoding)
        }
    }

    fn uint(&mut self) -> Result<u64, CertificateError> {
        match self.byte()? {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = self.byte()?;
                (value >= 24)
                    .then_some(u64::from(value))
                    .ok_or(CertificateError::Encoding)
            }
            25 => {
                let value = u16::from_be_bytes(self.take::<2>()?);
                (value > 0xff)
                    .then_some(u64::from(value))
                    .ok_or(CertificateError::Encoding)
            }
            26 => {
                let value = u32::from_be_bytes(self.take::<4>()?);
                (value > 0xffff)
                    .then_some(u64::from(value))
                    .ok_or(CertificateError::Encoding)
            }
            27 => {
                let value = u64::from_be_bytes(self.take::<8>()?);
                (value > 0xffff_ffff)
                    .then_some(value)
                    .ok_or(CertificateError::Encoding)
            }
            _ => Err(CertificateError::Encoding),
        }
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], CertificateError> {
        if self.byte()? != 0x58 || self.byte()? != N as u8 {
            return Err(CertificateError::Encoding);
        }
        self.take::<N>()
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], CertificateError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(CertificateError::Encoding)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(CertificateError::Encoding)?;
        self.position = end;
        bytes.try_into().map_err(|_| CertificateError::Encoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn certificate(counter: u64, start: u64) -> (SigningKey, OperationalCertificate) {
        let cold = SigningKey::from_bytes(&[7; 32]);
        let hot = [8; 32];
        let signature = cold
            .sign(&Certificate::signing_bytes(&hot, counter, start))
            .to_bytes();
        let certificate = Certificate::new(hot, counter, start, signature);
        let operational =
            OperationalCertificate::from_parts(certificate, cold.verifying_key().to_bytes());
        (cold, operational)
    }

    #[test]
    fn canonical_roundtrip_and_signature_verification() {
        for value in [
            0,
            23,
            24,
            0xff,
            0x100,
            0xffff,
            0x1_0000,
            u32::MAX as u64 + 1,
        ] {
            let (cold, certificate) = certificate(value, value);
            let decoded = OperationalCertificate::decode(certificate.encoded()).unwrap();
            assert_eq!(decoded, certificate);
            decoded
                .certificate()
                .verify(&cold.verifying_key().to_bytes())
                .unwrap();
        }
    }

    #[test]
    fn rejects_noncanonical_trailing_and_tampered_certificates() {
        let (_, certificate) = certificate(1, 0);
        let mut changed = [0; MAX_ENCODED_CERTIFICATE_LEN + 1];
        let len = certificate.encoded().len();
        changed[..len].copy_from_slice(certificate.encoded());
        changed[len] = 0;
        assert_eq!(
            OperationalCertificate::decode(&changed[..=len]),
            Err(CertificateError::TrailingData)
        );
        let mut changed = certificate.encoded().to_vec();
        changed[10] ^= 1;
        let decoded = OperationalCertificate::decode(&changed).unwrap();
        assert_eq!(
            decoded
                .certificate()
                .verify(decoded.cold_verification_key()),
            Err(CertificateError::Signature)
        );
    }

    #[test]
    fn history_is_idempotent_monotonic_and_identity_bound() {
        let (cold, accepted) = certificate(4, 10);
        let cold_key = cold.verifying_key().to_bytes();
        let pool = PoolId::from_cold_verification_key(&cold_key);
        let mut history = CertificateHistory::new();
        assert_eq!(
            history.install(&accepted, pool, &cold_key, &[8; 32], 64),
            Ok(true)
        );
        assert_eq!(
            history.install(&accepted, pool, &cold_key, &[8; 32], 64),
            Ok(false)
        );
        let (_, lower) = certificate(3, 10);
        assert_eq!(
            history.install(&lower, pool, &cold_key, &[8; 32], 64),
            Err(CertificateError::CounterRegressive)
        );
        assert_eq!(
            history.install(
                &accepted,
                PoolId::from_bytes([1; 28]),
                &cold_key,
                &[8; 32],
                64
            ),
            Err(CertificateError::ColdIdentity)
        );
    }
}
