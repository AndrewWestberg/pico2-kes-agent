use crate::identity::{DeviceId, Digest32, OperationId};
use crate::operation::{CommissioningRecord, PoolTarget, UsbSerial};
use crate::pool::{Enrollment, PoolDirectory, PoolError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const INITIAL_CONFIGURATION_MAX_BYTES: usize = 4_336;
const INITIAL_CONFIGURATION_MAGIC: &[u8; 8] = b"PKACFG01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareIdentity {
    silicon: Digest32,
    flash: Digest32,
}

impl HardwareIdentity {
    pub const fn new(silicon: Digest32, flash: Digest32) -> Self {
        Self { silicon, flash }
    }

    pub const fn silicon(self) -> Digest32 {
        self.silicon
    }

    pub const fn flash(self) -> Digest32 {
        self.flash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBlank {
    hardware: HardwareIdentity,
}

impl VerifiedBlank {
    pub fn verify(
        hardware: HardwareIdentity,
        whole_state_region_erased: bool,
        layout_supported: bool,
    ) -> Result<Self, DeviceError> {
        if !whole_state_region_erased || !layout_supported {
            return Err(DeviceError::NotBlank);
        }
        Ok(Self { hardware })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommissioningInput {
    pub sequence: u64,
    pub expected_revision: u64,
    pub serial: UsbSerial,
    pub operation_id: OperationId,
    pub request_digest: Digest32,
    pub protocol_version: u16,
    pub storage_version: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentRecord {
    public: CommissioningRecord,
    signature: [u8; 64],
}

impl EnrollmentRecord {
    fn message(record: &CommissioningRecord) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(b"pico2-kes-agent/enrollment-record/v1\0");
        hash.update(record.version().to_be_bytes());
        hash.update(record.device().as_bytes());
        hash.update(record.identity_public_key());
        hash.update(record.identity_fingerprint().as_bytes());
        hash.update((record.serial().as_slice().len() as u32).to_be_bytes());
        hash.update(record.serial().as_slice());
        hash.update(record.protocol_version().to_be_bytes());
        hash.update(record.storage_version().to_be_bytes());
        hash.update(record.device_revision().to_be_bytes());
        hash.update(record.operation_id().as_bytes());
        hash.update(record.request_digest().as_bytes());
        Digest32::from_bytes(hash.finalize().into())
    }

    fn new(public: CommissioningRecord, signing_key: &SigningKey) -> Self {
        let signature = signing_key
            .sign(Self::message(&public).as_bytes())
            .to_bytes();
        Self { public, signature }
    }

    pub const fn public(&self) -> &CommissioningRecord {
        &self.public
    }

    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn verify(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(self.public.identity_public_key()) else {
            return false;
        };
        key.verify_strict(
            Self::message(&self.public).as_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }

    pub fn verify_identity_message(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        VerifyingKey::from_bytes(public_key)
            .and_then(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedRecipient {
    public_key: [u8; 32],
    fingerprint: Digest32,
    revision: u64,
}

impl SharedRecipient {
    pub fn new(public_key: [u8; 32], revision: u64) -> Result<Self, DeviceError> {
        if revision == 0 {
            return Err(DeviceError::InvalidRecipient);
        }
        Ok(Self {
            public_key,
            fingerprint: Digest32::from_bytes(Sha256::digest(public_key).into()),
            revision,
        })
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn fingerprint(&self) -> Digest32 {
        self.fingerprint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceError {
    NotBlank,
    InvalidCommissioningSequence,
    InvalidCommissioningRevision,
    InvalidFormatVersion,
    InvalidRecipient,
    RecipientRegressive,
    RevisionOverflow,
    Pool(PoolError),
    InvalidConfiguration,
}

impl From<PoolError> for DeviceError {
    fn from(value: PoolError) -> Self {
        Self::Pool(value)
    }
}

pub struct Device {
    id: DeviceId,
    identity_seed: [u8; 32],
    storage_key: [u8; 32],
    hardware: HardwareIdentity,
    format_version: u16,
    revision: u64,
    next_management_sequence: u64,
    recipient: Option<SharedRecipient>,
    enrollment_record: EnrollmentRecord,
    pools: PoolDirectory,
}

impl Device {
    pub fn commission(
        blank: VerifiedBlank,
        id: DeviceId,
        identity_seed: [u8; 32],
        storage_key: [u8; 32],
        input: CommissioningInput,
    ) -> Result<Self, DeviceError> {
        if input.sequence != 0 {
            return Err(DeviceError::InvalidCommissioningSequence);
        }
        if input.expected_revision != 0 {
            return Err(DeviceError::InvalidCommissioningRevision);
        }
        if input.protocol_version == 0 || input.storage_version == 0 {
            return Err(DeviceError::InvalidFormatVersion);
        }
        let revision = 1;
        let signing_key = SigningKey::from_bytes(&identity_seed);
        let public = CommissioningRecord::new(
            id,
            signing_key.verifying_key().to_bytes(),
            input.serial,
            input.protocol_version,
            input.storage_version,
            revision,
            input.operation_id,
            input.request_digest,
        );
        let enrollment_record = EnrollmentRecord::new(public, &signing_key);
        Ok(Self {
            id,
            identity_seed,
            storage_key,
            hardware: blank.hardware,
            format_version: input.storage_version,
            revision,
            next_management_sequence: 1,
            recipient: None,
            enrollment_record,
            pools: PoolDirectory::new(),
        })
    }

    pub const fn id(&self) -> DeviceId {
        self.id
    }

    pub const fn identity_public_key(&self) -> &[u8; 32] {
        self.enrollment_record.public().identity_public_key()
    }

    pub const fn hardware(&self) -> HardwareIdentity {
        self.hardware
    }

    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn next_management_sequence(&self) -> u64 {
        self.next_management_sequence
    }

    pub const fn recipient(&self) -> Option<SharedRecipient> {
        self.recipient
    }

    pub const fn enrollment_record(&self) -> &EnrollmentRecord {
        &self.enrollment_record
    }

    pub(crate) fn identity_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.identity_seed)
    }

    pub fn sign_identity_message(&self, message: &[u8]) -> [u8; 64] {
        self.identity_signing_key().sign(message).to_bytes()
    }

    pub const fn pools(&self) -> &PoolDirectory {
        &self.pools
    }

    pub fn enroll(&mut self, enrollment: Enrollment) -> Result<PoolTarget, DeviceError> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DeviceError::RevisionOverflow)?;
        let target = self.pools.enroll(enrollment)?;
        self.revision = revision;
        Ok(target)
    }

    pub fn delete_pool(&mut self, target: PoolTarget) -> Result<(), DeviceError> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DeviceError::RevisionOverflow)?;
        self.pools.delete(target)?;
        self.revision = revision;
        Ok(())
    }

    pub fn set_recipient(&mut self, recipient: SharedRecipient) -> Result<(), DeviceError> {
        if self
            .recipient
            .is_some_and(|current| recipient.revision <= current.revision)
        {
            return Err(DeviceError::RecipientRegressive);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DeviceError::RevisionOverflow)?;
        self.recipient = Some(recipient);
        self.revision = revision;
        Ok(())
    }

    /// Serializes only the freshly commissioned state. Later revisions use the
    /// full configuration codec owned by the lifecycle service.
    pub fn encode_initial_configuration(&self, output: &mut [u8]) -> Result<usize, DeviceError> {
        let public = self.enrollment_record.public();
        let serial = public.serial().as_slice();
        let required = 226usize
            .checked_add(serial.len())
            .ok_or(DeviceError::InvalidConfiguration)?;
        let signing_key = SigningKey::from_bytes(&self.identity_seed);
        if output.len() < required
            || self.revision != 1
            || self.next_management_sequence != 1
            || self.recipient.is_some()
            || !self.pools.is_empty()
            || public.device() != self.id
            || public.identity_public_key() != &signing_key.verifying_key().to_bytes()
            || public.device_revision() != 1
            || public.storage_version() != self.format_version
            || !self.enrollment_record.verify()
        {
            return Err(DeviceError::InvalidConfiguration);
        }
        let mut cursor = 0;
        put(output, &mut cursor, INITIAL_CONFIGURATION_MAGIC)?;
        put(output, &mut cursor, &1u16.to_be_bytes())?;
        put(output, &mut cursor, self.id.as_bytes())?;
        put(output, &mut cursor, &self.identity_seed)?;
        put(output, &mut cursor, &self.storage_key)?;
        put(output, &mut cursor, &self.format_version.to_be_bytes())?;
        put(output, &mut cursor, &self.revision.to_be_bytes())?;
        put(
            output,
            &mut cursor,
            &self.next_management_sequence.to_be_bytes(),
        )?;
        put(
            output,
            &mut cursor,
            &public.protocol_version().to_be_bytes(),
        )?;
        put(output, &mut cursor, &public.storage_version().to_be_bytes())?;
        put(output, &mut cursor, &(serial.len() as u16).to_be_bytes())?;
        put(output, &mut cursor, serial)?;
        put(output, &mut cursor, public.operation_id().as_bytes())?;
        put(output, &mut cursor, public.request_digest().as_bytes())?;
        put(output, &mut cursor, self.enrollment_record.signature())?;
        debug_assert_eq!(cursor, required);
        Ok(cursor)
    }

    pub fn restore_initial_configuration(
        encoded: &[u8],
        hardware: HardwareIdentity,
    ) -> Result<Self, DeviceError> {
        if encoded.len() < 226 {
            return Err(DeviceError::InvalidConfiguration);
        }
        let mut cursor = 0;
        if take::<8>(encoded, &mut cursor)? != *INITIAL_CONFIGURATION_MAGIC
            || u16::from_be_bytes(take(encoded, &mut cursor)?) != 1
        {
            return Err(DeviceError::InvalidConfiguration);
        }
        let id = DeviceId::from_bytes(take(encoded, &mut cursor)?);
        let identity_seed = take(encoded, &mut cursor)?;
        let storage_key = take(encoded, &mut cursor)?;
        let format_version = u16::from_be_bytes(take(encoded, &mut cursor)?);
        let revision = u64::from_be_bytes(take(encoded, &mut cursor)?);
        let next_management_sequence = u64::from_be_bytes(take(encoded, &mut cursor)?);
        let protocol_version = u16::from_be_bytes(take(encoded, &mut cursor)?);
        let storage_version = u16::from_be_bytes(take(encoded, &mut cursor)?);
        let serial_len = usize::from(u16::from_be_bytes(take(encoded, &mut cursor)?));
        let serial_end = cursor
            .checked_add(serial_len)
            .ok_or(DeviceError::InvalidConfiguration)?;
        let serial = UsbSerial::new(
            encoded
                .get(cursor..serial_end)
                .ok_or(DeviceError::InvalidConfiguration)?,
        )
        .map_err(|_| DeviceError::InvalidConfiguration)?;
        cursor = serial_end;
        let operation_id = OperationId::from_bytes(take(encoded, &mut cursor)?);
        let request_digest = Digest32::from_bytes(take(encoded, &mut cursor)?);
        let signature = take(encoded, &mut cursor)?;
        if cursor != encoded.len()
            || format_version == 0
            || protocol_version == 0
            || storage_version != format_version
            || revision != 1
            || next_management_sequence != 1
        {
            return Err(DeviceError::InvalidConfiguration);
        }
        let signing_key = SigningKey::from_bytes(&identity_seed);
        let public = CommissioningRecord::new(
            id,
            signing_key.verifying_key().to_bytes(),
            serial,
            protocol_version,
            storage_version,
            revision,
            operation_id,
            request_digest,
        );
        let enrollment_record = EnrollmentRecord { public, signature };
        if !enrollment_record.verify() {
            return Err(DeviceError::InvalidConfiguration);
        }
        Ok(Self {
            id,
            identity_seed,
            storage_key,
            hardware,
            format_version,
            revision,
            next_management_sequence,
            recipient: None,
            enrollment_record,
            pools: PoolDirectory::new(),
        })
    }
}

fn put(output: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<(), DeviceError> {
    let end = cursor
        .checked_add(bytes.len())
        .ok_or(DeviceError::InvalidConfiguration)?;
    output
        .get_mut(*cursor..end)
        .ok_or(DeviceError::InvalidConfiguration)?
        .copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}

fn take<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], DeviceError> {
    let end = cursor
        .checked_add(N)
        .ok_or(DeviceError::InvalidConfiguration)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(DeviceError::InvalidConfiguration)?
        .try_into()
        .map_err(|_| DeviceError::InvalidConfiguration)?;
    *cursor = end;
    Ok(bytes)
}

impl Drop for Device {
    fn drop(&mut self) {
        self.identity_seed.zeroize();
        self.storage_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IncarnationId, NetworkBinding};

    fn hardware() -> HardwareIdentity {
        HardwareIdentity::new(Digest32::from_bytes([1; 32]), Digest32::from_bytes([2; 32]))
    }

    fn input() -> CommissioningInput {
        CommissioningInput {
            sequence: 0,
            expected_revision: 0,
            serial: UsbSerial::new(b"board-1").unwrap(),
            operation_id: OperationId::from_bytes([3; 16]),
            request_digest: Digest32::from_bytes([4; 32]),
            protocol_version: 1,
            storage_version: 1,
        }
    }

    fn commissioned() -> Device {
        let blank = VerifiedBlank::verify(hardware(), true, true).unwrap();
        Device::commission(
            blank,
            DeviceId::from_bytes([5; 16]),
            [6; 32],
            [7; 32],
            input(),
        )
        .unwrap()
    }

    #[test]
    fn commissioning_requires_verified_blank_and_sequence_zero() {
        assert_eq!(
            VerifiedBlank::verify(hardware(), false, true),
            Err(DeviceError::NotBlank)
        );
        let blank = VerifiedBlank::verify(hardware(), true, true).unwrap();
        let mut wrong = input();
        wrong.sequence = 1;
        assert!(matches!(
            Device::commission(
                blank,
                DeviceId::from_bytes([5; 16]),
                [6; 32],
                [7; 32],
                wrong
            ),
            Err(DeviceError::InvalidCommissioningSequence)
        ));
    }

    #[test]
    fn commissioned_record_is_bound_and_self_signed() {
        let device = commissioned();
        let record = device.enrollment_record();
        assert!(record.verify());
        assert_eq!(record.public().device(), device.id());
        assert_eq!(record.public().device_revision(), 1);
        assert_eq!(device.next_management_sequence(), 1);
        assert!(device.recipient().is_none());
    }

    #[test]
    fn initial_configuration_round_trips_and_rejects_tampering() {
        let device = commissioned();
        let mut encoded = [0; INITIAL_CONFIGURATION_MAX_BYTES];
        let len = device.encode_initial_configuration(&mut encoded).unwrap();
        let restored = Device::restore_initial_configuration(&encoded[..len], hardware()).unwrap();
        assert_eq!(restored.id(), device.id());
        assert_eq!(restored.enrollment_record(), device.enrollment_record());
        encoded[len - 1] ^= 1;
        assert!(matches!(
            Device::restore_initial_configuration(&encoded[..len], hardware()),
            Err(DeviceError::InvalidConfiguration)
        ));
    }

    #[test]
    fn device_enrollment_rejects_duplicate_and_capacity_without_revision_change() {
        let mut device = commissioned();
        let network = NetworkBinding::new(Digest32::from_bytes([8; 32]), 42, 100, 64).unwrap();
        for value in 0..64u8 {
            device
                .enroll(Enrollment {
                    cold_verification_key: [value; 32],
                    incarnation: IncarnationId::from_bytes([value; 16]),
                    network,
                    publication_floor_us: 0,
                })
                .unwrap();
        }
        let revision = device.revision();
        assert_eq!(
            device.enroll(Enrollment {
                cold_verification_key: [64; 32],
                incarnation: IncarnationId::from_bytes([64; 16]),
                network,
                publication_floor_us: 0,
            }),
            Err(DeviceError::Pool(PoolError::CapacityExceeded))
        );
        assert_eq!(device.revision(), revision);
    }
}
