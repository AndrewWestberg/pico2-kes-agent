//! Persistent single-owner lifecycle used by firmware and power-cut qualification.
//! Every externally visible key transition is committed and cleaned before use.
use crate::{
    backup::{self, BackupBindings},
    certificate::Certificate,
    device::{
        CommissioningInput, Device as IdentityDevice, EnrollmentRecord, HardwareIdentity,
        INITIAL_CONFIGURATION_MAX_BYTES, VerifiedBlank,
    },
    identity::{
        DeviceId, Digest32, GenerationId, IncarnationId, NetworkBinding, OperationId, PoolId,
        StorageSlot,
    },
    kes::{PUBLIC_TREE_BYTES, STATE_BYTES, Sum6Kes},
    operation::{PoolTarget, UsbSerial},
    platform::{Entropy, Flash, PAGE_SIZE, SECTOR_SIZE, fill_secret},
    public_object::{MAX_ARTIFACT_LEN, PublicObject},
    recipient::RecipientPolicy,
    storage::{
        ALLOCATED_END, Bank, CONFIG_START, MAX_PUBLIC_OBJECT_BYTES, MAX_SNAPSHOT_BYTES,
        POOL_BANK_BYTES, POOL_REGION_BYTES, POOLS_START, PUBLIC_OBJECT_BYTES, PublicObjectRef,
        PublicObjectWrite, RecordDomain, Snapshot, Storage,
    },
};
use core::cmp;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const CONFIG_MAGIC: &[u8; 8] = b"PKALCF01";
const POOL_MAGIC: &[u8; 8] = b"PKALPL01";
const OBJECT_MAGIC: &[u8; 8] = b"PKALOB01";
const PROTOCOL_VERSION: u16 = 1;
const STORAGE_VERSION: u16 = 2;
const SLOT_COUNT: usize = StorageSlot::CAPACITY as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Uncommissioned,
    AlreadyCommissioned,
    StorageFailure,
    EntropyFailure,
    InvalidRequest,
    DuplicatePool,
    CapacityExceeded,
    UnknownPool,
    TargetMismatch,
    RecipientUnavailable,
    GenerationUnavailable,
    StagedOccupied,
    TargetNotStaged,
    CertificateInvalid,
    CertificateRegressive,
    PeriodUnavailable,
    PeriodRegressive,
    ContextStale,
    Expired,
}

#[derive(Clone, Copy)]
pub struct CommissionRequest {
    pub serial: &'static [u8],
    pub operation_id: OperationId,
    pub request_digest: Digest32,
    pub expected_revision: u64,
    pub sequence: u64,
}

struct CommissionData<'a> {
    serial: &'a [u8],
    operation_id: OperationId,
    request_digest: Digest32,
    expected_revision: u64,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Enrollment {
    pub pool_id: PoolId,
    pub cold_verification_key: [u8; 32],
    pub incarnation_id: IncarnationId,
    pub network: NetworkBinding,
    pub publication_floor_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub pool_id: PoolId,
    pub incarnation_id: IncarnationId,
    pub network: NetworkBinding,
    pub absolute_period: u64,
    pub publication_time_us: u64,
    pub session: [u8; 16],
    pub sequence: u64,
    pub observed_us: u64,
    pub lease_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationKind {
    None,
    Key {
        generation: GenerationId,
        relative_period: u8,
        certificate_digest: Digest32,
    },
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Publication {
    pub revision: u64,
    pub kind: PublicationKind,
    pub timestamp_us: u64,
    pub high_water_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolStatus {
    pub pool_id: PoolId,
    pub incarnation_id: IncarnationId,
    pub slot: StorageSlot,
    pub revision: u64,
    pub period_floor: Option<u64>,
    pub kes_lifetime: u8,
    pub publication: Publication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Current {
    pub generation_id: GenerationId,
    pub verification_key: [u8; 32],
    pub state: [u8; STATE_BYTES],
    pub relative_period: u8,
    pub certificate: Certificate,
    pub publication: Publication,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationInfo {
    pub verification_key: [u8; 32],
    pub revision: u64,
    pub artifact_digest: Digest32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationStatus {
    pub generation: GenerationId,
    pub number: u64,
    pub period: u64,
    pub certificate_start: Option<u64>,
    pub artifact_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolGenerations {
    pub active: Option<GenerationStatus>,
    pub staged: Option<GenerationStatus>,
}

struct GenerationState {
    id: GenerationId,
    number: u64,
    operation: OperationId,
    key: Sum6Kes,
    certificate: Option<Certificate>,
    object_region: u8,
    object_len: u16,
    object_digest: Digest32,
    artifact_digest: Digest32,
}

#[derive(Clone, Copy)]
struct DiscardRecord {
    generation: GenerationId,
    operation: OperationId,
    revision: u64,
}

struct PoolState {
    enrollment: Enrollment,
    slot: StorageSlot,
    revision: u64,
    period_floor: Option<u64>,
    highest_certificate_counter: Option<u64>,
    publication: Publication,
    active: Option<GenerationState>,
    staged: Option<GenerationState>,
    last_discard: Option<DiscardRecord>,
    lease: Option<Context>,
    bank: Bank,
    snapshot: Snapshot,
}

impl PoolState {
    fn target_matches(&self, pool: PoolId, incarnation: IncarnationId) -> Result<(), Error> {
        if self.enrollment.pool_id != pool {
            return Err(Error::UnknownPool);
        }
        if self.enrollment.incarnation_id != incarnation {
            return Err(Error::TargetMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PoolSlot {
    Empty,
    Healthy(PoolId),
    Quarantined,
}

#[derive(Clone, Copy)]
struct DeletionRecord {
    target: PoolTarget,
    publication: Publication,
}
struct ConfigState {
    identity: IdentityDevice,
    initial: [u8; INITIAL_CONFIGURATION_MAX_BYTES],
    initial_len: u16,
    recipient: Option<RecipientPolicy>,
    occupied: u64,
    last_deletion: Option<DeletionRecord>,
    bank: Bank,
    snapshot: Snapshot,
    pools: [PoolSlot; SLOT_COUNT],
    leases: [Option<Context>; SLOT_COUNT],
}

struct HandoffState {
    bank: Bank,
    snapshot: Snapshot,
}

pub struct Device<F: Flash, E: Entropy> {
    storage: Storage<F, E>,
    hardware: HardwareIdentity,
    config: Option<ConfigState>,
    handoff: Option<HandoffState>,
    recovered: bool,
    failed: bool,
}

impl<F: Flash, E: Entropy> Device<F, E> {
    pub fn open(flash: F, mut entropy: E) -> Self {
        let mut root = [0; 32];
        let failed = fill_secret(&mut entropy, &mut root).is_err();
        let hardware =
            HardwareIdentity::new(Digest32::from_bytes([0; 32]), Digest32::from_bytes([0; 32]));
        let mut device = Self::open_with_root(flash, entropy, root, hardware)
            .expect("lifecycle requires qualified geometry");
        device.failed = failed;
        device
    }

    pub fn open_with_root(
        flash: F,
        entropy: E,
        root: [u8; 32],
        hardware: HardwareIdentity,
    ) -> Result<Self, Error> {
        let storage = Storage::new(flash, entropy, root).map_err(|_| Error::StorageFailure)?;
        Ok(Self {
            storage,
            hardware,
            config: None,
            handoff: None,
            recovered: false,
            failed: false,
        })
    }

    pub fn flash(&self) -> &F {
        self.storage.flash()
    }

    pub fn flash_mut(&mut self) -> &mut F {
        self.storage.flash_mut()
    }

    pub fn into_flash(self) -> F {
        self.storage.into_flash()
    }

    pub fn hello(&self) -> Result<EnrollmentRecord, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        self.config
            .as_ref()
            .map(|config| *config.identity.enrollment_record())
            .ok_or(Error::Uncommissioned)
    }

    pub fn identity(&self) -> Option<&IdentityDevice> {
        self.config.as_ref().map(|config| &config.identity)
    }

    pub fn revision(&self) -> Result<u64, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        self.config
            .as_ref()
            .map(|config| config.snapshot.meta().revision.saturating_add(1))
            .ok_or(Error::Uncommissioned)
    }

    pub fn pool_count(&self) -> u8 {
        self.config
            .as_ref()
            .map_or(0, |config| config.occupied.count_ones() as u8)
    }

    pub fn sign_identity_message(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        self.config
            .as_ref()
            .map(|config| config.identity.sign_identity_message(message))
            .ok_or(Error::Uncommissioned)
    }

    /// USB contexts are connection-local authorization leases. Durable period
    /// floors remain in pool snapshots, but every reconnect requires a fresh
    /// host context before evolution or key release.
    pub fn reconnect(&mut self) {
        if let Some(config) = self.config.as_mut() {
            config.leases.fill(None);
        }
    }

    pub fn commission(&mut self, request: &CommissionRequest) -> Result<EnrollmentRecord, Error> {
        self.commission_inner(&CommissionData {
            serial: request.serial,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            expected_revision: request.expected_revision,
            sequence: request.sequence,
        })
    }

    pub fn commission_values(
        &mut self,
        serial: &[u8],
        operation_id: OperationId,
        request_digest: Digest32,
        expected_revision: u64,
        sequence: u64,
    ) -> Result<EnrollmentRecord, Error> {
        self.commission_inner(&CommissionData {
            serial,
            operation_id,
            request_digest,
            expected_revision,
            sequence,
        })
    }

    fn commission_inner(
        &mut self,
        request: &CommissionData<'_>,
    ) -> Result<EnrollmentRecord, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        if let Some(config) = &self.config {
            return reconcile_commission(config, request);
        }
        if !self.whole_region_blank()? {
            if self.recover().is_err() {
                return Err(Error::StorageFailure);
            }
            return self
                .config
                .as_ref()
                .ok_or(Error::StorageFailure)
                .and_then(|config| reconcile_commission(config, request));
        }
        if request.sequence != 0 || request.expected_revision != 0 {
            return Err(Error::InvalidRequest);
        }
        let serial = UsbSerial::new(request.serial).map_err(|_| Error::InvalidRequest)?;
        let mut id = [0; 16];
        let mut seed = Zeroizing::new([0; 32]);
        let mut storage_key = Zeroizing::new([0; 32]);
        fill_secret(self.storage.entropy_mut(), &mut id).map_err(|_| Error::EntropyFailure)?;
        fill_secret(self.storage.entropy_mut(), &mut *seed).map_err(|_| Error::EntropyFailure)?;
        fill_secret(self.storage.entropy_mut(), &mut *storage_key)
            .map_err(|_| Error::EntropyFailure)?;
        let hardware = self.hardware;
        let blank =
            VerifiedBlank::verify(hardware, true, true).map_err(|_| Error::StorageFailure)?;
        let identity = IdentityDevice::commission(
            blank,
            DeviceId::from_bytes(id),
            *seed,
            *storage_key,
            CommissioningInput {
                sequence: request.sequence,
                expected_revision: request.expected_revision,
                serial,
                operation_id: request.operation_id,
                request_digest: request.request_digest,
                protocol_version: PROTOCOL_VERSION,
                storage_version: STORAGE_VERSION,
            },
        )
        .map_err(|_| Error::InvalidRequest)?;
        id.zeroize();
        let mut initial = [0; INITIAL_CONFIGURATION_MAX_BYTES];
        let initial_len = identity
            .encode_initial_configuration(&mut initial)
            .map_err(|_| Error::StorageFailure)?;
        let mut payload = Zeroizing::new([0; MAX_SNAPSHOT_BYTES]);
        let payload_len = encode_config(&initial[..initial_len], None, 0, None, &mut *payload)?;
        let snapshot = self
            .storage
            .transact(
                RecordDomain::Configuration,
                None,
                &payload[..payload_len],
                None,
            )
            .map_err(|_| {
                self.failed = true;
                Error::StorageFailure
            })?;
        let record = *identity.enrollment_record();
        self.config = Some(ConfigState {
            identity,
            initial,
            initial_len: initial_len as u16,
            recipient: None,
            occupied: 0,
            last_deletion: None,
            bank: Bank::First,
            snapshot,
            pools: [PoolSlot::Empty; SLOT_COUNT],
            leases: [None; SLOT_COUNT],
        });
        self.recovered = true;
        Ok(record)
    }

    pub fn recover(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        if self.whole_region_blank()? {
            self.config = None;
            self.handoff = None;
            self.recovered = true;
            return Ok(());
        }
        let (status, snapshot) = self
            .storage
            .recover(RecordDomain::Configuration, false)
            .map_err(|_| self.shared_failure())?;
        let bank = recovered_bank(status).ok_or_else(|| self.shared_failure())?;
        let snapshot = snapshot.ok_or_else(|| self.shared_failure())?;
        let decoded = decode_config(snapshot.payload()).map_err(|_| self.shared_failure())?;
        let hardware = self.hardware;
        let identity = IdentityDevice::restore_initial_configuration(decoded.initial, hardware)
            .map_err(|_| self.shared_failure())?;
        if identity.enrollment_record().public().storage_version() != STORAGE_VERSION {
            return Err(self.shared_failure());
        }
        let mut initial = [0; INITIAL_CONFIGURATION_MAX_BYTES];
        initial[..decoded.initial.len()].copy_from_slice(decoded.initial);
        let mut pools = [PoolSlot::Empty; SLOT_COUNT];
        for (index, slot) in pools.iter_mut().enumerate() {
            let storage_slot = StorageSlot::new(index as u8).map_err(|_| self.shared_failure())?;
            if decoded.occupied & (1u64 << index) == 0 {
                self.erase_pool_region_if_needed(storage_slot)?;
                continue;
            }
            let recovered = self
                .storage
                .recover(RecordDomain::Pool(storage_slot), false);
            let Ok((pool_status, pool_snapshot)) = recovered else {
                *slot = PoolSlot::Quarantined;
                continue;
            };
            let Some(pool_bank) = recovered_bank(pool_status) else {
                *slot = PoolSlot::Quarantined;
                continue;
            };
            let Some(pool_snapshot) = pool_snapshot else {
                *slot = PoolSlot::Quarantined;
                continue;
            };
            match self.decode_pool(storage_slot, pool_bank, pool_snapshot) {
                Ok(pool) => {
                    self.erase_unused_objects(&pool)?;
                    *slot = PoolSlot::Healthy(pool.enrollment.pool_id);
                }
                Err(_) => *slot = PoolSlot::Quarantined,
            }
        }
        self.config = Some(ConfigState {
            identity,
            initial,
            initial_len: decoded.initial.len() as u16,
            recipient: decoded.recipient,
            occupied: decoded.occupied,
            last_deletion: decoded.last_deletion,
            bank,
            snapshot,
            pools,
            leases: [None; SLOT_COUNT],
        });
        let (handoff_status, handoff_snapshot) = self
            .storage
            .recover(RecordDomain::Handoff, true)
            .map_err(|_| self.shared_failure())?;
        self.handoff = match (recovered_bank(handoff_status), handoff_snapshot) {
            (None, None) => None,
            (Some(bank), Some(snapshot)) => Some(HandoffState { bank, snapshot }),
            _ => return Err(self.shared_failure()),
        };
        self.recovered = true;
        Ok(())
    }

    pub fn persisted_handoff(&self) -> Result<Option<&[u8]>, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        Ok(self
            .handoff
            .as_ref()
            .map(|handoff| handoff.snapshot.payload()))
    }

    pub fn persist_handoff(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.failed || self.config.is_none() {
            return Err(Error::StorageFailure);
        }
        let next = self
            .handoff
            .as_ref()
            .map_or(Bank::First, |handoff| other_bank(handoff.bank));
        let authoritative = self
            .handoff
            .as_ref()
            .map(|handoff| (handoff.bank, &handoff.snapshot));
        match self
            .storage
            .transact(RecordDomain::Handoff, authoritative, payload, None)
        {
            Ok(snapshot) => {
                self.handoff = Some(HandoffState {
                    bank: next,
                    snapshot,
                });
                Ok(())
            }
            Err(_) => {
                self.failed = true;
                Err(Error::StorageFailure)
            }
        }
    }

    pub fn enroll(&mut self, enrollment: &Enrollment) -> Result<(), Error> {
        self.require_ready()?;
        if PoolId::from_cold_verification_key(&enrollment.cold_verification_key)
            != enrollment.pool_id
        {
            return Err(Error::InvalidRequest);
        }
        let config = self.config.as_ref().ok_or(Error::Uncommissioned)?;
        if config
            .pools
            .iter()
            .any(|slot| matches!(slot, PoolSlot::Healthy(pool) if *pool == enrollment.pool_id))
        {
            return Err(Error::DuplicatePool);
        }
        let index = (0..SLOT_COUNT)
            .find(|index| config.occupied & (1u64 << index) == 0)
            .ok_or(Error::CapacityExceeded)?;
        let slot = StorageSlot::new(index as u8).map_err(|_| Error::CapacityExceeded)?;
        let publication = Publication {
            revision: 0,
            kind: PublicationKind::None,
            timestamp_us: enrollment.publication_floor_us,
            high_water_us: enrollment.publication_floor_us,
        };
        let mut payload = Zeroizing::new([0; MAX_SNAPSHOT_BYTES]);
        let len = encode_pool_fields(
            enrollment,
            slot,
            0,
            None,
            None,
            publication,
            None,
            None,
            None,
            &mut *payload,
        )?;
        let _snapshot = self
            .storage
            .transact(RecordDomain::Pool(slot), None, &payload[..len], None)
            .map_err(|_| Error::StorageFailure)?;
        let config = self.config.as_mut().ok_or(Error::Uncommissioned)?;
        config.pools[index] = PoolSlot::Healthy(enrollment.pool_id);
        config.leases[index] = None;
        config.occupied |= 1u64 << index;
        self.commit_config()
    }

    pub fn enroll_generated(
        &mut self,
        cold_verification_key: [u8; 32],
        network: NetworkBinding,
        publication_floor_us: u64,
    ) -> Result<crate::operation::PoolTarget, Error> {
        let mut incarnation = [0; 16];
        fill_secret(self.storage.entropy_mut(), &mut incarnation)
            .map_err(|_| Error::EntropyFailure)?;
        let target = crate::operation::PoolTarget {
            pool: PoolId::from_cold_verification_key(&cold_verification_key),
            incarnation: IncarnationId::from_bytes(incarnation),
        };
        incarnation.zeroize();
        self.enroll(&Enrollment {
            pool_id: target.pool,
            cold_verification_key,
            incarnation_id: target.incarnation,
            network,
            publication_floor_us,
        })?;
        Ok(target)
    }

    pub fn recipient(&self) -> Result<Option<([u8; 32], u64)>, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        let config = self.config.as_ref().ok_or(Error::Uncommissioned)?;
        Ok(config
            .recipient
            .map(|recipient| (*recipient.public_key(), recipient.revision())))
    }

    pub fn set_recipient(&mut self, public_key: [u8; 32]) -> Result<(), Error> {
        self.require_ready()?;
        let config = self.config.as_mut().ok_or(Error::Uncommissioned)?;
        let revision = config
            .recipient
            .map_or(1, |current| current.revision().saturating_add(1));
        config.recipient =
            Some(RecipientPolicy::new(public_key, revision).map_err(|_| Error::InvalidRequest)?);
        self.commit_config()
    }

    pub fn accept_context(&mut self, context: &Context, now_us: u64) -> Result<(), Error> {
        self.require_ready()?;
        validate_context_time(context, now_us)?;
        let index = self.find_pool(context.pool_id)?;
        let mut pool = self.take_pool(index)?;
        pool.target_matches(context.pool_id, context.incarnation_id)?;
        if pool.enrollment.network != context.network {
            self.put_pool(index, pool);
            return Err(Error::TargetMismatch);
        }
        if let Some(lease) = pool.lease
            && lease.session == context.session
            && context.sequence <= lease.sequence
        {
            self.put_pool(index, pool);
            return Err(Error::ContextStale);
        }
        if pool
            .period_floor
            .is_some_and(|floor| context.absolute_period < floor)
        {
            self.put_pool(index, pool);
            return Err(Error::PeriodRegressive);
        }
        if pool.period_floor != Some(context.absolute_period) {
            pool.period_floor = Some(context.absolute_period);
            pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
            pool = self.commit_pool_for(index, pool, None)?;
        }
        pool.lease = Some(*context);
        self.put_pool(index, pool);
        Ok(())
    }

    pub fn generate(
        &mut self,
        pool_id: PoolId,
        operation: OperationId,
    ) -> Result<GenerationId, Error> {
        self.require_ready()?;
        let recipient = self
            .config
            .as_ref()
            .and_then(|config| config.recipient)
            .ok_or(Error::RecipientUnavailable)?;
        let device_id = self.config.as_ref().unwrap().identity.id();
        let index = self.find_pool(pool_id)?;
        let mut pool = self.take_pool(index)?;
        if pool.staged.is_some() {
            self.put_pool(index, pool);
            return Err(Error::StagedOccupied);
        }
        let mut generation_bytes = [0; 16];
        fill_secret(self.storage.entropy_mut(), &mut generation_bytes)
            .map_err(|_| Error::EntropyFailure)?;
        let generation_id = GenerationId::from_bytes(generation_bytes);
        generation_bytes.zeroize();
        let key = Sum6Kes::generate(
            self.storage.entropy_mut(),
            pool.enrollment.network.lifetime(),
        )
        .map_err(|_| Error::EntropyFailure)?;
        let number = pool
            .active
            .as_ref()
            .map_or(1, |active| active.number.saturating_add(1));
        let bindings = BackupBindings {
            device: device_id,
            pool: pool.enrollment.pool_id,
            incarnation: pool.enrollment.incarnation_id,
            generation: generation_id,
            generation_number: number,
            verification_key: key.verification_key(),
        };
        let identity_key = self
            .config
            .as_ref()
            .unwrap()
            .identity
            .identity_signing_key();
        let artifact = backup::create(
            &key,
            &bindings,
            &recipient,
            &identity_key,
            self.storage.entropy_mut(),
        )
        .map_err(|_| Error::EntropyFailure)?;
        let object = PublicObject::new(
            generation_id,
            *key.public_tree().as_bytes(),
            artifact.as_bytes(),
        )
        .map_err(|_| Error::StorageFailure)?;
        let region = pool
            .active
            .as_ref()
            .map_or(0, |active| 1 - active.object_region);
        let mut object_bytes = [0xff; MAX_PUBLIC_OBJECT_BYTES];
        let object_len = encode_object(&object, &mut object_bytes)?;
        let object_digest =
            Digest32::from_bytes(Sha256::digest(&object_bytes[..object_len]).into());
        let generation = GenerationState {
            id: generation_id,
            number,
            operation,
            key,
            certificate: None,
            object_region: region,
            object_len: object_len as u16,
            object_digest,
            artifact_digest: object.artifact_digest(),
        };
        if pool.active.is_none() {
            pool.active = Some(generation);
        } else {
            pool.staged = Some(generation);
        }
        pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
        let reference = PublicObjectRef {
            generation: *generation_id.as_bytes(),
            digest: object_digest,
            region,
            length: object_len as u16,
        };
        let write = PublicObjectWrite {
            reference,
            bytes: &object_bytes[..object_len],
        };
        pool = self.commit_pool_for(index, pool, Some(write))?;
        self.put_pool(index, pool);
        Ok(generation_id)
    }

    pub fn public_key(
        &mut self,
        pool_id: PoolId,
        generation: GenerationId,
    ) -> Result<[u8; 32], Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = find_generation(&pool, generation)
            .map(|generation| generation.key.verification_key())
            .ok_or(Error::GenerationUnavailable);
        self.put_pool(index, pool);
        result
    }

    pub fn generation_by_operation(
        &mut self,
        pool_id: PoolId,
        operation: OperationId,
    ) -> Result<(GenerationId, GenerationInfo), Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = pool
            .active
            .as_ref()
            .into_iter()
            .chain(pool.staged.as_ref())
            .find(|generation| generation.operation == operation)
            .map(|generation| {
                (
                    generation.id,
                    GenerationInfo {
                        verification_key: generation.key.verification_key(),
                        revision: pool.revision,
                        artifact_digest: generation.artifact_digest,
                    },
                )
            })
            .ok_or(Error::GenerationUnavailable);
        self.put_pool(index, pool);
        result
    }

    pub fn installed_certificate(
        &mut self,
        pool_id: PoolId,
        generation: GenerationId,
    ) -> Result<Option<Certificate>, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = find_generation(&pool, generation)
            .map(|generation| generation.certificate)
            .ok_or(Error::GenerationUnavailable);
        self.put_pool(index, pool);
        result
    }

    pub fn discarded_by_operation(
        &mut self,
        pool_id: PoolId,
        generation: GenerationId,
        operation: OperationId,
    ) -> Result<Option<u64>, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = pool
            .last_discard
            .filter(|record| record.generation == generation && record.operation == operation)
            .map(|record| record.revision);
        self.put_pool(index, pool);
        Ok(result)
    }

    pub fn pool_generations(&mut self, pool_id: PoolId) -> Result<PoolGenerations, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = PoolGenerations {
            active: pool.active.as_ref().map(generation_status),
            staged: pool.staged.as_ref().map(generation_status),
        };
        self.put_pool(index, pool);
        Ok(result)
    }

    pub fn generation_info(
        &mut self,
        pool_id: PoolId,
        generation: GenerationId,
    ) -> Result<GenerationInfo, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = find_generation(&pool, generation)
            .map(|generation| GenerationInfo {
                verification_key: generation.key.verification_key(),
                revision: pool.revision,
                artifact_digest: generation.artifact_digest,
            })
            .ok_or(Error::GenerationUnavailable);
        self.put_pool(index, pool);
        result
    }

    pub fn artifact(
        &mut self,
        pool_id: PoolId,
        generation: GenerationId,
        output: &mut [u8; MAX_ARTIFACT_LEN],
    ) -> Result<(usize, Digest32, u64), Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = if let Some(generation) = find_generation(&pool, generation) {
            let mut object_bytes = [0; MAX_PUBLIC_OBJECT_BYTES];
            let len = usize::from(generation.object_len);
            self.storage
                .flash_mut()
                .read(
                    public_address(pool.slot, generation.object_region),
                    &mut object_bytes[..len],
                )
                .map_err(|_| Error::StorageFailure)?;
            if Digest32::from_bytes(Sha256::digest(&object_bytes[..len]).into())
                != generation.object_digest
            {
                Err(Error::StorageFailure)
            } else {
                let object = decode_object(&object_bytes[..len])?;
                let artifact = object.artifact();
                output[..artifact.len()].copy_from_slice(artifact);
                Ok((artifact.len(), object.artifact_digest(), pool.revision))
            }
        } else {
            Err(Error::GenerationUnavailable)
        };
        self.put_pool(index, pool);
        result
    }

    pub fn install_certificate(
        &mut self,
        pool_id: PoolId,
        generation_id: GenerationId,
        certificate: &Certificate,
    ) -> Result<(), Error> {
        self.require_ready()?;
        let index = self.find_pool(pool_id)?;
        let mut pool = self.take_pool(index)?;
        certificate
            .verify(&pool.enrollment.cold_verification_key)
            .map_err(|_| Error::CertificateInvalid)?;
        if pool
            .highest_certificate_counter
            .is_some_and(|counter| certificate.counter() < counter)
        {
            self.put_pool(index, pool);
            return Err(Error::CertificateRegressive);
        }
        let Some(generation) = find_generation(&pool, generation_id) else {
            self.put_pool(index, pool);
            return Err(Error::GenerationUnavailable);
        };
        if generation.key.verification_key() != *certificate.hot_verification_key() {
            self.put_pool(index, pool);
            return Err(Error::CertificateInvalid);
        }
        if let Some(existing) = generation.certificate {
            if existing == *certificate {
                self.put_pool(index, pool);
                return Ok(());
            }
            if certificate.counter() <= existing.counter() {
                self.put_pool(index, pool);
                return Err(Error::CertificateRegressive);
            }
        }
        find_generation_mut(&mut pool, generation_id)
            .expect("generation checked")
            .certificate = Some(*certificate);
        pool.highest_certificate_counter = Some(certificate.counter());
        pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
        let cleanup = if pool.lease.is_some() {
            apply_period_context(&mut pool)?
        } else {
            PeriodTransition::unchanged()
        };
        pool = self.commit_pool_for(index, pool, None)?;
        self.erase_retired_objects(pool.slot, cleanup)?;
        self.put_pool(index, pool);
        Ok(())
    }

    pub fn discard(
        &mut self,
        pool_id: PoolId,
        incarnation: IncarnationId,
        generation_id: GenerationId,
        operation: OperationId,
    ) -> Result<(), Error> {
        self.require_ready()?;
        let index = self.find_pool(pool_id)?;
        let mut pool = self.take_pool(index)?;
        pool.target_matches(pool_id, incarnation)?;
        let staged = pool.staged.take().ok_or(Error::TargetNotStaged)?;
        if staged.id != generation_id {
            pool.staged = Some(staged);
            self.put_pool(index, pool);
            return Err(Error::TargetNotStaged);
        }
        let region = staged.object_region;
        pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
        pool.last_discard = Some(DiscardRecord {
            generation: generation_id,
            operation,
            revision: pool.revision,
        });
        pool = self.commit_pool_for(index, pool, None)?;
        self.erase_object_if_needed(pool.slot, region)?;
        self.put_pool(index, pool);
        Ok(())
    }

    pub fn evolve(&mut self, pool_id: PoolId, now_us: u64) -> Result<(), Error> {
        self.catch_up(pool_id, now_us)
    }

    pub fn catch_up(&mut self, pool_id: PoolId, now_us: u64) -> Result<(), Error> {
        self.require_ready()?;
        let index = self.find_pool(pool_id)?;
        let mut pool = self.take_pool(index)?;
        let lease = pool.lease.ok_or(Error::PeriodUnavailable)?;
        validate_context_time(&lease, now_us)?;
        let transition = apply_period_context(&mut pool)?;
        if transition.changed {
            pool = self.commit_pool_for(index, pool, None)?;
            self.erase_retired_objects(pool.slot, transition)?;
        }
        self.put_pool(index, pool);
        Ok(())
    }

    pub fn current(
        &mut self,
        pool_id: PoolId,
        incarnation: IncarnationId,
        now_us: u64,
    ) -> Result<Current, Error> {
        self.require_ready()?;
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = (|| {
            pool.target_matches(pool_id, incarnation)?;
            let lease = pool.lease.ok_or(Error::PeriodUnavailable)?;
            validate_context_time(&lease, now_us)?;
            let generation = pool.active.as_ref().ok_or({
                if matches!(pool.publication.kind, PublicationKind::Drop) {
                    Error::Expired
                } else {
                    Error::GenerationUnavailable
                }
            })?;
            let certificate = generation.certificate.ok_or(Error::PeriodUnavailable)?;
            let expected = lease
                .absolute_period
                .checked_sub(certificate.start_period())
                .ok_or(Error::PeriodUnavailable)?;
            if expected >= u64::from(pool.enrollment.network.lifetime()) {
                return Err(Error::Expired);
            }
            if generation.key.period() != expected {
                return Err(Error::PeriodUnavailable);
            }
            Ok(Current {
                generation_id: generation.id,
                verification_key: generation.key.verification_key(),
                state: generation.key.canonical_state(),
                relative_period: expected as u8,
                certificate,
                publication: pool.publication,
                revision: pool.revision,
            })
        })();
        self.put_pool(index, pool);
        result
    }

    pub fn publication(&mut self, pool_id: PoolId) -> Result<Publication, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = pool.publication;
        self.put_pool(index, pool);
        Ok(result)
    }

    pub fn enrollment(&mut self, pool_id: PoolId) -> Result<Enrollment, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let enrollment = pool.enrollment;
        self.put_pool(index, pool);
        Ok(enrollment)
    }

    pub fn deletion(&self, target: PoolTarget) -> Result<Option<Publication>, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        let config = self.config.as_ref().ok_or(Error::Uncommissioned)?;
        Ok(config
            .last_deletion
            .filter(|deletion| deletion.target == target)
            .map(|deletion| deletion.publication))
    }

    pub fn pool_status(&mut self, pool_id: PoolId) -> Result<PoolStatus, Error> {
        let index = self.find_pool(pool_id)?;
        let pool = self.take_pool(index)?;
        let result = PoolStatus {
            pool_id: pool.enrollment.pool_id,
            incarnation_id: pool.enrollment.incarnation_id,
            slot: pool.slot,
            revision: pool.revision,
            period_floor: pool.period_floor,
            kes_lifetime: pool.enrollment.network.lifetime(),
            publication: pool.publication,
        };
        self.put_pool(index, pool);
        Ok(result)
    }

    /// Read authenticated pool metadata for deletion, without restoring public objects.
    pub fn pool_deletion_status(&mut self, pool_id: PoolId) -> Result<PoolStatus, Error> {
        self.require_ready()?;
        let occupied = self.config.as_ref().ok_or(Error::Uncommissioned)?.occupied;
        let mut found = None;
        for index in 0..SLOT_COUNT {
            if occupied & (1u64 << index) == 0 {
                continue;
            }
            let slot = StorageSlot::new(index as u8).map_err(|_| Error::StorageFailure)?;
            let snapshot = self
                .storage
                .pool_snapshot_for_deletion(slot)
                .map_err(|_| Error::StorageFailure)?;
            let decoded = decode_pool_header(snapshot.payload(), slot)?;
            if decoded.enrollment.pool_id == pool_id {
                if found.is_some() {
                    return Err(Error::StorageFailure);
                }
                found = Some(PoolStatus {
                    pool_id,
                    incarnation_id: decoded.enrollment.incarnation_id,
                    slot,
                    revision: decoded.revision,
                    period_floor: decoded.period_floor,
                    kes_lifetime: decoded.enrollment.network.lifetime(),
                    publication: decoded.publication,
                });
            }
        }
        found.ok_or(Error::UnknownPool)
    }

    pub fn delete_pool(
        &mut self,
        target: PoolTarget,
        publication_time_us: Option<u64>,
    ) -> Result<Publication, Error> {
        self.require_ready()?;
        let status = self.pool_deletion_status(target.pool)?;
        if status.incarnation_id != target.incarnation {
            return Err(Error::TargetMismatch);
        }
        let index = usize::from(status.slot.get());
        let timestamp = publication_time_us
            .unwrap_or_else(|| status.publication.high_water_us.saturating_add(1));
        let terminal = Publication {
            revision: status.publication.revision.saturating_add(1),
            kind: PublicationKind::Drop,
            timestamp_us: cmp::max(
                timestamp,
                status.publication.high_water_us.saturating_add(1),
            ),
            high_water_us: cmp::max(
                timestamp,
                status.publication.high_water_us.saturating_add(1),
            ),
        };
        let config = self.config.as_mut().ok_or(Error::Uncommissioned)?;
        config.occupied &= !(1u64 << index);
        config.pools[index] = PoolSlot::Empty;
        config.leases[index] = None;
        config.last_deletion = Some(DeletionRecord {
            target,
            publication: terminal,
        });
        self.commit_config()?;
        if self.erase_pool_region(status.slot).is_err() {
            return Err(self.shared_failure());
        }
        Ok(terminal)
    }

    fn require_ready(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::StorageFailure)
        } else if !self.recovered || self.config.is_none() {
            Err(Error::Uncommissioned)
        } else {
            Ok(())
        }
    }

    fn shared_failure(&mut self) -> Error {
        self.failed = true;
        Error::StorageFailure
    }

    fn whole_region_blank(&mut self) -> Result<bool, Error> {
        let mut sector = [0; SECTOR_SIZE as usize];
        let mut address = CONFIG_START;
        while address < ALLOCATED_END {
            self.storage
                .flash_mut()
                .read(address, &mut sector)
                .map_err(|_| Error::StorageFailure)?;
            if sector.iter().any(|byte| *byte != 0xff) {
                return Ok(false);
            }
            address += SECTOR_SIZE;
        }
        Ok(true)
    }

    fn find_pool(&self, pool_id: PoolId) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::StorageFailure);
        }
        let config = self.config.as_ref().ok_or(Error::Uncommissioned)?;
        config
            .pools
            .iter()
            .position(|slot| matches!(slot, PoolSlot::Healthy(pool) if *pool == pool_id))
            .ok_or_else(|| {
                if config
                    .pools
                    .iter()
                    .any(|slot| matches!(slot, PoolSlot::Quarantined))
                {
                    Error::StorageFailure
                } else {
                    Error::UnknownPool
                }
            })
    }

    fn take_pool(&mut self, index: usize) -> Result<PoolState, Error> {
        if !matches!(
            self.config.as_ref().ok_or(Error::Uncommissioned)?.pools[index],
            PoolSlot::Healthy(_)
        ) {
            return Err(Error::StorageFailure);
        }
        let slot = StorageSlot::new(index as u8).map_err(|_| Error::StorageFailure)?;
        let recovered = self.storage.recover(RecordDomain::Pool(slot), false);
        let Ok((status, snapshot)) = recovered else {
            self.config.as_mut().unwrap().pools[index] = PoolSlot::Quarantined;
            return Err(Error::StorageFailure);
        };
        let Some(bank) = recovered_bank(status) else {
            self.config.as_mut().unwrap().pools[index] = PoolSlot::Quarantined;
            return Err(Error::StorageFailure);
        };
        let Some(snapshot) = snapshot else {
            self.config.as_mut().unwrap().pools[index] = PoolSlot::Quarantined;
            return Err(Error::StorageFailure);
        };
        let mut pool = match self.decode_pool(slot, bank, snapshot) {
            Ok(pool) => pool,
            Err(_) => {
                self.config.as_mut().unwrap().pools[index] = PoolSlot::Quarantined;
                return Err(Error::StorageFailure);
            }
        };
        pool.lease = self.config.as_ref().unwrap().leases[index];
        Ok(pool)
    }

    fn put_pool(&mut self, index: usize, pool: PoolState) {
        let config = self.config.as_mut().unwrap();
        config.leases[index] = pool.lease;
        config.pools[index] = PoolSlot::Healthy(pool.enrollment.pool_id);
    }
    fn commit_pool_for(
        &mut self,
        index: usize,
        pool: PoolState,
        object: Option<PublicObjectWrite<'_>>,
    ) -> Result<PoolState, Error> {
        match self.commit_pool(pool, object) {
            Ok(pool) => Ok(pool),
            Err(error) => {
                self.config.as_mut().unwrap().pools[index] = PoolSlot::Quarantined;
                self.config.as_mut().unwrap().leases[index] = None;
                Err(error)
            }
        }
    }

    fn commit_pool(
        &mut self,
        mut pool: PoolState,
        object: Option<PublicObjectWrite<'_>>,
    ) -> Result<PoolState, Error> {
        let mut payload = Zeroizing::new([0; MAX_SNAPSHOT_BYTES]);
        let len = encode_pool(&pool, &mut *payload)?;
        let bank = other_bank(pool.bank);
        match self.storage.transact(
            RecordDomain::Pool(pool.slot),
            Some((pool.bank, &pool.snapshot)),
            &payload[..len],
            object,
        ) {
            Ok(snapshot) => {
                pool.bank = bank;
                pool.snapshot = snapshot;
                Ok(pool)
            }
            Err(_) => Err(Error::StorageFailure),
        }
    }

    fn commit_config(&mut self) -> Result<(), Error> {
        let config = self.config.as_mut().ok_or(Error::Uncommissioned)?;
        let mut payload = Zeroizing::new([0; MAX_SNAPSHOT_BYTES]);
        let len = encode_config(
            &config.initial[..usize::from(config.initial_len)],
            config.recipient,
            config.occupied,
            config.last_deletion,
            &mut *payload,
        )?;
        let next = other_bank(config.bank);
        let result = self.storage.transact(
            RecordDomain::Configuration,
            Some((config.bank, &config.snapshot)),
            &payload[..len],
            None,
        );
        match result {
            Ok(snapshot) => {
                config.bank = next;
                config.snapshot = snapshot;
                Ok(())
            }
            Err(_) => {
                self.failed = true;
                Err(Error::StorageFailure)
            }
        }
    }

    fn decode_pool(
        &mut self,
        slot: StorageSlot,
        bank: Bank,
        snapshot: Snapshot,
    ) -> Result<PoolState, Error> {
        let decoded = decode_pool_header(snapshot.payload(), slot)?;
        let active = match decoded.active {
            Some(encoded) => {
                Some(self.restore_generation(slot, decoded.enrollment.network, encoded)?)
            }
            None => None,
        };
        let staged = match decoded.staged {
            Some(encoded) => {
                Some(self.restore_generation(slot, decoded.enrollment.network, encoded)?)
            }
            None => None,
        };
        Ok(PoolState {
            enrollment: decoded.enrollment,
            slot,
            revision: decoded.revision,
            period_floor: decoded.period_floor,
            highest_certificate_counter: decoded.highest_certificate_counter,
            publication: decoded.publication,
            active,
            staged,
            last_discard: decoded.last_discard,
            lease: None,
            bank,
            snapshot,
        })
    }

    fn restore_generation(
        &mut self,
        slot: StorageSlot,
        network: NetworkBinding,
        encoded: EncodedGeneration,
    ) -> Result<GenerationState, Error> {
        let mut object_bytes = [0; MAX_PUBLIC_OBJECT_BYTES];
        let base = public_address(slot, encoded.object_region);
        self.storage
            .flash_mut()
            .read(base, &mut object_bytes[..usize::from(encoded.object_len)])
            .map_err(|_| Error::StorageFailure)?;
        if Digest32::from_bytes(
            Sha256::digest(&object_bytes[..usize::from(encoded.object_len)]).into(),
        ) != encoded.object_digest
        {
            return Err(Error::StorageFailure);
        }
        let object = decode_object(&object_bytes[..usize::from(encoded.object_len)])?;
        if object.generation_id() != encoded.id
            || object.artifact_digest() != encoded.artifact_digest
        {
            return Err(Error::StorageFailure);
        }
        let key = Sum6Kes::restore(
            &encoded.state,
            encoded.period,
            network.lifetime(),
            object.public_tree(),
        )
        .map_err(|_| Error::StorageFailure)?;
        Ok(GenerationState {
            id: encoded.id,
            number: encoded.number,
            operation: encoded.operation,
            key,
            certificate: encoded.certificate,
            object_region: encoded.object_region,
            object_len: encoded.object_len,
            object_digest: encoded.object_digest,
            artifact_digest: encoded.artifact_digest,
        })
    }

    fn erase_unused_objects(&mut self, pool: &PoolState) -> Result<(), Error> {
        for region in 0..=1 {
            let used = pool
                .active
                .as_ref()
                .is_some_and(|value| value.object_region == region)
                || pool
                    .staged
                    .as_ref()
                    .is_some_and(|value| value.object_region == region);
            if !used {
                self.erase_object_if_needed(pool.slot, region)?;
            }
        }
        Ok(())
    }

    fn erase_retired_objects(
        &mut self,
        slot: StorageSlot,
        transition: PeriodTransition,
    ) -> Result<(), Error> {
        if let Some(region) = transition.first_retired_region {
            self.erase_object_if_needed(slot, region)?;
        }
        if let Some(region) = transition.second_retired_region
            && Some(region) != transition.first_retired_region
        {
            self.erase_object_if_needed(slot, region)?;
        }
        Ok(())
    }

    fn erase_object_if_needed(&mut self, slot: StorageSlot, region: u8) -> Result<(), Error> {
        let base = public_address(slot, region);
        self.erase_range_if_needed(base, PUBLIC_OBJECT_BYTES)
    }

    fn erase_pool_region_if_needed(&mut self, slot: StorageSlot) -> Result<(), Error> {
        let base = POOLS_START + u32::from(slot.get()) * POOL_REGION_BYTES;
        self.erase_range_if_needed(base, POOL_REGION_BYTES)
    }

    fn erase_pool_region(&mut self, slot: StorageSlot) -> Result<(), Error> {
        let base = POOLS_START + u32::from(slot.get()) * POOL_REGION_BYTES;
        let mut address = base;
        while address < base + POOL_REGION_BYTES {
            self.storage
                .flash_mut()
                .erase_sector(address)
                .map_err(|_| Error::StorageFailure)?;
            address += SECTOR_SIZE;
        }
        self.verify_erased(base, POOL_REGION_BYTES)
    }

    fn erase_range_if_needed(&mut self, start: u32, len: u32) -> Result<(), Error> {
        let mut page = [0; PAGE_SIZE as usize];
        let mut address = start;
        let mut dirty = false;
        while address < start + len {
            self.storage
                .flash_mut()
                .read(address, &mut page)
                .map_err(|_| Error::StorageFailure)?;
            dirty |= page.iter().any(|byte| *byte != 0xff);
            address += PAGE_SIZE;
        }
        if dirty {
            let mut sector = start;
            while sector < start + len {
                self.storage
                    .flash_mut()
                    .erase_sector(sector)
                    .map_err(|_| Error::StorageFailure)?;
                sector += SECTOR_SIZE;
            }
            self.verify_erased(start, len)?;
        }
        Ok(())
    }

    fn verify_erased(&mut self, start: u32, len: u32) -> Result<(), Error> {
        let mut page = [0; PAGE_SIZE as usize];
        let mut address = start;
        while address < start + len {
            self.storage
                .flash_mut()
                .read(address, &mut page)
                .map_err(|_| Error::StorageFailure)?;
            if page.iter().any(|byte| *byte != 0xff) {
                return Err(Error::StorageFailure);
            }
            address += PAGE_SIZE;
        }
        Ok(())
    }
}

fn reconcile_commission(
    config: &ConfigState,
    request: &CommissionData<'_>,
) -> Result<EnrollmentRecord, Error> {
    let public = config.identity.enrollment_record().public();
    if request.sequence == 0
        && request.expected_revision == 0
        && request.serial == public.serial().as_slice()
        && request.operation_id == public.operation_id()
        && request.request_digest == public.request_digest()
    {
        Ok(*config.identity.enrollment_record())
    } else {
        Err(Error::AlreadyCommissioned)
    }
}

fn validate_context_time(context: &Context, now_us: u64) -> Result<(), Error> {
    let age = now_us
        .checked_sub(context.observed_us)
        .ok_or(Error::ContextStale)?;
    if context.lease_us == 0 || age >= context.lease_us {
        Err(Error::ContextStale)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct PeriodTransition {
    changed: bool,
    first_retired_region: Option<u8>,
    second_retired_region: Option<u8>,
}

impl PeriodTransition {
    const fn unchanged() -> Self {
        Self {
            changed: false,
            first_retired_region: None,
            second_retired_region: None,
        }
    }

    fn retire(&mut self, region: u8) {
        if self.first_retired_region.is_none() {
            self.first_retired_region = Some(region);
        } else {
            self.second_retired_region = Some(region);
        }
        self.changed = true;
    }
}

fn apply_period_context(pool: &mut PoolState) -> Result<PeriodTransition, Error> {
    let context = pool.lease.ok_or(Error::PeriodUnavailable)?;
    let lifetime = u64::from(pool.enrollment.network.lifetime());
    let mut transition = PeriodTransition::unchanged();

    if let Some(certificate) = pool
        .staged
        .as_ref()
        .and_then(|generation| generation.certificate)
        && let Some(relative) = context
            .absolute_period
            .checked_sub(certificate.start_period())
    {
        if relative >= lifetime {
            let mut expired = pool.staged.take().expect("staged generation checked");
            expired.key.erase();
            transition.retire(expired.object_region);
            pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
        } else {
            if pool
                .staged
                .as_ref()
                .is_some_and(|generation| generation.key.period() > relative)
            {
                return Err(Error::PeriodRegressive);
            }
            let mut replacement = pool.staged.take().expect("staged generation checked");
            replacement
                .key
                .evolve_to(relative)
                .map_err(|_| Error::PeriodUnavailable)?;
            if let Some(mut predecessor) = pool.active.take() {
                predecessor.key.erase();
                transition.retire(predecessor.object_region);
            }
            let kind = PublicationKind::Key {
                generation: replacement.id,
                relative_period: relative as u8,
                certificate_digest: certificate.digest(),
            };
            pool.active = Some(replacement);
            pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
            publish(pool, kind, context.publication_time_us)?;
            transition.changed = true;
            return Ok(transition);
        }
    }

    let Some(active) = pool.active.as_mut() else {
        return if transition.changed {
            Ok(transition)
        } else {
            Err(Error::GenerationUnavailable)
        };
    };
    let certificate = active.certificate.ok_or(Error::PeriodUnavailable)?;
    let relative = context
        .absolute_period
        .checked_sub(certificate.start_period())
        .ok_or(Error::PeriodUnavailable)?;
    if relative >= lifetime {
        let mut expired = pool.active.take().expect("active generation checked");
        expired.key.erase();
        transition.retire(expired.object_region);
        pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
        publish(pool, PublicationKind::Drop, context.publication_time_us)?;
        return Ok(transition);
    }
    if active.key.period() > relative {
        return Err(Error::PeriodRegressive);
    }
    let kind = PublicationKind::Key {
        generation: active.id,
        relative_period: relative as u8,
        certificate_digest: certificate.digest(),
    };
    if active.key.period() == relative && pool.publication.kind == kind {
        return Ok(transition);
    }
    active
        .key
        .evolve_to(relative)
        .map_err(|_| Error::PeriodUnavailable)?;
    pool.revision = pool.revision.checked_add(1).ok_or(Error::StorageFailure)?;
    publish(pool, kind, context.publication_time_us)?;
    transition.changed = true;
    Ok(transition)
}

fn publish(pool: &mut PoolState, kind: PublicationKind, sample: u64) -> Result<(), Error> {
    let timestamp = cmp::max(sample, pool.publication.high_water_us.saturating_add(1));
    pool.publication = Publication {
        revision: pool
            .publication
            .revision
            .checked_add(1)
            .ok_or(Error::StorageFailure)?,
        kind,
        timestamp_us: timestamp,
        high_water_us: timestamp,
    };
    Ok(())
}

fn generation_status(generation: &GenerationState) -> GenerationStatus {
    GenerationStatus {
        generation: generation.id,
        number: generation.number,
        period: generation.key.period(),
        certificate_start: generation
            .certificate
            .as_ref()
            .map(Certificate::start_period),
        artifact_digest: generation.artifact_digest,
    }
}

fn find_generation(pool: &PoolState, id: GenerationId) -> Option<&GenerationState> {
    pool.active
        .as_ref()
        .filter(|generation| generation.id == id)
        .or_else(|| {
            pool.staged
                .as_ref()
                .filter(|generation| generation.id == id)
        })
}

fn find_generation_mut(pool: &mut PoolState, id: GenerationId) -> Option<&mut GenerationState> {
    if pool
        .active
        .as_ref()
        .is_some_and(|generation| generation.id == id)
    {
        pool.active.as_mut()
    } else {
        pool.staged
            .as_mut()
            .filter(|generation| generation.id == id)
    }
}

fn recovered_bank(recovered: crate::storage::Recovered) -> Option<Bank> {
    match recovered {
        crate::storage::Recovered::Clean(bank)
        | crate::storage::Recovered::CleanupRequired(bank) => Some(bank),
        crate::storage::Recovered::Empty => None,
    }
}

const fn other_bank(bank: Bank) -> Bank {
    match bank {
        Bank::First => Bank::Second,
        Bank::Second => Bank::First,
    }
}

fn public_address(slot: StorageSlot, region: u8) -> u32 {
    POOLS_START
        + u32::from(slot.get()) * POOL_REGION_BYTES
        + 2 * POOL_BANK_BYTES
        + u32::from(region) * PUBLIC_OBJECT_BYTES
}

struct DecodedConfig<'a> {
    initial: &'a [u8],
    recipient: Option<RecipientPolicy>,
    occupied: u64,
    last_deletion: Option<DeletionRecord>,
}

fn encode_config(
    initial: &[u8],
    recipient: Option<RecipientPolicy>,
    occupied: u64,
    last_deletion: Option<DeletionRecord>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut writer = Writer::new(output);
    writer.put(CONFIG_MAGIC)?;
    writer.u16(2)?;
    writer.u16(initial.len() as u16)?;
    writer.put(initial)?;
    match recipient {
        Some(recipient) => {
            writer.u8(1)?;
            writer.put(recipient.public_key())?;
            writer.u64(recipient.revision())?;
        }
        None => writer.u8(0)?,
    }
    writer.u64(occupied)?;
    match last_deletion {
        Some(deletion) => {
            writer.u8(1)?;
            writer.put(deletion.target.pool.as_bytes())?;
            writer.put(deletion.target.incarnation.as_bytes())?;
            writer.u64(deletion.publication.revision)?;
            writer.u64(deletion.publication.timestamp_us)?;
            writer.u64(deletion.publication.high_water_us)?;
        }
        None => writer.u8(0)?,
    }
    Ok(writer.finish())
}

fn decode_config(input: &[u8]) -> Result<DecodedConfig<'_>, Error> {
    let mut reader = Reader::new(input);
    if reader.take::<8>()? != *CONFIG_MAGIC || reader.u16()? != 2 {
        return Err(Error::StorageFailure);
    }
    let initial_len = usize::from(reader.u16()?);
    let initial = reader.bytes(initial_len)?;
    let recipient = match reader.u8()? {
        0 => None,
        1 => Some(
            RecipientPolicy::new(reader.take()?, reader.u64()?)
                .map_err(|_| Error::StorageFailure)?,
        ),
        _ => return Err(Error::StorageFailure),
    };
    let occupied = reader.u64()?;
    let last_deletion = match reader.u8()? {
        0 => None,
        1 => {
            let target = PoolTarget {
                pool: PoolId::from_bytes(reader.take()?),
                incarnation: IncarnationId::from_bytes(reader.take()?),
            };
            let publication = Publication {
                revision: reader.u64()?,
                kind: PublicationKind::Drop,
                timestamp_us: reader.u64()?,
                high_water_us: reader.u64()?,
            };
            if publication.timestamp_us != publication.high_water_us {
                return Err(Error::StorageFailure);
            }
            Some(DeletionRecord {
                target,
                publication,
            })
        }
        _ => return Err(Error::StorageFailure),
    };
    reader.finish()?;
    Ok(DecodedConfig {
        initial,
        recipient,
        occupied,
        last_deletion,
    })
}

fn encode_pool(pool: &PoolState, output: &mut [u8]) -> Result<usize, Error> {
    encode_pool_fields(
        &pool.enrollment,
        pool.slot,
        pool.revision,
        pool.period_floor,
        pool.highest_certificate_counter,
        pool.publication,
        pool.active.as_ref(),
        pool.staged.as_ref(),
        pool.last_discard,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_pool_fields(
    enrollment: &Enrollment,
    slot: StorageSlot,
    revision: u64,
    period_floor: Option<u64>,
    highest_certificate_counter: Option<u64>,
    publication: Publication,
    active: Option<&GenerationState>,
    staged: Option<&GenerationState>,
    last_discard: Option<DiscardRecord>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut writer = Writer::new(output);
    writer.put(POOL_MAGIC)?;
    writer.u16(2)?;
    writer.u8(slot.get())?;
    writer.put(enrollment.pool_id.as_bytes())?;
    writer.put(&enrollment.cold_verification_key)?;
    writer.put(enrollment.incarnation_id.as_bytes())?;
    writer.put(enrollment.network.genesis().as_bytes())?;
    writer.u32(enrollment.network.magic())?;
    writer.u64(enrollment.network.slots_per_period())?;
    writer.u8(enrollment.network.lifetime())?;
    writer.u64(enrollment.publication_floor_us)?;
    writer.u64(revision)?;
    writer.option_u64(period_floor)?;
    writer.option_u64(highest_certificate_counter)?;
    encode_publication(&mut writer, publication)?;
    encode_generation(&mut writer, active)?;
    encode_generation(&mut writer, staged)?;
    encode_discard(&mut writer, last_discard)?;
    Ok(writer.finish())
}

struct DecodedPool<'a> {
    enrollment: Enrollment,
    revision: u64,
    period_floor: Option<u64>,
    highest_certificate_counter: Option<u64>,
    publication: Publication,
    active: Option<EncodedGeneration>,
    staged: Option<EncodedGeneration>,
    last_discard: Option<DiscardRecord>,
    _input: core::marker::PhantomData<&'a [u8]>,
}

struct EncodedGeneration {
    id: GenerationId,
    number: u64,
    operation: OperationId,
    period: u8,
    certificate: Option<Certificate>,
    object_region: u8,
    object_len: u16,
    object_digest: Digest32,
    artifact_digest: Digest32,
    state: [u8; STATE_BYTES],
}

fn decode_pool_header(input: &[u8], expected_slot: StorageSlot) -> Result<DecodedPool<'_>, Error> {
    let mut reader = Reader::new(input);
    if reader.take::<8>()? != *POOL_MAGIC
        || reader.u16()? != 2
        || reader.u8()? != expected_slot.get()
    {
        return Err(Error::StorageFailure);
    }
    let pool_id = PoolId::from_bytes(reader.take()?);
    let cold_verification_key = reader.take()?;
    if PoolId::from_cold_verification_key(&cold_verification_key) != pool_id {
        return Err(Error::StorageFailure);
    }
    let incarnation_id = IncarnationId::from_bytes(reader.take()?);
    let genesis = Digest32::from_bytes(reader.take()?);
    let magic = reader.u32()?;
    let slots = reader.u64()?;
    let lifetime = reader.u8()?;
    let network =
        NetworkBinding::new(genesis, magic, slots, lifetime).map_err(|_| Error::StorageFailure)?;
    let publication_floor_us = reader.u64()?;
    let revision = reader.u64()?;
    let period_floor = reader.option_u64()?;
    let highest_certificate_counter = reader.option_u64()?;
    let publication = decode_publication(&mut reader)?;
    let active = decode_generation(&mut reader)?;
    let staged = decode_generation(&mut reader)?;
    let last_discard = decode_discard(&mut reader)?;
    reader.finish()?;
    Ok(DecodedPool {
        enrollment: Enrollment {
            pool_id,
            cold_verification_key,
            incarnation_id,
            network,
            publication_floor_us,
        },
        revision,
        period_floor,
        highest_certificate_counter,
        publication,
        active,
        staged,
        last_discard,
        _input: core::marker::PhantomData,
    })
}

fn encode_publication(writer: &mut Writer<'_>, publication: Publication) -> Result<(), Error> {
    writer.u64(publication.revision)?;
    match publication.kind {
        PublicationKind::None => writer.u8(0)?,
        PublicationKind::Key {
            generation,
            relative_period,
            certificate_digest,
        } => {
            writer.u8(1)?;
            writer.put(generation.as_bytes())?;
            writer.u8(relative_period)?;
            writer.put(certificate_digest.as_bytes())?;
        }
        PublicationKind::Drop => writer.u8(2)?,
    }
    writer.u64(publication.timestamp_us)?;
    writer.u64(publication.high_water_us)
}

fn decode_publication(reader: &mut Reader<'_>) -> Result<Publication, Error> {
    let revision = reader.u64()?;
    let kind = match reader.u8()? {
        0 => PublicationKind::None,
        1 => PublicationKind::Key {
            generation: GenerationId::from_bytes(reader.take()?),
            relative_period: reader.u8()?,
            certificate_digest: Digest32::from_bytes(reader.take()?),
        },
        2 => PublicationKind::Drop,
        _ => return Err(Error::StorageFailure),
    };
    let timestamp_us = reader.u64()?;
    let high_water_us = reader.u64()?;
    if timestamp_us > high_water_us {
        return Err(Error::StorageFailure);
    }
    Ok(Publication {
        revision,
        kind,
        timestamp_us,
        high_water_us,
    })
}

fn encode_discard(writer: &mut Writer<'_>, discarded: Option<DiscardRecord>) -> Result<(), Error> {
    let Some(discarded) = discarded else {
        return writer.u8(0);
    };
    writer.u8(1)?;
    writer.put(discarded.generation.as_bytes())?;
    writer.put(discarded.operation.as_bytes())?;
    writer.u64(discarded.revision)
}

fn decode_discard(reader: &mut Reader<'_>) -> Result<Option<DiscardRecord>, Error> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(DiscardRecord {
            generation: GenerationId::from_bytes(reader.take()?),
            operation: OperationId::from_bytes(reader.take()?),
            revision: reader.u64()?,
        })),
        _ => Err(Error::StorageFailure),
    }
}

fn encode_generation(
    writer: &mut Writer<'_>,
    generation: Option<&GenerationState>,
) -> Result<(), Error> {
    let Some(generation) = generation else {
        return writer.u8(0);
    };
    writer.u8(1)?;
    writer.put(generation.id.as_bytes())?;
    writer.u64(generation.number)?;
    writer.put(generation.operation.as_bytes())?;
    writer.u8(generation.key.period() as u8)?;
    match generation.certificate {
        Some(certificate) => {
            writer.u8(1)?;
            writer.put(&certificate.direct_bytes())?;
        }
        None => writer.u8(0)?,
    }
    writer.u8(generation.object_region)?;
    writer.u16(generation.object_len)?;
    writer.put(generation.object_digest.as_bytes())?;
    writer.put(generation.artifact_digest.as_bytes())?;
    writer.put(&generation.key.canonical_state())
}

fn decode_generation(reader: &mut Reader<'_>) -> Result<Option<EncodedGeneration>, Error> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let id = GenerationId::from_bytes(reader.take()?);
            let number = reader.u64()?;
            if number == 0 {
                return Err(Error::StorageFailure);
            }
            let operation = OperationId::from_bytes(reader.take()?);
            let period = reader.u8()?;
            let certificate = match reader.u8()? {
                0 => None,
                1 => {
                    let bytes = reader.take::<112>()?;
                    Some(Certificate::new(
                        bytes[..32].try_into().unwrap(),
                        u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
                        u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
                        bytes[48..].try_into().unwrap(),
                    ))
                }
                _ => return Err(Error::StorageFailure),
            };
            let object_region = reader.u8()?;
            if object_region > 1 {
                return Err(Error::StorageFailure);
            }
            let object_len = reader.u16()?;
            let object_digest = Digest32::from_bytes(reader.take()?);
            let artifact_digest = Digest32::from_bytes(reader.take()?);
            let state = reader.take()?;
            Ok(Some(EncodedGeneration {
                id,
                number,
                operation,
                period,
                certificate,
                object_region,
                object_len,
                object_digest,
                artifact_digest,
                state,
            }))
        }
        _ => Err(Error::StorageFailure),
    }
}

fn encode_object(object: &PublicObject, output: &mut [u8]) -> Result<usize, Error> {
    let mut writer = Writer::new(output);
    writer.put(OBJECT_MAGIC)?;
    writer.u16(1)?;
    writer.put(object.generation_id().as_bytes())?;
    writer.put(object.public_tree())?;
    writer.u16(object.artifact().len() as u16)?;
    writer.put(object.artifact())?;
    Ok(writer.finish())
}

fn decode_object(input: &[u8]) -> Result<PublicObject, Error> {
    let mut reader = Reader::new(input);
    if reader.take::<8>()? != *OBJECT_MAGIC || reader.u16()? != 1 {
        return Err(Error::StorageFailure);
    }
    let id = GenerationId::from_bytes(reader.take()?);
    let tree = reader.take::<PUBLIC_TREE_BYTES>()?;
    let artifact_len = usize::from(reader.u16()?);
    if artifact_len == 0 || artifact_len > MAX_ARTIFACT_LEN {
        return Err(Error::StorageFailure);
    }
    let artifact = reader.bytes(artifact_len)?;
    reader.finish()?;
    PublicObject::new(id, tree, artifact).map_err(|_| Error::StorageFailure)
}

struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn finish(self) -> usize {
        self.position
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(Error::StorageFailure)?;
        self.output
            .get_mut(self.position..end)
            .ok_or(Error::StorageFailure)?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.put(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.put(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.put(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.put(&value.to_be_bytes())
    }

    fn option_u64(&mut self, value: Option<u64>) -> Result<(), Error> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.u64(value)
            }
            None => self.u8(0),
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::StorageFailure)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(Error::StorageFailure)?;
        self.position = end;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes(N)?.try_into().map_err(|_| Error::StorageFailure)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn option_u64(&mut self) -> Result<Option<u64>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(Error::StorageFailure),
        }
    }

    fn finish(&self) -> Result<(), Error> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(Error::StorageFailure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_v2_round_trips_without_a_deletion() {
        let mut bytes = [0; MAX_SNAPSHOT_BYTES];
        let length = encode_config(&[1, 2, 3], None, 0, None, &mut bytes).unwrap();
        let decoded = decode_config(&bytes[..length]).unwrap();
        assert_eq!(decoded.initial, [1, 2, 3]);
        assert_eq!(decoded.occupied, 0);
        assert!(decoded.last_deletion.is_none());
    }

    #[test]
    fn pool_v2_round_trips_discard_recovery_identity() {
        let cold = [7; 32];
        let enrollment = Enrollment {
            pool_id: PoolId::from_cold_verification_key(&cold),
            cold_verification_key: cold,
            incarnation_id: IncarnationId::from_bytes([8; 16]),
            network: NetworkBinding::new(Digest32::from_bytes([9; 32]), 42, 100, 64).unwrap(),
            publication_floor_us: 11,
        };
        let target = PoolTarget {
            pool: enrollment.pool_id,
            incarnation: enrollment.incarnation_id,
        };
        let discarded = DiscardRecord {
            generation: GenerationId::from_bytes([10; 16]),
            operation: OperationId::from_bytes([12; 16]),
            revision: 4,
        };
        let publication = Publication {
            revision: 0,
            kind: PublicationKind::None,
            timestamp_us: 11,
            high_water_us: 11,
        };
        let mut bytes = [0; MAX_SNAPSHOT_BYTES];
        let length = encode_pool_fields(
            &enrollment,
            StorageSlot::new(0).unwrap(),
            4,
            None,
            None,
            publication,
            None,
            None,
            Some(discarded),
            &mut bytes,
        )
        .unwrap();
        let decoded = decode_pool_header(&bytes[..length], StorageSlot::new(0).unwrap()).unwrap();
        let recovered = decoded.last_discard.unwrap();
        assert_eq!(recovered.generation, discarded.generation);
        assert_eq!(recovered.operation, discarded.operation);
        assert_eq!(recovered.revision, discarded.revision);
        assert_eq!(decoded.publication.kind, PublicationKind::None);
        assert_eq!(target.pool, decoded.enrollment.pool_id);
    }
}
