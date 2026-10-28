//! Public mutation identities, exact retries and receipt handoff.
use crate::identity::{
    BoundedBytes, DeviceId, Digest32, GenerationId, IncarnationId, NetworkBinding, OperationId,
    PoolId, ValueError,
};
use sha2::{Digest, Sha256};

// USB strings and management arguments are bounded by the v1 frame.
pub type UsbSerial = BoundedBytes<4096>;
pub type CertificateBytes = BoundedBytes<4096>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolTarget {
    pub pool: PoolId,
    pub incarnation: IncarnationId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationTarget {
    pub pool: PoolTarget,
    pub generation: GenerationId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveTarget {
    Pool(PoolTarget),
    Generation(GenerationTarget),
}

// Fixed-size variants keep the no_std mutation path allocation-free.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Enroll {
        cold_key: [u8; 32],
        network: NetworkBinding,
        publication_floor_us: u64,
    },
    Generate {
        target: PoolTarget,
    },
    InstallCertificate {
        target: GenerationTarget,
        certificate: CertificateBytes,
    },
    Discard {
        target: GenerationTarget,
    },
    SetRecipient {
        public_key: [u8; 32],
    },
    Delete {
        target: PoolTarget,
        publication_time_us: Option<u64>,
    },
}
impl Action {
    pub fn pool_target(&self) -> Option<PoolTarget> {
        match self {
            Self::Generate { target } | Self::Delete { target, .. } => Some(*target),
            Self::InstallCertificate { target, .. } | Self::Discard { target } => Some(target.pool),
            _ => None,
        }
    }
    pub fn target(&self) -> Option<LiveTarget> {
        match self {
            Self::Generate { target } | Self::Delete { target, .. } => {
                Some(LiveTarget::Pool(*target))
            }
            Self::InstallCertificate { target, .. } | Self::Discard { target } => {
                Some(LiveTarget::Generation(*target))
            }
            _ => None,
        }
    }
    fn hash(&self, h: &mut Sha256, usb: bool) {
        fn pool(h: &mut Sha256, p: PoolTarget) {
            h.update(p.pool.as_bytes());
            h.update(p.incarnation.as_bytes());
        }
        fn generation(h: &mut Sha256, g: GenerationTarget) {
            pool(h, g.pool);
            h.update(g.generation.as_bytes());
        }
        match self {
            Self::Enroll {
                cold_key,
                network,
                publication_floor_us,
            } => {
                h.update([1]);
                h.update(cold_key);
                h.update(network.genesis().as_bytes());
                h.update(network.magic().to_be_bytes());
                h.update(network.slots_per_period().to_be_bytes());
                h.update([network.lifetime()]);
                if usb {
                    h.update(publication_floor_us.to_be_bytes());
                }
            }
            Self::Generate { target } => {
                h.update([2]);
                pool(h, *target);
            }
            Self::InstallCertificate {
                target,
                certificate,
            } => {
                h.update([3]);
                generation(h, *target);
                h.update((certificate.as_slice().len() as u32).to_be_bytes());
                h.update(certificate.as_slice());
            }
            Self::Discard { target } => {
                h.update([4]);
                generation(h, *target);
            }
            Self::SetRecipient { public_key } => {
                h.update([5]);
                h.update(public_key);
            }
            Self::Delete {
                target,
                publication_time_us,
            } => {
                h.update([6]);
                pool(h, *target);
                if usb {
                    match publication_time_us {
                        Some(t) => {
                            h.update([1]);
                            h.update(t.to_be_bytes());
                        }
                        None => h.update([0]),
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    Commission { serial: UsbSerial },
    Managed { device: DeviceId, action: Action },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mutation {
    sequence: u64,
    operation_id: OperationId,
    expected_revision: u64,
    binding: Binding,
    cli_digest: Digest32,
    usb_digest: Digest32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationError {
    InvalidSequence,
    InvalidRevision,
    InvalidSerial,
    SequenceExhausted,
    Busy,
    Conflict,
    TargetMismatch,
    RevisionConflict,
    WrongDevice,
    NotPending,
    NotTerminal,
    ReceiptMismatch,
    ResultMismatch,
}
impl Mutation {
    pub fn commission(
        serial: UsbSerial,
        operation_id: OperationId,
        expected_revision: u64,
    ) -> Result<Self, OperationError> {
        if serial.as_slice().is_empty() {
            return Err(OperationError::InvalidSerial);
        }
        if expected_revision != 0 {
            return Err(OperationError::InvalidRevision);
        }
        Ok(Self::build(
            0,
            operation_id,
            expected_revision,
            Binding::Commission { serial },
        ))
    }
    pub fn managed(
        device: DeviceId,
        sequence: u64,
        operation_id: OperationId,
        expected_revision: u64,
        action: Action,
    ) -> Result<Self, OperationError> {
        if sequence == 0 {
            return Err(OperationError::InvalidSequence);
        }
        Ok(Self::build(
            sequence,
            operation_id,
            expected_revision,
            Binding::Managed { device, action },
        ))
    }
    fn build(
        sequence: u64,
        operation_id: OperationId,
        expected_revision: u64,
        binding: Binding,
    ) -> Self {
        fn digest(
            sequence: u64,
            id: OperationId,
            revision: u64,
            binding: &Binding,
            usb: bool,
        ) -> Digest32 {
            let mut h = Sha256::new();
            h.update(if usb {
                b"pico2-kes-usb-v1\0".as_slice()
            } else {
                b"pico2-kes-cli-v1\0".as_slice()
            });
            h.update(id.as_bytes());
            h.update(revision.to_be_bytes());
            if usb {
                h.update(sequence.to_be_bytes());
            }
            match binding {
                Binding::Commission { serial } => {
                    h.update([0]);
                    h.update((serial.as_slice().len() as u32).to_be_bytes());
                    h.update(serial.as_slice());
                }
                Binding::Managed { device, action } => {
                    if usb {
                        h.update(device.as_bytes());
                    }
                    action.hash(&mut h, usb);
                }
            }
            Digest32::from_bytes(h.finalize().into())
        }
        Self {
            sequence,
            operation_id,
            expected_revision,
            binding,
            cli_digest: digest(sequence, operation_id, expected_revision, &binding, false),
            usb_digest: digest(sequence, operation_id, expected_revision, &binding, true),
        }
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    pub const fn binding(&self) -> &Binding {
        &self.binding
    }
    pub const fn cli_digest(&self) -> Digest32 {
        self.cli_digest
    }
    pub const fn usb_digest(&self) -> Digest32 {
        self.usb_digest
    }
    pub fn require_revision(&self, actual: u64) -> Result<(), OperationError> {
        if actual == self.expected_revision {
            Ok(())
        } else {
            Err(OperationError::RevisionConflict)
        }
    }
    pub fn reconcile(&self, retry: &Self) -> Result<(), OperationError> {
        if self == retry {
            Ok(())
        } else {
            Err(OperationError::Conflict)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommissioningRecord {
    device: DeviceId,
    identity_public_key: [u8; 32],
    identity_fingerprint: Digest32,
    serial: UsbSerial,
    protocol_version: u16,
    storage_version: u16,
    device_revision: u64,
    operation_id: OperationId,
    request_digest: Digest32,
}
impl CommissioningRecord {
    // Commissioning binds all fields in one atomic public record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device: DeviceId,
        identity_public_key: [u8; 32],
        serial: UsbSerial,
        protocol_version: u16,
        storage_version: u16,
        device_revision: u64,
        operation_id: OperationId,
        request_digest: Digest32,
    ) -> Self {
        Self {
            device,
            identity_public_key,
            identity_fingerprint: Digest32::from_bytes(Sha256::digest(identity_public_key).into()),
            serial,
            protocol_version,
            storage_version,
            device_revision,
            operation_id,
            request_digest,
        }
    }
    pub const fn version(&self) -> u16 {
        1
    }
    pub const fn device(&self) -> DeviceId {
        self.device
    }
    pub const fn identity_public_key(&self) -> &[u8; 32] {
        &self.identity_public_key
    }
    pub const fn identity_fingerprint(&self) -> Digest32 {
        self.identity_fingerprint
    }
    pub const fn serial(&self) -> &UsbSerial {
        &self.serial
    }
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }
    pub const fn storage_version(&self) -> u16 {
        self.storage_version
    }
    pub const fn device_revision(&self) -> u64 {
        self.device_revision
    }
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionPublication {
    target: PoolTarget,
    revision: u64,
    drop_timestamp_us: Option<u64>,
    high_water_us: u64,
}
impl DeletionPublication {
    pub fn new(
        target: PoolTarget,
        revision: u64,
        drop_timestamp_us: Option<u64>,
        high_water_us: u64,
    ) -> Result<Self, ValueError> {
        if let Some(timestamp) = drop_timestamp_us
            && timestamp != high_water_us
        {
            return Err(ValueError::OutOfRange);
        }
        Ok(Self {
            target,
            revision,
            drop_timestamp_us,
            high_water_us,
        })
    }
    pub const fn target(&self) -> PoolTarget {
        self.target
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn drop_timestamp_us(&self) -> Option<u64> {
        self.drop_timestamp_us
    }
    pub const fn high_water_us(&self) -> u64 {
        self.high_water_us
    }
}
// Fixed-size results remain copyable for bounded durable receipt handoff.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommittedResult {
    Commissioned(CommissioningRecord),
    Deleted(DeletionPublication),
    Enrolled {
        target: PoolTarget,
        revision: u64,
    },
    Generated {
        generation: GenerationId,
        revision: u64,
        artifact_digest: Digest32,
    },
    Applied {
        revision: u64,
    },
}
// Retaining the committed result inline avoids allocation in firmware.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    Pending,
    Committed(CommittedResult),
    Rejected { code: u16 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    mutation: Mutation,
    outcome: ReceiptOutcome,
    result_digest: Option<Digest32>,
}
impl Receipt {
    pub const fn mutation(&self) -> &Mutation {
        &self.mutation
    }
    pub const fn outcome(&self) -> &ReceiptOutcome {
        &self.outcome
    }
    pub const fn result_digest(&self) -> Option<Digest32> {
        self.result_digest
    }
}
fn receipt_digest(mutation: &Mutation, outcome: &ReceiptOutcome) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"pico2-kes-receipt-v1\0");
    h.update(mutation.usb_digest.as_bytes());
    match outcome {
        ReceiptOutcome::Pending => unreachable!(),
        ReceiptOutcome::Rejected { code } => {
            h.update([0]);
            h.update(code.to_be_bytes());
        }
        ReceiptOutcome::Committed(CommittedResult::Commissioned(r)) => {
            h.update([1]);
            h.update(r.device.as_bytes());
            h.update(r.identity_public_key);
            h.update(r.identity_fingerprint.as_bytes());
            h.update((r.serial.as_slice().len() as u32).to_be_bytes());
            h.update(r.serial.as_slice());
            h.update(r.protocol_version.to_be_bytes());
            h.update(r.storage_version.to_be_bytes());
            h.update(r.device_revision.to_be_bytes());
            h.update(r.operation_id.as_bytes());
            h.update(r.request_digest.as_bytes());
        }
        ReceiptOutcome::Committed(CommittedResult::Deleted(d)) => {
            h.update([2]);
            h.update(d.target.pool.as_bytes());
            h.update(d.target.incarnation.as_bytes());
            h.update(d.revision.to_be_bytes());
            match d.drop_timestamp_us {
                Some(t) => {
                    h.update([1]);
                    h.update(t.to_be_bytes());
                }
                None => h.update([0]),
            }
            h.update(d.high_water_us.to_be_bytes());
        }
        ReceiptOutcome::Committed(CommittedResult::Enrolled { target, revision }) => {
            h.update([3]);
            h.update(target.pool.as_bytes());
            h.update(target.incarnation.as_bytes());
            h.update(revision.to_be_bytes());
        }
        ReceiptOutcome::Committed(CommittedResult::Generated {
            generation,
            revision,
            artifact_digest,
        }) => {
            h.update([4]);
            h.update(generation.as_bytes());
            h.update(revision.to_be_bytes());
            h.update(artifact_digest.as_bytes());
        }
        ReceiptOutcome::Committed(CommittedResult::Applied { revision }) => {
            h.update([5]);
            h.update(revision.to_be_bytes());
        }
    }
    Digest32::from_bytes(h.finalize().into())
}

/// State to be persisted at each transition; persistence and fsync are owned by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handoff {
    device: Option<DeviceId>,
    next_sequence: Option<u64>,
    receipt: Option<Receipt>,
    commissioning: Option<CommissioningRecord>,
}
impl Handoff {
    pub const fn blank() -> Self {
        Self {
            device: None,
            next_sequence: Some(0),
            receipt: None,
            commissioning: None,
        }
    }
    pub const fn commissioned(record: CommissioningRecord, next_sequence: u64) -> Self {
        Self {
            device: Some(record.device),
            next_sequence: Some(next_sequence),
            receipt: None,
            commissioning: Some(record),
        }
    }
    pub const fn receipt(&self) -> Option<&Receipt> {
        self.receipt.as_ref()
    }
    pub const fn commissioning_record(&self) -> Option<&CommissioningRecord> {
        self.commissioning.as_ref()
    }
    pub const fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }
    pub const fn autonomous_admitted(&self) -> bool {
        true
    }
    pub fn admit(
        &mut self,
        mutation: Mutation,
        actual_revision: u64,
        actual_target: Option<LiveTarget>,
        selected_serial: Option<&UsbSerial>,
    ) -> Result<(), OperationError> {
        if self.receipt.is_some() {
            return Err(OperationError::Busy);
        }
        if self
            .next_sequence
            .ok_or(OperationError::SequenceExhausted)?
            != mutation.sequence
        {
            return Err(OperationError::InvalidSequence);
        }
        match (&mutation.binding, self.device) {
            (Binding::Commission { serial }, None)
                if selected_serial == Some(serial) && actual_target.is_none() => {}
            (Binding::Managed { device, action }, Some(pinned)) if *device == pinned => {
                if action.target() != actual_target {
                    return Err(OperationError::TargetMismatch);
                }
            }
            _ => return Err(OperationError::WrongDevice),
        }
        mutation.require_revision(actual_revision)?;
        self.receipt = Some(Receipt {
            mutation,
            outcome: ReceiptOutcome::Pending,
            result_digest: None,
        });
        Ok(())
    }
    pub fn reconcile(&self, mutation: &Mutation) -> Result<&Receipt, OperationError> {
        let receipt = self.receipt.as_ref().ok_or(OperationError::NotPending)?;
        receipt.mutation.reconcile(mutation)?;
        Ok(receipt)
    }
    pub fn reconcile_commissioning(
        &self,
        mutation: &Mutation,
    ) -> Result<&CommissioningRecord, OperationError> {
        let record = self
            .commissioning
            .as_ref()
            .ok_or(OperationError::NotPending)?;
        match mutation.binding() {
            Binding::Commission { serial }
                if *serial == record.serial
                    && mutation.operation_id == record.operation_id
                    && mutation.usb_digest == record.request_digest =>
            {
                Ok(record)
            }
            _ => Err(OperationError::Conflict),
        }
    }
    pub fn finish(&mut self, outcome: ReceiptOutcome) -> Result<(), OperationError> {
        let receipt = self.receipt.as_mut().ok_or(OperationError::NotPending)?;
        if receipt.outcome != ReceiptOutcome::Pending {
            return Err(OperationError::NotPending);
        }
        match (&receipt.mutation.binding, &outcome) {
            (_, ReceiptOutcome::Pending) => return Err(OperationError::NotTerminal),
            (
                Binding::Commission { serial },
                ReceiptOutcome::Committed(CommittedResult::Commissioned(record)),
            ) if *serial == record.serial
                && record.operation_id == receipt.mutation.operation_id
                && record.request_digest == receipt.mutation.usb_digest =>
            {
                self.device = Some(record.device);
                self.commissioning = Some(*record);
            }
            (
                Binding::Managed {
                    action: Action::Delete { target, .. },
                    ..
                },
                ReceiptOutcome::Committed(CommittedResult::Deleted(d)),
            ) if *target == d.target => (),
            (
                Binding::Managed {
                    action: Action::Enroll { cold_key, .. },
                    ..
                },
                ReceiptOutcome::Committed(CommittedResult::Enrolled { target, .. }),
            ) if target.pool == PoolId::from_cold_verification_key(cold_key) => (),
            (
                Binding::Managed {
                    action: Action::Generate { .. },
                    ..
                },
                ReceiptOutcome::Committed(CommittedResult::Generated { .. }),
            ) => (),
            (
                Binding::Managed {
                    action:
                        Action::InstallCertificate { .. }
                        | Action::Discard { .. }
                        | Action::SetRecipient { .. },
                    ..
                },
                ReceiptOutcome::Committed(CommittedResult::Applied { .. }),
            ) => (),
            (_, ReceiptOutcome::Rejected { .. }) => (),
            _ => return Err(OperationError::ResultMismatch),
        }
        receipt.result_digest = Some(receipt_digest(&receipt.mutation, &outcome));
        receipt.outcome = outcome;
        Ok(())
    }
    /// Call only after the public terminal receipt has been durably handed off.
    pub fn acknowledge(
        &mut self,
        sequence: u64,
        result_digest: Digest32,
    ) -> Result<(), OperationError> {
        let receipt = self.receipt.as_ref().ok_or(OperationError::NotPending)?;
        if receipt.result_digest.is_none() {
            return Err(OperationError::NotTerminal);
        }
        if receipt.mutation.sequence != sequence || receipt.result_digest != Some(result_digest) {
            return Err(OperationError::ReceiptMismatch);
        }
        // A rejected commissioning leaves the device blank, so a new ceremony still uses sequence zero.
        self.next_sequence = if self.device.is_none() {
            Some(0)
        } else {
            sequence.checked_add(1)
        };
        self.receipt = None;
        Ok(())
    }
}

pub const MAX_HANDOFF_BYTES: usize = 6_144;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffCodecError {
    Bounds,
    Invalid,
}

impl Handoff {
    pub fn recover_commissioning(record: CommissioningRecord) -> Result<Self, HandoffCodecError> {
        let mutation = Mutation::commission(record.serial, record.operation_id, 0)
            .map_err(|_| HandoffCodecError::Invalid)?;
        if mutation.usb_digest != record.request_digest {
            return Err(HandoffCodecError::Invalid);
        }
        let outcome = ReceiptOutcome::Committed(CommittedResult::Commissioned(record));
        Ok(Self {
            device: Some(record.device),
            next_sequence: Some(0),
            receipt: Some(Receipt {
                mutation,
                outcome,
                result_digest: Some(receipt_digest(&mutation, &outcome)),
            }),
            commissioning: Some(record),
        })
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, HandoffCodecError> {
        let mut writer = HandoffWriter::new(output);
        writer.put(b"PKAHOF01")?;
        writer.u16(1)?;
        match self.device {
            Some(device) => {
                writer.u8(1)?;
                writer.put(device.as_bytes())?;
            }
            None => writer.u8(0)?,
        }
        match self.next_sequence {
            Some(sequence) => {
                writer.u8(1)?;
                writer.u64(sequence)?;
            }
            None => writer.u8(0)?,
        }
        match self.commissioning {
            Some(record) => {
                writer.u8(1)?;
                encode_commissioning(record, &mut writer)?;
            }
            None => writer.u8(0)?,
        }
        match self.receipt {
            Some(receipt) => {
                writer.u8(1)?;
                encode_mutation(receipt.mutation, &mut writer)?;
                encode_outcome(receipt.outcome, &mut writer)?;
                match receipt.result_digest {
                    Some(digest) => {
                        writer.u8(1)?;
                        writer.put(digest.as_bytes())?;
                    }
                    None => writer.u8(0)?,
                }
            }
            None => writer.u8(0)?,
        }
        Ok(writer.finish())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HandoffCodecError> {
        let mut reader = HandoffReader::new(input);
        if reader.take::<8>()? != *b"PKAHOF01" || reader.u16()? != 1 {
            return Err(HandoffCodecError::Invalid);
        }
        let device = match reader.u8()? {
            0 => None,
            1 => Some(DeviceId::from_bytes(reader.take()?)),
            _ => return Err(HandoffCodecError::Invalid),
        };
        let next_sequence = match reader.u8()? {
            0 => None,
            1 => Some(reader.u64()?),
            _ => return Err(HandoffCodecError::Invalid),
        };
        let commissioning = match reader.u8()? {
            0 => None,
            1 => Some(decode_commissioning(&mut reader)?),
            _ => return Err(HandoffCodecError::Invalid),
        };
        let receipt = match reader.u8()? {
            0 => None,
            1 => {
                let mutation = decode_mutation(&mut reader)?;
                let outcome = decode_outcome(&mut reader)?;
                let result_digest = match reader.u8()? {
                    0 => None,
                    1 => Some(Digest32::from_bytes(reader.take()?)),
                    _ => return Err(HandoffCodecError::Invalid),
                };
                let expected = match outcome {
                    ReceiptOutcome::Pending => None,
                    _ => Some(receipt_digest(&mutation, &outcome)),
                };
                if result_digest != expected {
                    return Err(HandoffCodecError::Invalid);
                }
                Some(Receipt {
                    mutation,
                    outcome,
                    result_digest,
                })
            }
            _ => return Err(HandoffCodecError::Invalid),
        };
        reader.finish()?;
        if device != commissioning.map(|record| record.device)
            || receipt.as_ref().is_some_and(|receipt| {
                next_sequence != Some(receipt.mutation.sequence)
                    || match (receipt.mutation.binding, device) {
                        (Binding::Commission { .. }, None) => false,
                        (Binding::Managed { device: bound, .. }, Some(actual)) => bound != actual,
                        _ => true,
                    }
            })
            || device.is_none() && (commissioning.is_some() || next_sequence != Some(0))
        {
            return Err(HandoffCodecError::Invalid);
        }
        Ok(Self {
            device,
            next_sequence,
            receipt,
            commissioning,
        })
    }
}

fn encode_mutation(
    mutation: Mutation,
    writer: &mut HandoffWriter<'_>,
) -> Result<(), HandoffCodecError> {
    writer.u64(mutation.sequence)?;
    writer.put(mutation.operation_id.as_bytes())?;
    writer.u64(mutation.expected_revision)?;
    match mutation.binding {
        Binding::Commission { serial } => {
            writer.u8(0)?;
            writer.bytes(serial.as_slice())?;
        }
        Binding::Managed { device, action } => {
            writer.u8(1)?;
            writer.put(device.as_bytes())?;
            encode_action(action, writer)?;
        }
    }
    Ok(())
}

fn decode_mutation(reader: &mut HandoffReader<'_>) -> Result<Mutation, HandoffCodecError> {
    let sequence = reader.u64()?;
    let operation = OperationId::from_bytes(reader.take()?);
    let revision = reader.u64()?;
    match reader.u8()? {
        0 => {
            if sequence != 0 {
                return Err(HandoffCodecError::Invalid);
            }
            let serial = UsbSerial::new(reader.bytes()?).map_err(|_| HandoffCodecError::Invalid)?;
            Mutation::commission(serial, operation, revision)
                .map_err(|_| HandoffCodecError::Invalid)
        }
        1 => {
            let device = DeviceId::from_bytes(reader.take()?);
            let action = decode_action(reader)?;
            Mutation::managed(device, sequence, operation, revision, action)
                .map_err(|_| HandoffCodecError::Invalid)
        }
        _ => Err(HandoffCodecError::Invalid),
    }
}

fn encode_action(action: Action, writer: &mut HandoffWriter<'_>) -> Result<(), HandoffCodecError> {
    match action {
        Action::Enroll {
            cold_key,
            network,
            publication_floor_us,
        } => {
            writer.u8(1)?;
            writer.put(&cold_key)?;
            writer.put(network.genesis().as_bytes())?;
            writer.u32(network.magic())?;
            writer.u64(network.slots_per_period())?;
            writer.u8(network.lifetime())?;
            writer.u64(publication_floor_us)?;
        }
        Action::Generate { target } => {
            writer.u8(2)?;
            encode_pool_target(target, writer)?;
        }
        Action::InstallCertificate {
            target,
            certificate,
        } => {
            writer.u8(3)?;
            encode_generation_target(target, writer)?;
            writer.bytes(certificate.as_slice())?;
        }
        Action::Discard { target } => {
            writer.u8(4)?;
            encode_generation_target(target, writer)?;
        }
        Action::SetRecipient { public_key } => {
            writer.u8(5)?;
            writer.put(&public_key)?;
        }
        Action::Delete {
            target,
            publication_time_us,
        } => {
            writer.u8(6)?;
            encode_pool_target(target, writer)?;
            encode_optional_u64(publication_time_us, writer)?;
        }
    }
    Ok(())
}

fn decode_action(reader: &mut HandoffReader<'_>) -> Result<Action, HandoffCodecError> {
    Ok(match reader.u8()? {
        1 => Action::Enroll {
            cold_key: reader.take()?,
            network: NetworkBinding::new(
                Digest32::from_bytes(reader.take()?),
                reader.u32()?,
                reader.u64()?,
                reader.u8()?,
            )
            .map_err(|_| HandoffCodecError::Invalid)?,
            publication_floor_us: reader.u64()?,
        },
        2 => Action::Generate {
            target: decode_pool_target(reader)?,
        },
        3 => Action::InstallCertificate {
            target: decode_generation_target(reader)?,
            certificate: CertificateBytes::new(reader.bytes()?)
                .map_err(|_| HandoffCodecError::Invalid)?,
        },
        4 => Action::Discard {
            target: decode_generation_target(reader)?,
        },
        5 => Action::SetRecipient {
            public_key: reader.take()?,
        },
        6 => Action::Delete {
            target: decode_pool_target(reader)?,
            publication_time_us: decode_optional_u64(reader)?,
        },
        _ => return Err(HandoffCodecError::Invalid),
    })
}

fn encode_outcome(
    outcome: ReceiptOutcome,
    writer: &mut HandoffWriter<'_>,
) -> Result<(), HandoffCodecError> {
    match outcome {
        ReceiptOutcome::Pending => writer.u8(0),
        ReceiptOutcome::Rejected { code } => {
            writer.u8(1)?;
            writer.u16(code)
        }
        ReceiptOutcome::Committed(result) => {
            writer.u8(2)?;
            match result {
                CommittedResult::Commissioned(record) => {
                    writer.u8(1)?;
                    encode_commissioning(record, writer)
                }
                CommittedResult::Deleted(deleted) => {
                    writer.u8(2)?;
                    encode_pool_target(deleted.target, writer)?;
                    writer.u64(deleted.revision)?;
                    encode_optional_u64(deleted.drop_timestamp_us, writer)?;
                    writer.u64(deleted.high_water_us)
                }
                CommittedResult::Enrolled { target, revision } => {
                    writer.u8(3)?;
                    encode_pool_target(target, writer)?;
                    writer.u64(revision)
                }
                CommittedResult::Generated {
                    generation,
                    revision,
                    artifact_digest,
                } => {
                    writer.u8(4)?;
                    writer.put(generation.as_bytes())?;
                    writer.u64(revision)?;
                    writer.put(artifact_digest.as_bytes())
                }
                CommittedResult::Applied { revision } => {
                    writer.u8(5)?;
                    writer.u64(revision)
                }
            }
        }
    }
}

fn decode_outcome(reader: &mut HandoffReader<'_>) -> Result<ReceiptOutcome, HandoffCodecError> {
    Ok(match reader.u8()? {
        0 => ReceiptOutcome::Pending,
        1 => ReceiptOutcome::Rejected {
            code: reader.u16()?,
        },
        2 => ReceiptOutcome::Committed(match reader.u8()? {
            1 => CommittedResult::Commissioned(decode_commissioning(reader)?),
            2 => CommittedResult::Deleted(
                DeletionPublication::new(
                    decode_pool_target(reader)?,
                    reader.u64()?,
                    decode_optional_u64(reader)?,
                    reader.u64()?,
                )
                .map_err(|_| HandoffCodecError::Invalid)?,
            ),
            3 => CommittedResult::Enrolled {
                target: decode_pool_target(reader)?,
                revision: reader.u64()?,
            },
            4 => CommittedResult::Generated {
                generation: GenerationId::from_bytes(reader.take()?),
                revision: reader.u64()?,
                artifact_digest: Digest32::from_bytes(reader.take()?),
            },
            5 => CommittedResult::Applied {
                revision: reader.u64()?,
            },
            _ => return Err(HandoffCodecError::Invalid),
        }),
        _ => return Err(HandoffCodecError::Invalid),
    })
}

fn encode_commissioning(
    record: CommissioningRecord,
    writer: &mut HandoffWriter<'_>,
) -> Result<(), HandoffCodecError> {
    writer.put(record.device.as_bytes())?;
    writer.put(&record.identity_public_key)?;
    writer.bytes(record.serial.as_slice())?;
    writer.u16(record.protocol_version)?;
    writer.u16(record.storage_version)?;
    writer.u64(record.device_revision)?;
    writer.put(record.operation_id.as_bytes())?;
    writer.put(record.request_digest.as_bytes())
}

fn decode_commissioning(
    reader: &mut HandoffReader<'_>,
) -> Result<CommissioningRecord, HandoffCodecError> {
    let device = DeviceId::from_bytes(reader.take()?);
    let public_key = reader.take()?;
    let serial = UsbSerial::new(reader.bytes()?).map_err(|_| HandoffCodecError::Invalid)?;
    Ok(CommissioningRecord::new(
        device,
        public_key,
        serial,
        reader.u16()?,
        reader.u16()?,
        reader.u64()?,
        OperationId::from_bytes(reader.take()?),
        Digest32::from_bytes(reader.take()?),
    ))
}

fn encode_pool_target(
    target: PoolTarget,
    writer: &mut HandoffWriter<'_>,
) -> Result<(), HandoffCodecError> {
    writer.put(target.pool.as_bytes())?;
    writer.put(target.incarnation.as_bytes())
}

fn decode_pool_target(reader: &mut HandoffReader<'_>) -> Result<PoolTarget, HandoffCodecError> {
    Ok(PoolTarget {
        pool: PoolId::from_bytes(reader.take()?),
        incarnation: IncarnationId::from_bytes(reader.take()?),
    })
}

fn encode_generation_target(
    target: GenerationTarget,
    writer: &mut HandoffWriter<'_>,
) -> Result<(), HandoffCodecError> {
    encode_pool_target(target.pool, writer)?;
    writer.put(target.generation.as_bytes())
}

fn decode_generation_target(
    reader: &mut HandoffReader<'_>,
) -> Result<GenerationTarget, HandoffCodecError> {
    Ok(GenerationTarget {
        pool: decode_pool_target(reader)?,
        generation: GenerationId::from_bytes(reader.take()?),
    })
}

fn encode_optional_u64(
    value: Option<u64>,
    writer: &mut HandoffWriter<'_>,
) -> Result<(), HandoffCodecError> {
    match value {
        Some(value) => {
            writer.u8(1)?;
            writer.u64(value)
        }
        None => writer.u8(0),
    }
}

fn decode_optional_u64(reader: &mut HandoffReader<'_>) -> Result<Option<u64>, HandoffCodecError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u64()?)),
        _ => Err(HandoffCodecError::Invalid),
    }
}

struct HandoffWriter<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> HandoffWriter<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }
    fn put(&mut self, bytes: &[u8]) -> Result<(), HandoffCodecError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(HandoffCodecError::Bounds)?;
        let destination = self
            .output
            .get_mut(self.position..end)
            .ok_or(HandoffCodecError::Bounds)?;
        destination.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
    fn u8(&mut self, value: u8) -> Result<(), HandoffCodecError> {
        self.put(&[value])
    }
    fn u16(&mut self, value: u16) -> Result<(), HandoffCodecError> {
        self.put(&value.to_be_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), HandoffCodecError> {
        self.put(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), HandoffCodecError> {
        self.put(&value.to_be_bytes())
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), HandoffCodecError> {
        let length = u16::try_from(bytes.len()).map_err(|_| HandoffCodecError::Bounds)?;
        self.u16(length)?;
        self.put(bytes)
    }
    const fn finish(self) -> usize {
        self.position
    }
}

struct HandoffReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> HandoffReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    fn slice(&mut self, length: usize) -> Result<&'a [u8], HandoffCodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HandoffCodecError::Bounds)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(HandoffCodecError::Bounds)?;
        self.position = end;
        Ok(value)
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], HandoffCodecError> {
        self.slice(N)?
            .try_into()
            .map_err(|_| HandoffCodecError::Bounds)
    }
    fn u8(&mut self) -> Result<u8, HandoffCodecError> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, HandoffCodecError> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32, HandoffCodecError> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, HandoffCodecError> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn bytes(&mut self) -> Result<&'a [u8], HandoffCodecError> {
        let length = usize::from(self.u16()?);
        self.slice(length)
    }
    fn finish(self) -> Result<(), HandoffCodecError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(HandoffCodecError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u8) -> OperationId {
        OperationId::from_bytes([n; 16])
    }
    fn device(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }
    fn target(n: u8) -> PoolTarget {
        PoolTarget {
            pool: PoolId::from_bytes([n; 28]),
            incarnation: IncarnationId::from_bytes([n; 16]),
        }
    }
    fn serial() -> UsbSerial {
        UsbSerial::new(b"board-1").unwrap()
    }
    fn commissioned() -> (Handoff, Mutation) {
        let mut h = Handoff::blank();
        let mutation = Mutation::commission(serial(), id(1), 0).unwrap();
        h.admit(mutation, 0, None, Some(&serial())).unwrap();
        let record = CommissioningRecord::new(
            device(1),
            [3; 32],
            serial(),
            1,
            1,
            0,
            id(1),
            mutation.usb_digest(),
        );
        h.finish(ReceiptOutcome::Committed(CommittedResult::Commissioned(
            record,
        )))
        .unwrap();
        let digest = h.receipt().unwrap().result_digest().unwrap();
        h.acknowledge(0, digest).unwrap();
        (h, mutation)
    }
    #[test]
    fn commissioning_binds_serial_and_sequence() {
        assert_eq!(
            Mutation::commission(serial(), id(1), 1),
            Err(OperationError::InvalidRevision)
        );
        assert_eq!(
            Mutation::managed(
                device(1),
                0,
                id(2),
                0,
                Action::SetRecipient {
                    public_key: [0; 32]
                }
            ),
            Err(OperationError::InvalidSequence)
        );
        let mut h = Handoff::blank();
        let m = Mutation::commission(serial(), id(1), 0).unwrap();
        assert_eq!(
            h.admit(m, 0, None, Some(&UsbSerial::new(b"other").unwrap())),
            Err(OperationError::WrongDevice)
        );
        let (h, original) = commissioned();
        assert!(h.reconcile_commissioning(&original).is_ok());
        let changed = Mutation::commission(serial(), id(2), 0).unwrap();
        assert_eq!(
            h.reconcile_commissioning(&changed),
            Err(OperationError::Conflict)
        );
    }
    #[test]
    fn retry_binds_exact_derived_arguments_and_live_target() {
        let (mut h, _) = commissioned();
        let network = NetworkBinding::new(Digest32::from_bytes([5; 32]), 42, 100, 64).unwrap();
        let a = Mutation::managed(
            device(1),
            1,
            id(3),
            0,
            Action::Enroll {
                cold_key: [7; 32],
                network,
                publication_floor_us: 10,
            },
        )
        .unwrap();
        let b = Mutation::managed(
            device(1),
            1,
            id(3),
            0,
            Action::Enroll {
                cold_key: [7; 32],
                network,
                publication_floor_us: 11,
            },
        )
        .unwrap();
        assert_eq!(a.cli_digest(), b.cli_digest());
        assert_ne!(a.usb_digest(), b.usb_digest());
        h.admit(a, 0, None, None).unwrap();
        assert!(h.reconcile(&a).is_ok());
        assert_eq!(h.reconcile(&b), Err(OperationError::Conflict));
        let (mut h, _) = commissioned();
        let generation_target = GenerationTarget {
            pool: target(2),
            generation: GenerationId::from_bytes([1; 16]),
        };
        let other = GenerationTarget {
            generation: GenerationId::from_bytes([2; 16]),
            ..generation_target
        };
        let m = Mutation::managed(
            device(1),
            1,
            id(4),
            9,
            Action::Discard {
                target: generation_target,
            },
        )
        .unwrap();
        assert_eq!(
            h.admit(m, 9, Some(LiveTarget::Generation(other)), None),
            Err(OperationError::TargetMismatch)
        );
        assert_eq!(
            h.admit(m, 10, Some(LiveTarget::Generation(generation_target)), None),
            Err(OperationError::RevisionConflict)
        );
        assert!(
            h.admit(m, 9, Some(LiveTarget::Generation(generation_target)), None)
                .is_ok()
        );
    }
    #[test]
    fn receipt_handoff_blocks_managed_not_autonomous() {
        let (mut h, _) = commissioned();
        let m = Mutation::managed(
            device(1),
            1,
            id(3),
            3,
            Action::Delete {
                target: target(1),
                publication_time_us: None,
            },
        )
        .unwrap();
        h.admit(m, 3, Some(LiveTarget::Pool(target(1))), None)
            .unwrap();
        assert!(h.autonomous_admitted());
        assert_eq!(
            h.acknowledge(1, Digest32::from_bytes([0; 32])),
            Err(OperationError::NotTerminal)
        );
        assert!(DeletionPublication::new(target(1), 4, Some(10), 11).is_err());
        let deletion = DeletionPublication::new(target(1), 4, Some(11), 11).unwrap();
        h.finish(ReceiptOutcome::Committed(CommittedResult::Deleted(
            deletion,
        )))
        .unwrap();
        let digest = h.receipt().unwrap().result_digest().unwrap();
        let next = Mutation::managed(
            device(1),
            2,
            id(4),
            4,
            Action::SetRecipient {
                public_key: [3; 32],
            },
        )
        .unwrap();
        assert_eq!(h.admit(next, 4, None, None), Err(OperationError::Busy));
        assert_eq!(
            h.acknowledge(1, Digest32::from_bytes([0; 32])),
            Err(OperationError::ReceiptMismatch)
        );
        assert_eq!(
            h.acknowledge(0, digest),
            Err(OperationError::ReceiptMismatch)
        );
        assert!(h.autonomous_admitted());
        h.acknowledge(1, digest).unwrap();
        assert!(h.admit(next, 4, None, None).is_ok());
    }
    #[test]
    fn durable_handoff_round_trips_idle_pending_and_terminal_states() {
        let (idle, _) = commissioned();
        let mut encoded = [0; MAX_HANDOFF_BYTES];
        let len = idle.encode(&mut encoded).unwrap();
        assert_eq!(Handoff::decode(&encoded[..len]), Ok(idle));

        let mut pending = idle;
        let generation = GenerationTarget {
            pool: target(4),
            generation: GenerationId::from_bytes([5; 16]),
        };
        let mutation = Mutation::managed(
            device(1),
            1,
            id(6),
            12,
            Action::InstallCertificate {
                target: generation,
                certificate: CertificateBytes::new(&[9; 4096]).unwrap(),
            },
        )
        .unwrap();
        pending
            .admit(mutation, 12, Some(LiveTarget::Generation(generation)), None)
            .unwrap();
        let len = pending.encode(&mut encoded).unwrap();
        assert_eq!(Handoff::decode(&encoded[..len]), Ok(pending));

        pending
            .finish(ReceiptOutcome::Committed(CommittedResult::Applied {
                revision: 13,
            }))
            .unwrap();
        let len = pending.encode(&mut encoded).unwrap();
        assert_eq!(Handoff::decode(&encoded[..len]), Ok(pending));
        encoded[len - 1] ^= 1;
        assert_eq!(
            Handoff::decode(&encoded[..len]),
            Err(HandoffCodecError::Invalid)
        );
    }

    #[test]
    fn commissioning_record_reconstructs_the_lost_terminal_handoff() {
        let (_, mutation) = commissioned();
        let record = CommissioningRecord::new(
            device(1),
            [3; 32],
            serial(),
            1,
            1,
            0,
            id(1),
            mutation.usb_digest(),
        );
        let recovered = Handoff::recover_commissioning(record).unwrap();
        let receipt = recovered.receipt().unwrap();
        assert_eq!(receipt.mutation(), &mutation);
        assert!(matches!(
            receipt.outcome(),
            ReceiptOutcome::Committed(CommittedResult::Commissioned(value)) if *value == record
        ));
    }
}
