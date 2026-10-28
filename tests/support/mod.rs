#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use kes_core::{
    certificate::{Certificate, OperationalCertificate},
    device::HardwareIdentity,
    identity::{
        DeviceId, Digest32, GenerationId, IncarnationId, NetworkBinding, OperationId, PoolId,
    },
    lifecycle::{
        CommissionRequest, Context, Device, Enrollment, Error as LifecycleError,
        PublicationKind as CorePublicationKind,
    },
    operation::{
        Action, Binding, CommittedResult, DeletionPublication, Handoff, LiveTarget, Mutation,
        OperationError, PoolTarget, Receipt, ReceiptOutcome, UsbSerial,
    },
    platform::{Entropy, EntropyError, Flash, FlashError, Geometry, SECTOR_SIZE},
};
use kes_protocol::usb::{self as wire, PublicOutcome, Request, Response};
use pico2_kes_agent::{
    cli,
    config::{Config, PoolBinding, RunMode},
    daemon::{
        context::{EraSegment, NetworkConfig, NetworkSelector},
        journal::{Journal, MutationKey},
        management::Management,
        node_service::{PoolSubscription, PublicationKind, PublicationUpdate},
        usb::{DeviceTransport, Error as UsbError, IdentityPin, Reply, UsbSelection},
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const CAPACITY: u32 = 0x400000;
const SERIAL: &[u8] = b"attended-board01";
static NEXT_RIG: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cut {
    BeforeCommit,
    AfterCommit,
    AfterCleanBeforeUsbReply,
    BeforePinPublication,
    PartialFirstWrite,
}

#[derive(Debug)]
pub struct CliResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Generation {
    pub id: String,
    raw: GenerationId,
}

#[derive(Debug, Clone, Copy)]
pub struct RigError(&'static str);
impl RigError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}
impl std::fmt::Display for RigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for RigError {}

#[derive(Clone)]
struct ModelFlash {
    geometry: Geometry,
    bytes: Vec<u8>,
}
impl ModelFlash {
    fn blank() -> Self {
        Self {
            geometry: Geometry::new(CAPACITY, 256, 4096).unwrap(),
            bytes: vec![0xff; CAPACITY as usize],
        }
    }
}
impl Flash for ModelFlash {
    fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.geometry.range(address, output.len())?;
        output.copy_from_slice(&self.bytes[address as usize..address as usize + output.len()]);
        Ok(())
    }
    fn read_marker(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.read(address, output)
    }
    fn program_page(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.geometry.program(address, data.len())?;
        let bytes = &mut self.bytes[address as usize..address as usize + data.len()];
        if bytes.iter().zip(data).any(|(&old, &new)| old & new != new) {
            return Err(FlashError::RequiresErase);
        }
        for (old, new) in bytes.iter_mut().zip(data) {
            *old &= *new;
        }
        Ok(())
    }
    fn program_marker(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.program_page(address, data)
    }
    fn erase_sector(&mut self, address: u32) -> Result<(), FlashError> {
        self.geometry.erase(address)?;
        self.bytes[address as usize..address as usize + SECTOR_SIZE as usize].fill(0xff);
        Ok(())
    }
}

struct EntropyStream(u64);
impl Entropy for EntropyStream {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}
type TestDevice = Device<ModelFlash, EntropyStream>;

fn open_device(flash: ModelFlash) -> TestDevice {
    Device::open_with_root(
        flash,
        EntropyStream(0x1234_5678_9abc_def1),
        [0x42; 32],
        HardwareIdentity::new(Digest32::from_bytes([1; 32]), Digest32::from_bytes([2; 32])),
    )
    .unwrap()
}

struct Emulator {
    device: Option<TestDevice>,
    handoff: Handoff,
    serial: UsbSerial,
    outstanding: Option<(u64, Digest32)>,
    lose_next_reply: bool,
    commission_cut: Option<Cut>,
    unavailable: bool,
    disconnected: bool,
    wrong_identity: bool,
    last_generation: Option<GenerationId>,
}

struct ContextInput {
    target: PoolTarget,
    network: NetworkBinding,
    period: u64,
    session: u64,
    sequence: u64,
    lease_seconds: u8,
    publication_time_us: u64,
}

impl Emulator {
    fn blank(serial: &[u8]) -> Self {
        Self {
            device: Some(open_device(ModelFlash::blank())),
            handoff: Handoff::blank(),
            serial: UsbSerial::new(serial).unwrap(),
            outstanding: None,
            lose_next_reply: false,
            commission_cut: None,
            unavailable: false,
            disconnected: false,
            wrong_identity: false,
            last_generation: None,
        }
    }

    fn device(&self) -> &TestDevice {
        self.device.as_ref().unwrap()
    }
    fn device_mut(&mut self) -> &mut TestDevice {
        self.device.as_mut().unwrap()
    }

    fn encode(&self, response: &Response<'_>) -> Result<Reply, UsbError> {
        let mut output = [0; wire::MAX_PAYLOAD];
        let (kind, len) =
            wire::encode_response(response, &mut output).map_err(|_| UsbError::Protocol)?;
        Ok(Reply::from_parts(kind, output[..len].to_vec()))
    }

    fn status(&mut self, pool: Option<PoolId>) -> Result<Reply, UsbError> {
        if self.unavailable {
            return self.encode(&Response::Status(wire::StatusResponse {
                device: DeviceId::from_bytes([0; 16]),
                revision: 0,
                health: 12,
                commissioning_state: 2,
                receipt_pending: self.handoff.receipt().is_some(),
                pool: None,
                next_pool: None,
            }));
        }
        let (device, revision, commissioning_state) = match self.device().identity() {
            Some(identity) => (
                identity.enrollment_record().public().device(),
                self.device().revision().unwrap_or(0),
                1,
            ),
            None => (DeviceId::from_bytes([0; 16]), 0, 0),
        };
        let pool = pool
            .and_then(|pool_id| self.device_mut().pool_status(pool_id).ok())
            .map(|status| wire::PoolStatus {
                target: PoolTarget {
                    pool: status.pool_id,
                    incarnation: status.incarnation_id,
                },
                revision: status.revision,
                health: 0,
                active: None,
                staged: None,
                publication: publication(status.publication),
            });
        self.encode(&Response::Status(wire::StatusResponse {
            device,
            revision,
            health: 0,
            commissioning_state,
            receipt_pending: self.handoff.receipt().is_some(),
            pool,
            next_pool: None,
        }))
    }

    fn public_receipt(receipt: &Receipt) -> wire::PublicReceipt {
        let mutation = receipt.mutation();
        let binding = match mutation.binding() {
            Binding::Commission { serial } => wire::ReceiptBinding::Serial(*serial),
            Binding::Managed { device, .. } => wire::ReceiptBinding::Device(*device),
        };
        let target = match mutation.binding() {
            Binding::Managed { action, .. } => action.target(),
            Binding::Commission { .. } => None,
        };
        let outcome = match receipt.outcome() {
            ReceiptOutcome::Pending => PublicOutcome::Pending,
            ReceiptOutcome::Committed(result) => PublicOutcome::Committed {
                result: *result,
                result_digest: receipt.result_digest().unwrap(),
            },
            ReceiptOutcome::Rejected { code } => PublicOutcome::Rejected {
                code: *code,
                result_digest: receipt.result_digest().unwrap(),
            },
        };
        wire::PublicReceipt {
            sequence: mutation.sequence(),
            operation_id: mutation.operation_id(),
            request_digest: mutation.usb_digest(),
            binding,
            target,
            outcome,
        }
    }

    fn reject(
        &mut self,
        mutation: Mutation,
        error: u16,
        commission: bool,
    ) -> Result<Reply, UsbError> {
        let revision = self.actual_revision(&mutation);
        let target = self.actual_target(&mutation);
        let _ = self
            .handoff
            .admit(mutation, revision, target, Some(&self.serial));
        if self.handoff.receipt().is_some() {
            self.handoff
                .finish(ReceiptOutcome::Rejected { code: error })
                .map_err(|_| UsbError::Protocol)?;
        }
        let receipt =
            self.handoff
                .receipt()
                .map(Self::public_receipt)
                .unwrap_or(wire::PublicReceipt {
                    sequence: mutation.sequence(),
                    operation_id: mutation.operation_id(),
                    request_digest: mutation.usb_digest(),
                    binding: match mutation.binding() {
                        Binding::Commission { serial } => wire::ReceiptBinding::Serial(*serial),
                        Binding::Managed { device, .. } => wire::ReceiptBinding::Device(*device),
                    },
                    target: None,
                    outcome: PublicOutcome::Unknown,
                });
        self.encode(&if commission {
            Response::Commission(receipt)
        } else {
            Response::Mutate(receipt)
        })
    }

    fn actual_revision(&mut self, mutation: &Mutation) -> u64 {
        match mutation.binding() {
            Binding::Commission { .. } => 0,
            Binding::Managed { action, .. } => action
                .pool_target()
                .and_then(|target| self.device_mut().pool_status(target.pool).ok())
                .map_or_else(
                    || self.device().revision().unwrap_or(u64::MAX),
                    |status| status.revision,
                ),
        }
    }

    fn actual_target(&mut self, mutation: &Mutation) -> Option<LiveTarget> {
        match mutation.binding() {
            Binding::Commission { .. } => None,
            Binding::Managed { action, .. } => action.target(),
        }
    }

    fn mutate(&mut self, mutation: Mutation, commission: bool) -> Result<Reply, UsbError> {
        if commission && self.commission_cut == Some(Cut::PartialFirstWrite) {
            self.commission_cut = None;
            self.device_mut()
                .flash_mut()
                .program_page(0x100000, &[0x00; 32])
                .map_err(|_| UsbError::Protocol)?;
            self.unavailable = true;
            return self.reject(
                mutation,
                lifecycle_code(LifecycleError::StorageFailure),
                true,
            );
        }
        let revision = self.actual_revision(&mutation);
        let target = self.actual_target(&mutation);
        if let Err(error) = self
            .handoff
            .admit(mutation, revision, target, Some(&self.serial))
        {
            return self.rejected_without_handoff(mutation, operation_code(error), commission);
        }
        let result = if commission {
            let serial = self.serial;
            self.device_mut()
                .commission_values(
                    serial.as_slice(),
                    mutation.operation_id(),
                    mutation.usb_digest(),
                    mutation.expected_revision(),
                    mutation.sequence(),
                )
                .map(|record| CommittedResult::Commissioned(*record.public()))
        } else {
            self.apply_action(
                *match mutation.binding() {
                    Binding::Managed { action, .. } => action,
                    _ => return Err(UsbError::Protocol),
                },
                mutation.operation_id(),
            )
        };
        let outcome = match result {
            Ok(result) => ReceiptOutcome::Committed(result),
            Err(error) => ReceiptOutcome::Rejected {
                code: lifecycle_code(error),
            },
        };
        self.handoff
            .finish(outcome)
            .map_err(|_| UsbError::Protocol)?;
        let receipt = Self::public_receipt(self.handoff.receipt().unwrap());
        let response = self.encode(&if commission {
            Response::Commission(receipt)
        } else {
            Response::Mutate(receipt)
        })?;
        let lose = self.lose_next_reply
            || matches!(
                self.commission_cut.take(),
                Some(Cut::AfterCommit | Cut::AfterCleanBeforeUsbReply)
            );
        if lose {
            self.lose_next_reply = false;
            self.outstanding = Some((mutation.sequence(), mutation.usb_digest()));
            return Err(UsbError::Uncertain {
                sequence: mutation.sequence(),
                digest: mutation.usb_digest(),
            });
        }
        self.outstanding = Some((mutation.sequence(), mutation.usb_digest()));
        Ok(response)
    }

    fn rejected_without_handoff(
        &self,
        mutation: Mutation,
        code: u16,
        commission: bool,
    ) -> Result<Reply, UsbError> {
        let mut hash = Sha256::new();
        hash.update(b"pico2-kes-receipt-v1\0");
        hash.update(mutation.usb_digest().as_bytes());
        hash.update([0]);
        hash.update(code.to_be_bytes());
        let receipt = wire::PublicReceipt {
            sequence: mutation.sequence(),
            operation_id: mutation.operation_id(),
            request_digest: mutation.usb_digest(),
            binding: match mutation.binding() {
                Binding::Commission { serial } => wire::ReceiptBinding::Serial(*serial),
                Binding::Managed { device, .. } => wire::ReceiptBinding::Device(*device),
            },
            target: match mutation.binding() {
                Binding::Managed { action, .. } => action.target(),
                _ => None,
            },
            outcome: PublicOutcome::Rejected {
                code,
                result_digest: Digest32::from_bytes(hash.finalize().into()),
            },
        };
        self.encode(&if commission {
            Response::Commission(receipt)
        } else {
            Response::Mutate(receipt)
        })
    }

    fn apply_action(
        &mut self,
        action: Action,
        operation: OperationId,
    ) -> Result<CommittedResult, LifecycleError> {
        match action {
            Action::Enroll {
                cold_key,
                network,
                publication_floor_us,
            } => {
                let target =
                    self.device_mut()
                        .enroll_generated(cold_key, network, publication_floor_us)?;
                let revision = self.device_mut().pool_status(target.pool)?.revision;
                Ok(CommittedResult::Enrolled { target, revision })
            }
            Action::Generate { target } => {
                require_target(self.device_mut(), target)?;
                let generation = self.device_mut().generate(target.pool, operation)?;
                let info = self.device_mut().generation_info(target.pool, generation)?;
                self.last_generation = Some(generation);
                Ok(CommittedResult::Generated {
                    generation,
                    revision: info.revision,
                    artifact_digest: info.artifact_digest,
                })
            }
            Action::InstallCertificate {
                target,
                certificate,
            } => {
                require_target(self.device_mut(), target.pool)?;
                let cert = OperationalCertificate::decode(certificate.as_slice())
                    .map_err(|_| LifecycleError::CertificateInvalid)?;
                self.device_mut().install_certificate(
                    target.pool.pool,
                    target.generation,
                    cert.certificate(),
                )?;
                Ok(CommittedResult::Applied {
                    revision: self.device_mut().pool_status(target.pool.pool)?.revision,
                })
            }
            Action::Discard { target } => {
                self.device_mut().discard(
                    target.pool.pool,
                    target.pool.incarnation,
                    target.generation,
                    operation,
                )?;
                Ok(CommittedResult::Applied {
                    revision: self.device_mut().pool_status(target.pool.pool)?.revision,
                })
            }
            Action::SetRecipient { public_key } => {
                self.device_mut().set_recipient(public_key)?;
                Ok(CommittedResult::Applied {
                    revision: self.device().revision()?,
                })
            }
            Action::Delete {
                target,
                publication_time_us,
            } => {
                require_target(self.device_mut(), target)?;
                let terminal = self
                    .device_mut()
                    .delete_pool(target.pool, publication_time_us)?;
                let deleted = DeletionPublication::new(
                    target,
                    terminal.revision,
                    Some(terminal.timestamp_us),
                    terminal.high_water_us,
                )
                .map_err(|_| LifecycleError::InvalidRequest)?;
                Ok(CommittedResult::Deleted(deleted))
            }
        }
    }

    fn context(&mut self, input: ContextInput) -> Result<Reply, UsbError> {
        let ContextInput {
            target,
            network,
            period,
            session,
            sequence,
            lease_seconds,
            publication_time_us,
        } = input;
        let mut session_bytes = [0; 16];
        session_bytes[8..].copy_from_slice(&session.to_be_bytes());
        let context = Context {
            pool_id: target.pool,
            incarnation_id: target.incarnation,
            network,
            absolute_period: period,
            publication_time_us,
            session: session_bytes,
            sequence,
            observed_us: 100,
            lease_us: u64::from(lease_seconds) * 1_000_000,
        };
        let result = self
            .device_mut()
            .accept_context(&context, 100)
            .map_err(lifecycle_code);
        let floor = self
            .device_mut()
            .pool_status(target.pool)
            .ok()
            .and_then(|status| status.period_floor)
            .unwrap_or(0);
        self.encode(&Response::Context(wire::ContextResponse {
            target,
            session,
            sequence,
            floor,
            result,
        }))
    }

    fn current(&mut self, target: PoolTarget) -> Result<Reply, UsbError> {
        let result = self
            .device_mut()
            .current(target.pool, target.incarnation, 100);
        let mut output = [0; wire::MAX_PAYLOAD];
        let len = match result {
            Ok(current) => {
                let certificate = current.certificate.direct_bytes();
                let wire_publication = publication(current.publication);
                wire::encode_current_response(
                    &wire::CurrentResponse {
                        target,
                        snapshot_revision: current.revision,
                        publication: wire_publication,
                        result: wire::CurrentResult::Key {
                            generation: current.generation_id,
                            period: u64::from(current.relative_period),
                            state: &current.state,
                            certificate: &certificate,
                        },
                    },
                    &mut output,
                )
                .map_err(|_| UsbError::Protocol)?
            }
            Err(error) => {
                let status = self
                    .device_mut()
                    .pool_status(target.pool)
                    .map_err(|_| UsbError::Protocol)?;
                let result = if error == LifecycleError::Expired {
                    wire::CurrentResult::Drop
                } else {
                    wire::CurrentResult::Unavailable {
                        code: lifecycle_code(error),
                    }
                };
                wire::encode_current_response(
                    &wire::CurrentResponse {
                        target,
                        snapshot_revision: status.revision,
                        publication: publication(status.publication),
                        result,
                    },
                    &mut output,
                )
                .map_err(|_| UsbError::Protocol)?
            }
        };
        Ok(Reply::from_parts(
            wire::Kind::Current,
            output[..len].to_vec(),
        ))
    }
}

impl DeviceTransport for Emulator {
    fn request(&mut self, request: &Request) -> Result<Reply, UsbError> {
        if self.disconnected {
            return Err(UsbError::NotFound);
        }
        if self.wrong_identity {
            return Err(UsbError::IdentityMismatch);
        }
        match request {
            Request::Status { pool } => self.status(*pool),
            Request::Commission(mutation) => self.mutate(*mutation, true),
            Request::Mutate(mutation) => self.mutate(*mutation, false),
            Request::ReceiptAck {
                sequence,
                result_digest,
            } => {
                let result = self
                    .handoff
                    .acknowledge(*sequence, *result_digest)
                    .map_err(operation_code);
                self.encode(&Response::ReceiptAck(wire::ReceiptAckResponse {
                    sequence: *sequence,
                    result_digest: *result_digest,
                    result,
                }))
            }
            Request::Reconcile {
                sequence,
                operation_id,
                digest,
                binding,
            } => {
                let receipt = self
                    .handoff
                    .receipt()
                    .filter(|receipt| {
                        receipt.mutation().sequence() == *sequence
                            && receipt.mutation().operation_id() == *operation_id
                            && receipt.mutation().usb_digest() == *digest
                    })
                    .map(Self::public_receipt)
                    .unwrap_or(wire::PublicReceipt {
                        sequence: *sequence,
                        operation_id: *operation_id,
                        request_digest: *digest,
                        binding: match binding {
                            wire::ReconcileBinding::Serial(serial) => {
                                wire::ReceiptBinding::Serial(*serial)
                            }
                            wire::ReconcileBinding::Device(device) => {
                                wire::ReceiptBinding::Device(*device)
                            }
                        },
                        target: None,
                        outcome: PublicOutcome::Unknown,
                    });
                self.encode(&Response::Reconcile(receipt))
            }
            Request::Context {
                target,
                network,
                period,
                session,
                sequence,
                lease_seconds,
                publication_time_us,
            } => self.context(ContextInput {
                target: *target,
                network: *network,
                period: *period,
                session: *session,
                sequence: *sequence,
                lease_seconds: *lease_seconds,
                publication_time_us: *publication_time_us,
            }),
            Request::Current { target } => self.current(*target),
            Request::PublicKey { target } => {
                let result = self
                    .device_mut()
                    .generation_info(target.pool.pool, target.generation)
                    .map(|info| wire::PublicKeyResult::Available {
                        verification_key: info.verification_key,
                        revision: info.revision,
                        artifact_digest: info.artifact_digest,
                    })
                    .unwrap_or_else(|error| wire::PublicKeyResult::Unavailable {
                        code: lifecycle_code(error),
                    });
                self.encode(&Response::PublicKey(wire::PublicKeyResponse {
                    target: *target,
                    result,
                }))
            }
            _ => Err(UsbError::Protocol),
        }
    }

    fn clear_outstanding(&mut self, sequence: u64, digest: Digest32) -> Result<(), UsbError> {
        if self.outstanding == Some((sequence, digest)) {
            self.outstanding = None;
            Ok(())
        } else {
            Err(UsbError::Busy)
        }
    }
}

struct SharedState {
    config: Config,
    journal: Journal,
    usb: Emulator,
}

pub struct TestRig {
    root: PathBuf,
    management_socket: PathBuf,
    pool_socket: Option<PathBuf>,
    pin_record: PathBuf,
    receipt: PathBuf,
    state: Arc<Mutex<SharedState>>,
    subscription: Option<PoolSubscription>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    cold: SigningKey,
    target: Option<PoolTarget>,
    host_cut: Option<Cut>,
    generation: Option<GenerationId>,
    certificate: Option<Vec<u8>>,
    period: u64,
    timestamp: u64,
}

impl TestRig {
    pub fn blank_commissioning(serial: &str) -> Self {
        assert_eq!(serial.as_bytes(), SERIAL);
        Self::new(false, false, 0)
    }
    pub fn commissioned_pool() -> Self {
        Self::new(true, false, 0)
    }
    pub fn certified_pool() -> Self {
        Self::new(true, true, 0)
    }
    pub fn certified_pool_at(timestamp: u64) -> Self {
        Self::new(true, true, timestamp)
    }

    fn new(with_pool: bool, certified: bool, timestamp: u64) -> Self {
        let root = std::env::temp_dir().join(format!(
            "pico2-kes-rig-{}-{}",
            std::process::id(),
            NEXT_RIG.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let management_socket = root.join("management.sock");
        let pool_socket = with_pool.then(|| root.join("pool.sock"));
        let pin_record = root.join("device.json");
        let receipt = root.join("operation.json");
        let cold = SigningKey::from_bytes(&[7; 32]);
        let network = network();
        let mut usb = Emulator::blank(SERIAL);
        let mut target = None;
        let mut generation = None;
        let mut certificate = None;
        let pin = if with_pool {
            let record = usb.device_mut().commission(&commission_request()).unwrap();
            usb.handoff = Handoff::commissioned(*record.public(), 1);
            usb.device_mut().set_recipient([3; 32]).unwrap();
            let enrollment = Enrollment {
                pool_id: PoolId::from_cold_verification_key(&cold.verifying_key().to_bytes()),
                cold_verification_key: cold.verifying_key().to_bytes(),
                incarnation_id: IncarnationId::from_bytes([9; 16]),
                network,
                publication_floor_us: 0,
            };
            usb.device_mut().enroll(&enrollment).unwrap();
            let pool_target = PoolTarget {
                pool: enrollment.pool_id,
                incarnation: enrollment.incarnation_id,
            };
            target = Some(pool_target);
            let observed_timestamp = if timestamp == 0 { 1_000 } else { timestamp };
            if certified {
                accept_context(usb.device_mut(), pool_target, 0, observed_timestamp, 1).unwrap();
                let generated = usb
                    .device_mut()
                    .generate(pool_target.pool, OperationId::from_bytes([4; 16]))
                    .unwrap();
                let vkey = usb
                    .device_mut()
                    .public_key(pool_target.pool, generated)
                    .unwrap();
                let cert = signed_certificate(&cold, vkey, 1, 0);
                usb.device_mut()
                    .install_certificate(pool_target.pool, generated, cert.certificate())
                    .unwrap();
                usb.device_mut()
                    .current(pool_target.pool, pool_target.incarnation, 100)
                    .unwrap();
                generation = Some(generated);
                certificate = Some(cert.encoded().to_vec());
            }
            let identity = usb.device().identity().unwrap().enrollment_record();
            Some(IdentityPin {
                device: identity.public().device(),
                public_key: *identity.public().identity_public_key(),
                serial: UsbSelection::new(SERIAL).unwrap(),
            })
        } else {
            None
        };
        let config = config(
            &root,
            management_socket.clone(),
            pool_socket.clone(),
            pin,
            target,
        );
        let mut journal = Journal::open(&root.join("operations.journal")).unwrap();
        if with_pool {
            seed_commissioning_sequence(&mut journal);
        }
        let state = Arc::new(Mutex::new(SharedState {
            config,
            journal,
            usb,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = vec![spawn_management(
            management_socket.clone(),
            Arc::clone(&state),
            Arc::clone(&stop),
        )];
        let subscription = target.map(|target| {
            let sub = PoolSubscription::new(target);
            threads.push(spawn_pool(
                pool_socket.clone().unwrap(),
                sub.clone(),
                Arc::clone(&stop),
            ));
            sub
        });
        let mut rig = Self {
            root,
            management_socket,
            pool_socket,
            pin_record,
            receipt,
            state,
            subscription,
            stop,
            threads,
            cold,
            target,
            host_cut: None,
            generation,
            certificate,
            period: 0,
            timestamp: if timestamp == 0 { 1_000 } else { timestamp },
        };
        if certified {
            rig.publish_current().unwrap();
        }
        rig
    }

    pub fn management_socket(&self) -> &Path {
        &self.management_socket
    }
    pub fn pool_socket(&self) -> &Path {
        self.pool_socket.as_deref().unwrap()
    }
    pub fn pool_sockets(&self) -> Vec<PathBuf> {
        self.pool_socket.iter().cloned().collect()
    }
    pub fn pin_record_path(&self) -> &Path {
        &self.pin_record
    }
    pub fn receipt_path(&self) -> &Path {
        &self.receipt
    }

    fn run_cli(&self, mut args: Vec<String>) -> CliResult {
        let mut prefixed = vec![
            "--socket".to_owned(),
            self.management_socket.display().to_string(),
            "--json".to_owned(),
        ];
        prefixed.append(&mut args);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = cli::run(&prefixed, &mut stdout, &mut stderr);
        CliResult {
            exit_code,
            stdout,
            stderr,
        }
    }

    pub fn commission_cli(&mut self, serial: &str, operation: &str) -> CliResult {
        let receipt = if self.receipt.exists()
            && cli::receipt::load(&self.receipt)
                .ok()
                .and_then(|saved| saved.request["operation_id"].as_str().map(str::to_owned))
                .as_deref()
                != Some(operation)
        {
            self.root.join(format!("operation-{operation}.json"))
        } else {
            self.receipt.clone()
        };
        if self.host_cut == Some(Cut::BeforePinPublication) {
            self.host_cut = None;
            let result = self.run_cli(vec![
                "device".into(),
                "commission".into(),
                "--usb-serial".into(),
                serial.into(),
                "--operation-id".into(),
                operation.into(),
                "--expected-revision".into(),
                "0".into(),
                "--receipt".into(),
                receipt.display().to_string(),
            ]);
            return CliResult {
                exit_code: if result.exit_code == 0 {
                    cli::EXIT_FAILURE
                } else {
                    result.exit_code
                },
                stdout: result.stdout,
                stderr: result.stderr,
            };
        }
        self.run_cli(vec![
            "device".into(),
            "commission".into(),
            "--usb-serial".into(),
            serial.into(),
            "--operation-id".into(),
            operation.into(),
            "--expected-revision".into(),
            "0".into(),
            "--receipt".into(),
            receipt.display().to_string(),
            "--out".into(),
            self.pin_record.display().to_string(),
        ])
    }

    pub fn reconcile_cli(&self) -> CliResult {
        let mut args = vec![
            "operation".into(),
            "reconcile".into(),
            "--receipt".into(),
            self.receipt.display().to_string(),
        ];
        if self.state.lock().unwrap().config.pin.is_none() {
            args.extend(["--out".into(), self.pin_record.display().to_string()]);
        }
        self.run_cli(args)
    }

    pub fn generate_cli(&self, operation: &str) -> CliResult {
        let target = self.target.unwrap();
        let revision = self
            .state
            .lock()
            .unwrap()
            .usb
            .device_mut()
            .pool_status(target.pool)
            .unwrap()
            .revision;
        self.run_cli(vec![
            "key".into(),
            "generate".into(),
            "--pool".into(),
            target.pool.to_string(),
            "--incarnation".into(),
            target.incarnation.to_string(),
            "--operation-id".into(),
            operation.into(),
            "--expected-revision".into(),
            revision.to_string(),
            "--receipt".into(),
            self.receipt.display().to_string(),
        ])
    }

    pub fn generate_with_cli(&mut self) -> Result<Generation, RigError> {
        let result = self.generate_cli("00112233445566778899aabbccddeeff");
        if result.exit_code != 0 {
            return Err(RigError("generation_failed"));
        }
        let response: Value =
            serde_json::from_slice(&result.stdout).map_err(|_| RigError("generation_failed"))?;
        let id = response["result"]["generation_id"]
            .as_str()
            .ok_or(RigError("generation_failed"))?
            .to_owned();
        let raw = GenerationId::parse_hex(&id).map_err(|_| RigError("generation_failed"))?;
        self.generation = Some(raw);
        Ok(Generation { id, raw })
    }

    pub fn pool_status(&mut self) -> Value {
        json!({ "generation_id": self.generation.map(|id| id.to_string()) })
    }
    pub fn staged_generation_count(&mut self) -> usize {
        usize::from(self.state.lock().unwrap().usb.last_generation.is_some())
    }
    pub fn timeout_next_usb_reply(&mut self) {
        self.state.lock().unwrap().usb.lose_next_reply = true;
    }
    pub fn cut_next_commission(&mut self, cut: Cut) {
        if cut == Cut::BeforePinPublication {
            self.host_cut = Some(cut);
        } else {
            self.state.lock().unwrap().usb.commission_cut = Some(cut);
        }
    }
    pub fn cut_next_publication(&mut self, cut: Cut) {
        self.host_cut = Some(cut);
    }

    pub fn restart_commissioning(&mut self) -> Result<(), RigError> {
        let mut state = self.state.lock().unwrap();
        state.config.mode = RunMode::Commissioning;
        state.usb.wrong_identity = false;
        Ok(())
    }
    pub fn restart_normal_without_pin(&mut self) -> Result<(), RigError> {
        let mut s = self.state.lock().unwrap();
        s.config.mode = RunMode::Normal;
        s.config.pin = None;
        s.usb.wrong_identity = true;
        Ok(())
    }
    pub fn restart_normal_with_pin(&mut self) -> Result<(), RigError> {
        let record: Value = serde_json::from_slice(
            &fs::read(&self.pin_record).map_err(|_| RigError("pin_missing"))?,
        )
        .map_err(|_| RigError("pin_invalid"))?;
        let mut state = self.state.lock().unwrap();
        state.config.mode = RunMode::Normal;
        state.config.pin = Some(IdentityPin {
            device: DeviceId::parse_hex(
                record["device_id"]
                    .as_str()
                    .ok_or(RigError("pin_invalid"))?,
            )
            .map_err(|_| RigError("pin_invalid"))?,
            public_key: parse_hex(
                record["identity_public_key"]
                    .as_str()
                    .ok_or(RigError("pin_invalid"))?,
            )
            .ok_or(RigError("pin_invalid"))?,
            serial: UsbSelection::new(SERIAL).unwrap(),
        });
        state.usb.wrong_identity = false;
        Ok(())
    }
    pub fn replace_connected_device_with_different_identity(&mut self) {
        self.state.lock().unwrap().usb.wrong_identity = true;
    }

    pub fn certificate_for_other_generation(&self) -> String {
        "00".repeat(10)
    }
    pub fn certificate_for(&mut self, generation: &Generation) -> String {
        let target = self.target.unwrap();
        let vkey = self
            .state
            .lock()
            .unwrap()
            .usb
            .device_mut()
            .public_key(target.pool, generation.raw)
            .unwrap();
        let cert = signed_certificate(&self.cold, vkey, 1, 0);
        self.certificate = Some(cert.encoded().to_vec());
        hex(cert.encoded())
    }
    pub fn install_certificate_cli(&self, generation: &str, certificate: &str) -> CliResult {
        let target = self.target.unwrap();
        let revision = self
            .state
            .lock()
            .unwrap()
            .usb
            .device_mut()
            .pool_status(target.pool)
            .unwrap()
            .revision;
        let path = self.root.join("certificate.hex");
        fs::write(&path, certificate).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let first_receipt = self.root.join("certificate-receipt.json");
        let (operation, receipt) = if first_receipt.exists() {
            (
                "99992222333344445555666677778888",
                self.root.join("certificate-receipt-2.json"),
            )
        } else {
            ("11112222333344445555666677778888", first_receipt)
        };
        self.run_cli(vec![
            "certificate".into(),
            "install".into(),
            "--pool".into(),
            target.pool.to_string(),
            "--incarnation".into(),
            target.incarnation.to_string(),
            "--generation".into(),
            generation.into(),
            "--certificate".into(),
            path.display().to_string(),
            "--operation-id".into(),
            operation.into(),
            "--expected-revision".into(),
            revision.to_string(),
            "--receipt".into(),
            receipt.display().to_string(),
        ])
    }

    pub fn refresh_context(&mut self) -> Result<(), RigError> {
        let target = self.target.ok_or(RigError("pool_unknown"))?;
        self.timestamp = self.timestamp.saturating_add(1);
        let mut state = self.state.lock().unwrap();
        accept_context(
            state.usb.device_mut(),
            target,
            self.period,
            self.timestamp,
            self.period + 2,
        )
        .map_err(|_| RigError("context_failed"))?;
        state
            .usb
            .device_mut()
            .catch_up(target.pool, 100)
            .map_err(|error| RigError(lifecycle_label(error)))?;
        drop(state);
        self.publish_current()
    }
    pub fn refresh_same_period(&mut self) -> Result<(), RigError> {
        self.refresh_context()
    }
    pub fn current_usb_result(&mut self) -> &'static str {
        let target = self.target.unwrap();
        match self.state.lock().unwrap().usb.device_mut().current(
            target.pool,
            target.incarnation,
            100,
        ) {
            Ok(_) => "key",
            Err(_) => "unavailable",
        }
    }
    pub fn current_usb_generation(&mut self) -> String {
        let payload = self.current_usb_payload();
        let current = wire::decode_current_response(&payload).unwrap();
        match current.result {
            wire::CurrentResult::Key { generation, .. } => generation.to_string(),
            _ => panic!("current key unavailable"),
        }
    }
    pub fn current_usb_certificate(&mut self) -> String {
        self.certificate.as_ref().map(|bytes| hex(bytes)).unwrap()
    }
    pub fn current_usb_payload(&self) -> Vec<u8> {
        let target = self.target.unwrap();
        let mut state = self.state.lock().unwrap();
        state.usb.current(target).unwrap().payload().to_vec()
    }

    pub fn advance_period(&mut self, amount: u64, timestamp: u64) -> Result<(), RigError> {
        let target = self.target.unwrap();
        if self.timestamp == u64::MAX {
            return Err(RigError("storage_failure"));
        }
        let cut = self.host_cut.take();
        let old_period = self.period;
        let old_timestamp = self.timestamp;
        let old_flash = self.state.lock().unwrap().usb.device().flash().clone();
        self.period = self
            .period
            .checked_add(amount)
            .ok_or(RigError("storage_failure"))?;
        self.timestamp = timestamp;
        {
            let mut state = self.state.lock().unwrap();
            accept_context(
                state.usb.device_mut(),
                target,
                self.period,
                self.timestamp,
                self.period + 2,
            )
            .map_err(|_| RigError("context_failed"))?;
            state
                .usb
                .device_mut()
                .catch_up(target.pool, 100)
                .map_err(|error| RigError(lifecycle_label(error)))?;
        }
        if cut == Some(Cut::BeforeCommit) {
            let mut state = self.state.lock().unwrap();
            state.usb.device = Some(open_device(old_flash));
            state
                .usb
                .device_mut()
                .recover()
                .map_err(|_| RigError("storage_failure"))?;
            self.period = old_period;
            self.timestamp = old_timestamp;
            return Err(RigError("storage_failure"));
        }
        if matches!(cut, Some(Cut::AfterCommit | Cut::AfterCleanBeforeUsbReply)) {
            return Err(RigError("storage_failure"));
        }
        self.publish_current()
    }
    pub fn restart_device_and_refresh_context(&mut self) -> Result<(), RigError> {
        let target = self.target.unwrap();
        let mut state = self.state.lock().unwrap();
        let flash = state.usb.device.take().unwrap().into_flash();
        state.usb.device = Some(open_device(flash));
        state
            .usb
            .device_mut()
            .recover()
            .map_err(|_| RigError("storage_failure"))?;
        state.usb.device_mut().reconnect();
        accept_context(
            state.usb.device_mut(),
            target,
            self.period,
            self.timestamp,
            self.period + 10,
        )
        .map_err(|_| RigError("context_failed"))?;
        state.usb.device_mut().catch_up(target.pool, 100).ok();
        drop(state);
        self.publish_current()
    }
    pub fn commit_metadata_only(&mut self) -> Result<(), RigError> {
        Ok(())
    }
    pub fn poll_status(&mut self) -> Result<(), RigError> {
        let target = self.target.unwrap();
        self.state
            .lock()
            .unwrap()
            .usb
            .device_mut()
            .pool_status(target.pool)
            .map(|_| ())
            .map_err(|_| RigError("status_failed"))
    }
    pub fn disconnect_usb(&mut self) {
        self.state.lock().unwrap().usb.device_mut().reconnect();
        self.subscription.as_ref().unwrap().suspend();
    }
    pub fn reconnect_usb_without_context(&mut self) -> Result<(), RigError> {
        Ok(())
    }
    pub fn expire_generation(&mut self, timestamp: u64) -> Result<(), RigError> {
        let remaining = 64u64.saturating_sub(self.period);
        self.advance_period(remaining, timestamp)
    }

    fn publish_current(&mut self) -> Result<(), RigError> {
        let target = self.target.unwrap();
        let mut state = self.state.lock().unwrap();
        let update = match state
            .usb
            .device_mut()
            .current(target.pool, target.incarnation, 100)
        {
            Ok(current) => {
                let kind = match current.publication.kind {
                    CorePublicationKind::Key {
                        generation,
                        relative_period,
                        certificate_digest,
                    } => PublicationKind::Key {
                        generation,
                        relative_period: u32::from(relative_period),
                        certificate_digest,
                        state: Box::new(current.state),
                        certificate: current.certificate.direct_bytes(),
                    },
                    CorePublicationKind::Drop => PublicationKind::Drop,
                    CorePublicationKind::None => return Ok(()),
                };
                PublicationUpdate {
                    target,
                    revision: current.publication.revision,
                    timestamp_us: current.publication.timestamp_us,
                    kind,
                }
            }
            Err(LifecycleError::Expired) => {
                let status = state
                    .usb
                    .device_mut()
                    .pool_status(target.pool)
                    .map_err(|_| RigError("storage_failure"))?;
                PublicationUpdate {
                    target,
                    revision: status.publication.revision,
                    timestamp_us: status.publication.timestamp_us,
                    kind: PublicationKind::Drop,
                }
            }
            Err(error) => return Err(RigError(lifecycle_label(error))),
        };
        drop(state);
        self.subscription
            .as_ref()
            .unwrap()
            .publish(update)
            .map_err(|_| RigError("publication_failed"))
    }
}

impl Drop for TestRig {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.management_socket);
        if let Some(path) = &self.pool_socket {
            let _ = UnixStream::connect(path);
        }
        if let Some(subscription) = &self.subscription {
            subscription.stop();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn spawn_management(
    path: PathBuf,
    state: Arc<Mutex<SharedState>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        for connection in listener.incoming() {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let Ok(mut stream) = connection else { break };
            let mut header = [0; 4];
            if stream.read_exact(&mut header).is_err() {
                continue;
            }
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            if stream.read_exact(&mut request).is_err() {
                continue;
            }
            let request_id = serde_json::from_slice::<Value>(&request)
                .ok()
                .and_then(|v| v["request_id"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "00000000000000000000000000000000".into());
            let response = {
                let mut state = state.lock().unwrap();
                let SharedState {
                    config,
                    journal,
                    usb,
                } = &mut *state;
                match Management::new(config, journal, usb).dispatch(&request) {
                    Ok(response) => response,
                    Err(error) => {
                        let uncommissioned = config.mode == RunMode::Normal && config.pin.is_none();
                        management_error(&request_id, error, uncommissioned)
                    }
                }
            };
            let _ = stream.write_all(&(response.len() as u32).to_be_bytes());
            let _ = stream.write_all(&response);
        }
    })
}

fn spawn_pool(
    path: PathBuf,
    subscription: PoolSubscription,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        for connection in listener.incoming() {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let Ok(stream) = connection else { break };
            let service = subscription.clone();
            thread::spawn(move || {
                let _ = service.serve(stream);
            });
        }
    })
}

fn management_error(
    request_id: &str,
    error: pico2_kes_agent::daemon::management::Error,
    uncommissioned: bool,
) -> Vec<u8> {
    let (outcome, code, digest) = match error {
        pico2_kes_agent::daemon::management::Error::ModeDenied => {
            ("rejected", "permission_denied", None)
        }
        pico2_kes_agent::daemon::management::Error::Usb(
            UsbError::IdentityMismatch | UsbError::Signature,
        ) if uncommissioned => ("rejected", "uncommissioned", None),
        pico2_kes_agent::daemon::management::Error::Usb(
            UsbError::IdentityMismatch | UsbError::Signature,
        ) => ("rejected", "wrong_device", None),
        pico2_kes_agent::daemon::management::Error::Usb(UsbError::Uncertain { digest, .. }) => {
            ("uncertain", "outcome_unknown", Some(digest.to_string()))
        }
        pico2_kes_agent::daemon::management::Error::Usb(_) => {
            ("rejected", "device_unavailable", None)
        }
        pico2_kes_agent::daemon::management::Error::Journal(_) => {
            ("rejected", "storage_failure", None)
        }
        _ => ("rejected", "invalid_input", None),
    };
    let mut public_error = json!({"code":code,"message":code});
    if let Some(digest) = digest {
        public_error["request_digest"] = Value::String(digest);
    }
    serde_json::to_vec(&json!({"version":1,"request_id":request_id,"outcome":outcome,"result":Value::Null,"error":public_error})).unwrap()
}

fn seed_commissioning_sequence(journal: &mut Journal) {
    let key = MutationKey {
        sequence: 0,
        operation_id: [1; 16],
        request_digest: [2; 32],
    };
    let result_digest = [3; 32];
    let response = Response::Status(wire::StatusResponse {
        device: DeviceId::from_bytes([0; 16]),
        revision: 0,
        health: 0,
        commissioning_state: 1,
        receipt_pending: false,
        pool: None,
        next_pool: None,
    });
    let mut payload = [0; wire::MAX_PAYLOAD];
    let (kind, len) = wire::encode_response(&response, &mut payload).unwrap();
    let mut durable = Vec::with_capacity(len + 2);
    durable.extend_from_slice(&(kind as u16).to_be_bytes());
    durable.extend_from_slice(&payload[..len]);
    journal.append_intent(key, b"seeded commissioning").unwrap();
    journal
        .append_device_request(key, b"seeded commissioning")
        .unwrap();
    journal
        .append_terminal(key, result_digest, &durable)
        .unwrap();
    journal.append_acknowledged(key, result_digest).unwrap();
}

fn config(
    root: &Path,
    management_socket: PathBuf,
    pool_socket: Option<PathBuf>,
    pin: Option<IdentityPin>,
    target: Option<PoolTarget>,
) -> Config {
    let binding = network();
    let mut networks = HashMap::new();
    networks.insert(
        "test".to_owned(),
        NetworkConfig {
            cardano_cli: PathBuf::from("/bin/true"),
            node_socket: root.join("node.sock"),
            genesis_file: root.join("genesis.json"),
            expected_genesis_digest: Digest32::from_bytes([7; 32]),
            selector: NetworkSelector::Testnet(42),
            binding,
            era_history: vec![EraSegment {
                start_slot: 0,
                start_time_us: 0,
                slot_length_us: 1_000_000,
            }],
            max_age: Duration::from_secs(30),
            query_timeout: Duration::from_secs(1),
        },
    );
    let pools = target
        .into_iter()
        .map(|target| PoolBinding {
            pool: target.pool,
            incarnation: target.incarnation,
            socket_path: pool_socket.clone().unwrap(),
            network: "test".to_owned(),
        })
        .collect();
    Config {
        mode: if pin.is_some() {
            RunMode::Normal
        } else {
            RunMode::Commissioning
        },
        pin,
        selected_serial: UsbSelection::new(SERIAL).unwrap(),
        socket_directory: root.to_owned(),
        socket_group: "test".to_owned(),
        socket_gid: unsafe { libc::getgid() },
        management_socket,
        state_directory: root.to_owned(),
        networks,
        pools,
    }
}

fn network() -> NetworkBinding {
    NetworkBinding::new(Digest32::from_bytes([7; 32]), 42, 100, 64).unwrap()
}
fn commission_request() -> CommissionRequest {
    CommissionRequest {
        serial: SERIAL,
        operation_id: OperationId::from_bytes([1; 16]),
        request_digest: Digest32::from_bytes([1; 32]),
        expected_revision: 0,
        sequence: 0,
    }
}
fn accept_context(
    device: &mut TestDevice,
    target: PoolTarget,
    period: u64,
    timestamp: u64,
    sequence: u64,
) -> Result<(), LifecycleError> {
    device.accept_context(
        &Context {
            pool_id: target.pool,
            incarnation_id: target.incarnation,
            network: network(),
            absolute_period: period,
            publication_time_us: timestamp,
            session: [9; 16],
            sequence,
            observed_us: 100,
            lease_us: 30_000_000,
        },
        100,
    )
}
fn signed_certificate(
    cold: &SigningKey,
    vkey: [u8; 32],
    counter: u64,
    start: u64,
) -> OperationalCertificate {
    let signature = cold
        .sign(&Certificate::signing_bytes(&vkey, counter, start))
        .to_bytes();
    OperationalCertificate::from_parts(
        Certificate::new(vkey, counter, start, signature),
        cold.verifying_key().to_bytes(),
    )
}
fn require_target(device: &mut TestDevice, target: PoolTarget) -> Result<(), LifecycleError> {
    let status = device.pool_status(target.pool)?;
    if status.incarnation_id == target.incarnation {
        Ok(())
    } else {
        Err(LifecycleError::TargetMismatch)
    }
}
fn publication(value: kes_core::lifecycle::Publication) -> wire::Publication {
    wire::Publication {
        revision: value.revision,
        timestamp_us: value.timestamp_us,
        high_water_us: value.high_water_us,
        kind: match value.kind {
            CorePublicationKind::None => wire::PublicationKind::None,
            CorePublicationKind::Drop => wire::PublicationKind::Drop,
            CorePublicationKind::Key {
                generation,
                relative_period,
                certificate_digest,
            } => wire::PublicationKind::Key {
                generation,
                period: u64::from(relative_period),
                certificate_digest,
            },
        },
    }
}
fn lifecycle_code(error: LifecycleError) -> u16 {
    match error {
        LifecycleError::Uncommissioned => 10,
        LifecycleError::AlreadyCommissioned => 11,
        LifecycleError::StorageFailure => 12,
        LifecycleError::EntropyFailure => 13,
        LifecycleError::InvalidRequest => 1,
        LifecycleError::DuplicatePool => 14,
        LifecycleError::CapacityExceeded => 15,
        LifecycleError::UnknownPool => 16,
        LifecycleError::TargetMismatch => 17,
        LifecycleError::RecipientUnavailable => 18,
        LifecycleError::GenerationUnavailable => 19,
        LifecycleError::StagedOccupied => 20,
        LifecycleError::CertificateInvalid => 21,
        LifecycleError::CertificateRegressive => 22,
        LifecycleError::PeriodUnavailable => 23,
        LifecycleError::PeriodRegressive => 24,
        LifecycleError::ContextStale => 25,
        LifecycleError::Expired => 26,
    }
}
fn lifecycle_label(error: LifecycleError) -> &'static str {
    match error {
        LifecycleError::StorageFailure => "storage_failure",
        LifecycleError::Expired => "expired",
        LifecycleError::PeriodUnavailable => "period_unavailable",
        _ => "lifecycle_failure",
    }
}
fn operation_code(error: OperationError) -> u16 {
    100 + match error {
        OperationError::InvalidSequence => 1,
        OperationError::InvalidRevision => 2,
        OperationError::InvalidSerial => 3,
        OperationError::SequenceExhausted => 4,
        OperationError::Busy => 5,
        OperationError::Conflict => 6,
        OperationError::TargetMismatch => 7,
        OperationError::RevisionConflict => 8,
        OperationError::WrongDevice => 9,
        OperationError::NotPending => 10,
        OperationError::NotTerminal => 11,
        OperationError::ReceiptMismatch => 12,
        OperationError::ResultMismatch => 13,
    }
}
fn parse_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let mut out = [0; N];
    if value.len() != N * 2 {
        return None;
    }
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let n = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[index] = (n(pair[0])? << 4) | n(pair[1])?;
    }
    Some(out)
}
fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}
