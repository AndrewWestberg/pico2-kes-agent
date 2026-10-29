//! Typed request dispatch. Wire validation is completed before any stateful
//! operation and responses are encoded directly into caller-owned storage.
use kes_core::{
    certificate::OperationalCertificate,
    identity::Digest32,
    lifecycle::{
        Context, Error as LifecycleError, GenerationStatus as CoreGenerationStatus,
        PoolStatus as CorePoolStatus, Publication as CorePublication,
        PublicationKind as CorePublicationKind,
    },
    operation::{
        Action, Binding, CommittedResult, DeletionPublication, LiveTarget, Mutation,
        OperationError, PoolTarget, Receipt, ReceiptOutcome,
    },
    public_object::MAX_ARTIFACT_LEN,
};
use kes_protocol::usb::{self as wire, Kind, Request, Response};
use sha2::{Digest, Sha256};

use crate::{
    Runtime,
    usb::{DispatchError, Dispatcher},
};

const HEALTHY: u8 = 0;
const NOT_YET_VALID: u8 = 1;
const EXPIRED: u8 = 2;
const DELAYED_EVOLUTION: u8 = 3;
const PERIOD_UNAVAILABLE: u8 = 4;
const COMMISSIONED: u8 = 1;
const CODE_INVALID: u16 = 1;

pub trait Operations {
    fn reconnect(&mut self);

    fn execute(
        &mut self,
        request: Request,
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError>;
}

pub struct Service<B> {
    backend: B,
}

impl<B> Service<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B: Operations> Dispatcher for Service<B> {
    fn reconnect(&mut self) {
        self.backend.reconnect();
    }

    fn dispatch(
        &mut self,
        kind: Kind,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError> {
        let request = wire::decode_request(kind, payload).map_err(|_| DispatchError::Protocol)?;
        self.backend.execute(request, output)
    }
}

impl Operations for Runtime<'_> {
    fn reconnect(&mut self) {
        Runtime::reconnect(self);
    }

    fn execute(
        &mut self,
        request: Request,
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError> {
        match request {
            Request::Hello { nonce } => self.hello(nonce, output),
            Request::Status { pool } => self.status(pool, output),
            Request::SecurityStatus => {
                let status = crate::security::read(
                    self.flash_identity,
                    self.boot_admission,
                    self.serial.as_slice(),
                )
                .map_err(|_| DispatchError::State)?;
                encode(&Response::SecurityStatus(status), output)
            }
            Request::Context {
                target,
                network,
                period,
                session,
                sequence,
                lease_seconds,
                publication_time_us,
            } => {
                let mut session_bytes = [0; 16];
                session_bytes[8..].copy_from_slice(&session.to_be_bytes());
                let now = now_us();
                let context = Context {
                    pool_id: target.pool,
                    incarnation_id: target.incarnation,
                    network,
                    absolute_period: period,
                    publication_time_us,
                    session: session_bytes,
                    sequence,
                    observed_us: now,
                    lease_us: u64::from(lease_seconds) * 1_000_000,
                };
                let scheduled = self
                    .device_mut()
                    .accept_context(&context, now)
                    .and_then(|()| {
                        self.device_mut()
                            .pool_status(target.pool)
                            .map(|status| status.slot)
                    });
                let result = match scheduled {
                    Ok(slot) => {
                        self.scheduler.enroll(slot);
                        self.scheduler.request(slot);
                        let mut selected = None;
                        self.scheduler.run_one(|next| selected = Some(next));
                        if selected == Some(slot) {
                            match self.device_mut().catch_up(target.pool, now) {
                                Ok(())
                                | Err(LifecycleError::PeriodUnavailable)
                                | Err(LifecycleError::GenerationUnavailable) => Ok(()),
                                Err(error) => Err(error),
                            }
                        } else {
                            Err(LifecycleError::StorageFailure)
                        }
                    }
                    Err(error) => Err(error),
                }
                .map_err(lifecycle_error_code);
                let floor = self
                    .device_mut()
                    .pool_status(target.pool)
                    .ok()
                    .and_then(|status| status.period_floor)
                    .unwrap_or(0);
                encode(
                    &Response::Context(wire::ContextResponse {
                        target,
                        session,
                        sequence,
                        floor,
                        result,
                    }),
                    output,
                )
            }
            Request::Mutate(mutation) => self.mutate(mutation, false, output),
            Request::Commission(mutation) => self.mutate(mutation, true, output),
            Request::Reconcile {
                sequence,
                operation_id,
                digest,
                binding,
            } => {
                let receipt = self.handoff().receipt().filter(|receipt| {
                    let mutation = receipt.mutation();
                    mutation.sequence() == sequence
                        && mutation.operation_id() == operation_id
                        && mutation.usb_digest() == digest
                        && reconcile_binding(mutation.binding(), &binding)
                });
                let public = receipt.map_or_else(
                    || wire::PublicReceipt {
                        sequence,
                        operation_id,
                        request_digest: digest,
                        binding: match binding {
                            wire::ReconcileBinding::Serial(serial) => {
                                wire::ReceiptBinding::Serial(serial)
                            }
                            wire::ReconcileBinding::Device(device) => {
                                wire::ReceiptBinding::Device(device)
                            }
                        },
                        target: None,
                        outcome: match self.handoff().next_sequence() {
                            Some(next) if sequence < next => wire::PublicOutcome::Stale,
                            _ => wire::PublicOutcome::Unknown,
                        },
                    },
                    public_receipt,
                );
                encode(&Response::Reconcile(public), output)
            }
            Request::ReceiptAck {
                sequence,
                result_digest,
            } => {
                let result = match self.handoff_mut().acknowledge(sequence, result_digest) {
                    Ok(()) => {
                        self.persist_handoff().map_err(|_| DispatchError::State)?;
                        Ok(())
                    }
                    Err(error) => Err(operation_error_code(error)),
                };
                encode(
                    &Response::ReceiptAck(wire::ReceiptAckResponse {
                        sequence,
                        result_digest,
                        result,
                    }),
                    output,
                )
            }
            Request::Current { target } => self.current(target, output),
            Request::Artifact { target } => {
                let mut artifact = [0; MAX_ARTIFACT_LEN];
                let result = match self.device_mut().artifact(
                    target.pool.pool,
                    target.generation,
                    &mut artifact,
                ) {
                    Ok((len, digest, _)) => wire::ArtifactResult::Retained {
                        artifact: &artifact[..len],
                        digest,
                        retention_policy: 1,
                    },
                    Err(LifecycleError::GenerationUnavailable) => wire::ArtifactResult::Retired,
                    Err(error) => wire::ArtifactResult::Unavailable {
                        code: lifecycle_error_code(error),
                    },
                };
                encode(
                    &Response::Artifact(wire::ArtifactResponse { target, result }),
                    output,
                )
            }
            Request::PublicKey { target } => {
                let result = match self
                    .device_mut()
                    .generation_info(target.pool.pool, target.generation)
                {
                    Ok(info) => wire::PublicKeyResult::Available {
                        verification_key: info.verification_key,
                        revision: info.revision,
                        artifact_digest: info.artifact_digest,
                    },
                    Err(error) => wire::PublicKeyResult::Unavailable {
                        code: lifecycle_error_code(error),
                    },
                };
                encode(
                    &Response::PublicKey(wire::PublicKeyResponse { target, result }),
                    output,
                )
            }
        }
    }
}

impl Runtime<'_> {
    fn hello(
        &mut self,
        nonce: [u8; 32],
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError> {
        let Some(identity) = self.device().identity() else {
            return encode(
                &Response::Hello(wire::HelloResponse {
                    nonce,
                    state: wire::HelloState::Uncommissioned,
                }),
                output,
            );
        };
        let record = identity.enrollment_record().public();
        let mut response = wire::HelloResponse {
            nonce,
            state: wire::HelloState::Committed(wire::HelloIdentity {
                device: record.device(),
                public_key: *record.identity_public_key(),
                serial: *record.serial(),
                protocol_version: record.protocol_version(),
                storage_version: record.storage_version(),
                capacity: 64,
                commissioning_state: COMMISSIONED,
                signature: [0; 64],
            }),
        };
        let signing_len =
            wire::encode_hello_signing(&response, output).map_err(|_| DispatchError::Protocol)?;
        let signature = self
            .device()
            .sign_identity_message(&output[..signing_len])
            .map_err(|_| DispatchError::State)?;
        let wire::HelloState::Committed(mut committed) = response.state else {
            unreachable!()
        };
        committed.signature = signature;
        response.state = wire::HelloState::Committed(committed);
        encode(&Response::Hello(response), output)
    }

    fn status(
        &mut self,
        pool: Option<kes_core::identity::PoolId>,
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError> {
        let record = *self
            .device()
            .identity()
            .ok_or(DispatchError::State)?
            .enrollment_record()
            .public();
        let pool = match pool {
            Some(pool_id) => {
                let status = self.device_mut().pool_status(pool_id).ok();
                let generations = self.device_mut().pool_generations(pool_id).ok();
                match (status, generations) {
                    (Some(status), Some(generations)) => {
                        let active = generations
                            .active
                            .map(|generation| generation_status(generation, status, true));
                        let staged = generations
                            .staged
                            .map(|generation| generation_status(generation, status, false));
                        let health = pool_health(status, active, staged);
                        Some(wire::PoolStatus {
                            target: PoolTarget {
                                pool: status.pool_id,
                                incarnation: status.incarnation_id,
                            },
                            revision: status.revision,
                            health,
                            active,
                            staged,
                            publication: publication(status.publication),
                        })
                    }
                    _ => None,
                }
            }
            None => None,
        };
        let response = wire::StatusResponse {
            device: record.device(),
            revision: self.device().revision().map_err(|_| DispatchError::State)?,
            health: HEALTHY,
            commissioning_state: COMMISSIONED,
            receipt_pending: self.handoff().receipt().is_some(),
            pool,
            next_pool: None,
        };
        encode(&Response::Status(response), output)
    }

    fn current(
        &mut self,
        target: PoolTarget,
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError> {
        match self
            .device_mut()
            .current(target.pool, target.incarnation, now_us())
        {
            Ok(current) => {
                let certificate = current.certificate.direct_bytes();
                encode(
                    &Response::Current(wire::CurrentResponse {
                        target,
                        snapshot_revision: current.revision,
                        publication: publication(current.publication),
                        result: wire::CurrentResult::Key {
                            generation: current.generation_id,
                            period: u64::from(current.relative_period),
                            state: &current.state,
                            certificate: &certificate,
                        },
                    }),
                    output,
                )
            }
            Err(error) => {
                let descriptor =
                    self.device_mut()
                        .publication(target.pool)
                        .unwrap_or(CorePublication {
                            revision: 0,
                            kind: CorePublicationKind::None,
                            timestamp_us: 0,
                            high_water_us: 0,
                        });
                let result = if error == LifecycleError::Expired {
                    wire::CurrentResult::Drop
                } else {
                    wire::CurrentResult::Unavailable {
                        code: lifecycle_error_code(error),
                    }
                };
                encode(
                    &Response::Current(wire::CurrentResponse {
                        target,
                        snapshot_revision: descriptor.revision,
                        publication: publication(descriptor),
                        result,
                    }),
                    output,
                )
            }
        }
    }

    fn mutate(
        &mut self,
        mutation: Mutation,
        commissioning: bool,
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError> {
        if commissioning != matches!(mutation.binding(), Binding::Commission { .. }) {
            return Err(DispatchError::Protocol);
        }
        let resuming = if let Ok(existing) = self.handoff().reconcile(&mutation) {
            if !matches!(existing.outcome(), ReceiptOutcome::Pending) {
                return encode(
                    &if commissioning {
                        Response::Commission(public_receipt(existing))
                    } else {
                        Response::Mutate(public_receipt(existing))
                    },
                    output,
                );
            }
            true
        } else {
            false
        };
        if !resuming {
            let actual_revision = self.actual_revision(&mutation);
            let selected = self.serial();
            let actual_target = mutation.binding().managed_target();
            if let Err(error) =
                self.handoff_mut()
                    .admit(mutation, actual_revision, actual_target, Some(&selected))
            {
                let public = rejected_receipt(&mutation, operation_error_code(error));
                return encode(
                    &if commissioning {
                        Response::Commission(public)
                    } else {
                        Response::Mutate(public)
                    },
                    output,
                );
            }
            if !commissioning {
                self.persist_handoff().map_err(|_| DispatchError::State)?;
            }
        }
        let outcome =
            self.recover_committed(&mutation)
                .unwrap_or_else(|| match *mutation.binding() {
                    Binding::Commission { serial } => self
                        .device_mut()
                        .commission_values(
                            serial.as_slice(),
                            mutation.operation_id(),
                            mutation.usb_digest(),
                            mutation.expected_revision(),
                            mutation.sequence(),
                        )
                        .map(|record| CommittedResult::Commissioned(*record.public())),
                    Binding::Managed { action, .. } => {
                        self.apply_action(action, mutation.operation_id())
                    }
                });
        let outcome = match outcome {
            Ok(result) => ReceiptOutcome::Committed(result),
            Err(error) => ReceiptOutcome::Rejected {
                code: lifecycle_error_code(error),
            },
        };
        self.handoff_mut()
            .finish(outcome)
            .map_err(|_| DispatchError::State)?;
        if self.device().identity().is_some() {
            self.persist_handoff().map_err(|_| DispatchError::State)?;
        }
        let public = public_receipt(self.handoff().receipt().ok_or(DispatchError::State)?);
        encode(
            &if commissioning {
                Response::Commission(public)
            } else {
                Response::Mutate(public)
            },
            output,
        )
    }

    fn actual_revision(&mut self, mutation: &Mutation) -> u64 {
        match mutation.binding() {
            Binding::Commission { .. } => 0,
            Binding::Managed { action, .. } => match action.pool_target() {
                None => self.device().revision().unwrap_or(u64::MAX),
                Some(target) => self
                    .device_mut()
                    .pool_status(target.pool)
                    .ok()
                    .filter(|status| status.incarnation_id == target.incarnation)
                    .map_or(u64::MAX, |status| status.revision),
            },
        }
    }

    fn recover_committed(
        &mut self,
        mutation: &Mutation,
    ) -> Option<Result<CommittedResult, LifecycleError>> {
        if !matches!(
            self.handoff().receipt().map(Receipt::outcome),
            Some(ReceiptOutcome::Pending)
        ) {
            return None;
        }
        let expected = mutation.expected_revision().checked_add(1)?;
        let Binding::Managed { action, .. } = *mutation.binding() else {
            return None;
        };
        match action {
            Action::Enroll {
                cold_key,
                network,
                publication_floor_us,
            } => {
                let pool = kes_core::identity::PoolId::from_cold_verification_key(&cold_key);
                let enrollment = self.device_mut().enrollment(pool).ok()?;
                let revision = self.device().revision().ok()?;
                (revision == expected
                    && enrollment.cold_verification_key == cold_key
                    && enrollment.network == network
                    && enrollment.publication_floor_us == publication_floor_us)
                    .then_some(Ok(CommittedResult::Enrolled {
                        target: PoolTarget {
                            pool,
                            incarnation: enrollment.incarnation_id,
                        },
                        revision: self.device_mut().pool_status(pool).ok()?.revision,
                    }))
            }
            Action::Generate { target } => {
                let (generation, info) = self
                    .device_mut()
                    .generation_by_operation(target.pool, mutation.operation_id())
                    .ok()?;
                Some(Ok(CommittedResult::Generated {
                    generation,
                    revision: expected,
                    artifact_digest: info.artifact_digest,
                }))
            }
            Action::InstallCertificate {
                target,
                certificate,
            } => {
                let certificate = OperationalCertificate::decode(certificate.as_slice()).ok()?;
                let installed = self
                    .device_mut()
                    .installed_certificate(target.pool.pool, target.generation)
                    .ok()?;
                let revision = self
                    .device_mut()
                    .pool_status(target.pool.pool)
                    .ok()?
                    .revision;
                (installed == Some(*certificate.certificate()) && revision == expected)
                    .then_some(Ok(CommittedResult::Applied { revision }))
            }
            Action::Discard { target } => {
                let revision = self
                    .device_mut()
                    .discarded_by_operation(
                        target.pool.pool,
                        target.generation,
                        mutation.operation_id(),
                    )
                    .ok()??;
                (revision == expected).then_some(Ok(CommittedResult::Applied { revision }))
            }
            Action::SetRecipient { public_key } => {
                let revision = self.device().revision().ok()?;
                let recipient = self.device().recipient().ok()?;
                (revision == expected
                    && recipient.is_some_and(|(current, _)| current == public_key))
                .then_some(Ok(CommittedResult::Applied { revision }))
            }
            Action::Delete { target, .. } => {
                let revision = self.device().revision().ok()?;
                let publication = self.device().deletion(target).ok()??;
                (revision == expected).then_some(
                    DeletionPublication::new(
                        target,
                        publication.revision,
                        Some(publication.timestamp_us),
                        publication.high_water_us,
                    )
                    .map(CommittedResult::Deleted)
                    .map_err(|_| LifecycleError::StorageFailure),
                )
            }
        }
    }

    fn apply_action(
        &mut self,
        action: Action,
        operation_id: kes_core::identity::OperationId,
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
                require_target(self, target)?;
                let generation = self.device_mut().generate(target.pool, operation_id)?;
                let info = self.device_mut().generation_info(target.pool, generation)?;
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
                require_target(self, target.pool)?;
                let certificate = OperationalCertificate::decode(certificate.as_slice())
                    .map_err(|_| LifecycleError::CertificateInvalid)?;
                self.device_mut().install_certificate(
                    target.pool.pool,
                    target.generation,
                    certificate.certificate(),
                )?;
                let revision = self.device_mut().pool_status(target.pool.pool)?.revision;
                Ok(CommittedResult::Applied { revision })
            }
            Action::Discard { target } => {
                self.device_mut().discard(
                    target.pool.pool,
                    target.pool.incarnation,
                    target.generation,
                    operation_id,
                )?;
                let revision = self.device_mut().pool_status(target.pool.pool)?.revision;
                Ok(CommittedResult::Applied { revision })
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
                require_target(self, target)?;
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
}

fn require_target(runtime: &mut Runtime<'_>, target: PoolTarget) -> Result<(), LifecycleError> {
    let status = runtime.device_mut().pool_status(target.pool)?;
    if status.incarnation_id == target.incarnation {
        Ok(())
    } else {
        Err(LifecycleError::TargetMismatch)
    }
}

fn reconcile_binding(binding: &Binding, requested: &wire::ReconcileBinding) -> bool {
    matches!(
        (binding, requested),
        (Binding::Commission { serial: left }, wire::ReconcileBinding::Serial(right)) if left == right
    ) || matches!(
        (binding, requested),
        (Binding::Managed { device: left, .. }, wire::ReconcileBinding::Device(right)) if left == right
    )
}

trait ManagedTarget {
    fn managed_target(&self) -> Option<LiveTarget>;
}
impl ManagedTarget for Binding {
    fn managed_target(&self) -> Option<LiveTarget> {
        match self {
            Binding::Managed { action, .. } => action.target(),
            Binding::Commission { .. } => None,
        }
    }
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
        ReceiptOutcome::Pending => wire::PublicOutcome::Pending,
        ReceiptOutcome::Committed(result) => wire::PublicOutcome::Committed {
            result: *result,
            result_digest: receipt
                .result_digest()
                .unwrap_or(Digest32::from_bytes([0; 32])),
        },
        ReceiptOutcome::Rejected { code } => wire::PublicOutcome::Rejected {
            code: *code,
            result_digest: receipt
                .result_digest()
                .unwrap_or(Digest32::from_bytes([0; 32])),
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

fn rejected_receipt(mutation: &Mutation, code: u16) -> wire::PublicReceipt {
    let mut hash = Sha256::new();
    hash.update(b"pico2-kes-receipt-v1\0");
    hash.update(mutation.usb_digest().as_bytes());
    hash.update([0]);
    hash.update(code.to_be_bytes());
    let result_digest = Digest32::from_bytes(hash.finalize().into());
    let binding = match mutation.binding() {
        Binding::Commission { serial } => wire::ReceiptBinding::Serial(*serial),
        Binding::Managed { device, .. } => wire::ReceiptBinding::Device(*device),
    };
    wire::PublicReceipt {
        sequence: mutation.sequence(),
        operation_id: mutation.operation_id(),
        request_digest: mutation.usb_digest(),
        binding,
        target: mutation.binding().managed_target(),
        outcome: wire::PublicOutcome::Rejected {
            code,
            result_digest,
        },
    }
}

fn generation_status(
    generation: CoreGenerationStatus,
    pool: CorePoolStatus,
    active: bool,
) -> wire::GenerationStatus {
    let health = match (generation.certificate_start, pool.period_floor) {
        (None, _) => NOT_YET_VALID,
        (_, None) => PERIOD_UNAVAILABLE,
        (Some(start), Some(floor)) if floor < start => NOT_YET_VALID,
        (Some(start), Some(floor))
            if floor.saturating_sub(start) >= u64::from(pool.kes_lifetime) =>
        {
            EXPIRED
        }
        (Some(start), Some(floor))
            if !active || generation.period < floor.saturating_sub(start) =>
        {
            DELAYED_EVOLUTION
        }
        (Some(_), Some(_)) => HEALTHY,
    };
    wire::GenerationStatus {
        generation: generation.generation,
        revision: pool.revision,
        role: u8::from(!active),
        period: generation.period,
        health,
        artifact_digest: generation.artifact_digest,
    }
}

fn pool_health(
    status: CorePoolStatus,
    active: Option<wire::GenerationStatus>,
    staged: Option<wire::GenerationStatus>,
) -> u8 {
    if status.publication.kind == CorePublicationKind::Drop {
        return EXPIRED;
    }
    if staged.is_some_and(|generation| generation.health == DELAYED_EVOLUTION) {
        return DELAYED_EVOLUTION;
    }
    active.map_or(PERIOD_UNAVAILABLE, |generation| generation.health)
}

fn publication(value: CorePublication) -> wire::Publication {
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

pub fn lifecycle_error_code(error: LifecycleError) -> u16 {
    match error {
        LifecycleError::Uncommissioned => 10,
        LifecycleError::AlreadyCommissioned => 11,
        LifecycleError::StorageFailure => 12,
        LifecycleError::EntropyFailure => 13,
        LifecycleError::InvalidRequest => CODE_INVALID,
        LifecycleError::DuplicatePool => 14,
        LifecycleError::CapacityExceeded => 15,
        LifecycleError::UnknownPool => 16,
        LifecycleError::TargetMismatch => 17,
        LifecycleError::RecipientUnavailable => 18,
        LifecycleError::GenerationUnavailable => 19,
        LifecycleError::StagedOccupied => 20,
        LifecycleError::TargetNotStaged => 27,
        LifecycleError::CertificateInvalid => 21,
        LifecycleError::CertificateRegressive => 22,
        LifecycleError::PeriodUnavailable => 23,
        LifecycleError::PeriodRegressive => 24,
        LifecycleError::ContextStale => 25,
        LifecycleError::Expired => 26,
    }
}

fn operation_error_code(error: OperationError) -> u16 {
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

fn encode(value: &Response<'_>, output: &mut [u8]) -> Result<(Kind, usize), DispatchError> {
    wire::encode_response(value, output).map_err(|_| DispatchError::Protocol)
}

fn now_us() -> u64 {
    loop {
        let high = rp_pac::TIMER0.timerawh().read();
        let low = rp_pac::TIMER0.timerawl().read();
        let high_again = rp_pac::TIMER0.timerawh().read();
        if high == high_again {
            return (u64::from(high) << 32) | u64::from(low);
        }
    }
}
