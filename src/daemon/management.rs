//! Management JSON to journaled USB dispatch.

use crate::{
    config::{Config, PoolBinding, RunMode},
    daemon::{
        journal::{Journal, MutationKey},
        usb::{DeviceTransport, Error as UsbError},
    },
};
use kes_core::{
    identity::{Digest32, GenerationId, IncarnationId, OperationId, PoolId},
    operation::{
        Action as DeviceAction, Binding, CertificateBytes, CommittedResult, GenerationTarget,
        Mutation, PoolTarget, UsbSerial,
    },
};
use kes_protocol::{
    management::{Action, Kind as ManagementKind, Message},
    usb::{self as wire, PublicOutcome, ReceiptBinding, Request, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Debug)]
pub enum Error {
    Protocol,
    InvalidInput,
    ModeDenied,
    Journal(crate::daemon::journal::Error),
    Usb(UsbError),
}
impl From<crate::daemon::journal::Error> for Error {
    fn from(value: crate::daemon::journal::Error) -> Self {
        Self::Journal(value)
    }
}
impl From<UsbError> for Error {
    fn from(value: UsbError) -> Self {
        Self::Usb(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    request_id: String,
    action: String,
    arguments: Value,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    expected_revision: Option<u64>,
}

pub struct Management<'a, T: DeviceTransport> {
    config: &'a Config,
    journal: &'a mut Journal,
    usb: &'a mut T,
}

impl<'a, T: DeviceTransport> Management<'a, T> {
    pub fn new(config: &'a Config, journal: &'a mut Journal, usb: &'a mut T) -> Self {
        Self {
            config,
            journal,
            usb,
        }
    }

    pub fn dispatch(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let message = Message::decode(bytes).map_err(|_| Error::Protocol)?;
        let ManagementKind::Request {
            action,
            request_id,
            operation_id,
            expected_revision,
        } = message.kind()
        else {
            return Err(Error::Protocol);
        };
        enforce_mode(self.config.mode, action)?;
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Protocol)?;
        if envelope.version != 1
            || envelope.request_id != request_id.to_string()
            || envelope.action != action_name(action)
        {
            return Err(Error::Protocol);
        }

        let result = match action {
            Action::DeviceStatus => self.query(Request::Status { pool: None })?,
            Action::PoolStatus => {
                let pool =
                    parse_id::<28, PoolId>(&envelope.arguments, "pool_id", PoolId::from_bytes)?;
                self.query(Request::Status { pool: Some(pool) })?
            }
            Action::PoolList => self.pool_list(&envelope.arguments)?,
            Action::GenerationPublicKey => {
                let target = generation_target(&envelope.arguments)?;
                self.query(Request::PublicKey { target })?
            }
            Action::GenerationArtifact => {
                let target = generation_target(&envelope.arguments)?;
                self.query(Request::Artifact { target })?
            }
            Action::OperationReconcile => self.reconcile(&envelope.arguments)?,
            action if action.is_mutation() => {
                let operation_id = operation_id.ok_or(Error::Protocol)?;
                if envelope.operation_id.as_deref() != Some(&operation_id.to_string())
                    || envelope.expected_revision != expected_revision
                {
                    return Err(Error::Protocol);
                }
                let mutation = self.mutation(
                    action,
                    operation_id,
                    expected_revision.ok_or(Error::Protocol)?,
                    &envelope.arguments,
                )?;
                self.execute_mutation(bytes, mutation)?
            }
            _ => return Err(Error::Protocol),
        };
        let (outcome, result, error) = normalize_result(result)?;
        serde_json::to_vec(&json!({
            "version": 1,
            "request_id": request_id.to_string(),
            "outcome": outcome,
            "result": result,
            "error": error
        }))
        .map_err(|_| Error::Protocol)
    }

    fn query(&mut self, request: Request) -> Result<Value, Error> {
        let reply = self.usb.request(&request)?;
        response_value(reply.decode().map_err(|_| Error::Protocol)?)
    }

    fn pool_list(&self, arguments: &Value) -> Result<Value, Error> {
        let page_size = arguments
            .get("page_size")
            .and_then(Value::as_u64)
            .unwrap_or(16)
            .min(16) as usize;
        let registry = self.reconstructed_registry()?;
        let cursor = arguments
            .get("cursor")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            .min(registry.len());
        let pools: Vec<_> = registry
            .iter()
            .skip(cursor)
            .take(page_size)
            .map(|pool| {
                json!({
                    "pool_id": pool.pool.to_string(),
                    "incarnation_id": pool.incarnation.to_string(),
                    "network": pool.network,
                    "socket_path": pool.socket_path,
                })
            })
            .collect();
        let next =
            (cursor + pools.len() < registry.len()).then(|| (cursor + pools.len()).to_string());
        Ok(json!({ "pools": pools, "cursor": next }))
    }

    fn reconstructed_registry(&self) -> Result<Vec<PoolBinding>, Error> {
        let mut registry: HashMap<PoolId, PoolBinding> = self
            .config
            .pools
            .iter()
            .cloned()
            .map(|binding| (binding.pool, binding))
            .collect();
        for completed in self.journal.completed() {
            let response = decode_durable(&completed.terminal.public_result)?;
            let receipt = match response {
                Response::Mutate(receipt) | Response::Reconcile(receipt) => receipt,
                _ => continue,
            };
            let PublicOutcome::Committed { result, .. } = receipt.outcome else {
                continue;
            };
            match result {
                CommittedResult::Enrolled { target, .. } => {
                    let intent: Envelope =
                        serde_json::from_slice(&completed.intent).map_err(|_| Error::Protocol)?;
                    let network = string(&intent.arguments, "network")?.to_owned();
                    if !self.config.networks.contains_key(&network) {
                        return Err(Error::Protocol);
                    }
                    if let Some(existing) = registry.get(&target.pool) {
                        if existing.incarnation != target.incarnation || existing.network != network
                        {
                            return Err(Error::Protocol);
                        }
                        continue;
                    }
                    registry.insert(
                        target.pool,
                        PoolBinding {
                            pool: target.pool,
                            incarnation: target.incarnation,
                            socket_path: self
                                .config
                                .socket_directory
                                .join(format!("{}.sock", target.pool)),
                            network,
                        },
                    );
                }
                CommittedResult::Deleted(deleted)
                    if registry.get(&deleted.target().pool).is_some_and(|binding| {
                        binding.incarnation == deleted.target().incarnation
                    }) =>
                {
                    registry.remove(&deleted.target().pool);
                }
                _ => {}
            }
        }
        let mut registry: Vec<_> = registry.into_values().collect();
        registry.sort_by_key(|binding| binding.pool.to_string());
        Ok(registry)
    }

    fn mutation(
        &self,
        action: Action,
        operation_id: OperationId,
        expected_revision: u64,
        arguments: &Value,
    ) -> Result<Mutation, Error> {
        if action == Action::DeviceCommission {
            let serial = string(arguments, "usb_serial")?;
            if serial.as_bytes() != self.config.selected_serial.as_bytes() {
                return Err(Error::InvalidInput);
            }
            return Mutation::commission(
                UsbSerial::new(serial.as_bytes()).map_err(|_| Error::InvalidInput)?,
                operation_id,
                expected_revision,
            )
            .map_err(|_| Error::InvalidInput);
        }
        let device = self.config.pin.ok_or(Error::ModeDenied)?.device;
        let device_action = match action {
            Action::PoolEnroll => {
                let cold = parse_hex::<32>(string(arguments, "cold_verification_key")?)?;
                let network_name = string(arguments, "network")?;
                let network = self
                    .config
                    .networks
                    .get(network_name)
                    .ok_or(Error::InvalidInput)?;
                DeviceAction::Enroll {
                    cold_key: cold,
                    network: network.binding,
                    publication_floor_us: self
                        .deletion_floor(PoolId::from_cold_verification_key(&cold)),
                }
            }
            Action::GenerationCreate => DeviceAction::Generate {
                target: pool_target(arguments)?,
            },
            Action::GenerationCertificate => DeviceAction::InstallCertificate {
                target: generation_target(arguments)?,
                certificate: CertificateBytes::new(&decode_hex(string(arguments, "certificate")?)?)
                    .map_err(|_| Error::InvalidInput)?,
            },
            Action::GenerationDiscard => DeviceAction::Discard {
                target: generation_target(arguments)?,
            },
            Action::RecipientSet => DeviceAction::SetRecipient {
                public_key: parse_hex::<32>(string(arguments, "public_key")?)?,
            },
            Action::PoolDelete => DeviceAction::Delete {
                target: pool_target(arguments)?,
                publication_time_us: None,
            },
            _ => return Err(Error::Protocol),
        };
        Mutation::managed(
            device,
            self.journal.next_sequence(),
            operation_id,
            expected_revision,
            device_action,
        )
        .map_err(|_| Error::InvalidInput)
    }

    fn execute_mutation(&mut self, intent: &[u8], mutation: Mutation) -> Result<Value, Error> {
        let request = if matches!(mutation.binding(), Binding::Commission { .. }) {
            Request::Commission(mutation)
        } else {
            Request::Mutate(mutation)
        };
        let key = MutationKey {
            sequence: mutation.sequence(),
            operation_id: mutation.operation_id().into_bytes(),
            request_digest: mutation.usb_digest().into_bytes(),
        };
        let mut encoded = [0; wire::MAX_PAYLOAD];
        let (kind, len) =
            wire::encode_request(&request, &mut encoded).map_err(|_| Error::Protocol)?;
        let mut durable_request = Vec::with_capacity(len + 2);
        durable_request.extend_from_slice(&(kind as u16).to_be_bytes());
        durable_request.extend_from_slice(&encoded[..len]);
        self.journal.append_intent(key, intent)?;
        self.journal.append_device_request(key, &durable_request)?;

        let reply = self.usb.request(&request)?;
        let response = reply.decode().map_err(|_| Error::Protocol)?;
        let receipt = match &response {
            Response::Mutate(receipt) | Response::Commission(receipt) => *receipt,
            _ => return Err(Error::Protocol),
        };
        let result_digest = match receipt.outcome {
            PublicOutcome::Committed { result_digest, .. }
            | PublicOutcome::Rejected { result_digest, .. } => result_digest,
            PublicOutcome::Pending | PublicOutcome::Unknown | PublicOutcome::Stale => {
                return response_value(response);
            }
        };
        let mut terminal = Vec::with_capacity(reply.payload().len() + 2);
        terminal.extend_from_slice(&(reply.kind as u16).to_be_bytes());
        terminal.extend_from_slice(reply.payload());
        self.journal
            .append_terminal(key, result_digest.into_bytes(), &terminal)?;
        let value = response_value(response)?;

        let ack = self.usb.request(&Request::ReceiptAck {
            sequence: mutation.sequence(),
            result_digest,
        })?;
        match ack.decode().map_err(|_| Error::Protocol)? {
            Response::ReceiptAck(response) if response.result.is_ok() => {
                self.usb
                    .clear_outstanding(mutation.sequence(), mutation.usb_digest())?;
                self.journal
                    .append_acknowledged(key, result_digest.into_bytes())?;
            }
            _ => return Err(Error::Protocol),
        }
        Ok(value)
    }

    fn reconcile(&mut self, arguments: &Value) -> Result<Value, Error> {
        let operation_id = OperationId::parse_hex(string(arguments, "operation_id")?)
            .map_err(|_| Error::InvalidInput)?;
        let digest = Digest32::parse_hex(string(arguments, "request_digest")?)
            .map_err(|_| Error::InvalidInput)?;
        if let Some(completed) = self.journal.completed().iter().rev().find(|entry| {
            entry.key.operation_id == operation_id.into_bytes()
                && entry.key.request_digest == digest.into_bytes()
        }) {
            return decode_durable_response(&completed.terminal.public_result);
        }
        let pending = self.journal.pending().ok_or(Error::InvalidInput)?;
        if pending.key.operation_id != operation_id.into_bytes()
            || pending.key.request_digest != digest.into_bytes()
        {
            return Err(Error::InvalidInput);
        }
        if let Some(terminal) = &pending.terminal {
            return decode_durable_response(&terminal.public_result);
        }
        let binding = self.config.pin.map_or_else(
            || {
                ReceiptBinding::Serial(
                    UsbSerial::new(self.config.selected_serial.as_bytes()).unwrap(),
                )
            },
            |pin| ReceiptBinding::Device(pin.device),
        );
        let binding = match binding {
            ReceiptBinding::Serial(serial) => wire::ReconcileBinding::Serial(serial),
            ReceiptBinding::Device(device) => wire::ReconcileBinding::Device(device),
        };
        self.query(Request::Reconcile {
            sequence: pending.key.sequence,
            operation_id,
            digest,
            binding,
        })
    }

    fn deletion_floor(&self, pool: PoolId) -> u64 {
        self.journal
            .completed()
            .iter()
            .filter_map(|completed| {
                let response = decode_durable(&completed.terminal.public_result).ok()?;
                let receipt = match response {
                    Response::Mutate(receipt)
                    | Response::Commission(receipt)
                    | Response::Reconcile(receipt) => receipt,
                    _ => return None,
                };
                match receipt.outcome {
                    PublicOutcome::Committed {
                        result: CommittedResult::Deleted(deleted),
                        ..
                    } if deleted.target().pool == pool => Some(deleted.high_water_us()),
                    _ => None,
                }
            })
            .max()
            .unwrap_or(0)
    }
}

fn enforce_mode(mode: RunMode, action: Action) -> Result<(), Error> {
    if mode == RunMode::Commissioning
        && !matches!(
            action,
            Action::DeviceStatus | Action::DeviceCommission | Action::OperationReconcile
        )
    {
        return Err(Error::ModeDenied);
    }
    if mode == RunMode::Normal && action == Action::DeviceCommission {
        return Err(Error::ModeDenied);
    }
    Ok(())
}

fn response_value(response: Response<'_>) -> Result<Value, Error> {
    Ok(match response {
        Response::Hello(_) => return Err(Error::Protocol),
        Response::Status(status) => json!({
            "device_id": status.device.to_string(),
            "revision": status.revision,
            "health": health_name(status.health),
            "commissioning_state": commissioning_state_name(status.commissioning_state),
            "receipt_pending": status.receipt_pending,
        }),
        Response::Context(_) | Response::Current(_) => return Err(Error::Protocol),
        Response::Mutate(receipt)
        | Response::Commission(receipt)
        | Response::Reconcile(receipt) => receipt_value(receipt),
        Response::ReceiptAck(response) => json!({
            "sequence": response.sequence,
            "result_digest": response.result_digest.to_string(),
            "accepted": response.result.is_ok(),
        }),
        Response::Artifact(response) => match response.result {
            wire::ArtifactResult::Retained {
                artifact, digest, ..
            } => json!({
                "artifact": hex(artifact),
                "artifact_digest": digest.to_string(),
                "retired": false,
            }),
            wire::ArtifactResult::Retired => json!({ "retired": true }),
            wire::ArtifactResult::Unavailable { code } => json!({ "unavailable_code": code }),
        },
        Response::PublicKey(response) => match response.result {
            wire::PublicKeyResult::Available {
                verification_key,
                revision,
                artifact_digest,
            } => json!({
                "verification_key": hex(&verification_key),
                "revision": revision,
                "artifact_digest": artifact_digest.to_string(),
            }),
            wire::PublicKeyResult::Unavailable { code } => json!({ "unavailable_code": code }),
        },
    })
}

fn receipt_value(receipt: wire::PublicReceipt) -> Value {
    let outcome = match receipt.outcome {
        PublicOutcome::Pending => json!({ "state": "pending" }),
        PublicOutcome::Unknown => json!({ "state": "unknown" }),
        PublicOutcome::Stale => json!({ "state": "stale" }),
        PublicOutcome::Rejected {
            code,
            result_digest,
        } => json!({
            "state": "rejected", "code": code, "result_digest": result_digest.to_string()
        }),
        PublicOutcome::Committed {
            result,
            result_digest,
        } => json!({
            "state": "committed",
            "result": committed_value(result),
            "result_digest": result_digest.to_string()
        }),
    };
    json!({
        "sequence": receipt.sequence,
        "operation_id": receipt.operation_id.to_string(),
        "request_digest": receipt.request_digest.to_string(),
        "outcome": outcome,
    })
}

fn normalize_result(value: Value) -> Result<(&'static str, Value, Value), Error> {
    let Some(outcome) = value.get("outcome").and_then(Value::as_object).cloned() else {
        return Ok(("success", value, Value::Null));
    };
    let state = outcome
        .get("state")
        .and_then(Value::as_str)
        .ok_or(Error::Protocol)?
        .to_owned();
    let mut receipt = value.as_object().ok_or(Error::Protocol)?.clone();
    receipt.remove("outcome");
    match state.as_str() {
        "committed" => {
            let committed = outcome
                .get("result")
                .and_then(Value::as_object)
                .ok_or(Error::Protocol)?;
            receipt.insert("version".to_owned(), Value::from(1));
            for (name, field) in committed {
                receipt.insert(name.clone(), field.clone());
            }
            receipt.insert(
                "result_digest".to_owned(),
                outcome
                    .get("result_digest")
                    .cloned()
                    .ok_or(Error::Protocol)?,
            );
            Ok(("success", Value::Object(receipt), Value::Null))
        }
        "rejected" => {
            let code = outcome
                .get("code")
                .and_then(Value::as_u64)
                .and_then(|code| u16::try_from(code).ok())
                .ok_or(Error::Protocol)?;
            receipt.insert("device_code".to_owned(), Value::from(code));
            Ok((
                "rejected",
                Value::Null,
                json!({
                    "code": device_error_code(code),
                    "message": "device rejected the lifecycle operation",
                    "operation_id": receipt.get("operation_id").cloned().unwrap_or(Value::Null),
                }),
            ))
        }
        "pending" | "unknown" | "stale" => Ok((
            if state == "pending" {
                "pending"
            } else {
                "uncertain"
            },
            Value::Null,
            json!({
                "code": "outcome_unknown",
                "message": if state == "pending" {
                    "device operation is still pending"
                } else {
                    "device has no matching terminal receipt"
                },
                "operation_id": receipt.get("operation_id").cloned().unwrap_or(Value::Null),
            }),
        )),
        _ => Err(Error::Protocol),
    }
}

fn health_name(value: u8) -> &'static str {
    match value {
        0 => "ready",
        13 => "entropy_failure",
        _ => "storage_failure",
    }
}

fn commissioning_state_name(value: u8) -> &'static str {
    match value {
        0 => "blank",
        1 => "committed",
        _ => "unavailable",
    }
}

fn device_error_code(code: u16) -> &'static str {
    match code {
        10 => "uncommissioned",
        11 => "already_commissioned",
        12 => "storage_failure",
        13 => "entropy_failure",
        14 => "pool_duplicate",
        15 => "capacity_exceeded",
        16 => "pool_unknown",
        17 => "generation_mismatch",
        18 => "recipient_mismatch",
        19 => "generation_mismatch",
        20 => "staged_occupied",
        21 => "certificate_invalid",
        22 => "certificate_regressive",
        23 => "period_unavailable",
        24 => "period_regressive",
        25 => "period_unavailable",
        26 => "expired",
        101 => "operation_conflict",
        102 => "revision_conflict",
        105 => "busy",
        106 => "operation_conflict",
        109 => "wrong_device",
        _ => "invalid_input",
    }
}

fn committed_value(result: CommittedResult) -> Value {
    match result {
        CommittedResult::Commissioned(record) => json!({
            "kind": "commissioned",
            "device_id": record.device().to_string(),
            "identity_public_key": hex(record.identity_public_key()),
            "identity_fingerprint": record.identity_fingerprint().to_string(),
            "usb_serial": core::str::from_utf8(record.serial().as_slice())
                .map_or_else(|_| hex(record.serial().as_slice()), str::to_owned),
            "protocol_version": record.protocol_version(),
            "storage_version": record.storage_version(),
            "revision": record.device_revision(),
        }),
        CommittedResult::Deleted(deleted) => json!({
            "kind": "deleted",
            "pool_id": deleted.target().pool.to_string(),
            "incarnation_id": deleted.target().incarnation.to_string(),
            "revision": deleted.revision(),
            "drop_timestamp_us": deleted.drop_timestamp_us(),
            "high_water_us": deleted.high_water_us(),
        }),
        CommittedResult::Enrolled { target, revision } => json!({
            "kind": "enrolled",
            "pool_id": target.pool.to_string(),
            "incarnation_id": target.incarnation.to_string(),
            "revision": revision,
        }),
        CommittedResult::Generated {
            generation,
            revision,
            artifact_digest,
        } => json!({
            "kind": "generated",
            "generation_id": generation.to_string(),
            "revision": revision,
            "artifact_digest": artifact_digest.to_string(),
        }),
        CommittedResult::Applied { revision } => json!({
            "kind": "applied",
            "revision": revision,
        }),
    }
}

fn decode_durable_response(bytes: &[u8]) -> Result<Value, Error> {
    response_value(decode_durable(bytes)?)
}

fn decode_durable(bytes: &[u8]) -> Result<Response<'_>, Error> {
    if bytes.len() < 2 {
        return Err(Error::Protocol);
    }
    let kind = wire::Kind::try_from(u16::from_be_bytes([bytes[0], bytes[1]]))
        .map_err(|_| Error::Protocol)?;
    wire::decode_response(kind, &bytes[2..]).map_err(|_| Error::Protocol)
}

fn pool_target(arguments: &Value) -> Result<PoolTarget, Error> {
    Ok(PoolTarget {
        pool: parse_id::<28, PoolId>(arguments, "pool_id", PoolId::from_bytes)?,
        incarnation: parse_id::<16, IncarnationId>(
            arguments,
            "incarnation_id",
            IncarnationId::from_bytes,
        )?,
    })
}
fn generation_target(arguments: &Value) -> Result<GenerationTarget, Error> {
    Ok(GenerationTarget {
        pool: pool_target(arguments)?,
        generation: parse_id::<16, GenerationId>(
            arguments,
            "generation_id",
            GenerationId::from_bytes,
        )?,
    })
}
fn parse_id<const N: usize, T>(
    arguments: &Value,
    field: &'static str,
    constructor: impl FnOnce([u8; N]) -> T,
) -> Result<T, Error> {
    Ok(constructor(parse_hex(string(arguments, field)?)?))
}
fn string<'a>(arguments: &'a Value, field: &'static str) -> Result<&'a str, Error> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidInput)
}
fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|_| Error::InvalidInput)
}
fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::InvalidInput);
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Ok((nibble(pair[0]).ok_or(Error::InvalidInput)? << 4)
                | nibble(pair[1]).ok_or(Error::InvalidInput)?)
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::DeviceStatus => "device.status",
        Action::DeviceCommission => "device.commission",
        Action::PoolList => "pool.list",
        Action::PoolStatus => "pool.status",
        Action::PoolEnroll => "pool.enroll",
        Action::GenerationCreate => "generation.create",
        Action::GenerationPublicKey => "generation.public_key",
        Action::GenerationArtifact => "generation.artifact",
        Action::GenerationCertificate => "generation.certificate",
        Action::GenerationDiscard => "generation.discard",
        Action::RecipientSet => "recipient.set",
        Action::PoolDelete => "pool.delete",
        Action::OperationReconcile => "operation.reconcile",
    }
}

trait IntoBytes<const N: usize> {
    fn into_bytes(self) -> [u8; N];
}
impl IntoBytes<16> for OperationId {
    fn into_bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}
impl IntoBytes<32> for Digest32 {
    fn into_bytes(self) -> [u8; 32] {
        *self.as_bytes()
    }
}
