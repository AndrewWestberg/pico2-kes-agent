//! Management JSON to journaled USB dispatch.

use crate::{
    config::{Config, PoolBinding, RunMode},
    daemon::{
        journal::{Journal, MutationKey, PendingMutation},
        status,
        usb::{DeviceTransport, Error as UsbError},
    },
};
use kes_core::{
    identity::{DeviceId, Digest32, GenerationId, IncarnationId, OperationId, PoolId},
    operation::{
        Action as DeviceAction, Binding, CertificateBytes, CommittedResult, GenerationTarget,
        LiveTarget, Mutation, PoolTarget, UsbSerial,
    },
};
use kes_protocol::{
    management::{Action, Kind as ManagementKind, Message},
    usb::{self as wire, PublicOutcome, ReceiptBinding, Request, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub enum Error {
    Protocol,
    InvalidInput,
    OperationConflict,
    ModeDenied,
    RevisionConflict,
    DeviceTarget(u16),
    ArtifactRetired,
    GenerationUnknown,
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

#[derive(Default)]
pub struct SnapshotCache {
    snapshot: Option<HostSnapshot>,
}

struct HostSnapshot {
    id: String,
    config_identity: String,
    journal_position: u64,
    last_result: Option<[u8; 32]>,
    observed_at_unix_us: u64,
    bindings: Vec<Value>,
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
            Action::DeviceStatus => self.status(None)?,
            Action::DeviceSecurity => self.query(Request::SecurityStatus)?,
            Action::DeviceInventory => self.inventory()?,
            Action::HostObserve => self.host_observe(&envelope.arguments)?,
            Action::DeviceInfo => self.device_info()?,
            Action::PoolObserve => self.pool_observe(pool_target(&envelope.arguments)?)?,
            Action::PoolStatus => {
                let pool =
                    parse_id::<28, PoolId>(&envelope.arguments, "pool_id", PoolId::from_bytes)?;
                self.status(Some(pool))?
            }
            Action::PoolList => self.pool_list(&envelope.arguments)?,
            Action::GenerationPublicKey => {
                let target = generation_target(&envelope.arguments)?;
                self.query(Request::PublicKey { target })?
            }
            Action::GenerationArtifact => {
                let target = generation_target(&envelope.arguments)?;
                if !self.generation_was_created(target) {
                    return Err(Error::GenerationUnknown);
                }
                self.artifact(target)?
            }
            Action::OperationReconcile => self.reconcile(&envelope.arguments)?,
            action if action.is_mutation() => {
                let operation_id = operation_id.ok_or(Error::Protocol)?;
                if envelope.operation_id.as_deref() != Some(&operation_id.to_string())
                    || envelope.expected_revision != expected_revision
                {
                    return Err(Error::Protocol);
                }
                match self.replay_mutation(&envelope)? {
                    Some(result) => result,
                    None => {
                        let mutation = self.mutation(
                            action,
                            operation_id,
                            expected_revision.ok_or(Error::Protocol)?,
                            &envelope.arguments,
                        )?;
                        self.execute_mutation(bytes, mutation)?
                    }
                }
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

    fn status(&mut self, pool: Option<PoolId>) -> Result<Value, Error> {
        let recovering = self.journal.pending().is_some();
        let probe = if self.config.mode == RunMode::Commissioning {
            let mut nonce = [0; 32];
            File::open("/dev/urandom")
                .and_then(|mut file| file.read_exact(&mut nonce))
                .map_err(|error| Error::Usb(UsbError::Io(error)))?;
            self.usb
                .request(&Request::Hello { nonce })
                .map_err(Error::Usb)
                .and_then(|reply| {
                    if reply.kind != wire::Kind::Hello {
                        return Err(Error::Protocol);
                    }
                    let Response::Hello(hello) = reply.decode().map_err(|_| Error::Protocol)?
                    else {
                        return Err(Error::Protocol);
                    };
                    if hello.nonce != nonce {
                        return Err(Error::Protocol);
                    }
                    Ok(matches!(hello.state, wire::HelloState::Uncommissioned))
                })
        } else {
            Ok(false)
        };
        let result = probe.and_then(|blank| {
            if blank {
                return Ok(json!({
                    "health": if recovering { "recovering" } else { "ready" },
                    "commissioning_state": "blank",
                }));
            }
            let reply = self.usb.request(&Request::Status { pool })?;
            let Response::Status(response) = reply.decode().map_err(|_| Error::Protocol)? else {
                return Err(Error::Protocol);
            };
            Ok(status::response(response, recovering))
        });
        match result {
            Ok(response) => Ok(response),
            Err(Error::Usb(
                UsbError::NotFound | UsbError::Usb(_) | UsbError::Io(_) | UsbError::Interface,
            )) => Ok(status::unavailable(recovering, pool)),
            Err(Error::Usb(UsbError::Busy)) => Ok(status::unavailable(true, pool)),
            Err(error) => Err(error),
        }
    }

    fn query(&mut self, request: Request) -> Result<Value, Error> {
        let reply = self.usb.request(&request)?;
        response_value(reply.decode().map_err(|_| Error::Protocol)?)
    }

    fn inventory(&mut self) -> Result<Value, Error> {
        let expected_device = match self.config.mode {
            RunMode::Normal => self
                .config
                .pin
                .map(|pin| pin.device)
                .ok_or(Error::Protocol)?,
            RunMode::Commissioning => {
                parse_id::<16, DeviceId>(&self.device_info()?, "device_id", DeviceId::from_bytes)?
            }
        };
        let reply = self.usb.request(&Request::PoolInventory)?;
        if reply.kind != wire::Kind::PoolInventory {
            return Err(Error::Protocol);
        }
        let Response::PoolInventory(response) = reply.decode().map_err(|_| Error::Protocol)? else {
            return Err(Error::Protocol);
        };
        if expected_device != response.device {
            return Err(Error::Protocol);
        }
        let count = usize::from(response.inventory.count);
        let entries = response
            .inventory
            .entries
            .get(..count)
            .ok_or(Error::Protocol)?;
        for (index, entry) in entries.iter().enumerate() {
            if entries[..index]
                .iter()
                .any(|previous| previous.target.pool == entry.target.pool)
            {
                return Err(Error::Protocol);
            }
        }
        let pools: Vec<_> = entries
            .iter()
            .map(|entry| {
                json!({
                    "pool_id": entry.target.pool.to_string(),
                    "incarnation_id": entry.target.incarnation.to_string(),
                    "revision": entry.revision,
                })
            })
            .collect();
        Ok(json!({
            "device_id": response.device.to_string(),
            "revision": response.inventory.revision,
            "pools": pools,
        }))
    }

    fn host_observe(&mut self, arguments: &Value) -> Result<Value, Error> {
        let config_identity = self.config.identity_hex();
        let journal_position = self.journal.completed().len() as u64;
        let last_result = self
            .journal
            .completed()
            .last()
            .map(|entry| entry.terminal.result_digest);
        let cached_id = self
            .usb
            .observation_cache()
            .and_then(|cache| cache.snapshot.as_ref())
            .filter(|snapshot| {
                snapshot.config_identity == config_identity
                    && snapshot.journal_position == journal_position
                    && snapshot.last_result == last_result
            })
            .map(|snapshot| snapshot.id.clone());
        let id = cached_id.unwrap_or_else(|| {
            let mut hash = Sha256::new();
            hash.update(config_identity.as_bytes());
            hash.update(journal_position.to_be_bytes());
            for entry in self.journal.completed() {
                hash.update(entry.key.sequence.to_be_bytes());
                hash.update(entry.key.operation_id);
                hash.update(entry.key.request_digest);
                hash.update(entry.terminal.result_digest);
                hash.update(Sha256::digest(&entry.intent));
                hash.update(Sha256::digest(&entry.terminal.public_result));
            }
            hex(&hash.finalize())
        });
        if let Some(expected) = arguments.get("snapshot_id").and_then(Value::as_str)
            && expected != id
        {
            return Err(Error::RevisionConflict);
        }
        let cursor = arguments
            .get("cursor")
            .and_then(Value::as_str)
            .map(|value| value.parse::<usize>().map_err(|_| Error::InvalidInput))
            .transpose()?
            .unwrap_or(0);
        if cursor != 0 && arguments.get("snapshot_id").is_none() {
            return Err(Error::InvalidInput);
        }
        let page_size = arguments
            .get("page_size")
            .and_then(Value::as_u64)
            .unwrap_or(16) as usize;
        if !(1..=16).contains(&page_size) {
            return Err(Error::InvalidInput);
        }
        let cached = self
            .usb
            .observation_cache()
            .and_then(|cache| cache.snapshot.as_ref())
            .is_some_and(|snapshot| snapshot.id == id);
        if !cached {
            let effective = self.reconstructed_registry_observe(true)?;
            let mut bindings = Vec::new();
            for configured in &self.config.pools {
                let matching = effective.iter().find(|entry| entry.pool == configured.pool);
                let same = matching.is_some_and(|entry| {
                    entry.incarnation == configured.incarnation
                        && entry.network == configured.network
                });
                let conflicting = matching.is_some() && !same
                    || !self.config.networks.contains_key(&configured.network);
                bindings.push(binding_value(
                    configured,
                    true,
                    same && !conflicting,
                    matching.is_none(),
                    conflicting,
                ));
            }
            for entry in &effective {
                if !self.config.pools.iter().any(|configured| {
                    configured.pool == entry.pool
                        && configured.incarnation == entry.incarnation
                        && configured.network == entry.network
                }) {
                    let conflicting = self
                        .config
                        .pools
                        .iter()
                        .any(|configured| configured.pool == entry.pool)
                        || !self.config.networks.contains_key(&entry.network);
                    bindings.push(binding_value(
                        entry,
                        false,
                        self.config.networks.contains_key(&entry.network),
                        false,
                        conflicting,
                    ));
                }
            }
            let observed_at_unix_us = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Protocol)?
                    .as_micros(),
            )
            .map_err(|_| Error::Protocol)?;
            let snapshot = HostSnapshot {
                id: id.clone(),
                config_identity,
                journal_position,
                last_result,
                observed_at_unix_us,
                bindings,
            };
            if let Some(cache) = self.usb.observation_cache() {
                cache.snapshot = Some(snapshot);
            } else {
                return host_page(&snapshot, cursor, page_size);
            }
        }
        let snapshot = self
            .usb
            .observation_cache()
            .and_then(|cache| cache.snapshot.as_ref())
            .ok_or(Error::Protocol)?;
        host_page(snapshot, cursor, page_size)
    }

    fn device_info(&mut self) -> Result<Value, Error> {
        let reply = self.usb.request(&Request::FirmwareInfo)?;
        let Response::FirmwareInfo(info) = reply.decode().map_err(|_| Error::Protocol)? else {
            return Err(Error::Protocol);
        };
        if info.serial.as_slice() != self.config.selected_serial.as_bytes()
            || (self.config.mode == RunMode::Normal
                && self.config.pin.map(|pin| pin.device) != info.device)
        {
            return Err(Error::Usb(UsbError::IdentityMismatch));
        }
        let serial = std::str::from_utf8(info.serial.as_slice()).map_err(|_| Error::Protocol)?;
        Ok(
            json!({"schema_version":1,"device_id":info.device.map(|id| id.to_string()),
            "usb_serial":serial,"version":info.version,"build_id":hex(&info.build_id),
            "source_commit":info.source_commit,"protocol_major":info.protocol_major,
            "storage_version":info.storage_version,"capacity":info.capacity,
            "security_profile":info.security_profile,"supported_observations":info.supported_observations}),
        )
    }

    fn pool_observe(&mut self, target: PoolTarget) -> Result<Value, Error> {
        let reply = self.usb.request(&Request::PoolObservation { target })?;
        let observed = match reply.decode().map_err(|_| Error::Protocol)? {
            Response::PoolObservation(value) => value,
            Response::PoolObservationError {
                device,
                target: returned,
                code,
            } => {
                if returned != target || self.config.pin.map(|pin| pin.device) != Some(device) {
                    return Err(Error::Usb(UsbError::IdentityMismatch));
                }
                return Err(Error::DeviceTarget(code));
            }
            _ => return Err(Error::Protocol),
        };
        if observed.target != target
            || self.config.pin.map(|pin| pin.device) != Some(observed.device)
        {
            return Err(Error::Usb(UsbError::IdentityMismatch));
        }
        match self.host_observe(&json!({})) {
            Ok(_) | Err(Error::InvalidInput) => {}
            Err(error) => return Err(error),
        }
        let network = if let Some(snapshot) = self
            .usb
            .observation_cache()
            .and_then(|cache| cache.snapshot.as_ref())
        {
            snapshot
                .bindings
                .iter()
                .find(|entry| {
                    entry["effective"] == true
                        && entry["pool_id"] == target.pool.to_string()
                        && entry["incarnation_id"] == target.incarnation.to_string()
                })
                .and_then(|entry| entry["network"].as_str())
                .map(str::to_owned)
        } else {
            self.reconstructed_registry_observe(true)?
                .iter()
                .find(|entry| entry.pool == target.pool && entry.incarnation == target.incarnation)
                .map(|entry| entry.network.clone())
        };
        let reason = if network.is_some() {
            "context observation unavailable"
        } else {
            "no effective host binding"
        };
        let context = network.as_ref().and_then(|name| {
            let (accepted_period, age) = self.usb.observed_context(target)?;
            let config = self.config.networks.get(name)?;
            let now = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()?
                    .as_micros(),
            )
            .ok()?;
            let period = config.timing.slot_at_time(now).ok()? / config.binding.slots_per_period();
            (period >= accepted_period).then_some((period, age))
        });
        Ok(
            json!({"schema_version":1,"device_id":observed.device.to_string(),
            "pool_id":target.pool.to_string(),"incarnation_id":target.incarnation.to_string(),
            "revision":observed.revision,"health":observed.health,
            "active":observed.active.map(|value| generation_observation(value, context.map(|(period, _)| period))).transpose()?,
            "staged":observed.staged.map(|value| generation_observation(value, context.map(|(period, _)| period))).transpose()?,
            "publication":observation_publication(observed.publication),
            "period_floor":observed.period_floor,"failure":observed.failure,
            "context":{"valid":context.is_some(),"source":context.map(|_| "host_utc"),"age_us":context.map(|(_, age)| age),"reason":if context.is_none() {Some(reason)} else {None}}}),
        )
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

    pub(crate) fn reconstructed_registry(&self) -> Result<Vec<PoolBinding>, Error> {
        self.reconstructed_registry_observe(false)
    }

    fn reconstructed_registry_observe(&self, observe: bool) -> Result<Vec<PoolBinding>, Error> {
        let mut registry: HashMap<PoolId, Option<PoolBinding>> = HashMap::new();
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
                    if let Some(Some(existing)) = registry.get(&target.pool) {
                        if existing.incarnation != target.incarnation || existing.network != network
                        {
                            return Err(Error::Protocol);
                        }
                        continue;
                    }
                    registry.insert(
                        target.pool,
                        Some(PoolBinding {
                            pool: target.pool,
                            incarnation: target.incarnation,
                            socket_path: self
                                .config
                                .socket_directory
                                .join(format!("{}.sock", target.pool)),
                            network,
                        }),
                    );
                }
                CommittedResult::Deleted(deleted) => {
                    let target = deleted.target();
                    if registry
                        .get(&target.pool)
                        .and_then(Option::as_ref)
                        .is_none_or(|binding| binding.incarnation == target.incarnation)
                    {
                        // Keep tombstones only where configuration could resurrect a retired pool.
                        if self
                            .config
                            .pools
                            .iter()
                            .any(|binding| binding.pool == target.pool)
                        {
                            registry.insert(target.pool, None);
                        } else {
                            registry.remove(&target.pool);
                        }
                    }
                }
                _ => {}
            }
        }
        for configured in &self.config.pools {
            match registry.get_mut(&configured.pool) {
                None => {
                    registry.insert(configured.pool, Some(configured.clone()));
                }
                Some(Some(binding)) if binding.incarnation == configured.incarnation => {
                    if binding.network != configured.network {
                        if observe {
                            continue;
                        }
                        return Err(Error::Protocol);
                    }
                    binding.socket_path.clone_from(&configured.socket_path);
                }
                _ => {}
            }
        }
        let mut registry: Vec<_> = registry.into_values().flatten().collect();
        if !observe
            && registry
                .iter()
                .any(|binding| !self.config.networks.contains_key(&binding.network))
        {
            return Err(Error::Protocol);
        }
        registry.sort_by_key(|binding| binding.pool.to_string());
        Ok(registry)
    }

    fn replay_mutation(&mut self, request: &Envelope) -> Result<Option<Value>, Error> {
        let operation_id =
            OperationId::parse_hex(request.operation_id.as_deref().ok_or(Error::Protocol)?)
                .map_err(|_| Error::Protocol)?;
        if let Some(pending) = self.journal.pending()
            && pending.key.operation_id == operation_id.into_bytes()
        {
            validate_repeated_intent(&pending.intent, request)?;
            let digest = Digest32::from_bytes(pending.key.request_digest);
            return self.reconcile_operation(operation_id, digest).map(Some);
        }
        if let Some(completed) = self
            .journal
            .completed()
            .iter()
            .rev()
            .find(|entry| entry.key.operation_id == operation_id.into_bytes())
        {
            validate_repeated_intent(&completed.intent, request)?;
            return decode_durable_response(&completed.terminal.public_result).map(Some);
        }
        Ok(None)
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
        self.usb.prepare_mutation()?;
        let request = mutation_request(mutation);
        let key = mutation_key(&mutation);
        let mut encoded = [0; wire::MAX_PAYLOAD];
        let (kind, len) =
            wire::encode_request(&request, &mut encoded).map_err(|_| Error::Protocol)?;
        let mut durable_request = Vec::with_capacity(len + 2);
        durable_request.extend_from_slice(&(kind as u16).to_be_bytes());
        durable_request.extend_from_slice(&encoded[..len]);
        self.journal.append_intent(key, intent)?;
        self.journal.append_device_request(key, &durable_request)?;

        self.submit_mutation(mutation)
    }

    fn submit_mutation(&mut self, mutation: Mutation) -> Result<Value, Error> {
        let request = mutation_request(mutation);
        let key = mutation_key(&mutation);
        let reply = self
            .usb
            .request(&request)
            .map_err(|_| UsbError::Uncertain {
                sequence: key.sequence,
                digest: mutation.usb_digest(),
            })?;
        let response = reply.decode().map_err(|_| Error::Protocol)?;
        let receipt = match &response {
            Response::Mutate(receipt) | Response::Commission(receipt) => *receipt,
            _ => return Err(Error::Protocol),
        };
        validate_reconciled_receipt(
            &receipt,
            key,
            mutation.operation_id(),
            mutation.usb_digest(),
        )?;
        let (result_digest, retained_receipt) = match receipt.outcome {
            PublicOutcome::Committed { result_digest, .. } => (result_digest, true),
            PublicOutcome::Rejected {
                code,
                result_digest,
            } => (result_digest, code < 100),
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
        if !retained_receipt {
            self.usb
                .clear_outstanding(mutation.sequence(), mutation.usb_digest())?;
            self.journal
                .append_declined(key, result_digest.into_bytes())?;
            return Ok(value);
        }

        self.acknowledge(key, mutation.usb_digest(), result_digest)?;
        Ok(value)
    }

    /// Reconciles the sole durable pending mutation without requiring an
    /// operator-owned receipt file. Used by the unattended daemon before it
    /// resumes context delivery and subscriptions after reconnect.
    pub fn reconcile_pending(&mut self) -> Result<Option<Value>, Error> {
        let Some(pending) = self.journal.pending().cloned() else {
            return Ok(None);
        };
        let operation_id = OperationId::from_bytes(pending.key.operation_id);
        let digest = Digest32::from_bytes(pending.key.request_digest);
        self.reconcile_operation(operation_id, digest).map(Some)
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
        self.reconcile_operation(operation_id, digest)
    }

    fn reconcile_operation(
        &mut self,
        operation_id: OperationId,
        digest: Digest32,
    ) -> Result<Value, Error> {
        let mut pending = self.journal.pending().cloned().ok_or(Error::InvalidInput)?;
        if pending.key.operation_id != operation_id.into_bytes()
            || pending.key.request_digest != digest.into_bytes()
        {
            return Err(Error::InvalidInput);
        }
        if pending.device_request.is_none() {
            let message = Message::decode(&pending.intent).map_err(|_| Error::Protocol)?;
            let ManagementKind::Request { action, .. } = message.kind() else {
                return Err(Error::Protocol);
            };
            let intent: Envelope =
                serde_json::from_slice(&pending.intent).map_err(|_| Error::Protocol)?;
            let mutation = self.mutation(
                action,
                operation_id,
                intent.expected_revision.ok_or(Error::Protocol)?,
                &intent.arguments,
            )?;
            if mutation_key(&mutation) != pending.key {
                return Err(Error::Protocol);
            }
            let mut payload = [0; wire::MAX_PAYLOAD];
            let (kind, length) = wire::encode_request(&mutation_request(mutation), &mut payload)
                .map_err(|_| Error::Protocol)?;
            let mut encoded = Vec::with_capacity(length + 2);
            encoded.extend_from_slice(&(kind as u16).to_be_bytes());
            encoded.extend_from_slice(&payload[..length]);
            self.journal.append_device_request(pending.key, &encoded)?;
            pending.device_request = Some(encoded);
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
        if let Some(terminal) = pending.terminal {
            let declined = matches!(
                decode_durable(&terminal.public_result)?,
                Response::Mutate(wire::PublicReceipt {
                    outcome: PublicOutcome::Rejected { code: 100.., .. },
                    ..
                }) | Response::Commission(wire::PublicReceipt {
                    outcome: PublicOutcome::Rejected { code: 100.., .. },
                    ..
                })
            );
            if declined {
                self.usb.clear_outstanding(pending.key.sequence, digest)?;
                self.journal
                    .append_declined(pending.key, terminal.result_digest)?;
                return decode_durable_response(&terminal.public_result);
            }
            let result = decode_durable_response(&terminal.public_result)?;
            let observed = self.usb.request(&Request::Reconcile {
                sequence: pending.key.sequence,
                operation_id,
                digest,
                binding,
            })?;
            let Response::Reconcile(observed) = observed.decode().map_err(|_| Error::Protocol)?
            else {
                return Err(Error::Protocol);
            };
            validate_reconciled_receipt(&observed, pending.key, operation_id, digest)?;
            let observed_digest = match observed.outcome {
                PublicOutcome::Committed { result_digest, .. }
                | PublicOutcome::Rejected { result_digest, .. } => result_digest,
                PublicOutcome::Stale => {
                    self.usb.clear_outstanding(pending.key.sequence, digest)?;
                    self.journal
                        .append_acknowledged(pending.key, terminal.result_digest)?;
                    return Ok(result);
                }
                PublicOutcome::Pending | PublicOutcome::Unknown => return Err(Error::Protocol),
            };
            if observed_digest.into_bytes() != terminal.result_digest {
                return Err(Error::Protocol);
            }
            self.acknowledge(pending.key, digest, observed_digest)?;
            return Ok(result);
        }

        let reply = self.usb.request(&Request::Reconcile {
            sequence: pending.key.sequence,
            operation_id,
            digest,
            binding,
        })?;
        let Response::Reconcile(observed) = reply.decode().map_err(|_| Error::Protocol)? else {
            return Err(Error::Protocol);
        };
        validate_reconciled_receipt(&observed, pending.key, operation_id, digest)?;
        let result_digest = match observed.outcome {
            PublicOutcome::Committed { result_digest, .. }
            | PublicOutcome::Rejected { result_digest, .. } => result_digest,
            PublicOutcome::Unknown | PublicOutcome::Pending => {
                let encoded = pending.device_request.as_deref().ok_or(Error::Protocol)?;
                let (kind, payload) = encoded.split_at_checked(2).ok_or(Error::Protocol)?;
                let kind = wire::Kind::try_from(u16::from_be_bytes([kind[0], kind[1]]))
                    .map_err(|_| Error::Protocol)?;
                let request = wire::decode_request(kind, payload).map_err(|_| Error::Protocol)?;
                let mutation = match request {
                    Request::Mutate(mutation) | Request::Commission(mutation) => mutation,
                    _ => return Err(Error::Protocol),
                };
                if mutation_key(&mutation) != pending.key {
                    return Err(Error::Protocol);
                }
                self.usb.clear_outstanding(pending.key.sequence, digest)?;
                return self.submit_mutation(mutation);
            }
            PublicOutcome::Stale => return Err(Error::Protocol),
        };
        let original = original_terminal_response(&pending, observed)?;
        let mut payload = [0; wire::MAX_PAYLOAD];
        let (kind, length) =
            wire::encode_response(&original, &mut payload).map_err(|_| Error::Protocol)?;
        let value = response_value(original)?;
        let mut durable = Vec::with_capacity(length + 2);
        durable.extend_from_slice(&(kind as u16).to_be_bytes());
        durable.extend_from_slice(&payload[..length]);
        self.journal
            .append_terminal(pending.key, result_digest.into_bytes(), &durable)?;
        self.acknowledge(pending.key, digest, result_digest)?;
        Ok(value)
    }

    fn acknowledge(
        &mut self,
        key: MutationKey,
        digest: Digest32,
        result_digest: Digest32,
    ) -> Result<(), Error> {
        let ack = self
            .usb
            .request(&Request::ReceiptAck {
                sequence: key.sequence,
                result_digest,
            })
            .map_err(|_| UsbError::Uncertain {
                sequence: key.sequence,
                digest,
            })?;
        match ack.decode().map_err(|_| Error::Protocol)? {
            Response::ReceiptAck(response) if response.result.is_ok() => {
                self.usb.clear_outstanding(key.sequence, digest)?;
                self.journal
                    .append_acknowledged(key, result_digest.into_bytes())?;
                Ok(())
            }
            _ => Err(Error::Protocol),
        }
    }

    fn artifact(&mut self, target: GenerationTarget) -> Result<Value, Error> {
        let reply = self.usb.request(&Request::Artifact { target })?;
        match reply.decode().map_err(|_| Error::Protocol)? {
            Response::Artifact(wire::ArtifactResponse {
                result: wire::ArtifactResult::Retired,
                ..
            }) => Err(Error::ArtifactRetired),
            response @ Response::Artifact(_) => response_value(response),
            _ => Err(Error::Protocol),
        }
    }

    fn generation_was_created(&self, target: GenerationTarget) -> bool {
        self.journal.completed().iter().any(|completed| {
            let Ok(Response::Mutate(receipt)) = decode_durable(&completed.terminal.public_result)
            else {
                return false;
            };
            matches!(
                (receipt.target, receipt.outcome),
                (
                    Some(LiveTarget::Pool(pool)),
                    PublicOutcome::Committed {
                        result: CommittedResult::Generated { generation, .. },
                        ..
                    }
                ) if pool == target.pool && generation == target.generation
            )
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

fn binding_value(
    binding: &PoolBinding,
    configured: bool,
    effective: bool,
    retired: bool,
    conflicting: bool,
) -> Value {
    json!({"pool_id":binding.pool.to_string(),"incarnation_id":binding.incarnation.to_string(),
        "network":binding.network,"socket_path":binding.socket_path,
        "configured":configured,"effective":effective,"retired":retired,"conflicting":conflicting})
}

fn host_page(snapshot: &HostSnapshot, cursor: usize, size: usize) -> Result<Value, Error> {
    if cursor > snapshot.bindings.len() {
        return Err(Error::InvalidInput);
    }
    let mut daemon = serde_json::to_value(crate::build_info::identity("pico2-kes-agentd"))
        .map_err(|_| Error::Protocol)?;
    daemon["pid"] = json!(std::process::id());
    let mut page = json!({"schema_version":1,"snapshot_id":snapshot.id,"bindings":[],
        "next_cursor":null,"total":snapshot.bindings.len(),"observed_at_unix_us":snapshot.observed_at_unix_us,
        "daemon":daemon,"config_identity":snapshot.config_identity,"journal_position":snapshot.journal_position});
    for entry in snapshot.bindings.iter().skip(cursor).take(size) {
        page["bindings"]
            .as_array_mut()
            .ok_or(Error::Protocol)?
            .push(entry.clone());
        let next = cursor + page["bindings"].as_array().ok_or(Error::Protocol)?.len();
        page["next_cursor"] = if next < snapshot.bindings.len() {
            json!(next.to_string())
        } else {
            Value::Null
        };
        if serde_json::to_vec(&page)
            .map_err(|_| Error::Protocol)?
            .len()
            + 256
            > kes_protocol::management::MAX_FRAME
        {
            page["bindings"]
                .as_array_mut()
                .ok_or(Error::Protocol)?
                .pop();
            if page["bindings"]
                .as_array()
                .ok_or(Error::Protocol)?
                .is_empty()
            {
                return Err(Error::InvalidInput);
            }
            let next = cursor + page["bindings"].as_array().ok_or(Error::Protocol)?.len();
            page["next_cursor"] = json!(next.to_string());
            break;
        }
    }
    Ok(page)
}

fn generation_observation(
    value: wire::GenerationObservation,
    current: Option<u64>,
) -> Result<Value, Error> {
    let expiry = match (value.certificate_start, value.certificate_lifetime) {
        (Some(start), Some(lifetime)) => Some(start.checked_add(lifetime).ok_or(Error::Protocol)?),
        (None, None) => None,
        _ => return Err(Error::Protocol),
    };
    let relative = current
        .zip(value.certificate_start)
        .and_then(|(current, start)| current.checked_sub(start));
    let remaining = current
        .zip(expiry)
        .map(|(current, expiry)| expiry.saturating_sub(current));
    Ok(
        json!({"generation_id":value.generation.to_string(),"revision":value.revision,"role":value.role,
        "period":value.period,"health":value.health,"artifact_digest":value.artifact_digest.to_string(),
        "certificate_present":value.certificate_start.is_some(),"certificate_start":value.certificate_start,
        "certificate_lifetime":value.certificate_lifetime,"certificate_expiry":expiry,
        "current_absolute_period":current,"relative_period":relative,"remaining_valid_periods":remaining,
        "reason":if expiry.is_none() { Some("certificate absent") } else if current.is_none() { Some("context unavailable") } else if relative.is_none() { Some("before certificate start") } else { None }}),
    )
}

fn observation_publication(value: wire::Publication) -> Value {
    let (kind, generation, period, digest) = match value.kind {
        wire::PublicationKind::None => ("none", None, None, None),
        wire::PublicationKind::Drop => ("drop", None, None, None),
        wire::PublicationKind::Key {
            generation,
            period,
            certificate_digest,
        } => (
            "key",
            Some(generation.to_string()),
            Some(period),
            Some(certificate_digest.to_string()),
        ),
    };
    json!({"revision":value.revision,"timestamp_us":value.timestamp_us,"high_water_us":value.high_water_us,
        "kind":kind,"generation_id":generation,"relative_period":period,"certificate_digest":digest})
}

fn enforce_mode(mode: RunMode, action: Action) -> Result<(), Error> {
    if mode == RunMode::Commissioning
        && !matches!(
            action,
            Action::DeviceStatus
                | Action::DeviceSecurity
                | Action::DeviceInfo
                | Action::DeviceInventory
                | Action::HostObserve
                | Action::DeviceCommission
                | Action::OperationReconcile
        )
    {
        return Err(Error::ModeDenied);
    }
    if mode == RunMode::Normal && action == Action::DeviceCommission {
        return Err(Error::ModeDenied);
    }
    Ok(())
}

fn validate_repeated_intent(bytes: &[u8], request: &Envelope) -> Result<(), Error> {
    let saved: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Protocol)?;
    if saved.version != request.version
        || saved.action != request.action
        || saved.operation_id != request.operation_id
        || saved.expected_revision != request.expected_revision
        || saved.arguments != request.arguments
    {
        return Err(Error::OperationConflict);
    }
    Ok(())
}

fn mutation_key(mutation: &Mutation) -> MutationKey {
    MutationKey {
        sequence: mutation.sequence(),
        operation_id: mutation.operation_id().into_bytes(),
        request_digest: mutation.usb_digest().into_bytes(),
    }
}

fn mutation_request(mutation: Mutation) -> Request {
    if matches!(mutation.binding(), Binding::Commission { .. }) {
        Request::Commission(mutation)
    } else {
        Request::Mutate(mutation)
    }
}

fn validate_reconciled_receipt(
    observed: &wire::PublicReceipt,
    key: MutationKey,
    operation_id: OperationId,
    digest: Digest32,
) -> Result<(), Error> {
    if observed.sequence != key.sequence
        || observed.operation_id != operation_id
        || observed.request_digest != digest
    {
        return Err(Error::Protocol);
    }
    Ok(())
}

fn original_terminal_response<'a>(
    pending: &PendingMutation,
    observed: wire::PublicReceipt,
) -> Result<Response<'a>, Error> {
    let request = pending.device_request.as_deref().ok_or(Error::Protocol)?;
    if request.len() < 2 {
        return Err(Error::Protocol);
    }
    match wire::Kind::try_from(u16::from_be_bytes([request[0], request[1]]))
        .map_err(|_| Error::Protocol)?
    {
        wire::Kind::Mutate => Ok(Response::Mutate(observed)),
        wire::Kind::Commission => Ok(Response::Commission(observed)),
        _ => Err(Error::Protocol),
    }
}

fn security_value(report: kes_protocol::security::SecurityStatus) -> Result<Value, Error> {
    use kes_protocol::security::AUTHORIZED_BOOTKEY;
    let serial = std::str::from_utf8(&report.usb_serial).map_err(|_| Error::Protocol)?;
    if !serial
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Protocol);
    }
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(output, "{byte:02x}").unwrap();
        }
        output
    }
    Ok(json!({
        "chip_revision": report.chip_revision,
        "rom_version": report.rom_version,
        "critical": report.critical,
        "boot_flags0": report.boot_flags0,
        "boot_flags1": report.boot_flags1,
        "bootkey0": hex(&report.bootkey0),
        "page2_lock0": report.page2_lock0,
        "page2_lock1": report.page2_lock1,
        "page63_lock0": report.page63_lock0,
        "page63_lock1": report.page63_lock1,
        "debugen": report.debugen,
        "debugen_lock": report.debugen_lock,
        "redundancy_ok": report.redundancy_ok,
        "jedec_id": hex(&report.jedec_id),
        "sfdp_header": hex(&report.sfdp_header),
        "density_bits_minus_one": report.density_bits_minus_one,
        "usb_serial": serial,
        "storage_blank_at_boot": report.storage_blank_at_boot,
        "profile": report.profile(AUTHORIZED_BOOTKEY.as_ref()),
        "stepping": report.stepping(),
    }))
}

fn response_value(response: Response<'_>) -> Result<Value, Error> {
    Ok(match response {
        Response::Hello(_)
        | Response::PoolInventory(_)
        | Response::FirmwareInfo(_)
        | Response::PoolObservation(_)
        | Response::PoolObservationError { .. } => return Err(Error::Protocol),
        Response::Status(response) => status::response(response, false),
        Response::SecurityStatus(response) => security_value(response)?,
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
                "artifact_retention": "retrievable until replacement, expiry, explicit discard, or pool deletion; external copies are unaffected",
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

pub(crate) fn device_error_code(code: u16) -> &'static str {
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
        27 => "target_not_staged",
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
            "artifact_retention": "retrievable until replacement, expiry, explicit discard, or pool deletion; external copies are unaffected",
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
        Action::DeviceSecurity => "device.security",
        Action::DeviceInventory => "device.inventory",
        Action::HostObserve => "host.observe",
        Action::DeviceInfo => "device.info",
        Action::PoolObserve => "pool.observe",
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

#[cfg(test)]
mod observation_tests {
    use super::*;

    #[test]
    fn certificate_arithmetic_is_checked_and_context_is_not_invented() {
        let mut generation = wire::GenerationObservation {
            generation: GenerationId::from_bytes([1; 16]),
            revision: 1,
            role: 0,
            period: 0,
            health: 0,
            artifact_digest: Digest32::from_bytes([2; 32]),
            certificate_start: Some(10),
            certificate_lifetime: Some(5),
        };
        let unknown = generation_observation(generation, None).unwrap();
        assert_eq!(unknown["certificate_expiry"], 15);
        assert!(unknown["remaining_valid_periods"].is_null());
        let before = generation_observation(generation, Some(9)).unwrap();
        assert!(before["relative_period"].is_null());
        assert_eq!(before["remaining_valid_periods"], 6);
        let expired = generation_observation(generation, Some(20)).unwrap();
        assert_eq!(expired["relative_period"], 10);
        assert_eq!(expired["remaining_valid_periods"], 0);
        generation.certificate_start = Some(u64::MAX);
        assert!(generation_observation(generation, Some(1)).is_err());
    }
}
