//! Ownership checks for reviewed host maintenance.

use super::{
    lifecycle::TrustedCli,
    model::{
        INSTALLATION_REGISTRY, InstallationRegistry, InstallationRole, MAX_ARTIFACT_BYTES,
        MaintenanceCheckpoint, MaintenanceRecord, ManagedFile,
    },
    records::RecordStore,
};
use kes_core::identity::{Digest32, OperationId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::Command,
};

mod upgrade;
pub use upgrade::{review_upgrade_recovery, trusted_upgrade_recovery_manager, verify_installed_ownership};

pub(super) fn read_confirmation(input: impl io::BufRead) -> io::Result<String> {
    let mut line = String::new();
    io::BufRead::read_line(&mut input.take(257), &mut line)?;
    if line.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "confirmation exceeds 256 bytes",
        ));
    }
    Ok(line)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostAction {
    Install {
        bundle: PathBuf,
        role: InstallationRole,
        manifest_digest: String,
        candidate_accepted: bool,
    },
    Upgrade {
        bundle: PathBuf,
        manifest_digest: String,
        candidate_accepted: bool,
        expected_registry_digest: String,
        expected_service_state: Option<String>,
        pre_state: Option<super::maintenance::Evidence>,
        temporary_validation: bool,
        serial: Option<String>,
        device_id: Option<String>,
        identity_public_key: Option<String>,
        record: Option<PathBuf>,
    },
    UpgradeRecovery {
        operation_id: String,
        original_plan_digest: String,
        expected_service_state: Option<String>,
        temporary_validation: bool,
    },
    Update {
        authorizing_bundle: PathBuf,
        sources: Vec<PathBuf>,
        candidate_source: Option<PathBuf>,
        selection: super::model::ReleaseSelection,
        expected_registry_digest: String,
        expected_service_state: Option<String>,
        stop_service: bool,
        pre_state: Option<super::maintenance::Evidence>,
        temporary_validation: bool,
    },
    UpdateRecovery {
        operation_id: String,
        original_plan_digest: String,
        expected_registry_digest: String,
        expected_current_link: PathBuf,
        expected_service_state: Option<String>,
        stop_service: bool,
        temporary_validation: bool,
        restore_deployment: bool,
    },
    FirmwareUpdate {
        bundle: PathBuf,
        manifest_digest: String,
        candidate_accepted: bool,
        target_selection: super::model::ReleaseSelection,
        serial: String,
        device_id: String,
        identity_public_key: String,
        record: PathBuf,
        apply: bool,
        expected_service_state: String,
        pre_state: super::maintenance::Evidence,
        temporary_validation: bool,
    },
    FirmwarePreview {
        expected_service_state: String,
    },
    FirmwareRecovery {
        operation_id: String,
        original_plan_digest: String,
        receipts: Vec<super::setup::PublicInput>,
        expected_service_state: String,
        temporary_validation: bool,
    },
    FirmwareFirstInstall {
        bundle: PathBuf,
        manifest_digest: String,
        candidate_accepted: bool,
        record: PathBuf,
        apply: bool,
    },
    Config {
        candidate: PathBuf,
        candidate_digest: String,
        expected_current_digest: Option<String>,
        commissioning: bool,
        inputs: Vec<super::setup::PublicInput>,
        recovery_operation: Option<String>,
    },
    CommissionService {
        start: bool,
        expected_state: String,
        recovery_operation: Option<String>,
    },
    Service {
        operation: ServiceAction,
        expected_state: String,
    },
    ReconcileFirstInstall {
        operation_id: String,
        serial: String,
        expected_service_state: String,
    },
    CommissionAdmission {
        bundle: PathBuf,
        manifest_digest: String,
        candidate_accepted: bool,
        serial: String,
        socket: PathBuf,
        expected_service_state: String,
    },
    Provisioning {
        request: super::provisioning::Request,
    },
    ProducerHardening {
        request: super::producer::Request,
    },
    ProducerRecovery {
        operation_id: String,
        original_plan_digest: String,
        observed_digest: String,
    },
    HostReconcile {
        operation_id: String,
        original_plan_digest: String,
    },
    UninstallRecovery {
        operation_id: String,
        original_plan_digest: String,
        observed_digest: String,
        bootstrap: Option<PathBuf>,
        bootstrap_manifest_digest: Option<String>,
        candidate_accepted: bool,
    },
    Uninstall {
        selected_components: Vec<String>,
        registry_digest: String,
        expected_service_state: Option<String>,
        stop_service: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPlan {
    pub schema_version: u64,
    pub plan_id: String,
    pub action: HostAction,
    pub approved_digest: String,
}

impl HostPlan {
    pub fn new(action: HostAction) -> io::Result<Self> {
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let plan_id = OperationId::from_bytes(random).to_string();
        let approved_digest = plan_digest(&plan_id, &action)?;
        Ok(Self {
            schema_version: 1,
            plan_id,
            action,
            approved_digest,
        })
    }

    pub fn validate(&self) -> io::Result<()> {
        let digest_ok = |digest: &str| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let id_ok = |value: &str| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let serial_ok = |value: &str| {
            value.len() == 16
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let valid = match &self.action {
            HostAction::Install {
                bundle,
                manifest_digest,
                ..
            } => bundle.is_absolute() && digest_ok(manifest_digest),
            HostAction::Upgrade {
                bundle, manifest_digest, expected_registry_digest,
                expected_service_state, pre_state, serial, device_id, identity_public_key,
                record, ..
            } => {
                bundle.is_absolute() && digest_ok(manifest_digest) && digest_ok(expected_registry_digest)
                    && match (expected_service_state, pre_state, serial, device_id, identity_public_key, record) {
                        (None, None, None, None, None, None) => true,
                        (Some(state), Some(_), Some(serial), Some(device), Some(key), Some(record)) => {
                            !state.is_empty() && state.len() <= 512 && state.bytes().all(|b| (32..127).contains(&b))
                                && serial_ok(serial) && id_ok(device) && digest_ok(key)
                                && record.parent() == Some(Path::new("/var/lib/p2kesup/firmware"))
                                && record.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".json")).is_some_and(id_ok)
                        }
                        _ => false,
                    }
            }
            HostAction::UpgradeRecovery { operation_id, original_plan_digest, expected_service_state, .. } => {
                id_ok(operation_id) && digest_ok(original_plan_digest)
                    && expected_service_state.as_ref().is_none_or(|s| !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| (32..127).contains(&b)))
            }
            HostAction::Update {
                authorizing_bundle,
                sources,
                candidate_source,
                selection,
                expected_registry_digest,
                expected_service_state,
                ..
            } => {
                authorizing_bundle.is_absolute()
                    && !sources.is_empty()
                    && sources.len() <= 6
                    && sources.iter().all(|p| p.is_absolute())
                    && candidate_source.as_ref().is_none_or(|p| {
                        p.is_absolute() && (p == authorizing_bundle || sources.contains(p))
                    })
                    && selection.components.len() == 6
                    && digest_ok(expected_registry_digest)
                    && expected_service_state.as_ref().is_none_or(|s| {
                        !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| (32..127).contains(&b))
                    })
            }
            HostAction::UpdateRecovery {
                operation_id,
                original_plan_digest,
                expected_registry_digest,
                expected_current_link,
                expected_service_state,
                ..
            } => {
                id_ok(operation_id)
                    && digest_ok(original_plan_digest)
                    && digest_ok(expected_registry_digest)
                    && expected_current_link
                        .components()
                        .all(|c| matches!(c, Component::Normal(_)))
                    && !expected_current_link.as_os_str().is_empty()
                    && expected_service_state.as_ref().is_none_or(|s| {
                        !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| (32..127).contains(&b))
                    })
            }
            HostAction::FirmwareUpdate {
                bundle,
                manifest_digest,
                serial,
                record,
                apply,
                expected_service_state,
                target_selection,
                ..
            } => {
                bundle.is_absolute()
                    && digest_ok(manifest_digest)
                    && serial_ok(serial)
                    && *apply
                    && target_selection.components.len() == 6
                    && target_selection.manifest_digest.to_string() == *manifest_digest
                    && record.parent() == Some(Path::new("/var/lib/p2kesup/firmware"))
                    && record
                        .file_name()
                        .and_then(|n| n.to_str())
                        .and_then(|n| n.strip_suffix(".json"))
                        .is_some_and(id_ok)
                    && !expected_service_state.is_empty()
                    && expected_service_state.len() <= 512
                    && expected_service_state
                        .bytes()
                        .all(|b| (32..127).contains(&b))
            }
            HostAction::FirmwarePreview {
                expected_service_state,
            } => {
                !expected_service_state.is_empty()
                    && expected_service_state.len() <= 512
                    && expected_service_state
                        .bytes()
                        .all(|b| (32..127).contains(&b))
            }
            HostAction::FirmwareRecovery {
                operation_id,
                original_plan_digest,
                receipts,
                expected_service_state,
                ..
            } => {
                id_ok(operation_id)
                    && digest_ok(original_plan_digest)
                    && receipts.len() <= 128
                    && receipts
                        .iter()
                        .all(|r| r.path.is_absolute() && digest_ok(&r.sha256))
                    && !expected_service_state.is_empty()
                    && expected_service_state.len() <= 512
                    && expected_service_state
                        .bytes()
                        .all(|b| (32..127).contains(&b))
            }
            HostAction::CommissionAdmission {
                bundle,
                manifest_digest,
                serial,
                socket,
                expected_service_state,
                ..
            } => {
                bundle.is_absolute()
                    && digest_ok(manifest_digest)
                    && serial_ok(serial)
                    && socket.is_absolute()
                    && !socket
                        .components()
                        .any(|part| matches!(part, Component::ParentDir))
                    && !expected_service_state.is_empty()
                    && expected_service_state.len() <= 512
                    && expected_service_state
                        .bytes()
                        .all(|b| (32..127).contains(&b))
            }
            HostAction::FirmwareFirstInstall {
                bundle,
                manifest_digest,
                record,
                ..
            } => {
                bundle.is_absolute()
                    && digest_ok(manifest_digest)
                    && record.parent() == Some(Path::new("/var/lib/p2kesup/firmware"))
                    && record
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| {
                            n.strip_suffix(".json").is_some_and(|s| {
                                s.len() == 32
                                    && s.bytes()
                                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            })
                        })
            }
            HostAction::Config {
                candidate,
                candidate_digest,
                expected_current_digest,
                inputs,
                commissioning,
                recovery_operation,
            } => {
                candidate.is_absolute()
                    && digest_ok(candidate_digest)
                    && expected_current_digest
                        .as_ref()
                        .is_none_or(|d| digest_ok(d))
                    && inputs
                        .iter()
                        .all(|i| i.path.is_absolute() && digest_ok(&i.sha256))
                    && recovery_operation
                        .as_ref()
                        .is_none_or(|id| *commissioning && id_ok(id))
            }
            HostAction::CommissionService {
                expected_state,
                recovery_operation,
                ..
            } => {
                !expected_state.is_empty()
                    && expected_state.len() <= 512
                    && expected_state.bytes().all(|b| (32..127).contains(&b))
                    && recovery_operation.as_ref().is_none_or(|id| id_ok(id))
            }
            HostAction::Service { expected_state, .. } => {
                !expected_state.is_empty()
                    && expected_state.len() <= 512
                    && expected_state.bytes().all(|b| (32..127).contains(&b))
            }
            HostAction::ReconcileFirstInstall {
                operation_id,
                serial,
                expected_service_state,
            } => {
                id_ok(operation_id)
                    && serial_ok(serial)
                    && !expected_service_state.is_empty()
                    && expected_service_state.len() <= 512
                    && expected_service_state
                        .bytes()
                        .all(|b| (32..127).contains(&b))
            }
            HostAction::Provisioning { request } => request.validate().is_ok(),
            HostAction::ProducerHardening { request } => request.validate().is_ok(),
            HostAction::ProducerRecovery {
                operation_id,
                original_plan_digest,
                observed_digest,
            } => {
                id_ok(operation_id) && digest_ok(original_plan_digest) && digest_ok(observed_digest)
            }
            HostAction::HostReconcile {
                operation_id,
                original_plan_digest,
            } => id_ok(operation_id) && digest_ok(original_plan_digest),
            HostAction::UninstallRecovery {
                operation_id,
                original_plan_digest,
                observed_digest,
                bootstrap,
                bootstrap_manifest_digest,
                candidate_accepted,
            } => {
                id_ok(operation_id)
                    && digest_ok(original_plan_digest)
                    && digest_ok(observed_digest)
                    && match (bootstrap, bootstrap_manifest_digest) {
                        (Some(path), Some(digest)) => path.is_absolute() && digest_ok(digest),
                        (None, None) => !candidate_accepted,
                        _ => false,
                    }
            }
            HostAction::Uninstall {
                selected_components,
                registry_digest,
                expected_service_state,
                ..
            } => {
                !selected_components.is_empty()
                    && selected_components.len() <= 64
                    && selected_components.iter().all(|c| {
                        ["manager", "daemon", "cli", "firmware", "tool", "deployment"]
                            .contains(&c.as_str())
                    })
                    && digest_ok(registry_digest)
                    && expected_service_state.as_ref().is_none_or(|s| {
                        !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| (32..127).contains(&b))
                    })
            }
        };
        if !valid
            || self.schema_version != 1
            || !id_ok(&self.plan_id)
            || self.approved_digest != plan_digest(&self.plan_id, &self.action)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid or changed host plan",
            ));
        }
        Ok(())
    }
}

fn plan_digest(plan_id: &str, action: &HostAction) -> io::Result<String> {
    let bytes = serde_json::to_vec(&(1u64, plan_id, action)).map_err(io::Error::other)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Check the exact inode, ownership and content against registry evidence.
/// Callers must independently pin and validate directory ancestry before use.
pub fn check_owned_file(path: &Path, entry: Option<&ManagedFile>) -> io::Result<()> {
    let entry = entry.filter(|e| e.path == path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "external or unregistered path",
        )
    })?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != entry.owner
        || metadata.gid() != entry.group
        || metadata.mode() & 0o7777 != entry.mode
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed file ownership or mode changed",
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if hash.finalize().as_slice() != entry.digest.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed file content changed",
        ));
    }
    Ok(())
}

pub(super) fn trusted_ancestry(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not absolute",
        ));
    }
    let mut current = PathBuf::from("/");
    for part in path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?
        .components()
    {
        match part {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsafe path ancestry",
                ));
            }
        }
        let meta = fs::symlink_metadata(&current)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted path ancestry",
            ));
        }
    }
    Ok(())
}

pub(super) fn installation_registry() -> io::Result<InstallationRegistry> {
    let path = Path::new(INSTALLATION_REGISTRY);
    trusted_ancestry(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o644
        || m.nlink() != 1
        || m.len() > 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe installation registry",
        ));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installation registry too large",
        ));
    }
    let registry: InstallationRegistry =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if registry.schema_version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported installation registry",
        ));
    }
    let mut paths = std::collections::HashSet::new();
    for entry in &registry.files {
        let path = &entry.path;
        let approved = path.starts_with("/usr/lib/pico2-kes-agent/components")
            || path == Path::new("/usr/libexec/pico2-kes-agent-host-check")
            || path == Path::new("/usr/lib/systemd/system/pico2-kes-agentd.service")
            || path == Path::new("/usr/lib/udev/rules.d/70-pico2-kes-agent.rules")
            || path.starts_with("/etc/systemd/system");
        if !approved
            || !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || !paths.insert(path)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsafe or duplicate registry path",
            ));
        }
    }
    if let Some(selection) = &registry.current {
        let mut names = std::collections::HashSet::new();
        if selection
            .components
            .iter()
            .any(|component| !names.insert(&component.component))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate selected component",
            ));
        }
    }
    Ok(registry)
}

pub(super) fn trusted_component(component: &str, binary: &str) -> io::Result<PathBuf> {
    let registry = installation_registry()?;
    let selection = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("no selected installation"))?;
    let selected = selection
        .components
        .iter()
        .find(|c| c.component == component)
        .ok_or_else(|| io::Error::other("component not selected"))?;
    if selection
        .components
        .iter()
        .filter(|c| c.component == component)
        .count()
        != 1
    {
        return Err(io::Error::other("ambiguous selected component"));
    }
    let expected = PathBuf::from(format!(
        "/usr/lib/pico2-kes-agent/components/{component}/{}/{}",
        selected.digest, binary
    ));
    let mut entries = registry
        .files
        .iter()
        .filter(|f| f.path == expected && f.component == component);
    let entry = entries
        .next()
        .ok_or_else(|| io::Error::other("component is not registered"))?;
    if entries.next().is_some()
        || entry.owner != 0
        || entry.mode & 0o022 != 0
        || entry.digest != selected.entrypoint_digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid component ownership",
        ));
    }
    trusted_ancestry(&expected)?;
    check_owned_file(&expected, Some(entry))?;
    let link = Path::new("/usr/bin").join(binary);
    trusted_ancestry(&link)?;
    let link_meta = fs::symlink_metadata(&link)?;
    if !link_meta.file_type().is_symlink()
        || link_meta.uid() != 0
        || fs::canonicalize(&link)? != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "active component link does not match registry",
        ));
    }
    Ok(expected)
}

/// Resolve only a registry-proven, currently selected immutable manager.
pub fn trusted_manager() -> io::Result<PathBuf> {
    trusted_component("manager", "p2kesup")
}

/// Acquire the existing CLI authority only after host ownership verification.
pub fn trusted_cli() -> io::Result<TrustedCli> {
    TrustedCli::from_authenticated_host(trusted_component("cli", "pico2-kes-agent-cli")?)
}

struct HostLock(File);
impl Drop for HostLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn maintenance_lock() -> io::Result<HostLock> {
    let base = Path::new("/var/lib/p2kesup");
    trusted_ancestry(&base.join("host.lock"))?;
    let metadata = fs::symlink_metadata(base)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o755
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe maintenance directory",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base.join("host.lock"))?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o600 || m.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe maintenance lock",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(HostLock(file))
}

pub(super) fn systemctl(arguments: &[&str]) -> io::Result<std::process::Output> {
    let program = Path::new("/usr/bin/systemctl");
    trusted_ancestry(program)?;
    trusted_ancestry(&fs::canonicalize(program)?)?;
    let meta = fs::metadata(program)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe systemctl",
        ));
    }
    Command::new(program).env_clear().args(arguments).output()
}

pub(super) fn service_state(unit: &str) -> io::Result<String> {
    let output = systemctl(&["show", unit, "--property=ActiveState", "--value"])?;
    if !output.status.success() {
        return Err(io::Error::other("systemd state unavailable"));
    }
    let state = std::str::from_utf8(&output.stdout)
        .map_err(io::Error::other)?
        .trim();
    if !matches!(state, "active" | "inactive" | "failed") {
        return Err(io::Error::other(
            "service state is unknown or transitioning",
        ));
    }
    Ok(state.to_owned())
}

pub(super) fn checked_service() -> io::Result<()> {
    let registry = installation_registry()?;
    if registry.role != InstallationRole::Primary {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backup installation has no primary service",
        ));
    }
    check_service_overrides()?;
    let path = Path::new("/usr/lib/systemd/system/pico2-kes-agentd.service");
    trusted_ancestry(path)?;
    let entry = registry
        .files
        .iter()
        .find(|f| f.path == path)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "service is not registered")
        })?;
    if entry.owner != 0 || entry.mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe service ownership",
        ));
    }
    check_owned_file(path, Some(entry))
}

fn check_service_overrides() -> io::Result<()> {
    for override_path in [
        "/etc/systemd/system/pico2-kes-agentd.service",
        "/run/systemd/system/pico2-kes-agentd.service",
        "/etc/systemd/system/pico2-kes-agentd.service.d",
        "/run/systemd/system/pico2-kes-agentd.service.d",
    ] {
        match fs::symlink_metadata(override_path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("external service override: {override_path}"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn run_service(
    operation: ServiceAction,
    expected: &str,
    effects: &mut bool,
) -> io::Result<String> {
    checked_service()?;
    if observed_service_state(false)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service target changed after approval",
        ));
    }
    let running = operation != ServiceAction::Stop;
    if running && service_state("pico2-kes-agent-commission.service")? != "inactive" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "commissioning service must be stopped before normal startup",
        ));
    }
    let action = match operation {
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
    };
    *effects = true;
    let output = systemctl(&[action, "pico2-kes-agentd.service"])?;
    if !output.status.success() {
        return Err(io::Error::other(format!("systemctl {action} failed")));
    }
    let state = service_state("pico2-kes-agentd.service")?;
    if (running && state != "active") || (!running && state != "inactive") {
        return Err(io::Error::other(format!("service post-check: {state}")));
    }
    if running {
        authenticated_running_daemon_observation()?;
    }
    let observed = observed_service_state(false)?;
    if !observed.starts_with(if running {
        "state=active;"
    } else {
        "state=inactive;"
    }) {
        return Err(io::Error::other("service state changed during post-check"));
    }
    Ok(observed)
}

pub(super) fn checkpoint(name: &str, evidence: String) -> MaintenanceCheckpoint {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u64::MAX as u128) as u64;
    MaintenanceCheckpoint {
        name: name.into(),
        observed_at_unix_us: now,
        evidence,
    }
}

fn host_record(plan: &HostPlan, previous: Option<String>) -> io::Result<MaintenanceRecord> {
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let operation_id = if let HostAction::FirmwareUpdate { record, .. }
        | HostAction::Upgrade { record: Some(record), .. } = &plan.action {
        let name = record
            .file_stem()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::other("invalid firmware record"))?;
        OperationId::parse_hex(name)
            .map_err(|_| io::Error::other("invalid firmware operation id"))?
    } else {
        OperationId::from_bytes(random)
    };
    Ok(MaintenanceRecord {
        schema_version: 1,
        operation_id,
        action: match &plan.action {
            HostAction::Install { .. } => "install",
            HostAction::Upgrade { .. } => "upgrade",
            HostAction::UpgradeRecovery { .. } => "upgrade-recovery",
            HostAction::FirmwareFirstInstall { .. } => "firmware_transfer",
            HostAction::Update { .. } => "update",
            HostAction::UpdateRecovery { .. } => "update-recovery",
            HostAction::FirmwareUpdate { .. } => "firmware-update",
            HostAction::FirmwarePreview { .. } => "firmware-preview",
            HostAction::FirmwareRecovery { .. } => "firmware-recovery",
            HostAction::Config { .. } => "config",
            HostAction::CommissionService { .. } => "commission_service",
            HostAction::Service { .. } => "service",
            HostAction::ReconcileFirstInstall { .. } => "first_install_postcheck",
            HostAction::CommissionAdmission { .. } => "commission_admission",
            HostAction::Provisioning { .. } => "provisioning",
            HostAction::ProducerHardening { .. } => "producer-hardening",
            HostAction::ProducerRecovery { .. } => "producer-recovery",
            HostAction::HostReconcile { .. } => "host-reconciliation",
            HostAction::UninstallRecovery { .. } => "uninstall-recovery",
            HostAction::Uninstall { .. } => "uninstall",
        }
        .into(),
        plan_digest: Digest32::parse_hex(&plan.approved_digest)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid approval digest"))?,
        selected: None,
        approved_scope: vec![serde_json::to_string(&plan.action).map_err(io::Error::other)?],
        previous_service_state: previous,
        pre_observations: Vec::new(),
        checkpoints: vec![checkpoint("intent-durable", plan.approved_digest.clone())],
        post_observations: Vec::new(),
        outcome: "intent-durable".into(),
        bundle_digest: None,
        image_digest: None,
        physical_selection: None,
    })
}

fn commissioning_unit() -> io::Result<Vec<u8>> {
    checked_service()?;
    let original = fs::read_to_string("/usr/lib/systemd/system/pico2-kes-agentd.service")?;
    let old_pre = "ExecStartPre=/usr/libexec/pico2-kes-agent-host-check";
    let old_start = "ExecStart=/usr/bin/pico2-kes-agentd --config /etc/pico2-kes-agent/config.json";
    if original.matches(old_pre).count() != 1 || original.matches(old_start).count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected service definition",
        ));
    }
    Ok(original
        .replace(old_pre, &format!("{old_pre} --commission"))
        .replace(old_start, &format!("{old_start} --commission"))
        .into_bytes())
}

fn verify_commissioning_file(content: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/run/systemd/system/pico2-kes-agent-commission.service")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o644
        || metadata.nlink() != 1
        || metadata.len() != content.len() as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "commissioning unit ownership changed",
        ));
    }
    let mut bytes = vec![0; content.len()];
    file.read_exact(&mut bytes)?;
    if bytes != content {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "commissioning unit changed or is external",
        ));
    }
    Ok(())
}

/// Prepare only the authenticated unit for the tool's attended second terminal.
pub(super) fn ensure_commission_handoff_unit(effects: &mut bool) -> io::Result<()> {
    let path = Path::new("/run/systemd/system/pico2-kes-agent-commission.service");
    trusted_ancestry(path)?;
    ensure_no_commission_overrides()?;
    let content = commissioning_unit()?;
    match fs::symlink_metadata(path) {
        Ok(_) => verify_commissioning_file(&content)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            *effects = true;
            crate::files::publish_no_clobber(path, &content, 0o644)?;
            verify_commissioning_file(&content)?;
        }
        Err(error) => return Err(error),
    }
    *effects = true;
    if !systemctl(&["daemon-reload"])?.status.success() {
        return Err(io::Error::other("commissioning handoff unit reload failed"));
    }
    Ok(())
}

/// Unlike ordinary teardown, retain the verified unit for attended tool readbacks.
pub(super) fn pause_commission_service(expected: &str, effects: &mut bool) -> io::Result<String> {
    ensure_no_commission_overrides()?;
    verify_commissioning_file(&commissioning_unit()?)?;
    if observed_service_state(true)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "commissioning service changed after approval",
        ));
    }
    *effects = true;
    let result = systemctl(&["stop", "pico2-kes-agent-commission.service"])?;
    if !result.status.success()
        || service_state("pico2-kes-agent-commission.service")? != "inactive"
    {
        return Err(io::Error::other(format!(
            "commissioning handoff stop failed: {}",
            result.status
        )));
    }
    observed_service_state(true)
}

pub(super) fn run_commission_service(
    start: bool,
    expected: &str,
    effects: &mut bool,
) -> io::Result<String> {
    let path = Path::new("/run/systemd/system/pico2-kes-agent-commission.service");
    trusted_ancestry(path)?;
    ensure_no_commission_overrides()?;
    let content = commissioning_unit()?;
    if observed_service_state(true)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "commissioning service target changed after approval",
        ));
    }
    if start {
        if service_state("pico2-kes-agentd.service")? != "inactive" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "normal service must be stopped before commissioning",
            ));
        }
        ensure_commission_handoff_unit(effects)?;
        if !systemctl(&["start", "pico2-kes-agent-commission.service"])?
            .status
            .success()
        {
            return Err(io::Error::other("commissioning service start failed"));
        }
        let state = service_state("pico2-kes-agent-commission.service")?;
        if state != "active" {
            return Err(io::Error::other(
                "commissioning service did not become active",
            ));
        }
        Ok(state)
    } else {
        verify_commissioning_file(&content)?;
        *effects = true;
        if !systemctl(&["stop", "pico2-kes-agent-commission.service"])?
            .status
            .success()
        {
            return Err(io::Error::other("commissioning service stop failed"));
        }
        if service_state("pico2-kes-agent-commission.service")? != "inactive" {
            return Err(io::Error::other("commissioning service remains active"));
        }
        fs::remove_file(path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
        if !systemctl(&["daemon-reload"])?.status.success() {
            return Err(io::Error::other("commissioning unit reload failed"));
        }
        Ok("inactive".into())
    }
}

/// Privileged finite dispatcher. It re-displays and confirms the exact digest;
/// plan bytes alone are never approval.
pub fn apply_plan(path: &Path) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host apply requires root",
        ));
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host apply requires an attended terminal",
        ));
    }
    let plan = read_host_plan(path)?;
    if matches!(
        &plan.action,
        HostAction::CommissionAdmission { .. } | HostAction::FirmwarePreview { .. }
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "read-only admission requires host-admit",
        ));
    }
    if reopen_existing_plan(&plan)? {
        return Ok(());
    }
    println!(
        "Host maintenance scope: {}",
        serde_json::to_string_pretty(&plan.action).map_err(io::Error::other)?
    );
    println!("Approval digest: {}", plan.approved_digest);
    if matches!(
        &plan.action,
        HostAction::Install {
            candidate_accepted: true,
            ..
        } | HostAction::FirmwareFirstInstall {
            candidate_accepted: true,
            ..
        }
    ) {
        println!(
            "This is explicit offline candidate acceptance on a disposable host, not release qualification."
        );
    }
    print!("Type the complete digest to approve this exact scope: ");
    io::stdout().flush()?;
    let answer = read_confirmation(io::stdin().lock())?;
    if answer.trim() != plan.approved_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host plan not approved",
        ));
    }
    if let HostAction::ReconcileFirstInstall {
        operation_id,
        serial,
        ..
    } = &plan.action
    {
        println!(
            "Confirm physically that application {serial} is the same intended board as original transfer {operation_id}; the BOOTSEL CHIPID is not an application identity."
        );
        print!("Type the exact application serial to attest this association: ");
        io::stdout().flush()?;
        let physical = read_confirmation(io::stdin().lock())?;
        if physical.trim() != serial {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "physical same-board association not confirmed",
            ));
        }
    }
    let verified = match &plan.action {
        HostAction::Install {
            bundle,
            role,
            manifest_digest,
            candidate_accepted,
        } => {
            let admission = if *candidate_accepted {
                super::release::Admission::AttendedCandidate
            } else {
                super::release::Admission::Qualified
            };
            let verified = super::release::verify_bundle(bundle, admission)?;
            if verified.selection().manifest_digest.to_string() != *manifest_digest {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bundle changed after approval",
                ));
            }
            check_platform(verified.manifest())?;
            verify_running_manager(&verified)?;
            precheck_install(*role)?;
            root_directory(Path::new("/var/lib/p2kesup"), 0o755)?;
            Some(verified)
        }
        HostAction::FirmwareFirstInstall {
            bundle,
            manifest_digest,
            candidate_accepted,
            ..
        } => {
            let admission = if *candidate_accepted {
                super::release::Admission::AttendedCandidate
            } else {
                super::release::Admission::Qualified
            };
            let verified = super::release::verify_bundle(bundle, admission)?;
            if verified.selection().manifest_digest.to_string() != *manifest_digest {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bundle changed after approval",
                ));
            }
            check_platform(verified.manifest())?;
            Some(verified)
        }
        HostAction::FirmwareUpdate {
            bundle,
            manifest_digest,
            candidate_accepted,
            ..
        } | HostAction::Upgrade { bundle, manifest_digest, candidate_accepted, .. } => {
            let admission = if *candidate_accepted {
                super::release::Admission::AttendedCandidate
            } else {
                super::release::Admission::Qualified
            };
            let verified = super::release::verify_bundle(bundle, admission)?;
            if verified.selection().manifest_digest.to_string() != *manifest_digest {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bundle changed after approval",
                ));
            }
            check_platform(verified.manifest())?;
            Some(verified)
        }
        HostAction::UninstallRecovery {
            bootstrap: Some(bundle),
            bootstrap_manifest_digest: Some(digest),
            candidate_accepted,
            ..
        } => {
            let verified = super::release::verify_bundle(
                bundle,
                if *candidate_accepted {
                    super::release::Admission::AttendedCandidate
                } else {
                    super::release::Admission::Qualified
                },
            )?;
            if verified.selection().manifest_digest.to_string() != *digest {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "recovery bootstrap changed after review",
                ));
            }
            check_platform(verified.manifest())?;
            verify_running_manager(&verified)?;
            Some(verified)
        }
        _ => None,
    };
    let _lock = maintenance_lock()?;
    if !matches!(&plan.action, HostAction::Install { .. }) {
        let expected = match &plan.action {
            HostAction::UpgradeRecovery { operation_id, original_plan_digest, .. } =>
                trusted_upgrade_recovery_manager(operation_id, original_plan_digest)?,
            HostAction::UpdateRecovery {
                operation_id,
                original_plan_digest,
                ..
            } => trusted_recovery_manager(operation_id, original_plan_digest)?,
            HostAction::UninstallRecovery {
                bootstrap: Some(_), ..
            } => {
                verify_running_manager(
                    verified
                        .as_ref()
                        .ok_or_else(|| io::Error::other("verified recovery bootstrap missing"))?,
                )?;
                fs::canonicalize("/proc/self/exe")?
            }
            _ => trusted_manager()?,
        };
        if fs::canonicalize("/proc/self/exe")? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host apply is not the authenticated installed manager",
            ));
        }
    }
    if let HostAction::Install {
        role,
        candidate_accepted,
        ..
    } = &plan.action
    {
        precheck_install(*role)?;
        authenticate_protected_stage(verified.as_ref().unwrap(), *candidate_accepted)?;
    }
    let gid = if matches!(&plan.action, HostAction::Install { .. }) {
        ensure_service_account(&plan)?
    } else {
        super::setup::service_identity()?.1
    };
    let store = RecordStore::open_host(gid)?;
    if report_matching_plan(&plan, &store)? {
        return Ok(());
    }
    if let Some(id) = recovery_id(&plan.action) {
        let original = original_first_install(&store, id)?;
        if !matches!(&plan.action, HostAction::ReconcileFirstInstall { .. })
            && original.original.outcome == "completed"
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original transfer is already resolved; review ordinary setup instead",
            ));
        }
        check_other_pending_records(&store, &plan.action)?;
    }
    if matches!(&plan.action, HostAction::FirmwareRecovery { .. }) {
        return recover_firmware(&plan, &store);
    }
    if matches!(&plan.action, HostAction::UpdateRecovery { .. }) {
        return recover_update(&plan, &store);
    }
    if matches!(&plan.action, HostAction::UpgradeRecovery { .. }) {
        check_other_pending_records(&store, &plan.action)?;
        return upgrade::recover(&plan, &store);
    }
    if let HostAction::ProducerRecovery {
        operation_id,
        original_plan_digest,
        observed_digest,
    } = &plan.action
    {
        check_other_pending_records(&store, &plan.action)?;
        return super::producer::recover(
            operation_id,
            original_plan_digest,
            observed_digest,
            &store,
        );
    }
    if let HostAction::UninstallRecovery {
        operation_id,
        original_plan_digest,
        observed_digest,
        ..
    } = &plan.action
    {
        check_other_pending_records(&store, &plan.action)?;
        return super::uninstall::recover_uninstall(
            operation_id,
            original_plan_digest,
            observed_digest,
            &store,
        );
    }
    if matches!(&plan.action, HostAction::HostReconcile { .. }) {
        return reconcile_host_operation(&plan, &store);
    }
    if let HostAction::Provisioning { request } = &plan.action
        && request.original_operation.is_some()
    {
        return recover_provisioning(&plan, &store);
    }
    if let HostAction::ReconcileFirstInstall {
        operation_id,
        serial,
        expected_service_state,
    } = &plan.action
    {
        if &observed_service_state(true)? != expected_service_state {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "restricted daemon target changed after review",
            ));
        }
        return reconcile_first_install(&store, operation_id, serial);
    }
    let previous = match &plan.action {
        HostAction::Update {
            expected_service_state,
            ..
        } | HostAction::Upgrade { expected_service_state, .. } => expected_service_state.clone(),
        HostAction::FirmwareUpdate {
            expected_service_state,
            ..
        } => {
            let actual = observed_service_state(false)?;
            if actual != *expected_service_state {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "service changed after review",
                ));
            }
            Some(actual)
        }
        HostAction::Service { expected_state, .. } => {
            let actual = observed_service_state(false)?;
            if &actual != expected_state {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "service state changed after review",
                ));
            }
            Some(actual)
        }
        HostAction::CommissionService { expected_state, .. } => {
            let actual = observed_service_state(true)?;
            if &actual != expected_state {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "commissioning service state changed after review",
                ));
            }
            Some(actual)
        }
        HostAction::Uninstall {
            expected_service_state,
            ..
        } => {
            if let Some(expected) = expected_service_state {
                let actual = observed_service_state(false)?;
                if &actual != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "service target changed after review",
                    ));
                }
                Some(actual)
            } else {
                None
            }
        }
        _ => None,
    };
    let mut record = host_record(&plan, previous)?;
    if let Some(bundle) = &verified {
        record.selected = Some(bundle.selection().clone());
        record.bundle_digest = Some(bundle.selection().manifest_digest.to_string());
    }
    if matches!(&plan.action, HostAction::Uninstall { .. }) {
        record.selected = installation_registry()?.current;
    }
    if let HostAction::Update {
        selection,
        expected_registry_digest,
        ..
    } = &plan.action
    {
        if registry_digest()? != *expected_registry_digest {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "registry changed after review",
            ));
        }
        let previous = installation_registry()?
            .current
            .ok_or_else(|| io::Error::other("installed tuple unavailable"))?;
        let link = fs::read_link("/usr/lib/pico2-kes-agent/current")?;
        record
            .pre_observations
            .push(serde_json::to_string(&(previous, link)).map_err(io::Error::other)?);
        record.selected = Some(selection.clone());
        record.bundle_digest = Some(selection.manifest_digest.to_string());
    }
    if matches!(&plan.action, HostAction::Upgrade { .. }) {
        let previous = installation_registry()?.current.ok_or_else(|| io::Error::other("installed tuple unavailable"))?;
        let link = fs::read_link("/usr/lib/pico2-kes-agent/current")?;
        record.pre_observations.push(serde_json::to_string(&(previous, link)).map_err(io::Error::other)?);
        let image = verified.as_ref().unwrap().manifest().artifacts.iter()
            .find(|a| a.path == "firmware/pico2-kes-firmware.signed.uf2")
            .ok_or_else(|| io::Error::other("firmware image absent"))?;
        record.image_digest = Some(image.sha256.clone());
    }
    if let HostAction::FirmwareUpdate {
        pre_state,
        target_selection,
        ..
    } = &plan.action
    {
        record
            .pre_observations
            .push(serde_json::to_string(pre_state).map_err(io::Error::other)?);
        record.selected = Some(target_selection.clone());
        let image = verified
            .as_ref()
            .unwrap()
            .manifest()
            .artifacts
            .iter()
            .find(|a| a.path == "firmware/pico2-kes-firmware.signed.uf2")
            .ok_or_else(|| io::Error::other("firmware image absent"))?;
        record.image_digest = Some(image.sha256.clone());
    }
    if let HostAction::FirmwareFirstInstall {
        record: original,
        apply,
        ..
    } = &plan.action
    {
        if !*apply {
            let mut preview_effects = false;
            return run_first_install(
                verified.as_ref().unwrap(),
                original,
                false,
                None,
                &mut preview_effects,
            )
            .map(|_| ());
        }
        super::setup::admit_first_install(original)?;
    }
    check_other_pending_records(&store, &plan.action)?;
    store.create(&record)?;
    let mut effects = false;
    let mut runtime_created = false;
    let result = match &plan.action {
        HostAction::Config {
            candidate,
            candidate_digest,
            expected_current_digest,
            commissioning,
            inputs,
            ..
        } => super::setup::apply_configuration(
            candidate,
            candidate_digest,
            expected_current_digest.as_deref(),
            *commissioning,
            inputs,
            &mut effects,
            &mut runtime_created,
        )
        .map(|()| {
            "configuration validated and replaced; restart requires separate approval".to_owned()
        }),
        HostAction::Service {
            operation,
            expected_state,
        } => run_service(*operation, expected_state, &mut effects),
        HostAction::CommissionService {
            start,
            expected_state,
            ..
        } => run_commission_service(*start, expected_state, &mut effects),
        HostAction::Install {
            role,
            manifest_digest,
            candidate_accepted,
            ..
        } => install_bundle(
            verified.as_ref().unwrap(),
            *role,
            manifest_digest,
            *candidate_accepted,
            &store,
            &mut record,
            &mut effects,
        ),
        HostAction::Update { .. } => update_bundle(&plan, &store, &mut record, &mut effects, None),
        HostAction::Upgrade { .. } => upgrade::apply(&plan, verified.as_ref().unwrap(), &store, &mut record, &mut effects),
        HostAction::FirmwareUpdate { .. } => firmware_update(
            &plan,
            verified.as_ref().unwrap(),
            &store,
            &mut record,
            &mut effects,
        ),
        HostAction::FirmwareFirstInstall {
            record: original, ..
        } => run_first_install(
            verified.as_ref().unwrap(),
            original,
            true,
            Some((&store, &mut record)),
            &mut effects,
        ),
        HostAction::ProducerHardening { request } => {
            let result = super::producer::apply(request, &store, &mut record);
            effects = record
                .checkpoints
                .iter()
                .any(|c| c.name.starts_with("producer-") && c.name.ends_with("-starting"));
            result
        }
        HostAction::Provisioning { request } => {
            let result = super::provisioning::apply(request, &store, &mut record);
            effects = record.checkpoints.iter().any(|c| c.name == "tool-handoff");
            if result.is_err() && !effects {
                match (observed_service_state(false), observed_service_state(true)) {
                    (Ok(normal), Ok(commissioning)) => record.post_observations.push(format!(
                        "no tool handoff; current normal: {normal}; commissioning: {commissioning}"
                    )),
                    _ => effects = true,
                }
            }
            result
        }
        HostAction::Uninstall {
            selected_components,
            registry_digest,
            expected_service_state,
            stop_service,
        } => super::uninstall::uninstall(
            selected_components,
            registry_digest,
            expected_service_state.as_deref(),
            *stop_service,
            &store,
            &mut record,
            &mut effects,
        ),
        HostAction::HostReconcile { .. }
        | HostAction::UninstallRecovery { .. }
        | HostAction::UpgradeRecovery { .. }
        | HostAction::ProducerRecovery { .. } => {
            unreachable!("original host recovery returned before creating a record")
        }
        HostAction::ReconcileFirstInstall { .. } => {
            unreachable!("reconciliation returned before creating a new record")
        }
        HostAction::CommissionAdmission { .. } => {
            unreachable!("read-only admission is not a host mutation")
        }
        HostAction::FirmwarePreview { .. } => {
            unreachable!("firmware preview uses its dedicated finite dispatcher")
        }
        HostAction::FirmwareRecovery { .. } => {
            unreachable!("original firmware recovery returned before creating a record")
        }
        HostAction::UpdateRecovery { .. } => {
            unreachable!("original update recovery returned before creating a record")
        }
    };
    if runtime_created {
        record.checkpoints.push(checkpoint(
            "runtime-directory",
            "fixed service-owned runtime directory recreated".into(),
        ));
        store.update(&record)?;
    }
    match result {
        Ok(evidence) => {
            println!("{}", evidence.escape_default());
            record
                .checkpoints
                .push(checkpoint("post-check", evidence.clone()));
            record.post_observations.push(evidence);
            record.outcome = "completed".into();
            store.update(&record)
        }
        Err(error) => {
            record.post_observations.push(error.to_string());
            record.outcome = if effects { "uncertain" } else { "failed-known" }.into();
            if let Err(record_error) = store.update(&record) {
                return Err(io::Error::other(format!(
                    "{error}; retaining maintenance outcome failed: {record_error}"
                )));
            }
            Err(error)
        }
    }
}

pub(super) fn check_platform(manifest: &super::release::Manifest) -> io::Result<()> {
    if std::env::consts::ARCH != "x86_64" || !Path::new("/run/systemd/system").is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires x86-64 and a running systemd",
        ));
    }
    let os = fs::read_to_string("/etc/os-release")?;
    if os.len() > 16384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "os-release exceeds limit",
        ));
    }
    let field = |key: &str| {
        os.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(|v| v.trim_matches('"'))
    };
    let id = field("ID=").ok_or_else(|| io::Error::other("OS identity unavailable"))?;
    let version = field("VERSION_ID=").ok_or_else(|| io::Error::other("OS version unavailable"))?;
    if !manifest
        .platform
        .os
        .iter()
        .any(|item| item.id == id && item.version == version)
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported OS"));
    }
    unsafe extern "C" {
        fn gnu_get_libc_version() -> *const libc::c_char;
    }
    let glibc = unsafe { std::ffi::CStr::from_ptr(gnu_get_libc_version()) }
        .to_str()
        .map_err(io::Error::other)?;
    let version = glibc
        .split('.')
        .take(2)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if version.len() != 2 || (version[0], version[1]) < (2, 36) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "glibc 2.36 or later required",
        ));
    }
    if !Path::new("/usr/bin/udevadm").is_file() && !Path::new("/usr/sbin/udevadm").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "udevadm is required",
        ));
    }
    Ok(())
}

pub(super) fn root_directory(path: &Path, mode: u32) -> io::Result<()> {
    trusted_ancestry(path)?;
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            File::open(path)?.sync_all()?;
            File::open(path.parent().unwrap())?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe root directory",
        ));
    }
    Ok(())
}

fn write_immutable(source: &Path, target: &Path, mode: u32) -> io::Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    if !input.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact is not a regular file",
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    io::copy(&mut input, &mut output)?;
    output.set_permissions(fs::Permissions::from_mode(mode))?;
    output.sync_all()?;
    File::open(target.parent().unwrap())?.sync_all()
}

/// Resolve the firmware tool only from the selected, root-protected tool tree.
pub fn trusted_firmware_tool() -> io::Result<PathBuf> {
    let registry = installation_registry()?;
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("no selected installation"))?;
    let tools: Vec<_> = current
        .components
        .iter()
        .filter(|c| c.component == "tool")
        .collect();
    if tools.len() != 1 {
        return Err(io::Error::other("ambiguous selected tool"));
    }
    let path = PathBuf::from(format!(
        "/usr/lib/pico2-kes-agent/components/tool/{}/firmware.py",
        tools[0].digest
    ));
    let entries: Vec<_> = registry
        .files
        .iter()
        .filter(|f| f.path == path && f.component == "firmware-tool")
        .collect();
    if entries.len() != 1 || entries[0].owner != 0 || entries[0].mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware tool is not owned",
        ));
    }
    trusted_ancestry(&path)?;
    check_owned_file(&path, Some(entries[0]))?;
    let active = Path::new("/usr/lib/pico2-kes-agent/current/tool/firmware.py");
    if fs::canonicalize(active)? != path {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware tool is not selected",
        ));
    }
    Ok(path)
}

fn service_group() -> io::Result<Option<u32>> {
    let name = std::ffi::CString::new("pico2-kes-agent").unwrap();
    let mut entry = unsafe { std::mem::zeroed::<libc::group>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16384];
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    group_lookup_result(rc, if result.is_null() { None } else { Some(entry.gr_gid) })
}

fn group_lookup_result(rc: i32, gid: Option<u32>) -> io::Result<Option<u32>> {
    // NSS may report an absent group as ENOENT/ESRCH rather than success with NULL.
    if rc == 0 || (gid.is_none() && matches!(rc, libc::ENOENT | libc::ESRCH)) {
        Ok(gid)
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

pub(super) fn fixed_command(program: &str, arguments: &[&str]) -> io::Result<()> {
    let path = Path::new(program);
    trusted_ancestry(path)?;
    trusted_ancestry(&fs::canonicalize(path)?)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe system program",
        ));
    }
    if !Command::new(path)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(arguments)
        .status()?
        .success()
    {
        return Err(io::Error::other(format!("{program} failed")));
    }
    Ok(())
}

fn ensure_service_account(plan: &HostPlan) -> io::Result<u32> {
    let group = service_group()?;
    let account = super::setup::service_identity();
    if group.is_none()
        || account
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    {
        let intent = Path::new("/var/lib/p2kesup")
            .join(format!("account-intent-{}.json", plan.approved_digest));
        crate::files::publish_no_clobber(
            &intent,
            &serde_json::to_vec(plan).map_err(io::Error::other)?,
            0o600,
        )?;
        if group.is_none() {
            fixed_command("/usr/sbin/groupadd", &["--system", "pico2-kes-agent"])?;
        }
        if account
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        {
            fixed_command(
                "/usr/sbin/useradd",
                &[
                    "--system",
                    "--gid",
                    "pico2-kes-agent",
                    "--home-dir",
                    "/var/lib/pico2-kes-agent",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "pico2-kes-agent",
                ],
            )?;
        }
    }
    let gid = service_group()?.ok_or_else(|| io::Error::other("service group unavailable"))?;
    let (_, user_gid) = super::setup::service_identity()?;
    if gid != user_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service account/group mismatch",
        ));
    }
    Ok(gid)
}

fn verify_running_manager(bundle: &super::release::VerifiedBundle) -> io::Result<()> {
    let executable = fs::canonicalize("/proc/self/exe")?;
    trusted_ancestry(&executable)?;
    let meta = fs::symlink_metadata(&executable)?;
    let selected = bundle
        .selection()
        .components
        .iter()
        .find(|c| c.component == "manager")
        .ok_or_else(|| io::Error::other("manager missing from selected tuple"))?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "manager is not protected",
        ));
    }
    let entry = ManagedFile {
        path: executable.clone(),
        digest: selected.entrypoint_digest,
        mode: meta.mode() & 0o7777,
        owner: 0,
        group: meta.gid(),
        component: "manager".into(),
    };
    check_owned_file(&executable, Some(&entry))
}

fn precheck_install(role: InstallationRole) -> io::Result<()> {
    match fs::symlink_metadata(INSTALLATION_REGISTRY) {
        Ok(_) => {
            let registry = installation_registry()?;
            if registry.role != role {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "installation role differs",
                ));
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut targets = vec![
        "/usr/lib/pico2-kes-agent",
        "/usr/bin/p2kesup",
        "/usr/bin/pico2-kes-agent-cli",
        "/usr/bin/pico2-kes-agentd",
        "/etc/pico2-kes-agent",
        "/var/lib/pico2-kes-agent",
        "/run/pico2-kes-agent",
        "/usr/lib/systemd/system/pico2-kes-agentd.service",
        "/etc/systemd/system/pico2-kes-agentd.service",
        "/run/systemd/system/pico2-kes-agentd.service",
        "/etc/systemd/system/pico2-kes-agentd.service.d",
        "/run/systemd/system/pico2-kes-agentd.service.d",
    ];
    targets.extend(["/var/lib/p2kesup/records", "/var/lib/p2kesup/firmware"]);
    if role == InstallationRole::Primary {
        targets.extend([
            "/usr/libexec/pico2-kes-agent-host-check",
            "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules",
            "/etc/udev/rules.d/70-pico2-kes-agent.rules",
        ]);
    }
    for path in targets {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("external installation collision: {path}"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if service_group()?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "external service group collision",
        ));
    }
    match super::setup::service_identity() {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "external service account collision",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn install_bundle(
    bundle: &super::release::VerifiedBundle,
    role: InstallationRole,
    digest: &str,
    candidate_accepted: bool,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    let admission = if candidate_accepted {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let staging = Path::new("/var/lib/p2kesup/staging");
    root_directory(staging, 0o700)?;
    let staged = staging.join(record.operation_id.to_string());
    root_directory(&staged, 0o700)?;
    let mut names: Vec<&str> = bundle
        .manifest()
        .artifacts
        .iter()
        .map(|a| a.path.as_str())
        .collect();
    names.extend(["distribution.json", "distribution.json.sig"]);
    for name in names {
        let destination = staged.join(name);
        fs::create_dir_all(destination.parent().unwrap())?;
        write_immutable(&bundle.root().join(name), &destination, 0o600)?;
    }
    File::open(&staged)?.sync_all()?;
    let staged_bundle = super::release::verify_bundle(&staged, admission)?;
    if staged_bundle.selection().manifest_digest.to_string() != digest
        || !same_selection(staged_bundle.selection(), bundle.selection())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected staged bundle differs from approved tuple",
        ));
    }
    check_platform(staged_bundle.manifest())?;
    record
        .checkpoints
        .push(checkpoint("staged-authenticated", digest.into()));
    store.update(record)?;
    let mut retained_registry_digest = None;
    match fs::symlink_metadata(INSTALLATION_REGISTRY) {
        Ok(_) => {
            let registry = installation_registry()?;
            if registry.role != role
                || !registry
                    .current
                    .as_ref()
                    .is_some_and(|selected| same_selection(selected, staged_bundle.selection()))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "installed tuple differs; separate maintenance review required",
                ));
            }
            for entry in &registry.files {
                trusted_ancestry(&entry.path)?;
                check_owned_file(&entry.path, Some(entry))?;
            }
            if super::uninstall::retained_installation(store, &registry)? {
                // shortcut: restore only the exact single-bundle tuple; mixed-tuple reinstall needs an explicit source-selection review.
                retained_registry_digest = Some(registry_digest()?);
                record.checkpoints.push(checkpoint("retained-installation", "completed original removal proves the retained provenance; restore the same signed tuple without changing configuration, pins, state or accounts".into()));
                store.update(record)?;
            } else {
                *effects = true;
                retain_public_source(&staged_bundle, admission, &record.operation_id.to_string())?;
                verify_component_versions(staged_bundle.selection())?;
                if role == InstallationRole::Primary {
                    checked_service()?;
                    record.post_observations.push(running_daemon_observation()?);
                }
                return Ok("existing installation and selected files verified; configuration and state preserved".into());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let root = Path::new("/usr/lib/pico2-kes-agent");
    *effects = true;
    root_directory(root, 0o755)?;
    retain_public_source(&staged_bundle, admission, &record.operation_id.to_string())?;
    let components = root.join("components");
    root_directory(&components, 0o755)?;
    let generations = root.join("generations");
    root_directory(&generations, 0o755)?;
    let mut dirs = std::collections::BTreeMap::new();
    for component in &staged_bundle.selection().components {
        let component_dir = components.join(&component.component);
        root_directory(&component_dir, 0o755)?;
        let target = component_dir.join(component.digest.to_string());
        root_directory(&target, 0o755)?;
        dirs.insert(component.component.clone(), target);
    }
    let mut files = Vec::new();
    for artifact in &staged_bundle.manifest().artifacts {
        let Some((component, relative)) = component_artifact(&artifact.path) else {
            continue;
        };
        let base = dirs
            .get(component)
            .ok_or_else(|| io::Error::other("missing component directory"))?;
        let target = base.join(relative);
        let mut directory = base.clone();
        for part in target
            .parent()
            .unwrap()
            .strip_prefix(base)
            .map_err(io::Error::other)?
            .components()
        {
            let Component::Normal(name) = part else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsafe artifact directory",
                ));
            };
            directory.push(name);
            root_directory(&directory, 0o755)?;
        }
        trusted_ancestry(&target)?;
        write_immutable(
            &staged_bundle.root().join(&artifact.path),
            &target,
            artifact.mode,
        )?;
        let registered_component = if artifact.path == "tools/firmware.py" {
            "firmware-tool"
        } else {
            component
        };
        let entry = ManagedFile {
            path: target,
            digest: Digest32::parse_hex(&artifact.sha256)
                .map_err(|_| io::Error::other("invalid artifact digest"))?,
            mode: artifact.mode,
            owner: 0,
            group: 0,
            component: registered_component.into(),
        };
        check_owned_file(&entry.path, Some(&entry))?;
        files.push(entry);
    }
    let generation = generations.join(digest);
    root_directory(&generation, 0o755)?;
    for (component, path) in &dirs {
        std::os::unix::fs::symlink(path, generation.join(component))?;
    }
    File::open(&generation)?.sync_all()?;
    std::os::unix::fs::symlink(format!("generations/{digest}"), root.join("current"))?;
    File::open(root)?.sync_all()?;
    for (component, name) in [
        ("manager", "p2kesup"),
        ("cli", "pico2-kes-agent-cli"),
        ("daemon", "pico2-kes-agentd"),
    ] {
        let target = Path::new("/usr/bin").join(name);
        std::os::unix::fs::symlink(root.join("current").join(component).join(name), &target)?;
        File::open("/usr/bin")?.sync_all()?;
    }
    record
        .checkpoints
        .push(checkpoint("activated", format!("generation {digest}")));
    store.update(record)?;
    if role == InstallationRole::Primary {
        let (uid, gid) = super::setup::service_identity()?;
        agent_directory(Path::new("/etc/pico2-kes-agent"), 0o750, 0, gid)?;
        agent_directory(Path::new("/var/lib/pico2-kes-agent"), 0o700, uid, gid)?;
        agent_directory(Path::new("/run/pico2-kes-agent"), 0o750, uid, gid)?;
        record.checkpoints.push(checkpoint(
            "agent-directories",
            "created missing agent directories; existing operator directories preserved".into(),
        ));
        store.update(record)?;
        for (source, destination) in [
            (
                "deploy/pico2-kes-agent-host-check",
                "/usr/libexec/pico2-kes-agent-host-check",
            ),
            (
                "deploy/pico2-kes-agentd.service",
                "/usr/lib/systemd/system/pico2-kes-agentd.service",
            ),
            (
                "deploy/70-pico2-kes-agent.rules",
                "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules",
            ),
        ] {
            let artifact = staged_bundle
                .manifest()
                .artifacts
                .iter()
                .find(|a| a.path == source)
                .ok_or_else(|| io::Error::other("deployment artifact missing"))?;
            let target = PathBuf::from(destination);
            trusted_ancestry(&target)?;
            write_immutable(&staged_bundle.root().join(source), &target, artifact.mode)?;
            files.push(ManagedFile {
                path: target,
                digest: Digest32::parse_hex(&artifact.sha256)
                    .map_err(|_| io::Error::other("invalid artifact digest"))?,
                mode: artifact.mode,
                owner: 0,
                group: 0,
                component: "deployment".into(),
            });
            record.checkpoints.push(checkpoint(
                "deployment-file",
                format!("{destination}: {}", artifact.sha256),
            ));
            store.update(record)?;
        }
        if !systemctl(&["daemon-reload"])?.status.success() {
            return Err(io::Error::other("systemd reload failed"));
        }
        record.checkpoints.push(checkpoint(
            "systemd-reload",
            "systemd daemon-reload succeeded".into(),
        ));
        store.update(record)?;
        let udev = if Path::new("/usr/bin/udevadm").exists() {
            "/usr/bin/udevadm"
        } else {
            "/usr/sbin/udevadm"
        };
        fixed_command(udev, &["control", "--reload-rules"])?;
        record
            .checkpoints
            .push(checkpoint("udev-reload", "udev rules reloaded".into()));
        store.update(record)?;
        fixed_command(udev, &["trigger", "--subsystem-match=usb", "--action=add"])?;
        record.checkpoints.push(checkpoint(
            "udev-trigger",
            "USB add trigger succeeded".into(),
        ));
        store.update(record)?;
    }
    let registry = InstallationRegistry {
        schema_version: 1,
        role,
        files,
        current: Some(staged_bundle.selection().clone()),
        preserved_paths: vec![
            "/etc/pico2-kes-agent".into(),
            "/var/lib/pico2-kes-agent".into(),
            "/var/lib/p2kesup/records".into(),
        ],
    };
    let registry_bytes = serde_json::to_vec_pretty(&registry).map_err(io::Error::other)?;
    if registry_bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "registry too large",
        ));
    }
    if let Some(expected) = retained_registry_digest {
        if registry_digest()? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained installation registry changed during restoration",
            ));
        }
        let replacement = Path::new(INSTALLATION_REGISTRY)
            .with_file_name(format!("installation-{}.json", record.operation_id));
        crate::files::publish_no_clobber(&replacement, &registry_bytes, 0o644)?;
        fs::rename(&replacement, INSTALLATION_REGISTRY)?;
        File::open(Path::new(INSTALLATION_REGISTRY).parent().unwrap())?.sync_all()?;
    } else {
        crate::files::publish_no_clobber(Path::new(INSTALLATION_REGISTRY), &registry_bytes, 0o644)?;
    }
    verify_component_versions(staged_bundle.selection())?;
    if role == InstallationRole::Primary {
        checked_service()?;
        let state = service_state("pico2-kes-agentd.service")?;
        if state != "inactive" {
            return Err(io::Error::other(format!(
                "unexpected installed service state: {state}"
            )));
        }
        record.post_observations.push(format!(
            "service state: {state}; no running daemon build asserted"
        ));
    }
    Ok("installed immutable tuple and verified ownership and build identities; configuration, device and service readiness remain separate".into())
}

fn run_first_install(
    bundle: &super::release::VerifiedBundle,
    record_path: &Path,
    apply: bool,
    maintenance: Option<(&RecordStore, &mut MaintenanceRecord)>,
    effects: &mut bool,
) -> io::Result<String> {
    let registry = installation_registry()?;
    if registry.role != InstallationRole::Primary
        || registry.current.as_ref().map(|s| s.manifest_digest)
            != Some(bundle.selection().manifest_digest)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "first-install requires the selected primary tuple",
        ));
    }
    let tool = trusted_firmware_tool()?;
    let artifact = bundle
        .manifest()
        .artifacts
        .iter()
        .find(|a| a.path == "tools/firmware.py")
        .ok_or_else(|| io::Error::other("firmware tool absent"))?;
    let entry = registry
        .files
        .iter()
        .find(|f| f.path == tool)
        .ok_or_else(|| io::Error::other("firmware tool not registered"))?;
    if entry.digest.to_string() != artifact.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware tool differs from approved bundle",
        ));
    }
    let component = bundle
        .selection()
        .components
        .iter()
        .find(|c| c.component == "tool")
        .ok_or_else(|| io::Error::other("picotool missing"))?;
    let tool_dir = PathBuf::from(format!(
        "/usr/lib/pico2-kes-agent/components/tool/{}",
        component.digest
    ));
    for item in registry
        .files
        .iter()
        .filter(|f| f.path.starts_with(&tool_dir))
    {
        trusted_ancestry(&item.path)?;
        check_owned_file(&item.path, Some(item))?;
    }
    let picotool = tool_dir.join("picotool");
    let tool_entry = registry
        .files
        .iter()
        .find(|f| {
            f.path == picotool && f.component == "tool" && f.digest == component.entrypoint_digest
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "picotool not selected"))?;
    check_owned_file(&picotool, Some(tool_entry))?;
    let staged_bundle = if apply {
        if service_state("pico2-kes-agentd.service")? != "inactive"
            || service_state("pico2-kes-agent-commission.service")? != "inactive"
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stop both daemon modes before BOOTSEL transfer",
            ));
        }
        root_directory(Path::new("/var/lib/p2kesup/firmware"), 0o700)?;
        let (store, maintenance) =
            maintenance.ok_or_else(|| io::Error::other("missing maintenance authority"))?;
        let staging = Path::new("/var/lib/p2kesup/staging");
        root_directory(staging, 0o700)?;
        let path = staging.join(maintenance.operation_id.to_string());
        root_directory(&path, 0o700)?;
        let mut names: Vec<&str> = bundle
            .manifest()
            .artifacts
            .iter()
            .map(|a| a.path.as_str())
            .collect();
        names.extend(["distribution.json", "distribution.json.sig"]);
        for name in names {
            let destination = path.join(name);
            fs::create_dir_all(destination.parent().unwrap())?;
            write_immutable(&bundle.root().join(name), &destination, 0o600)?;
        }
        let admission =
            if bundle.selection().qualification == super::model::Qualification::Candidate {
                super::release::Admission::AttendedCandidate
            } else {
                super::release::Admission::Qualified
            };
        let staged = super::release::verify_bundle(&path, admission)?;
        if staged.selection().manifest_digest != bundle.selection().manifest_digest {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staged firmware bundle changed",
            ));
        }
        maintenance.checkpoints.push(checkpoint(
            "staged-authenticated",
            staged.selection().manifest_digest.to_string(),
        ));
        store.update(maintenance)?;
        Some((staged, path))
    } else {
        None
    };
    let firmware_bundle = staged_bundle.as_ref().map_or_else(
        || bundle.root().join("firmware"),
        |(_, path)| path.join("firmware"),
    );
    let python = Path::new("/usr/bin/python3");
    trusted_ancestry(python)?;
    let python_meta = fs::metadata(python)?;
    if python_meta.uid() != 0 || python_meta.mode() & 0o022 != 0 || !python_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe system Python",
        ));
    }
    let mut command = Command::new(python);
    command
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", tool_dir.display()))
        .env("LD_LIBRARY_PATH", tool_dir.join("runtime"))
        .arg("-I")
        .arg(tool)
        .arg("first-install")
        .arg("--bundle")
        .arg(firmware_bundle)
        .arg("--record")
        .arg(record_path);
    if apply {
        command.arg("--apply");
    }
    if apply {
        *effects = true;
    }
    if !command.status()?.success() {
        return Err(io::Error::other(
            "first-install tool failed or was interrupted; retain original record",
        ));
    }
    Ok(if apply {
        format!(
            "firmware transfer tool completed; retain {}; blank admission and commissioning remain separate",
            record_path.display()
        )
    } else {
        "first-install preview or original record inspection only".into()
    })
}

fn agent_directory(path: &Path, mode: u32, owner: u32, group: u32) -> io::Result<()> {
    trusted_ancestry(path)?;
    match fs::create_dir(path) {
        Ok(()) => {
            use std::os::unix::ffi::OsStrExt;
            let name =
                std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
            if unsafe { libc::chown(name.as_ptr(), owner, group) } != 0 {
                return Err(io::Error::last_os_error());
            }
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            File::open(path)?.sync_all()?;
            File::open(path.parent().unwrap())?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "existing agent directory is not a directory",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn authenticate_protected_stage(
    bundle: &super::release::VerifiedBundle,
    candidate_accepted: bool,
) -> io::Result<()> {
    let staging = Path::new("/var/lib/p2kesup/staging");
    root_directory(staging, 0o700)?;
    require_space(staging, bundle, 3)?;
    require_space(Path::new("/usr/lib"), bundle, 1)?;
    require_space(Path::new("/tmp"), bundle, 1)?;
    let mut nonce = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let path = staging.join(OperationId::from_bytes(nonce).to_string());
    root_directory(&path, 0o700)?;
    let mut names: Vec<&str> = bundle
        .manifest()
        .artifacts
        .iter()
        .map(|a| a.path.as_str())
        .collect();
    names.extend(["distribution.json", "distribution.json.sig"]);
    for name in names {
        let target = path.join(name);
        fs::create_dir_all(target.parent().unwrap())?;
        write_immutable(&bundle.root().join(name), &target, 0o600)?;
    }
    let admission = if candidate_accepted {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let staged = super::release::verify_bundle(&path, admission)?;
    if staged.selection().manifest_digest != bundle.selection().manifest_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected staged manifest differs from approval",
        ));
    }
    check_platform(staged.manifest())?;
    verify_running_manager(&staged)
}

/// Bootstrap helper authority is the protected running inode matched to the
/// authenticated selected manager, not an arbitrary current executable.
pub fn trusted_bootstrap_manager(bundle: &super::release::VerifiedBundle) -> io::Result<PathBuf> {
    match fs::symlink_metadata(INSTALLATION_REGISTRY) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installation registry already exists",
            ));
        }
        Err(error) => return Err(error),
    }
    verify_running_manager(bundle)?;
    fs::canonicalize("/proc/self/exe")
}

fn verify_component_versions(selection: &super::model::ReleaseSelection) -> io::Result<()> {
    for (component, binary) in [
        ("manager", "p2kesup"),
        ("daemon", "pico2-kes-agentd"),
        ("cli", "pico2-kes-agent-cli"),
    ] {
        let executable = trusted_component(component, binary)?;
        let selected = selection
            .components
            .iter()
            .find(|c| c.component == component)
            .ok_or_else(|| io::Error::other("missing selected component"))?;
        let output = Command::new(executable)
            .env_clear()
            .args(["--version", "--json"])
            .output()?;
        if !output.status.success() || output.stdout.len() > 65536 {
            return Err(io::Error::other("installed build observation failed"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
        if value["schema_version"] != 1
            || value["component"].as_str() != Some(binary)
            || value["version"].as_str() != Some(selected.version.as_str())
            || value["build_id"].as_str() != Some(selected.build_id.as_str())
            || value["source_commit"].as_str() != Some(selected.source_commit.as_str())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed build differs from signed selection",
            ));
        }
    }
    Ok(())
}

fn require_space(
    path: &Path,
    bundle: &super::release::VerifiedBundle,
    copies: u64,
) -> io::Result<()> {
    let file = File::open(path)?;
    let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut stats) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let available = (stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64);
    let bytes = bundle
        .manifest()
        .artifacts
        .iter()
        .try_fold(0u64, |total, a| total.checked_add(a.size_bytes))
        .and_then(|n| n.checked_mul(copies))
        .and_then(|n| n.checked_add(2 * 1024 * 1024))
        .ok_or_else(|| io::Error::other("bundle size overflow"))?;
    if available < bytes {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "insufficient space for protected staging",
        ));
    }
    Ok(())
}

fn running_daemon_observation() -> io::Result<String> {
    let state = service_state("pico2-kes-agentd.service")?;
    if state != "active" {
        return Ok(format!(
            "service state: {state}; no running daemon build asserted"
        ));
    }
    authenticated_running_daemon_observation()
}

fn authenticated_running_daemon_pid() -> io::Result<u32> {
    let output = systemctl(&[
        "show",
        "pico2-kes-agentd.service",
        "--property=MainPID",
        "--value",
    ])?;
    if !output.status.success() || output.stdout.len() > 32 {
        return Err(io::Error::other("running daemon PID unavailable"));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(io::Error::other)?
        .trim();
    let pid: u32 = text.parse().map_err(io::Error::other)?;
    if pid == 0 {
        return Err(io::Error::other("running daemon PID unavailable"));
    }
    let running = fs::canonicalize(format!("/proc/{pid}/exe"))?;
    if running != trusted_component("daemon", "pico2-kes-agentd")? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "running daemon differs from selected build",
        ));
    }
    Ok(pid)
}

fn authenticated_running_daemon_observation() -> io::Result<String> {
    let pid = authenticated_running_daemon_pid()?;
    Ok(format!(
        "running daemon PID {pid} independently matches selected build"
    ))
}

pub(super) fn lifecycle_authority() -> io::Result<super::lifecycle::PeerAuthority> {
    if !rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "lifecycle admission requires root",
        ));
    }
    let _lock = shared_maintenance_lock()?;
    checked_service()?;
    if service_state("pico2-kes-agentd.service")? != "active"
        || service_state("pico2-kes-agent-commission.service")? != "inactive"
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "normal daemon must be the sole active service",
        ));
    }
    let (_, device_id, identity_public_key, socket) = commissioned_config()?;
    kes_core::identity::DeviceId::parse_hex(&device_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid configured device identity",
        )
    })?;
    Digest32::parse_hex(&identity_public_key).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid configured identity public key",
        )
    })?;
    let pid = authenticated_running_daemon_pid()?;
    let uid = super::setup::service_identity()?.0;
    let status = super::setup::observation(
        &socket,
        "device.status",
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        (pid, uid),
    )?;
    if status["device_id"] != device_id || authenticated_running_daemon_pid()? != pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon or pinned device changed during admission",
        ));
    }
    Ok(super::lifecycle::PeerAuthority {
        socket,
        pid,
        uid,
        identity: super::lifecycle::AuthorityIdentity::Normal {
            device_id,
            identity_public_key,
        },
    })
}

pub(super) fn commissioning_authority(serial: &str) -> io::Result<super::lifecycle::PeerAuthority> {
    if !rustix::process::geteuid().is_root()
        || serial.len() != 16
        || !serial
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root and an exact commissioning serial are required",
        ));
    }
    let _lock = shared_maintenance_lock()?;
    checked_service()?;
    let socket = super::setup::commissioning_socket(serial)?;
    let peer = restricted_daemon_identity()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let before = super::setup::observation(&socket, "device.info", deadline, peer)?;
    let after = super::setup::observation(&socket, "device.info", deadline, peer)?;
    if before != after || after["usb_serial"] != serial || restricted_daemon_identity()? != peer {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon or selected device changed during admission",
        ));
    }
    Ok(super::lifecycle::PeerAuthority {
        socket,
        pid: peer.0,
        uid: peer.1,
        identity: super::lifecycle::AuthorityIdentity::Commissioning {
            serial: serial.to_owned(),
        },
    })
}

/// Observe only the selected agent unit before reviewing a service transition.
pub fn observed_service_state(commissioning: bool) -> io::Result<String> {
    checked_service()?;
    observed_service_state_inner(commissioning)
}

fn observed_service_state_inner(commissioning: bool) -> io::Result<String> {
    let unit = if commissioning {
        "pico2-kes-agent-commission.service"
    } else {
        "pico2-kes-agentd.service"
    };
    let state = service_state(unit)?;
    let output = systemctl(&["show", unit, "--property=MainPID", "--value"])?;
    if !output.status.success() || output.stdout.len() > 32 {
        return Err(io::Error::other("service PID unavailable"));
    }
    let pid: u32 = std::str::from_utf8(&output.stdout)
        .map_err(io::Error::other)?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    if state == "active" && pid == 0 {
        return Err(io::Error::other("active service PID unavailable"));
    }
    let unit_path = if commissioning {
        Path::new("/run/systemd/system/pico2-kes-agent-commission.service")
    } else {
        Path::new("/usr/lib/systemd/system/pico2-kes-agentd.service")
    };
    let unit_digest = match fs::symlink_metadata(unit_path) {
        Ok(meta) => {
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || meta.nlink() != 1
                || meta.len() > 1024 * 1024
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "service unit identity unavailable",
                ));
            }
            format!("{:x}", Sha256::digest(fs::read(unit_path)?))
        }
        Err(error) if commissioning && error.kind() == io::ErrorKind::NotFound => "absent".into(),
        Err(error) => return Err(error),
    };
    let lifecycle = systemctl(&["show", unit, "--property=InvocationID", "--property=Job"])?;
    if !lifecycle.status.success() || lifecycle.stdout.len() > 256 {
        return Err(io::Error::other("service invocation unavailable"));
    }
    let text = std::str::from_utf8(&lifecycle.stdout).map_err(io::Error::other)?;
    let invocation = text
        .lines()
        .find_map(|line| line.strip_prefix("InvocationID="))
        .ok_or_else(|| io::Error::other("service invocation missing"))?;
    let job = text
        .lines()
        .find_map(|line| line.strip_prefix("Job="))
        .ok_or_else(|| io::Error::other("service job state missing"))?;
    if !matches!(job, "" | "0")
        || (!invocation.is_empty()
            && (invocation.len() != 32 || !invocation.bytes().all(|b| b.is_ascii_hexdigit())))
        || (state == "active" && invocation.is_empty())
    {
        return Err(io::Error::other(
            "service transition is pending or invocation identity is unavailable",
        ));
    }
    Ok(format!(
        "state={state};pid={pid};registry={};unit={unit_digest};invocation={invocation}",
        registry_digest()?
    ))
}

pub(super) fn registry_digest() -> io::Result<String> {
    installation_registry()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(INSTALLATION_REGISTRY)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "registry too large",
        ));
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Reopen the original protected operation without creating or replaying work.
fn reopen_existing_plan(plan: &HostPlan) -> io::Result<bool> {
    match fs::symlink_metadata("/var/lib/p2kesup/records") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let _lock = shared_maintenance_lock()?;
    let store = existing_record_store()?;
    report_matching_plan(plan, &store)
}

fn report_matching_plan(plan: &HostPlan, store: &RecordStore) -> io::Result<bool> {
    let digest = Digest32::parse_hex(&plan.approved_digest)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid plan digest"))?;
    let mut found = None;
    for value in store.list()? {
        match value {
            super::records::Record::Supported(record) if record.plan_digest == digest => {
                if found.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "multiple original records match plan",
                    ));
                }
                found = Some(record);
            }
            super::records::Record::Unknown(_) => {}
            _ => {}
        }
    }
    let Some(record) = found else {
        return Ok(false);
    };
    println!("Original maintenance record (read-only; no action will be replayed):");
    println!(
        "{}",
        serde_json::to_string_pretty(&record).map_err(io::Error::other)?
    );
    let observation = match &plan.action {
        HostAction::HostReconcile { operation_id, .. } => Ok(format!("read-only reconciliation refers to original host operation {operation_id}")),
        HostAction::UninstallRecovery { operation_id, .. } => Ok(format!("removal recovery refers to original operation {operation_id}; {}", installation_recovery_observation())),
        HostAction::Provisioning { request } => Ok(format!("original OTP record /var/lib/p2kesup/provisioning/{}.json; reopen through Device security; no stage replay", request.serial)),
        HostAction::ProducerHardening { .. } => Ok("producer file/command outcomes are retained in the original checkpoints; no producer query or restart during inspection".into()),
        HostAction::ProducerRecovery { operation_id, .. } => Ok(format!("producer recovery refers to original operation {operation_id}; original approvals and partial outcomes remain authoritative")),
        HostAction::Config { .. } => configuration_recovery_observation(),
        HostAction::Service { .. } => observed_service_state(false),
        HostAction::UpdateRecovery { .. } => Ok(installation_recovery_observation()),
        HostAction::UpgradeRecovery { .. } | HostAction::Upgrade { .. } => Ok(installation_recovery_observation()),
        HostAction::FirmwarePreview { .. } => observed_service_state(false),
        HostAction::FirmwareRecovery { operation_id, .. } => Ok(format!(
            "original firmware operation {operation_id}; {}",
            installation_recovery_observation()
        )),
        HostAction::CommissionService { .. } => observed_service_state(true),
        HostAction::ReconcileFirstInstall { operation_id, .. } => Ok(format!(
            "reconciliation references original operation {operation_id}"
        )),
        HostAction::CommissionAdmission { .. } => {
            Ok("commission admission is read-only and creates no maintenance record".into())
        }
        HostAction::Install { .. } | HostAction::Uninstall { .. } | HostAction::Update { .. } => {
            Ok(installation_recovery_observation())
        }
        HostAction::FirmwareFirstInstall { record, .. }
        | HostAction::FirmwareUpdate { record, .. } => {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(record)
            {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    if !metadata.is_file()
                        || metadata.uid() != 0
                        || metadata.mode() & 0o077 != 0
                        || metadata.nlink() != 1
                        || metadata.len() > 8 * 1024 * 1024
                    {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "unsafe original firmware record",
                        ))
                    } else {
                        let mut bytes = Vec::new();
                        file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                        let value: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                        Ok(format!(
                            "original firmware record: {}; action={}; checkpoints={}",
                            record.display(),
                            value["action"],
                            value["checkpoints"]
                        ))
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Ok("original firmware record absent; transfer is not proven".into())
                }
                Err(error) => Err(error),
            }
        }
    };
    match observation {
        Ok(value) => println!("Current observation: {}", value.escape_default()),
        Err(error) => println!(
            "Current observation unavailable: {}",
            error.to_string().escape_default()
        ),
    }
    println!(
        "Prior uncertain outcomes remain unresolved; inspect the original evidence before any recovery."
    );
    Ok(true)
}

/// Confirmed pre-effect rejections do not block a separately approved action.
pub fn maintenance_outcome_allows_new_action(outcome: &str) -> bool {
    matches!(outcome, "completed" | "cancelled" | "failed-known")
}

/// These paths are hidden or replaced by the installed service's filesystem sandbox.
pub fn validate_service_input_visibility(inputs: &[super::setup::PublicInput]) -> io::Result<()> {
    for input in inputs {
        let path = fs::canonicalize(&input.path)?;
        if ["/home", "/root", "/run/user", "/tmp", "/var/tmp"]
            .iter()
            .any(|hidden| path.starts_with(hidden))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "genesis input is hidden by the installed service sandbox",
            ));
        }
    }
    Ok(())
}

/// Validate only the fixed sibling candidate using the authenticated daemon,
/// service identity and the filesystem restrictions of the installed unit.
pub(super) fn check_configuration_as_service(
    candidate: &Path,
    commissioning: bool,
) -> io::Result<()> {
    let expected = Path::new("/etc/pico2-kes-agent")
        .join(format!(".p2kesup-candidate-{}", std::process::id()));
    if candidate != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configuration candidate is outside the fixed service directory",
        ));
    }
    checked_service()?;
    let expected_unit = include_bytes!("../../deploy/pico2-kes-agentd.service");
    let service_path = Path::new("/usr/lib/systemd/system/pico2-kes-agentd.service");
    if fs::metadata(service_path)?.len() != expected_unit.len() as u64
        || fs::read(service_path)?.as_slice() != expected_unit.as_slice()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed service sandbox differs from the authenticated manager's unit",
        ));
    }
    let daemon = trusted_component("daemon", "pico2-kes-agentd")?;
    check_configuration_with_daemon(candidate, commissioning, &daemon)
}

fn check_configuration_with_daemon(
    candidate: &Path,
    commissioning: bool,
    daemon: &Path,
) -> io::Result<()> {
    let program = Path::new("/usr/bin/systemd-run");
    trusted_ancestry(program)?;
    trusted_ancestry(&fs::canonicalize(program)?)?;
    let meta = fs::metadata(program)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe systemd-run",
        ));
    }
    let mut random = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let unit = format!("p2kesup-config-check-{}", OperationId::from_bytes(random));
    let mut command = Command::new(program);
    command
        .env_clear()
        .args([
            "--quiet",
            "--wait",
            "--collect",
            "--pipe",
            "--unit",
            &unit,
            "--property=Type=exec",
            "--property=User=pico2-kes-agent",
            "--property=Group=pico2-kes-agent",
            "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectKernelLogs=yes",
            "--property=ProtectControlGroups=yes",
            "--property=ProtectProc=invisible",
            "--property=ProcSubset=pid",
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=ReadWritePaths=/run/pico2-kes-agent /var/lib/pico2-kes-agent",
            "--property=BindReadOnlyPaths=/proc/swaps:/run/pico2-kes-agent/host-swaps",
            "--",
        ])
        .arg(daemon)
        .arg("--config")
        .arg(candidate)
        .arg("--check-config");
    if commissioning {
        command.arg("--commission");
    }
    if !command.status()?.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service sandbox rejected candidate configuration",
        ));
    }
    Ok(())
}

fn ensure_runtime_at(path: &Path, uid: u32, gid: u32, effects: &mut bool) -> io::Result<bool> {
    let mut builder = fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    if created {
        let result = (|| {
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0
                || unsafe { libc::fchmod(directory.as_raw_fd(), 0o750) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            directory.sync_all()?;
            File::open(
                path.parent()
                    .ok_or_else(|| io::Error::other("missing runtime parent"))?,
            )?
            .sync_all()
        })();
        if let Err(error) = result {
            if fs::remove_dir(path).is_err() {
                *effects = true;
            }
            return Err(error);
        }
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            if created {
                *effects = true;
            }
            return Err(error);
        }
    };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o750
    {
        if created {
            *effects = true;
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory has external ownership or permissions",
        ));
    }
    Ok(created)
}

pub(super) fn ensure_service_runtime(effects: &mut bool) -> io::Result<bool> {
    let path = Path::new("/run/pico2-kes-agent");
    trusted_ancestry(path)?;
    let (uid, gid) = super::setup::service_identity()?;
    ensure_runtime_at(path, uid, gid, effects)
}

fn recovery_scope_permits(action: &HostAction, original_id: &str) -> bool {
    match action {
        HostAction::Config {
            commissioning: true,
            recovery_operation: Some(id),
            ..
        }
        | HostAction::CommissionService {
            recovery_operation: Some(id),
            ..
        } => id == original_id,
        HostAction::ReconcileFirstInstall { operation_id, .. } => operation_id == original_id,
        _ => false,
    }
}

fn recovery_id(action: &HostAction) -> Option<&str> {
    match action {
        HostAction::Config {
            recovery_operation: Some(id),
            ..
        }
        | HostAction::CommissionService {
            recovery_operation: Some(id),
            ..
        } => Some(id),
        HostAction::ReconcileFirstInstall { operation_id, .. } => Some(operation_id),
        _ => None,
    }
}

struct FirstInstallEvidence {
    original: MaintenanceRecord,
    bundle: super::release::VerifiedBundle,
    tool_record_digest: String,
    tool_record_path: PathBuf,
    physical_chipid: String,
    transfer_checkpoints: serde_json::Value,
}

fn original_first_install(store: &RecordStore, id: &str) -> io::Result<FirstInstallEvidence> {
    let operation = OperationId::parse_hex(id).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid original operation ID")
    })?;
    let original = store.load(&operation)?.supported()?;
    if original.action != "firmware_transfer"
        || !matches!(
            original.outcome.as_str(),
            "intent-durable" | "staged-authenticated" | "uncertain" | "post-check" | "completed"
        )
        || original.approved_scope.len() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original record is not an admitted first-install transfer",
        ));
    }
    let approved: HostAction =
        serde_json::from_str(&original.approved_scope[0]).map_err(io::Error::other)?;
    let validated = HostPlan {
        schema_version: 1,
        plan_id: id.to_owned(),
        approved_digest: plan_digest(id, &approved)?,
        action: approved,
    };
    validated.validate()?;
    let (manifest_digest, candidate_accepted, record_path) = match validated.action {
        HostAction::FirmwareFirstInstall {
            manifest_digest,
            candidate_accepted,
            record,
            apply: true,
            ..
        } => (manifest_digest, candidate_accepted, record),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original transfer scope is invalid",
            ));
        }
    };
    if original.bundle_digest.as_deref() != Some(manifest_digest.as_str())
        || !original
            .checkpoints
            .iter()
            .any(|c| c.name == "staged-authenticated" && c.evidence == manifest_digest)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original staged authentication evidence is missing",
        ));
    }
    let stage = Path::new("/var/lib/p2kesup/staging").join(id);
    trusted_ancestry(&stage.join("distribution.json"))?;
    let stage_meta = fs::symlink_metadata(&stage)?;
    if !stage_meta.is_dir()
        || stage_meta.uid() != 0
        || stage_meta.gid() != 0
        || stage_meta.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original protected stage is unsafe",
        ));
    }
    let admission = if candidate_accepted {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let bundle = super::release::verify_bundle(&stage, admission)?;
    if bundle.selection().manifest_digest.to_string() != manifest_digest
        || original.selected.as_ref().map(|s| s.manifest_digest)
            != Some(bundle.selection().manifest_digest)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original bundle differs from the reviewed transfer",
        ));
    }
    require_installed_tuple(&bundle)?;
    trusted_ancestry(&record_path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&record_path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > 8 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original firmware record is unsafe",
        ));
    }
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original firmware record is oversized",
        ));
    }
    let tool: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let chipid = tool["physical_chipid"].as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "original physical selection unavailable",
        )
    })?;
    let checkpoints = tool["checkpoints"].as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "original transfer checkpoints unavailable",
        )
    })?;
    let artifact = |path: &str| {
        bundle
            .manifest()
            .artifacts
            .iter()
            .find(|a| a.path == path)
            .map(|a| a.sha256.as_str())
    };
    if tool["schema_version"] != 1
        || tool["action"] != "first-install"
        || chipid.len() != 16
        || !chipid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !checkpoints.iter().any(|c| c == "transfer-started")
        || tool["bundle_sha256"].as_str() != artifact("firmware/release.json")
        || tool["uf2_sha256"].as_str() != artifact("firmware/pico2-kes-firmware.signed.uf2")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original firmware transfer evidence does not match the authenticated bundle",
        ));
    }
    Ok(FirstInstallEvidence {
        original,
        bundle,
        tool_record_digest: format!("{:x}", Sha256::digest(&bytes)),
        tool_record_path: record_path,
        physical_chipid: chipid.to_owned(),
        transfer_checkpoints: tool["checkpoints"].clone(),
    })
}

fn read_host_plan(path: &Path) -> io::Result<HostPlan> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plan must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "plan exceeds 1 MiB",
        ));
    }
    let plan: HostPlan = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    plan.validate()?;
    Ok(plan)
}

/// Inspect only a matching existing original record; never admit new work.
pub fn inspect_plan(path: &Path) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host inspection requires root",
        ));
    }
    let plan = read_host_plan(path)?;
    if !reopen_existing_plan(&plan)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no original record matches this plan",
        ));
    }
    Ok(())
}

pub(super) fn require_installed_tuple(bundle: &super::release::VerifiedBundle) -> io::Result<()> {
    let registry = installation_registry()?;
    let current = registry.current.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "installed selection is unavailable",
        )
    })?;
    if registry.role != InstallationRole::Primary || !same_selection(current, bundle.selection()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated bundle differs from the installed compatible tuple",
        ));
    }
    trusted_component("manager", "p2kesup")?;
    trusted_component("daemon", "pico2-kes-agentd")?;
    trusted_component("cli", "pico2-kes-agent-cli")?;
    trusted_firmware_tool()?;
    for (component, filename) in [
        ("firmware", "pico2-kes-firmware.signed.uf2"),
        ("tool", "picotool"),
        ("deployment", "install.sh"),
    ] {
        let selected = current
            .components
            .iter()
            .find(|item| item.component == component)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "installed tuple component is unavailable",
                )
            })?;
        let path = PathBuf::from(format!(
            "/usr/lib/pico2-kes-agent/components/{component}/{}/{filename}",
            selected.digest
        ));
        let entry = registry
            .files
            .iter()
            .find(|item| {
                item.path == path
                    && item.component == component
                    && item.digest == selected.entrypoint_digest
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "selected tuple component is not owned",
                )
            })?;
        trusted_ancestry(&path)?;
        check_owned_file(&path, Some(entry))?;
        let active = Path::new("/usr/lib/pico2-kes-agent/current")
            .join(component)
            .join(filename);
        if fs::canonicalize(active)? != path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "selected tuple link changed",
            ));
        }
    }
    Ok(())
}

fn check_other_pending_records(store: &RecordStore, action: &HostAction) -> io::Result<()> {
    for prior in store.list()? {
        match prior {
            super::records::Record::Supported(previous)
                if maintenance_outcome_allows_new_action(&previous.outcome) => {}
            super::records::Record::Supported(previous)
                if previous.action == "firmware_transfer"
                    && recovery_scope_permits(action, &previous.operation_id.to_string()) => {}
            super::records::Record::Supported(previous)
                if original_recovery_permits(action, &previous)? => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unresolved or unknown maintenance record requires original-operation recovery",
                ));
            }
        }
    }
    Ok(())
}

/// Gate commissioning on the exact installed tuple and any original transfer's
/// separately recorded, attended blank-application observation.
fn commissioning_recovery_gate(
    serial: &str,
    bundle: &super::release::VerifiedBundle,
) -> io::Result<()> {
    require_installed_tuple(bundle)?;
    let store = existing_record_store()?;
    let manifest_digest = bundle.selection().manifest_digest.to_string();
    let mut transfers = 0usize;
    for record in store.list()? {
        let previous = record.supported()?;
        if previous.action != "firmware_transfer" {
            if !maintenance_outcome_allows_new_action(&previous.outcome) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unresolved maintenance blocks commissioning",
                ));
            }
            continue;
        }
        if matches!(previous.outcome.as_str(), "failed-known" | "cancelled") {
            continue;
        }
        transfers += 1;
        if previous.outcome != "completed"
            || previous.bundle_digest.as_deref() != Some(manifest_digest.as_str())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original transfer requires attended post-state reconciliation",
            ));
        }
        let admitted = matching_blank_postcheck(&previous.checkpoints, serial, &manifest_digest);
        if !admitted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original transfer has no matching attended blank-application evidence",
            ));
        }
    }
    if transfers > 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ambiguous original transfer evidence",
        ));
    }
    Ok(())
}

pub(super) fn restricted_daemon_identity() -> io::Result<(u32, u32)> {
    ensure_no_commission_overrides()?;
    if service_state("pico2-kes-agentd.service")? != "inactive"
        || service_state("pico2-kes-agent-commission.service")? != "active"
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "exactly the restricted commissioning service must be active",
        ));
    }
    let expected_unit = commissioning_unit()?;
    let unit_path = Path::new("/run/systemd/system/pico2-kes-agent-commission.service");
    let meta = fs::symlink_metadata(unit_path)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != 0o644
        || meta.nlink() != 1
        || meta.len() != expected_unit.len() as u64
        || fs::read(unit_path)? != expected_unit
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted commissioning unit identity differs",
        ));
    }
    let output = systemctl(&[
        "show",
        "pico2-kes-agent-commission.service",
        "--property=MainPID",
        "--value",
    ])?;
    if !output.status.success() || output.stdout.len() > 32 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "restricted daemon PID unavailable",
        ));
    }
    let pid: u32 = std::str::from_utf8(&output.stdout)
        .map_err(io::Error::other)?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    if pid == 0
        || fs::canonicalize(format!("/proc/{pid}/exe"))?
            != trusted_component("daemon", "pico2-kes-agentd")?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon executable differs",
        ));
    }
    let mut cmdline = Vec::new();
    File::open(format!("/proc/{pid}/cmdline"))?
        .take(4097)
        .read_to_end(&mut cmdline)?;
    if cmdline.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "restricted daemon arguments exceed limit",
        ));
    }
    let arguments: Vec<&[u8]> = cmdline
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .collect();
    if arguments
        != [
            b"/usr/bin/pico2-kes-agentd".as_slice(),
            b"--config",
            b"/etc/pico2-kes-agent/config.json",
            b"--commission",
        ]
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon arguments differ",
        ));
    }
    Ok((pid, super::setup::service_identity()?.0))
}

fn ensure_no_commission_overrides() -> io::Result<()> {
    for path in [
        "/etc/systemd/system/pico2-kes-agent-commission.service",
        "/etc/systemd/system/pico2-kes-agent-commission.service.d",
        "/run/systemd/system/pico2-kes-agent-commission.service.d",
        "/usr/lib/systemd/system/pico2-kes-agent-commission.service",
        "/usr/lib/systemd/system/pico2-kes-agent-commission.service.d",
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("external commissioning service collision: {path}"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn reconcile_first_install(
    store: &RecordStore,
    operation_id: &str,
    serial: &str,
) -> io::Result<()> {
    let mut evidence = original_first_install(store, operation_id)?;
    let socket = super::setup::commissioning_socket(serial)?;
    let identity = restricted_daemon_identity()?;
    super::setup::admit_commissioning_from_pid(
        &socket,
        serial,
        &evidence.bundle,
        identity.0,
        identity.1,
    )?;
    if restricted_daemon_identity()? != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon changed during post-state admission",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&evidence.tool_record_path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 8 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original firmware record changed during admission",
        ));
    }
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024
        || format!("{:x}", Sha256::digest(&bytes)) != evidence.tool_record_digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original firmware record changed during admission",
        ));
    }
    if restricted_daemon_identity()? != identity
        || super::setup::commissioning_socket(serial)? != socket
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon or configured socket changed during reconciliation",
        ));
    }
    let report = serde_json::json!({
        "serial": serial,
        "manifest_digest": evidence.bundle.selection().manifest_digest.to_string(),
        "physical_chipid": evidence.physical_chipid,
        "physical_association": "operator attended same-board confirmation; bootloader CHIPID is not an application pin",
        "tool_record_sha256": evidence.tool_record_digest,
        "transfer_checkpoints": evidence.transfer_checkpoints,
        "transfer_flush": "original transfer and flush evidence is retained without inferring a successful flush",
        "daemon_pid": identity.0
    });
    evidence.original.checkpoints.push(checkpoint(
        "application-blank-attended",
        serde_json::to_string(&report).map_err(io::Error::other)?,
    ));
    evidence.original.post_observations.push("selected compatible blank application observed by the authenticated restricted daemon; physical association is attended".into());
    if evidence.original.outcome != "completed" {
        evidence.original.outcome = "post-check".into();
        store.update(&evidence.original)?;
        evidence.original.outcome = "completed".into();
    }
    store.update(&evidence.original)?;
    println!(
        "Original operation {operation_id} post-state reconciled. Its tool record and transfer/flush uncertainty remain unchanged; commissioning is a separate approval."
    );
    Ok(())
}

fn matching_blank_postcheck(
    checkpoints: &[MaintenanceCheckpoint],
    serial: &str,
    digest: &str,
) -> bool {
    checkpoints.iter().any(|checkpoint| {
        if checkpoint.name != "application-blank-attended" {
            return false;
        }
        serde_json::from_str::<serde_json::Value>(&checkpoint.evidence)
            .ok()
            .is_some_and(|evidence| {
                evidence["serial"] == serial && evidence["manifest_digest"] == digest
            })
    })
}

/// Fresh commissioning admission bound to the actual restricted daemon process,
/// selected bundle, configured socket and any original transfer evidence.
fn admit_commissioning_target(
    socket: &Path,
    serial: &str,
    bundle: &super::release::VerifiedBundle,
) -> io::Result<()> {
    require_installed_tuple(bundle)?;
    let configured = super::setup::commissioning_socket(serial)?;
    if socket != configured {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "selected management socket differs from the restricted daemon configuration",
        ));
    }
    let identity = restricted_daemon_identity()?;
    super::setup::admit_commissioning_from_pid(
        &configured,
        serial,
        bundle,
        identity.0,
        identity.1,
    )?;
    commissioning_recovery_gate(serial, bundle)?;
    if restricted_daemon_identity()? != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon changed during commissioning admission",
        ));
    }
    Ok(())
}

pub(super) fn same_selection(a: &super::model::ReleaseSelection, b: &super::model::ReleaseSelection) -> bool {
    a.tag == b.tag
        && a.version == b.version
        && a.source_commit == b.source_commit
        && a.channel == b.channel
        && a.qualification == b.qualification
        && a.platform == b.platform
        && a.manifest_digest == b.manifest_digest
        && a.components.len() == b.components.len()
        && a.components.iter().all(|left| {
            let mut matches = b
                .components
                .iter()
                .filter(|right| right.component == left.component);
            let Some(right) = matches.next() else {
                return false;
            };
            matches.next().is_none()
                && a.components
                    .iter()
                    .filter(|item| item.component == left.component)
                    .count()
                    == 1
                && left.version == right.version
                && left.build_id == right.build_id
                && left.digest == right.digest
                && left.entrypoint_digest == right.entrypoint_digest
                && left.source_commit == right.source_commit
                && left.manifest_digest == right.manifest_digest
        })
}

fn shared_maintenance_lock() -> io::Result<HostLock> {
    let lock_path = Path::new("/var/lib/p2kesup/host.lock");
    trusted_ancestry(lock_path)?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)?;
    let meta = lock.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe maintenance lock",
        ));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(HostLock(lock))
}

/// Read-only privileged admission for the existing unprivileged CLI.
/// It never creates a maintenance record or submits a device mutation.
pub fn admit_plan(path: &Path) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 || !io::stdin().is_terminal() || !io::stdout().is_terminal()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "attended privileged admission is required",
        ));
    }
    let plan = read_host_plan(path)?;
    let HostAction::CommissionAdmission {
        bundle,
        manifest_digest,
        candidate_accepted,
        serial,
        socket,
        expected_service_state,
    } = &plan.action
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host-admit requires a commissioning-admission plan",
        ));
    };
    let _lock = shared_maintenance_lock()?;
    if fs::canonicalize("/proc/self/exe")? != trusted_manager()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "admission helper is not the authenticated installed manager",
        ));
    }
    let admission = if *candidate_accepted {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let verified = super::release::verify_bundle(bundle, admission)?;
    if verified.selection().manifest_digest.to_string() != *manifest_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "admission bundle changed after review",
        ));
    }
    if &observed_service_state(true)? != expected_service_state {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted daemon target changed after review",
        ));
    }
    admit_commissioning_target(socket, serial, &verified)?;
    println!(
        "Authenticated restricted-daemon blank admission succeeded for {serial}; commissioning remains a separate CLI action."
    );
    Ok(())
}

pub(super) fn existing_record_store() -> io::Result<RecordStore> {
    let gid = super::setup::service_identity()?.1;
    let record_lock = Path::new("/var/lib/p2kesup/records/.lock");
    trusted_ancestry(record_lock)?;
    let metadata = fs::symlink_metadata(record_lock)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o640
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe or missing record lock",
        ));
    }
    RecordStore::open_host(gid)
}

fn configuration_recovery_observation() -> io::Result<String> {
    let path = Path::new("/etc/pico2-kes-agent/config.json");
    match super::setup::current_config_review()? {
        Some((digest, _bytes)) => {
            let metadata = fs::symlink_metadata(path)?;
            Ok(format!(
                "current configuration SHA-256={digest}, uid={}, gid={}, mode={:04o}",
                metadata.uid(),
                metadata.gid(),
                metadata.mode() & 0o7777
            ))
        }
        None => Ok("current configuration absent".into()),
    }
}

fn installation_recovery_observation() -> String {
    let registry = match fs::symlink_metadata(INSTALLATION_REGISTRY) {
        Ok(_) => registry_digest()
            .map(|digest| format!("SHA-256={digest}"))
            .unwrap_or_else(|e| format!("unavailable: {e}")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => "absent".into(),
        Err(error) => format!("unavailable: {error}"),
    };
    let link = |path: &Path| match fs::read_link(path) {
        Ok(target) => format!("{}", target.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => "absent".into(),
        Err(error) => format!("unavailable: {error}"),
    };
    let current = link(Path::new("/usr/lib/pico2-kes-agent/current"));
    let mut result = format!("registry: {registry}; current: {current}");
    for name in ["p2kesup", "pico2-kes-agent-cli", "pico2-kes-agentd"] {
        result.push_str(&format!(
            "; /usr/bin/{name}: {}",
            link(&Path::new("/usr/bin").join(name))
        ));
    }
    for (component, binary) in [
        ("manager", "p2kesup"),
        ("cli", "pico2-kes-agent-cli"),
        ("daemon", "pico2-kes-agentd"),
    ] {
        match trusted_component(component, binary) {
            Ok(path) => result.push_str(&format!(
                "; {component} owned hash verified: {}",
                path.display()
            )),
            Err(error) => result.push_str(&format!(
                "; {component} ownership/hash unavailable: {error}"
            )),
        }
    }
    match service_state("pico2-kes-agentd.service") {
        Ok(state) => result.push_str(&format!("; service state: {state}")),
        Err(error) => result.push_str(&format!("; service state unavailable: {error}")),
    }
    result
}

fn stage_source(
    bundle: &super::release::VerifiedBundle,
    path: &Path,
    admission: super::release::Admission,
) -> io::Result<super::release::VerifiedBundle> {
    root_directory(path, 0o700)?;
    require_space(path, bundle, 2)?;
    for name in bundle
        .manifest()
        .artifacts
        .iter()
        .map(|a| a.path.as_str())
        .chain(["distribution.json", "distribution.json.sig"])
    {
        let target = path.join(name);
        fs::create_dir_all(target.parent().unwrap())?;
        write_immutable(&bundle.root().join(name), &target, 0o600)?;
    }
    let staged = super::release::verify_bundle(path, admission)?;
    if staged.selection().manifest_digest != bundle.selection().manifest_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "staged source changed",
        ));
    }
    check_platform(staged.manifest())?;
    Ok(staged)
}

fn retain_public_source(
    bundle: &super::release::VerifiedBundle,
    admission: super::release::Admission,
    operation: &str,
) -> io::Result<PathBuf> {
    let root = Path::new("/usr/lib/pico2-kes-agent/sources");
    root_directory(root, 0o755)?;
    let digest = bundle.selection().manifest_digest.to_string();
    let target = root.join(&digest);
    if target.exists() {
        root_directory(&target, 0o755)?;
        let checked = super::release::verify_bundle(&target, admission)?;
        if checked.selection().manifest_digest.to_string() != digest {
            return Err(io::Error::other("retained source differs"));
        }
        return Ok(target);
    }
    require_space(root, bundle, 1)?;
    let temporary = root.join(format!(".{digest}-{operation}"));
    root_directory(&temporary, 0o755)?;
    for (name, mode) in bundle
        .manifest()
        .artifacts
        .iter()
        .map(|a| (a.path.as_str(), a.mode))
        .chain([
            ("distribution.json", 0o644),
            ("distribution.json.sig", 0o644),
        ])
    {
        let destination = temporary.join(name);
        let mut directory = temporary.clone();
        for part in destination
            .parent()
            .unwrap()
            .strip_prefix(&temporary)
            .map_err(io::Error::other)?
            .components()
        {
            let Component::Normal(part) = part else {
                return Err(io::Error::other("unsafe source path"));
            };
            directory.push(part);
            root_directory(&directory, 0o755)?;
        }
        write_immutable(&bundle.root().join(name), &destination, mode)?;
    }
    let checked = super::release::verify_bundle(&temporary, admission)?;
    if checked.selection().manifest_digest.to_string() != digest {
        return Err(io::Error::other("retained source changed"));
    }
    fs::rename(&temporary, &target)?;
    File::open(root)?.sync_all()?;
    Ok(target)
}

fn component_artifact(path: &str) -> Option<(&str, String)> {
    if let Some(name) = path.strip_prefix("bin/") {
        let component = match name {
            "p2kesup" => "manager",
            "pico2-kes-agentd" => "daemon",
            "pico2-kes-agent-cli" => "cli",
            _ => return None,
        };
        Some((component, name.into()))
    } else if let Some(name) = path.strip_prefix("firmware/") {
        Some(("firmware", name.into()))
    } else if let Some(name) = path.strip_prefix("tools/") {
        Some(("tool", name.into()))
    } else if path.starts_with("runtime/") || path.starts_with("licenses/") {
        Some(("tool", path.into()))
    } else if let Some(name) = path.strip_prefix("deploy/") {
        Some(("deployment", name.into()))
    } else if path == "install.sh" {
        Some(("deployment", "bootstrap/install.sh".into()))
    } else {
        None
    }
}

fn update_bundle(
    plan: &HostPlan,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
    coordinated: Option<&HostPlan>,
) -> io::Result<String> {
    let HostAction::Update {
        authorizing_bundle,
        sources,
        candidate_source,
        selection,
        expected_registry_digest,
        expected_service_state,
        stop_service,
        pre_state,
        temporary_validation,
    } = &plan.action
    else {
        return Err(io::Error::other("invalid update action"));
    };
    let registry = installation_registry()?;
    let old = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("no installed tuple"))?;
    let old_firmware = old
        .components
        .iter()
        .find(|c| c.component == "firmware")
        .ok_or_else(|| io::Error::other("installed firmware selection missing"))?;
    let next_firmware = selection
        .components
        .iter()
        .find(|c| c.component == "firmware")
        .ok_or_else(|| io::Error::other("reviewed firmware selection missing"))?;
    if coordinated.is_none() && (old_firmware.digest != next_firmware.digest
        || old_firmware.manifest_digest != next_firmware.manifest_digest)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware selection changes require attended firmware transfer",
        ));
    }
    let admission_for_source = |path: &Path| {
        let retained = old.components.iter().any(|c| {
            path == Path::new("/usr/lib/pico2-kes-agent/sources")
                .join(c.manifest_digest.to_string())
        });
        if candidate_source.as_deref() == Some(path) || (retained && path != authorizing_bundle) {
            super::release::Admission::AttendedCandidate
        } else {
            super::release::Admission::Qualified
        }
    };
    if registry_digest()? != *expected_registry_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry changed after review",
        ));
    }
    for entry in &registry.files {
        trusted_ancestry(&entry.path)?;
        check_owned_file(&entry.path, Some(entry))?;
    }
    for (component, binary) in [
        ("manager", "p2kesup"),
        ("daemon", "pico2-kes-agentd"),
        ("cli", "pico2-kes-agent-cli"),
    ] {
        trusted_component(component, binary)?;
    }
    let prior_active = if registry.role == InstallationRole::Primary {
        let expected = expected_service_state
            .as_ref()
            .ok_or_else(|| io::Error::other("service review required"))?;
        if observed_service_state(false)? != *expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "service changed after review",
            ));
        }
        service_state("pico2-kes-agentd.service")? == "active"
    } else {
        if expected_service_state.is_some() {
            return Err(io::Error::other("backup role has no service"));
        }
        false
    };
    let staging = Path::new("/var/lib/p2kesup/staging");
    root_directory(staging, 0o700)?;
    let operation = staging.join(record.operation_id.to_string());
    root_directory(&operation, 0o700)?;
    let previous_registry = fs::read(INSTALLATION_REGISTRY)?;
    if previous_registry.len() > 1024 * 1024
        || format!("{:x}", Sha256::digest(&previous_registry)) != *expected_registry_digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry changed during staging",
        ));
    }
    crate::files::publish_no_clobber(
        &operation.join("prior-registry.json"),
        &previous_registry,
        0o600,
    )?;
    let admission = if candidate_source.as_deref() == Some(authorizing_bundle.as_path()) {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let authorizing = super::release::verify_bundle(authorizing_bundle, admission)?;
    let authorizing = stage_source(&authorizing, &operation.join("authorization"), admission)?;
    let mut protected = Vec::new();
    for (i, path) in sources.iter().enumerate() {
        let admission = admission_for_source(path);
        let source = super::release::verify_bundle(path, admission)?;
        protected.push(stage_source(
            &source,
            &operation.join(format!("source-{i}")),
            admission,
        )?);
    }
    let choices = selection
        .components
        .iter()
        .map(|c| (c.component.clone(), c.manifest_digest.to_string()))
        .collect();
    let refs: Vec<_> = protected.iter().collect();
    let actual = super::release::select_components(&authorizing, &refs, &choices)?;
    if !same_selection(&actual, selection) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected tuple differs from approval",
        ));
    }
    for (source, path) in protected.iter().zip(sources) {
        if source.selection().qualification == super::model::Qualification::Candidate
            && candidate_source.as_deref() != Some(path.as_path())
        {
            let retained = Path::new("/usr/lib/pico2-kes-agent/sources")
                .join(source.selection().manifest_digest.to_string());
            if *path != retained {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "candidate source was not explicitly launched or retained",
                ));
            }
            root_directory(&retained, 0o755)?;
            for item in actual
                .components
                .iter()
                .filter(|c| c.manifest_digest == source.selection().manifest_digest)
            {
                let previous = old
                    .components
                    .iter()
                    .find(|c| c.component == item.component)
                    .ok_or_else(|| {
                        io::Error::other("retained candidate component not installed")
                    })?;
                if previous.digest != item.digest
                    || previous.entrypoint_digest != item.entrypoint_digest
                    || previous.manifest_digest != item.manifest_digest
                    || previous.source_commit != item.source_commit
                    || previous.version != item.version
                    || previous.build_id != item.build_id
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "retained candidate component changed",
                    ));
                }
            }
        }
    }
    *effects = true;
    retain_public_source(&authorizing, admission, &record.operation_id.to_string())?;
    for (source, path) in protected.iter().zip(sources) {
        retain_public_source(
            source,
            admission_for_source(path),
            &record.operation_id.to_string(),
        )?;
    }
    if registry_digest()? != *expected_registry_digest
        || (registry.role == InstallationRole::Primary
            && observed_service_state(false)? != *expected_service_state.as_ref().unwrap())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host changed during protected staging",
        ));
    }
    record.checkpoints.push(checkpoint(
        "staged-authenticated",
        actual.manifest_digest.to_string(),
    ));
    store.update(record)?;
    let changed = |name: &str| -> io::Result<bool> {
        let a = old
            .components
            .iter()
            .find(|c| c.component == name)
            .ok_or_else(|| io::Error::other("old component missing"))?;
        let b = actual
            .components
            .iter()
            .find(|c| c.component == name)
            .ok_or_else(|| io::Error::other("new component missing"))?;
        Ok(a.digest != b.digest)
    };
    let deployment_changed = changed("deployment")?;
    let disruptive = changed("daemon")? || deployment_changed || coordinated.is_some();
    if !service_change_allowed(prior_active, disruptive, *stop_service) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon/deployment change requires approved stop",
        ));
    }
    if registry.role == InstallationRole::Primary && disruptive {
        if !prior_active && service_state("pico2-kes-agentd.service")? != "inactive" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "failed or transitioning service cannot be temporarily started",
            ));
        }
        let reviewed = pre_state.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fresh pinned device review is required for daemon or deployment changes",
            )
        })?;
        if !prior_active && !temporary_validation {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temporary daemon validation was not approved",
            ));
        }
        let (serial, device_id, _, socket) = commissioned_config()?;
        let observation = (|| -> io::Result<()> {
            if !prior_active {
                run_service(
                    ServiceAction::Start,
                    expected_service_state.as_ref().unwrap(),
                    effects,
                )?;
            }
            let evidence = normal_snapshot(&socket)?;
            super::maintenance::revalidate(reviewed, &evidence).map_err(io::Error::other)?;
            super::maintenance::admit_firmware(&evidence, &serial, &actual, authorizing.manifest())
                .map_err(io::Error::other)?;
            if evidence.device_info["device_id"] != device_id
                || evidence.device_info["build_id"] != old_firmware.build_id
                || evidence.device_info["version"] != old_firmware.version
                || evidence.device_info["source_commit"] != old_firmware.source_commit
                || evidence.security["storage_blank_at_boot"] != false
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "live firmware or current storage is not proven compatible",
                ));
            }
            let config: serde_json::Value =
                serde_json::from_slice(&fs::read("/etc/pico2-kes-agent/config.json")?)
                    .map_err(io::Error::other)?;
            let state = PathBuf::from(
                config["state_directory"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("state directory unavailable"))?,
            );
            if !state.is_absolute()
                || state
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            {
                return Err(io::Error::other("unsafe state directory"));
            }
            crate::daemon::journal::inspect_completed(
                &state.join("operations.journal"),
                super::setup::service_identity()?.0,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            )
            .map_err(io::Error::other)?;
            Ok(())
        })();
        if !prior_active && service_state("pico2-kes-agentd.service")? != "inactive" {
            let state = observed_service_state(false)?;
            run_service(ServiceAction::Stop, &state, effects)?;
        }
        observation?;
        record.checkpoints.push(checkpoint(
            "live-compatibility",
            "pinned device and current storage revalidated".into(),
        ));
        store.update(record)?;
    }
    let root = Path::new("/usr/lib/pico2-kes-agent");
    let mut additions = Vec::new();
    for component in &actual.components {
        let source = protected
            .iter()
            .find(|s| s.selection().manifest_digest == component.manifest_digest)
            .ok_or_else(|| io::Error::other("selected source missing"))?;
        let base = root
            .join("components")
            .join(&component.component)
            .join(component.digest.to_string());
        root_directory(&base, 0o755)?;
        for artifact in &source.manifest().artifacts {
            let Some((name, relative)) = component_artifact(&artifact.path) else {
                continue;
            };
            if name != component.component {
                continue;
            }
            let target = base.join(relative);
            let mut dir = base.clone();
            for part in target
                .parent()
                .unwrap()
                .strip_prefix(&base)
                .map_err(io::Error::other)?
                .components()
            {
                let Component::Normal(name) = part else {
                    return Err(io::Error::other("unsafe artifact path"));
                };
                dir.push(name);
                root_directory(&dir, 0o755)?;
            }
            let entry = ManagedFile {
                path: target.clone(),
                digest: Digest32::parse_hex(&artifact.sha256)
                    .map_err(|_| io::Error::other("invalid artifact digest"))?,
                mode: artifact.mode,
                owner: 0,
                group: 0,
                component: if artifact.path == "tools/firmware.py" {
                    "firmware-tool".into()
                } else {
                    name.into()
                },
            };
            if !target.exists() {
                *effects = true;
                write_immutable(&source.root().join(&artifact.path), &target, artifact.mode)?;
            }
            trusted_ancestry(&target)?;
            check_owned_file(&target, Some(&entry))?;
            additions.push(entry);
        }
    }
    if registry.role == InstallationRole::Primary && disruptive {
        checked_service()?;
        if fs::read("/usr/lib/systemd/system/pico2-kes-agentd.service")?
            != include_bytes!("../../deploy/pico2-kes-agentd.service")
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installed sandbox differs from validator",
            ));
        }
        let deployment = actual
            .components
            .iter()
            .find(|c| c.component == "deployment")
            .unwrap();
        let unit = root
            .join("components/deployment")
            .join(deployment.digest.to_string())
            .join("pico2-kes-agentd.service");
        if fs::read(unit)? != include_bytes!("../../deploy/pico2-kes-agentd.service") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "selected service sandbox differs from validator",
            ));
        }
        let daemon = actual
            .components
            .iter()
            .find(|c| c.component == "daemon")
            .unwrap();
        let executable = root
            .join("components/daemon")
            .join(daemon.digest.to_string())
            .join("pico2-kes-agentd");
        let config = Path::new("/etc/pico2-kes-agent/config.json");
        let metadata = fs::symlink_metadata(config)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe working configuration",
            ));
        }
        check_configuration_with_daemon(config, false, &executable)?;
        record.checkpoints.push(checkpoint(
            "candidate-config",
            "selected daemon accepted current configuration as service identity".into(),
        ));
        store.update(record)?;
    }
    if let Some(original) = coordinated {
        return upgrade::activate_prepared(original, &authorizing, registry, actual, additions, store, record, effects);
    }
    if prior_active && disruptive {
        run_service(
            ServiceAction::Stop,
            expected_service_state.as_ref().unwrap(),
            effects,
        )?;
        record.checkpoints.push(checkpoint(
            "service-quiesced",
            "approved daemon stop observed".into(),
        ));
        store.update(record)?;
    }
    let generation = root.join("generations").join(&plan.approved_digest);
    root_directory(&generation, 0o755)?;
    for component in &actual.components {
        std::os::unix::fs::symlink(
            root.join("components")
                .join(&component.component)
                .join(component.digest.to_string()),
            generation.join(&component.component),
        )?;
    }
    File::open(&generation)?.sync_all()?;
    let temporary = root.join(format!(".current-{}", record.operation_id));
    std::os::unix::fs::symlink(format!("generations/{}", plan.approved_digest), &temporary)?;
    *effects = true;
    fs::rename(&temporary, root.join("current"))?;
    File::open(root)?.sync_all()?;
    record
        .checkpoints
        .push(checkpoint("activated", plan.approved_digest.clone()));
    store.update(record)?;
    let role = registry.role;
    let mut updated = registry;
    if role == InstallationRole::Primary && deployment_changed {
        let deployment = actual
            .components
            .iter()
            .find(|c| c.component == "deployment")
            .unwrap();
        let base = root
            .join("components/deployment")
            .join(deployment.digest.to_string());
        let mut reload_systemd = false;
        let mut reload_udev = false;
        for (name, destination) in [
            (
                "pico2-kes-agent-host-check",
                "/usr/libexec/pico2-kes-agent-host-check",
            ),
            (
                "pico2-kes-agentd.service",
                "/usr/lib/systemd/system/pico2-kes-agentd.service",
            ),
            (
                "70-pico2-kes-agent.rules",
                "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules",
            ),
        ] {
            let source = base.join(name);
            let source_entry = additions
                .iter()
                .find(|e| e.path == source)
                .ok_or_else(|| io::Error::other("deployment asset missing"))?;
            let target = Path::new(destination);
            let index = updated
                .files
                .iter()
                .position(|e| e.path == target)
                .ok_or_else(|| io::Error::other("deployment target not registered"))?;
            check_owned_file(target, Some(&updated.files[index]))?;
            if updated.files[index].digest != source_entry.digest
                || updated.files[index].mode != source_entry.mode
            {
                let temp =
                    target.with_file_name(format!(".p2kesup-{}-{name}", record.operation_id));
                write_immutable(&source, &temp, source_entry.mode)?;
                check_owned_file(target, Some(&updated.files[index]))?;
                fs::rename(&temp, target)?;
                File::open(target.parent().unwrap())?.sync_all()?;
                updated.files[index].digest = source_entry.digest;
                updated.files[index].mode = source_entry.mode;
                record.checkpoints.push(checkpoint(
                    "deployment-file",
                    format!("{destination}: {}", source_entry.digest),
                ));
                store.update(record)?;
                reload_systemd |= name == "pico2-kes-agentd.service";
                reload_udev |= name == "70-pico2-kes-agent.rules";
            }
        }
        if reload_systemd {
            if !systemctl(&["daemon-reload"])?.status.success() {
                return Err(io::Error::other("systemd reload failed"));
            }
            record.checkpoints.push(checkpoint(
                "systemd-reload",
                "systemd daemon-reload succeeded".into(),
            ));
            store.update(record)?;
        }
        if reload_udev {
            let udev = if Path::new("/usr/bin/udevadm").exists() {
                "/usr/bin/udevadm"
            } else {
                "/usr/sbin/udevadm"
            };
            fixed_command(udev, &["control", "--reload-rules"])?;
            record
                .checkpoints
                .push(checkpoint("udev-reload", "udev rules reloaded".into()));
            store.update(record)?;
        }
    }
    for entry in additions {
        if !updated.files.iter().any(|e| e.path == entry.path) {
            updated.files.push(entry);
        }
    }
    updated.current = Some(actual.clone());
    let bytes = serde_json::to_vec_pretty(&updated).map_err(io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("registry too large"));
    }
    let registry_temp =
        Path::new("/var/lib/p2kesup").join(format!(".installation-{}", record.operation_id));
    crate::files::publish_no_clobber(&registry_temp, &bytes, 0o644)?;
    fs::rename(&registry_temp, INSTALLATION_REGISTRY)?;
    File::open("/var/lib/p2kesup")?.sync_all()?;
    verify_component_versions(&actual)?;
    if role == InstallationRole::Primary {
        if prior_active && disruptive {
            let current = observed_service_state(false)?;
            run_service(ServiceAction::Start, &current, effects)?;
        }
        record.post_observations.push(final_service_observation(
            expected_service_state
                .as_deref()
                .ok_or_else(|| io::Error::other("original service state missing"))?,
        )?);
    }
    Ok("selected immutable tuple installed and verified; old manager retained, explicit re-exec may be offered; no device state rolled back".into())
}

/// Public review facts; the apply side checks them again under the maintenance lock.
pub fn update_review() -> io::Result<(String, InstallationRegistry, Option<String>, Vec<PathBuf>)> {
    let registry = installation_registry()?;
    let service = if registry.role == InstallationRole::Primary {
        Some(observed_service_state(false)?)
    } else {
        None
    };
    let selection = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    let mut paths = Vec::new();
    for item in &selection.components {
        let path =
            Path::new("/usr/lib/pico2-kes-agent/sources").join(item.manifest_digest.to_string());
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    Ok((registry_digest()?, registry, service, paths))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareReview {
    pub serial: String,
    pub device_id: String,
    pub identity_public_key: String,
    pub service_state: String,
    pub evidence: super::maintenance::Evidence,
}

/// Publish only public evidence under a fixed, bounded protected review directory.
pub fn firmware_preview_to(id: &str, temporary: Option<&str>) -> io::Result<PathBuf> {
    if unsafe { libc::geteuid() } != 0
        || id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid root firmware preview",
        ));
    }
    let review = match temporary {
        Some(state) => firmware_review_temporary(state)?,
        None => firmware_review()?,
    };
    let bytes = serde_json::to_vec(&review).map_err(io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("firmware review exceeds 1 MiB"));
    }
    let _lock = maintenance_lock()?;
    let gid = super::setup::service_identity()?.1;
    let directory = Path::new("/var/lib/p2kesup/reviews");
    agent_directory(directory, 0o750, 0, gid)?;
    let mut total = 0u64;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.gid() != gid
            || meta.mode() & 0o7777 != 0o640
            || meta.nlink() != 1
            || meta.len() > 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe retained review entry",
            ));
        }
        total = total
            .checked_add(meta.len())
            .ok_or_else(|| io::Error::other("review store size overflow"))?;
    }
    if total.saturating_add(bytes.len() as u64) > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "review store full; export and archive reviews",
        ));
    }
    let target = directory.join(format!("{id}.json"));
    let temp = directory.join(format!(".{id}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    let result = (|| -> io::Result<()> {
        if unsafe { libc::fchown(file.as_raw_fd(), 0, gid) } != 0
            || unsafe { libc::fchmod(file.as_raw_fd(), 0o640) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::hard_link(&temp, &target)?;
        fs::remove_file(&temp)?;
        File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    Ok(target)
}

fn commissioned_config() -> io::Result<(String, String, String, PathBuf)> {
    let path = Path::new("/etc/pico2-kes-agent/config.json");
    trusted_ancestry(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || meta.len() > 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe commissioned configuration",
        ));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let field = |name: &str| {
        value["device"][name]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("commissioned pin unavailable"))
    };
    let serial = field("usb_serial")?;
    let id = field("id")?;
    let key = field("identity_public_key")?;
    let socket = PathBuf::from(
        value["management_socket"]
            .as_str()
            .ok_or_else(|| io::Error::other("management socket unavailable"))?,
    );
    let directory = Path::new(
        value["socket_directory"]
            .as_str()
            .ok_or_else(|| io::Error::other("socket directory unavailable"))?,
    );
    if !socket.is_absolute()
        || socket.parent() != Some(directory)
        || socket
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::other("unsafe management socket"));
    }
    Ok((serial, id, key, socket))
}

fn normal_snapshot(socket: &Path) -> io::Result<super::maintenance::Evidence> {
    checked_service()?;
    if service_state("pico2-kes-agentd.service")? != "active"
        || service_state("pico2-kes-agent-commission.service")? != "inactive"
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "normal daemon must be the sole active service",
        ));
    }
    let pid = authenticated_running_daemon_pid()?;
    let uid = super::setup::service_identity()?.0;
    super::maintenance::snapshot(
        socket,
        pid,
        uid,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .map_err(io::Error::other)
}

/// Root-only, read-only firmware review; never starts a service or changes a device.
pub fn firmware_review() -> io::Result<FirmwareReview> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware review requires root",
        ));
    }
    let _lock = shared_maintenance_lock()?;
    let (serial, device_id, identity_public_key, socket) = commissioned_config()?;
    let service_state = observed_service_state(false)?;
    let evidence = normal_snapshot(&socket)?;
    if evidence.device_info["device_id"] != device_id
        || evidence.device_info["usb_serial"] != serial
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated device does not match configured pin",
        ));
    }
    Ok(FirmwareReview {
        serial,
        device_id,
        identity_public_key,
        service_state,
        evidence,
    })
}

/// An attended, separately recorded temporary start to obtain a stopped service's pre-state.
pub fn firmware_review_temporary(expected_service_state: &str) -> io::Result<FirmwareReview> {
    if unsafe { libc::geteuid() } != 0 || !io::stdin().is_terminal() || !io::stdout().is_terminal()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "temporary firmware review requires an attended root terminal",
        ));
    }
    let plan = HostPlan::new(HostAction::FirmwarePreview {
        expected_service_state: expected_service_state.into(),
    })?;
    plan.validate()?;
    println!(
        "Temporary firmware observation will start the stopped agent and restore it to stopped. Approval digest: {}",
        plan.approved_digest
    );
    print!("Type the complete digest to approve: ");
    io::stdout().flush()?;
    let answer = read_confirmation(io::stdin().lock())?;
    if answer.trim() != plan.approved_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "temporary observation not approved",
        ));
    }
    let _lock = maintenance_lock()?;
    if fs::canonicalize("/proc/self/exe")? != trusted_manager()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not the installed manager",
        ));
    }
    if observed_service_state(false)? != expected_service_state
        || service_state("pico2-kes-agentd.service")? != "inactive"
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reviewed stopped service changed",
        ));
    }
    let (serial, device_id, identity_public_key, socket) = commissioned_config()?;
    let store = RecordStore::open_host(super::setup::service_identity()?.1)?;
    check_other_pending_records(&store, &plan.action)?;
    let mut record = host_record(&plan, Some(expected_service_state.into()))?;
    store.create(&record)?;
    let mut effects = false;
    let result = (|| {
        run_service(ServiceAction::Start, expected_service_state, &mut effects)?;
        record.checkpoints.push(checkpoint(
            "service-started",
            "temporary observation start".into(),
        ));
        store.update(&record)?;
        let evidence = normal_snapshot(&socket)?;
        if evidence.device_info["device_id"] != device_id
            || evidence.device_info["usb_serial"] != serial
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authenticated device does not match configured pin",
            ));
        }
        Ok(evidence)
    })();
    let restored = (|| match service_state("pico2-kes-agentd.service")?.as_str() {
        "inactive" => Ok(()),
        "active" => {
            let state = observed_service_state(false)?;
            run_service(ServiceAction::Stop, &state, &mut effects).map(|_| ())
        }
        _ => Err(io::Error::other("service restoration unavailable")),
    })();
    if let Err(error) = restored {
        record.outcome = "uncertain".into();
        record
            .post_observations
            .push(format!("temporary review restoration failed: {error}"));
        store.update(&record)?;
        return Err(error);
    }
    record.checkpoints.push(checkpoint(
        "service-restored",
        "original stopped state observed".into(),
    ));
    match result {
        Ok(evidence) => {
            record
                .post_observations
                .push(serde_json::to_string(&evidence).map_err(io::Error::other)?);
            record.outcome = "completed".into();
            store.update(&record)?;
            Ok(FirmwareReview {
                serial,
                device_id,
                identity_public_key,
                service_state: observed_service_state(false)?,
                evidence,
            })
        }
        Err(error) => {
            record.outcome = "failed-known".into();
            record.post_observations.push(error.to_string());
            store.update(&record)?;
            Err(error)
        }
    }
}

fn require_firmware_selection(
    bundle: &super::release::VerifiedBundle,
    target: &super::model::ReleaseSelection,
) -> io::Result<()> {
    let registry = installation_registry()?;
    if registry.role != InstallationRole::Primary {
        return Err(io::Error::other("firmware requires a primary installation"));
    }
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed tuple unavailable"))?;
    let candidate_firmware = target
        .components
        .iter()
        .find(|c| c.component == "firmware")
        .ok_or_else(|| io::Error::other("target firmware missing"))?;
    let bundle_firmware = bundle
        .selection()
        .components
        .iter()
        .find(|c| c.component == "firmware")
        .ok_or_else(|| io::Error::other("bundle firmware missing"))?;
    if candidate_firmware.digest != bundle_firmware.digest
        || candidate_firmware.manifest_digest != bundle.selection().manifest_digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target firmware differs from authenticated bundle",
        ));
    }
    let installed_tool = current
        .components
        .iter()
        .find(|c| c.component == "tool")
        .ok_or_else(|| io::Error::other("installed tool missing"))?;
    let source_tool = bundle
        .selection()
        .components
        .iter()
        .find(|c| c.component == "tool")
        .ok_or_else(|| io::Error::other("bundle tool missing"))?;
    if installed_tool.digest != source_tool.digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target requires a different firmware tool",
        ));
    }
    for name in ["manager", "daemon", "cli", "tool", "deployment"] {
        let old = current
            .components
            .iter()
            .find(|c| c.component == name)
            .ok_or_else(|| io::Error::other("installed component missing"))?;
        let next = target
            .components
            .iter()
            .find(|c| c.component == name)
            .ok_or_else(|| io::Error::other("target component missing"))?;
        if old.digest != next.digest
            || old.entrypoint_digest != next.entrypoint_digest
            || old.manifest_digest != next.manifest_digest
            || old.source_commit != next.source_commit
            || old.version != next.version
            || old.build_id != next.build_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "firmware transfer cannot change host components",
            ));
        }
    }
    for entry in &registry.files {
        trusted_ancestry(&entry.path)?;
        check_owned_file(&entry.path, Some(entry))?;
    }
    trusted_manager()?;
    trusted_component("daemon", "pico2-kes-agentd")?;
    trusted_firmware_tool()?;
    let mut sources = Vec::new();
    for item in &target.components {
        if item.manifest_digest == bundle.selection().manifest_digest
            || sources.iter().any(|s: &super::release::VerifiedBundle| {
                s.selection().manifest_digest == item.manifest_digest
            })
        {
            continue;
        }
        let path =
            Path::new("/usr/lib/pico2-kes-agent/sources").join(item.manifest_digest.to_string());
        root_directory(&path, 0o755)?;
        sources.push(super::release::verify_bundle(
            &path,
            super::release::Admission::AttendedCandidate,
        )?);
    }
    let mut refs: Vec<_> = sources.iter().collect();
    refs.push(bundle);
    let choices = target
        .components
        .iter()
        .map(|c| (c.component.clone(), c.manifest_digest.to_string()))
        .collect();
    let selected = super::release::select_components(bundle, &refs, &choices)?;
    if !same_selection(&selected, target) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware target tuple differs from authenticated approval",
        ));
    }
    Ok(())
}

fn publish_firmware_selection(
    bundle: &super::release::VerifiedBundle,
    target: &super::model::ReleaseSelection,
    expected_registry: &str,
    record: &mut MaintenanceRecord,
    store: &RecordStore,
) -> io::Result<()> {
    if registry_digest()? != expected_registry {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry changed during firmware transfer",
        ));
    }
    require_firmware_selection(bundle, target)?;
    let admission = if bundle.selection().qualification == super::model::Qualification::Candidate {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    retain_public_source(bundle, admission, &record.operation_id.to_string())?;
    let root = Path::new("/usr/lib/pico2-kes-agent");
    let firmware = target
        .components
        .iter()
        .find(|c| c.component == "firmware")
        .ok_or_else(|| io::Error::other("firmware target missing"))?;
    let base = root
        .join("components/firmware")
        .join(firmware.digest.to_string());
    root_directory(&base, 0o755)?;
    let mut registry = installation_registry()?;
    for artifact in &bundle.manifest().artifacts {
        let Some(relative) = artifact.path.strip_prefix("firmware/") else {
            continue;
        };
        let destination = base.join(relative);
        let mut directory = base.clone();
        for part in destination
            .parent()
            .unwrap()
            .strip_prefix(&base)
            .map_err(io::Error::other)?
            .components()
        {
            let Component::Normal(part) = part else {
                return Err(io::Error::other("unsafe firmware artifact path"));
            };
            directory.push(part);
            root_directory(&directory, 0o755)?;
        }
        let entry = ManagedFile {
            path: destination.clone(),
            digest: Digest32::parse_hex(&artifact.sha256)
                .map_err(|_| io::Error::other("invalid firmware artifact digest"))?,
            mode: artifact.mode,
            owner: 0,
            group: 0,
            component: "firmware".into(),
        };
        if !destination.exists() {
            write_immutable(
                &bundle.root().join(&artifact.path),
                &destination,
                artifact.mode,
            )?;
        }
        trusted_ancestry(&destination)?;
        check_owned_file(&destination, Some(&entry))?;
        if !registry.files.iter().any(|item| item.path == destination) {
            registry.files.push(entry);
        }
    }
    if registry_digest()? != expected_registry {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry changed before firmware publication",
        ));
    }
    let name = format!("firmware-{}", record.operation_id);
    let generation = root.join("generations").join(&name);
    root_directory(&generation, 0o755)?;
    for component in &target.components {
        let link = generation.join(&component.component);
        let expected = root
            .join("components")
            .join(&component.component)
            .join(component.digest.to_string());
        match std::os::unix::fs::symlink(&expected, &link) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&link)?;
                if !meta.file_type().is_symlink()
                    || meta.uid() != 0
                    || fs::read_link(&link)? != expected
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing firmware generation changed",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    File::open(&generation)?.sync_all()?;
    let temporary = root.join(format!(
        ".firmware-{}-{}",
        record.operation_id,
        std::process::id()
    ));
    std::os::unix::fs::symlink(format!("generations/{name}"), &temporary)?;
    fs::rename(&temporary, root.join("current"))?;
    File::open(root)?.sync_all()?;
    record.checkpoints.push(checkpoint(
        "firmware-selection-activated",
        target.manifest_digest.to_string(),
    ));
    store.update(record)?;
    registry.current = Some(target.clone());
    let bytes = serde_json::to_vec_pretty(&registry).map_err(io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("registry too large"));
    }
    let temporary = Path::new("/var/lib/p2kesup").join(format!(
        ".firmware-{}-{}",
        record.operation_id,
        std::process::id()
    ));
    crate::files::publish_no_clobber(&temporary, &bytes, 0o644)?;
    fs::rename(&temporary, INSTALLATION_REGISTRY)?;
    File::open("/var/lib/p2kesup")?.sync_all()?;
    verify_component_versions(target)?;
    Ok(())
}

fn firmware_update(
    plan: &HostPlan,
    bundle: &super::release::VerifiedBundle,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    let HostAction::FirmwareUpdate {
        serial,
        device_id,
        identity_public_key,
        record: tool_record,
        expected_service_state,
        pre_state,
        temporary_validation,
        candidate_accepted,
        target_selection,
        ..
    } = &plan.action
    else {
        return Err(io::Error::other("invalid firmware action"));
    };
    require_firmware_selection(bundle, target_selection)?;
    let original_registry_digest = registry_digest()?;
    let (configured_serial, configured_id, configured_key, socket) = commissioned_config()?;
    if (&configured_serial, &configured_id, &configured_key)
        != (serial, device_id, identity_public_key)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configured device pin changed after review",
        ));
    }
    let previous = service_state("pico2-kes-agentd.service")?;
    if !matches!(previous.as_str(), "active" | "inactive")
        || observed_service_state(false)? != *expected_service_state
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service changed after approval",
        ));
    }
    if previous == "inactive" && !temporary_validation {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "temporary daemon validation was not approved",
        ));
    }
    let staging = Path::new("/var/lib/p2kesup/staging");
    root_directory(staging, 0o700)?;
    let path = staging.join(record.operation_id.to_string());
    let admission = if *candidate_accepted {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let protected = stage_source(bundle, &path, admission)?;
    require_firmware_selection(&protected, target_selection)?;
    if observed_service_state(false)? != *expected_service_state
        || commissioned_config()?
            != (
                configured_serial,
                configured_id,
                configured_key,
                socket.clone(),
            )
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target changed during staging",
        ));
    }
    record.checkpoints.push(checkpoint(
        "staged-authenticated",
        protected.selection().manifest_digest.to_string(),
    ));
    store.update(record)?;
    let result = (|| -> io::Result<String> {
        if previous == "inactive" {
            run_service(ServiceAction::Start, expected_service_state, effects)?;
        }
        let current = normal_snapshot(&socket)?;
        super::maintenance::revalidate(pre_state, &current).map_err(io::Error::other)?;
        super::maintenance::admit_firmware(
            &current,
            serial,
            target_selection,
            protected.manifest(),
        )
        .map_err(io::Error::other)?;
        if current.device_info["device_id"] != *device_id {
            return Err(io::Error::other("device pin mismatch"));
        }
        let installed = installation_registry()?
            .current
            .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
        let live = installed
            .components
            .iter()
            .find(|c| c.component == "firmware")
            .ok_or_else(|| io::Error::other("installed firmware unavailable"))?;
        if current.device_info["build_id"] != live.build_id
            || current.device_info["version"] != live.version
            || current.device_info["source_commit"] != live.source_commit
            || current.security["storage_blank_at_boot"] != false
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "live firmware does not match the installed pre-state",
            ));
        }
        let observed = observed_service_state(false)?;
        run_service(ServiceAction::Stop, &observed, effects)?;
        record.checkpoints.push(checkpoint(
            "service-quiesced",
            "approved daemon stop observed".into(),
        ));
        record.outcome = "service-quiesced".into();
        store.update(record)?;
        root_directory(Path::new("/var/lib/p2kesup/firmware"), 0o700)?;
        let tool = trusted_firmware_tool()?;
        let tool_entry = installation_registry()?
            .files
            .into_iter()
            .find(|f| f.path == tool)
            .ok_or_else(|| io::Error::other("firmware tool unavailable"))?;
        let staged_tool = protected
            .manifest()
            .artifacts
            .iter()
            .find(|a| a.path == "tools/firmware.py")
            .ok_or_else(|| io::Error::other("firmware tool absent"))?;
        if tool_entry.digest.to_string() != staged_tool.sha256 {
            return Err(io::Error::other("selected firmware tool differs"));
        }
        let selected_tool = protected
            .selection()
            .components
            .iter()
            .find(|c| c.component == "tool")
            .ok_or_else(|| io::Error::other("tool missing"))?;
        let tool_dir = Path::new("/usr/lib/pico2-kes-agent/components/tool")
            .join(selected_tool.digest.to_string());
        let python = Path::new("/usr/bin/python3");
        trusted_ancestry(python)?;
        trusted_ancestry(&fs::canonicalize(python)?)?;
        let meta = fs::metadata(python)?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(io::Error::other("unsafe Python"));
        }
        *effects = true;
        let status = Command::new(python)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", tool_dir.display()))
            .env("LD_LIBRARY_PATH", tool_dir.join("runtime"))
            .arg("-I")
            .arg(path.join("tools/firmware.py"))
            .arg("update")
            .arg("--bundle")
            .arg(path.join("firmware"))
            .arg("--serial")
            .arg(serial)
            .arg("--record")
            .arg(tool_record)
            .arg("--apply")
            .status()?;
        if !status.success() {
            return Err(io::Error::other(
                "firmware transfer failed or interrupted; original operation remains uncertain",
            ));
        }
        record.checkpoints.push(checkpoint(
            "activated",
            format!(
                "tool transfer completed; original record {}",
                tool_record.display()
            ),
        ));
        store.update(record)?;
        let observed = observed_service_state(false)?;
        run_service(ServiceAction::Start, &observed, effects)?;
        let after = normal_snapshot(&socket)?;
        let selected = target_selection
            .components
            .iter()
            .find(|c| c.component == "firmware")
            .ok_or_else(|| io::Error::other("firmware component missing"))?;
        let storage = current.device_info["storage_version"]
            .as_u64()
            .ok_or_else(|| io::Error::other("storage version unavailable"))?;
        super::maintenance::postcheck(&current, &after, &selected.build_id, storage)
            .map_err(io::Error::other)?;
        if after.device_info["version"] != selected.version
            || after.device_info["source_commit"] != selected.source_commit
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "live firmware provenance differs from selected source",
            ));
        }
        record
            .post_observations
            .push(serde_json::to_string(&after).map_err(io::Error::other)?);
        publish_firmware_selection(
            &protected,
            target_selection,
            &original_registry_digest,
            record,
            store,
        )?;
        Ok("firmware live build and forward state verified through the pinned daemon; original service state restored".into())
    })();
    if previous == "inactive" {
        let restore = (|| -> io::Result<()> {
            if service_state("pico2-kes-agentd.service")? != "inactive" {
                let observed = observed_service_state(false)?;
                run_service(ServiceAction::Stop, &observed, effects)?;
            }
            Ok(())
        })();
        if let Err(error) = restore {
            *effects = true;
            return Err(io::Error::other(format!(
                "temporary service restoration failed: {error}; update result: {result:?}"
            )));
        }
    }
    result
}

fn recover_firmware(plan: &HostPlan, store: &RecordStore) -> io::Result<()> {
    let HostAction::FirmwareRecovery {
        operation_id,
        original_plan_digest,
        receipts,
        expected_service_state,
        temporary_validation,
    } = &plan.action
    else {
        return Err(io::Error::other("invalid recovery action"));
    };
    let id = OperationId::parse_hex(operation_id)
        .map_err(|_| io::Error::other("invalid original operation"))?;
    let mut original = store.load(&id)?.supported()?;
    if original.action != "firmware-update"
        || original.plan_digest.to_string() != *original_plan_digest
        || maintenance_outcome_allows_new_action(&original.outcome)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original firmware operation is not unresolved",
        ));
    }
    for record in store.list()? {
        match record {
            super::records::Record::Supported(item)
                if item.operation_id == id
                    || maintenance_outcome_allows_new_action(&item.outcome) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "another unresolved record blocks recovery",
                ));
            }
        }
    }
    let original_action: HostAction = serde_json::from_str(
        original
            .approved_scope
            .first()
            .ok_or_else(|| io::Error::other("original scope missing"))?,
    )
    .map_err(io::Error::other)?;
    let HostAction::FirmwareUpdate {
        serial,
        device_id,
        identity_public_key,
        candidate_accepted,
        record: transfer_record,
        expected_service_state: original_service,
        ..
    } = original_action
    else {
        return Err(io::Error::other("original firmware scope is invalid"));
    };
    if transfer_record
        != Path::new("/var/lib/p2kesup/firmware").join(format!("{operation_id}.json"))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original transfer record identity differs",
        ));
    }
    trusted_ancestry(&transfer_record)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&transfer_record)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 8 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe original transfer evidence",
        ));
    }
    let mut transfer_bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut transfer_bytes)?;
    let transfer: serde_json::Value =
        serde_json::from_slice(&transfer_bytes).map_err(io::Error::other)?;
    if !transfer_flushed(
        &transfer,
        operation_id,
        &serial,
        original.image_digest.as_deref(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original transfer and flush are not proven",
        ));
    }
    let before: super::maintenance::Evidence = serde_json::from_str(
        original
            .pre_observations
            .first()
            .ok_or_else(|| io::Error::other("original pre-state missing"))?,
    )
    .map_err(io::Error::other)?;
    let selected = original
        .selected
        .clone()
        .ok_or_else(|| io::Error::other("original selected tuple missing"))?;
    let current = installation_registry()?
        .current
        .ok_or_else(|| io::Error::other("current tuple missing"))?;
    let already_published = same_selection(&selected, &current);
    let expected_registry = original_service
        .split(';')
        .find_map(|part| part.strip_prefix("registry="))
        .ok_or_else(|| io::Error::other("original registry identity missing"))?;
    if !already_published && registry_digest()? != expected_registry {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry differs from original firmware intent",
        ));
    }
    let source = Path::new("/var/lib/p2kesup/staging").join(operation_id);
    let admission = if candidate_accepted {
        super::release::Admission::AttendedCandidate
    } else {
        super::release::Admission::Qualified
    };
    let bundle = super::release::verify_bundle(&source, admission)?;
    if original.bundle_digest.as_deref()
        != Some(bundle.selection().manifest_digest.to_string().as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original source manifest changed",
        ));
    }
    require_firmware_selection(&bundle, &selected)?;
    let (actual_serial, actual_id, actual_key, socket) = commissioned_config()?;
    if (actual_serial, actual_id, actual_key)
        != (serial.clone(), device_id.clone(), identity_public_key)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original configured pin changed",
        ));
    }
    if observed_service_state(false)? != *expected_service_state {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reviewed service changed",
        ));
    }
    let initial = service_state("pico2-kes-agentd.service")?;
    if !matches!(initial.as_str(), "active" | "inactive") {
        return Err(io::Error::other("service state unavailable"));
    }
    if initial == "inactive" && !temporary_validation {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "temporary validation not approved",
        ));
    }
    let previous = original
        .previous_service_state
        .as_deref()
        .ok_or_else(|| io::Error::other("original service state missing"))?;
    let original_stopped = previous.starts_with("state=inactive;");
    if !original_stopped && !previous.starts_with("state=active;") {
        return Err(io::Error::other(
            "original service state is not recoverable",
        ));
    }
    if original_stopped && initial == "active" && !temporary_validation {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restoring the original stopped state requires approval",
        ));
    }
    let staged_receipts =
        Path::new("/var/lib/p2kesup/staging").join(format!("recovery-{}", plan.plan_id));
    root_directory(&staged_receipts, 0o700)?;
    let mut paths = Vec::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&receipt.path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > 1024 * 1024 {
            return Err(io::Error::other("unsafe original receipt"));
        }
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if format!("{:x}", Sha256::digest(&bytes)) != receipt.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original receipt changed",
            ));
        }
        let path = staged_receipts.join(format!("{index}.json"));
        crate::files::publish_no_clobber(&path, &bytes, 0o600)?;
        paths.push(path);
    }
    let mut effects = false;
    let result = (|| -> io::Result<super::maintenance::Evidence> {
        if initial == "inactive" {
            run_service(ServiceAction::Start, expected_service_state, &mut effects)?;
        }
        let after = normal_snapshot(&socket)?;
        let component = selected
            .components
            .iter()
            .find(|c| c.component == "firmware")
            .ok_or_else(|| io::Error::other("firmware selection missing"))?;
        if after.device_info["device_id"] != device_id
            || after.device_info["usb_serial"] != serial
            || after.device_info["build_id"] != component.build_id
            || after.device_info["version"] != component.version
            || after.device_info["source_commit"] != component.source_commit
            || after.device_info["storage_version"] != before.device_info["storage_version"]
            || after.security["storage_blank_at_boot"] != false
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "live pin, build or storage differs from original intent",
            ));
        }
        super::maintenance::admit_firmware(&after, &serial, &selected, bundle.manifest())
            .map_err(io::Error::other)?;
        let output = systemctl(&[
            "show",
            "pico2-kes-agentd.service",
            "--property=MainPID",
            "--value",
        ])?;
        if !output.status.success() || output.stdout.len() > 32 {
            return Err(io::Error::other("daemon PID unavailable"));
        }
        let pid: u32 = std::str::from_utf8(&output.stdout)
            .map_err(io::Error::other)?
            .trim()
            .parse()
            .map_err(io::Error::other)?;
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read("/etc/pico2-kes-agent/config.json")?)
                .map_err(io::Error::other)?;
        let state_dir = PathBuf::from(
            config["state_directory"]
                .as_str()
                .ok_or_else(|| io::Error::other("state directory unavailable"))?,
        );
        if !state_dir.is_absolute()
            || state_dir
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(io::Error::other("unsafe state directory"));
        }
        let journal = state_dir.join("operations.journal");
        super::maintenance::compare_authorized(
            &before,
            &after,
            &paths,
            &socket,
            (pid, super::setup::service_identity()?.0),
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &journal,
        )
        .map_err(io::Error::other)?;
        if !already_published {
            publish_firmware_selection(
                &bundle,
                &selected,
                expected_registry,
                &mut original,
                store,
            )?;
        }
        Ok(after)
    })();
    if original_stopped || (initial == "inactive" && result.is_err()) {
        let restore = (|| -> io::Result<()> {
            if service_state("pico2-kes-agentd.service")? != "inactive" {
                let current = observed_service_state(false)?;
                run_service(ServiceAction::Stop, &current, &mut effects)?;
            }
            Ok(())
        })();
        if let Err(error) = restore {
            original.outcome = "uncertain".into();
            original.post_observations.push(format!(
                "recovery temporary service restore failed: {error}"
            ));
            store.update(&original)?;
            return Err(error);
        }
    }
    let after = result?;
    original
        .post_observations
        .push(serde_json::to_string(&after).map_err(io::Error::other)?);
    original.checkpoints.push(checkpoint(
        "post-check",
        format!(
            "original firmware recovered; approval {}; {} reconciled receipts",
            plan.approved_digest,
            receipts.len()
        ),
    ));
    original.outcome = "completed".into();
    store.update(&original)
}

fn original_update(
    store: &RecordStore,
    id: &str,
    digest: &str,
) -> io::Result<(MaintenanceRecord, super::model::ReleaseSelection, PathBuf)> {
    let id =
        OperationId::parse_hex(id).map_err(|_| io::Error::other("invalid original operation"))?;
    let record = store.load(&id)?.supported()?;
    if record.action != "update"
        || record.plan_digest.to_string() != digest
        || maintenance_outcome_allows_new_action(&record.outcome)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original update is not unresolved",
        ));
    }
    let (previous, link): (super::model::ReleaseSelection, PathBuf) = serde_json::from_str(
        record
            .pre_observations
            .first()
            .ok_or_else(|| io::Error::other("original tuple evidence absent"))?,
    )
    .map_err(io::Error::other)?;
    if link.components().count() != 2
        || !link.starts_with("generations")
        || link
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(io::Error::other("original generation link invalid"));
    }
    Ok((record, previous, link))
}

/// Resolve the original protected manager even when activation and registry disagree.
pub fn trusted_recovery_manager(
    operation_id: &str,
    original_plan_digest: &str,
) -> io::Result<PathBuf> {
    let store = existing_record_store()?;
    let (_, previous, _) = original_update(&store, operation_id, original_plan_digest)?;
    let manager = previous
        .components
        .iter()
        .find(|c| c.component == "manager")
        .ok_or_else(|| io::Error::other("original manager unavailable"))?;
    let path = Path::new("/usr/lib/pico2-kes-agent/components/manager")
        .join(manager.digest.to_string())
        .join("p2kesup");
    trusted_ancestry(&path)?;
    let entry = ManagedFile {
        path: path.clone(),
        digest: manager.entrypoint_digest,
        mode: 0o755,
        owner: 0,
        group: 0,
        component: "manager".into(),
    };
    check_owned_file(&path, Some(&entry))?;
    Ok(path)
}

/// Observe the public registry, pointer and service independently for original-update recovery.
pub fn review_update_recovery(
    operation_id: &str,
    original_plan_digest: &str,
) -> io::Result<HostAction> {
    let store = existing_record_store()?;
    let (record, previous, _) = original_update(&store, operation_id, original_plan_digest)?;
    let registry = installation_registry()?;
    let link = Path::new("/usr/lib/pico2-kes-agent/current");
    let metadata = fs::symlink_metadata(link)?;
    if !metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "current generation pointer is not root-owned",
        ));
    }
    Ok(HostAction::UpdateRecovery {
        operation_id: operation_id.into(),
        original_plan_digest: original_plan_digest.into(),
        expected_registry_digest: registry_digest()?,
        expected_current_link: fs::read_link(link)?,
        expected_service_state: recovery_service_observation(registry.role, &record, &previous)?,
        stop_service: false,
        temporary_validation: false,
        restore_deployment: false,
    })
}

fn recovery_service_observation(
    role: InstallationRole,
    record: &MaintenanceRecord,
    previous: &super::model::ReleaseSelection,
) -> io::Result<Option<String>> {
    if role != InstallationRole::Primary {
        return Ok(None);
    }
    match observed_service_state(false) {
        Ok(state) => Ok(Some(state)),
        Err(_) => {
            check_service_overrides()?;
            let action: HostAction = serde_json::from_str(
                record
                    .approved_scope
                    .first()
                    .ok_or_else(|| io::Error::other("original update scope missing"))?,
            )
            .map_err(io::Error::other)?;
            let HostAction::Update {
                expected_registry_digest,
                ..
            } = action
            else {
                return Err(io::Error::other("original update scope invalid"));
            };
            let path = Path::new("/var/lib/p2kesup/staging")
                .join(record.operation_id.to_string())
                .join("prior-registry.json");
            trusted_ancestry(&path)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o7777 != 0o600
                || meta.nlink() != 1
                || meta.len() > 1024 * 1024
            {
                return Err(io::Error::other("unsafe original registry evidence"));
            }
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if format!("{:x}", Sha256::digest(&bytes)) != expected_registry_digest {
                return Err(io::Error::other("original registry digest changed"));
            }
            let prior: InstallationRegistry =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if prior.schema_version != 1
                || prior.role != role
                || !prior
                    .current
                    .as_ref()
                    .is_some_and(|s| same_selection(s, previous))
            {
                return Err(io::Error::other("original role or tuple unavailable"));
            }
            let target = record
                .selected
                .as_ref()
                .ok_or_else(|| io::Error::other("original target unavailable"))?;
            let assets = recovery_deployment_assets(&prior, previous, target)?;
            if !assets.iter().any(|(old, _, _)| {
                old.path == Path::new("/usr/lib/systemd/system/pico2-kes-agentd.service")
            }) {
                return Err(io::Error::other(
                    "original or target service authority unavailable",
                ));
            }
            Ok(Some(observed_service_state_inner(false)?))
        }
    }
}

fn recover_update(plan: &HostPlan, store: &RecordStore) -> io::Result<()> {
    let HostAction::UpdateRecovery {
        operation_id,
        original_plan_digest,
        expected_registry_digest,
        expected_current_link,
        expected_service_state,
        stop_service,
        temporary_validation,
        restore_deployment,
    } = &plan.action
    else {
        return Err(io::Error::other("invalid update recovery"));
    };
    let (mut record, previous, old_link) =
        original_update(store, operation_id, original_plan_digest)?;
    for prior in store.list()? {
        match prior {
            super::records::Record::Supported(item)
                if item.operation_id == record.operation_id
                    || maintenance_outcome_allows_new_action(&item.outcome) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "another unresolved record blocks recovery",
                ));
            }
        }
    }
    let original_action: HostAction = serde_json::from_str(
        record
            .approved_scope
            .first()
            .ok_or_else(|| io::Error::other("original update scope missing"))?,
    )
    .map_err(io::Error::other)?;
    let HostAction::Update {
        expected_registry_digest: prior_digest,
        ..
    } = original_action
    else {
        return Err(io::Error::other("original update scope invalid"));
    };
    let current = installation_registry()?;
    let observed = recovery_service_observation(current.role, &record, &previous)?;
    if observed != *expected_service_state {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service changed after recovery review",
        ));
    }
    let target = record
        .selected
        .as_ref()
        .ok_or_else(|| io::Error::other("original target unavailable"))?;
    let unchanged = ["daemon", "firmware", "tool", "deployment"]
        .iter()
        .all(|name| {
            let a = previous.components.iter().find(|c| c.component == *name);
            let b = target.components.iter().find(|c| c.component == *name);
            a.zip(b).is_some_and(|(a, b)| {
                a.digest == b.digest
                    && a.entrypoint_digest == b.entrypoint_digest
                    && a.manifest_digest == b.manifest_digest
                    && a.source_commit == b.source_commit
                    && a.version == b.version
                    && a.build_id == b.build_id
            })
        });
    let needs_live = current.role == InstallationRole::Primary && !unchanged;
    if current.role == InstallationRole::Primary {
        let original_state = record
            .previous_service_state
            .as_deref()
            .ok_or_else(|| io::Error::other("original service state missing"))?;
        if !service_state_matches(original_state, "active")
            && !service_state_matches(original_state, "inactive")
        {
            return Err(io::Error::other(
                "original service state is not recoverable",
            ));
        }
    }
    if !record.checkpoints.iter().any(|c| c.name == "activated")
        && *expected_current_link == old_link
        && *expected_registry_digest == prior_digest
        && record.previous_service_state.as_deref() == expected_service_state.as_deref()
        && registry_digest()? == prior_digest
        && fs::read_link("/usr/lib/pico2-kes-agent/current")? == old_link
        && recovery_service_observation(current.role, &record, &previous)?
            == *expected_service_state
    {
        let installed = installation_registry()?;
        if installed
            .current
            .as_ref()
            .is_some_and(|s| same_selection(s, &previous))
        {
            for entry in &installed.files {
                trusted_ancestry(&entry.path)?;
                check_owned_file(&entry.path, Some(entry))?;
            }
            if installed.role == InstallationRole::Primary {
                record.post_observations.push(final_service_observation(
                    record
                        .previous_service_state
                        .as_deref()
                        .ok_or_else(|| io::Error::other("original service state missing"))?,
                )?);
            }
            record.checkpoints.push(checkpoint(
                "post-check",
                format!(
                    "original tuple and service unchanged; recovery approval {}",
                    plan.approved_digest
                ),
            ));
            record.outcome = "failed-known".into();
            return store.update(&record);
        }
    }
    let prior_path = Path::new("/var/lib/p2kesup/staging")
        .join(operation_id)
        .join("prior-registry.json");
    trusted_ancestry(&prior_path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&prior_path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe original registry evidence",
        ));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if format!("{:x}", Sha256::digest(&bytes)) != prior_digest {
        return Err(io::Error::other("original registry digest changed"));
    }
    let mut prior: InstallationRegistry =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if prior.schema_version != 1
        || prior.role != current.role
        || !prior
            .current
            .as_ref()
            .is_some_and(|s| same_selection(s, &previous))
    {
        return Err(io::Error::other("original role or tuple unavailable"));
    }
    if registry_digest()? != *expected_registry_digest
        || fs::read_link("/usr/lib/pico2-kes-agent/current")? != *expected_current_link
        || recovery_service_observation(current.role, &record, &previous)?
            != *expected_service_state
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "current host changed after recovery review",
        ));
    }
    let deployment = if current.role == InstallationRole::Primary {
        recovery_deployment_assets(&prior, &previous, target)?
    } else {
        Vec::new()
    };
    if !deployment_restore_allowed(!deployment.is_empty(), *restore_deployment) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment asset restoration and reload were not approved",
        ));
    }
    for entry in prior.files.iter().chain(&current.files) {
        if deployment.iter().any(|(old, _, _)| old.path == entry.path) {
            continue;
        }
        trusted_ancestry(&entry.path)?;
        check_owned_file(&entry.path, Some(entry))?;
    }
    let retained = Path::new("/usr/lib/pico2-kes-agent/sources");
    let authorizer_path = retained.join(previous.manifest_digest.to_string());
    root_directory(&authorizer_path, 0o755)?;
    let authorizer = super::release::verify_bundle(
        &authorizer_path,
        super::release::Admission::AttendedCandidate,
    )?;
    let mut sources = Vec::new();
    for item in &previous.components {
        if sources.iter().any(|s: &super::release::VerifiedBundle| {
            s.selection().manifest_digest == item.manifest_digest
        }) {
            continue;
        }
        let path = retained.join(item.manifest_digest.to_string());
        root_directory(&path, 0o755)?;
        sources.push(super::release::verify_bundle(
            &path,
            super::release::Admission::AttendedCandidate,
        )?);
    }
    let choices = previous
        .components
        .iter()
        .map(|c| (c.component.clone(), c.manifest_digest.to_string()))
        .collect();
    let refs: Vec<_> = sources.iter().collect();
    let verified = super::release::select_components(&authorizer, &refs, &choices)?;
    if !same_selection(&verified, &previous) {
        return Err(io::Error::other(
            "original tuple is no longer authenticated",
        ));
    }
    let generation = Path::new("/usr/lib/pico2-kes-agent").join(&old_link);
    for component in &previous.components {
        let expected = Path::new("/usr/lib/pico2-kes-agent/components")
            .join(&component.component)
            .join(component.digest.to_string());
        if fs::canonicalize(generation.join(&component.component))? != expected {
            return Err(io::Error::other("original generation changed"));
        }
    }
    if needs_live {
        let initial = service_state("pico2-kes-agentd.service")?;
        if !recovery_validation_allowed(true, &initial, *temporary_validation, *stop_service) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "live recovery requires an approved stop and, when inactive, approved temporary validation",
            ));
        }
        let temporary_unit = if initial == "inactive" {
            if service_state("pico2-kes-agent-commission.service")? != "inactive" {
                return Err(io::Error::other("commissioning service must be inactive"));
            }
            let daemon = previous
                .components
                .iter()
                .find(|c| c.component == "daemon")
                .ok_or_else(|| io::Error::other("original daemon missing"))?;
            let path = Path::new("/usr/lib/pico2-kes-agent/components/daemon")
                .join(daemon.digest.to_string())
                .join("pico2-kes-agentd");
            let entry = prior
                .files
                .iter()
                .find(|e| {
                    e.path == path
                        && e.component == "daemon"
                        && e.digest == daemon.entrypoint_digest
                })
                .ok_or_else(|| io::Error::other("original daemon authority missing"))?;
            check_owned_file(&path, Some(entry))?;
            if fs::read("/usr/lib/systemd/system/pico2-kes-agentd.service")?
                != include_bytes!("../../deploy/pico2-kes-agentd.service")
            {
                return Err(io::Error::other(
                    "original service sandbox cannot be validated",
                ));
            }
            check_configuration_with_daemon(
                Path::new("/etc/pico2-kes-agent/config.json"),
                false,
                &path,
            )?;
            let unit = format!("p2kesup-recovery-{}.service", plan.plan_id);
            record.checkpoints.push(checkpoint(
                "recovery-validation-starting",
                format!("{unit}; approval {}", plan.approved_digest),
            ));
            store.update(&record)?;
            start_recovery_validation(&unit, &path)?;
            Some(unit)
        } else {
            None
        };
        let validation = (|| -> io::Result<()> {
            let (serial, device_id, _, socket) = commissioned_config()?;
            let output = systemctl(&[
                "show",
                temporary_unit
                    .as_deref()
                    .unwrap_or("pico2-kes-agentd.service"),
                "--property=MainPID",
                "--value",
            ])?;
            if !output.status.success() || output.stdout.len() > 32 {
                return Err(io::Error::other("running daemon PID unavailable"));
            }
            let pid: u32 = std::str::from_utf8(&output.stdout)
                .map_err(io::Error::other)?
                .trim()
                .parse()
                .map_err(io::Error::other)?;
            let executable = fs::canonicalize(format!("/proc/{pid}/exe"))?;
            let selected_daemons = previous
                .components
                .iter()
                .chain(current.current.iter().flat_map(|s| s.components.iter()))
                .chain(record.selected.iter().flat_map(|s| s.components.iter()))
                .filter(|c| c.component == "daemon");
            if !selected_daemons.into_iter().any(|component| {
                let path = Path::new("/usr/lib/pico2-kes-agent/components/daemon")
                    .join(component.digest.to_string())
                    .join("pico2-kes-agentd");
                path == executable
                    && current.files.iter().chain(prior.files.iter()).any(|entry| {
                        entry.path == path
                            && entry.component == "daemon"
                            && entry.digest == component.entrypoint_digest
                            && check_owned_file(&entry.path, Some(entry)).is_ok()
                    })
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "running daemon is not a reviewed authenticated binary",
                ));
            }
            let uid = super::setup::service_identity()?.0;
            if temporary_unit.is_some() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !socket.exists() && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            let evidence = super::maintenance::snapshot(
                &socket,
                pid,
                uid,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            )
            .map_err(io::Error::other)?;
            let firmware = previous
                .components
                .iter()
                .find(|c| c.component == "firmware")
                .ok_or_else(|| io::Error::other("original firmware missing"))?;
            if evidence.device_info["device_id"] != device_id
                || evidence.device_info["build_id"] != firmware.build_id
                || evidence.device_info["version"] != firmware.version
                || evidence.device_info["source_commit"] != firmware.source_commit
                || evidence.security["storage_blank_at_boot"] != false
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "current data is not proven readable by the original tuple",
                ));
            }
            super::maintenance::admit_firmware(
                &evidence,
                &serial,
                &previous,
                authorizer.manifest(),
            )
            .map_err(io::Error::other)?;
            let daemon = previous
                .components
                .iter()
                .find(|c| c.component == "daemon")
                .ok_or_else(|| io::Error::other("original daemon missing"))?;
            let daemon_path = Path::new("/usr/lib/pico2-kes-agent/components/daemon")
                .join(daemon.digest.to_string())
                .join("pico2-kes-agentd");
            if fs::read("/usr/lib/systemd/system/pico2-kes-agentd.service")?
                != include_bytes!("../../deploy/pico2-kes-agentd.service")
            {
                return Err(io::Error::other(
                    "original service sandbox cannot be validated",
                ));
            }
            check_configuration_with_daemon(
                Path::new("/etc/pico2-kes-agent/config.json"),
                false,
                &daemon_path,
            )?;
            let config: serde_json::Value =
                serde_json::from_slice(&fs::read("/etc/pico2-kes-agent/config.json")?)
                    .map_err(io::Error::other)?;
            let state = PathBuf::from(
                config["state_directory"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("state directory unavailable"))?,
            );
            if !state.is_absolute()
                || state
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            {
                return Err(io::Error::other("unsafe state directory"));
            }
            crate::daemon::journal::inspect_completed(
                &state.join("operations.journal"),
                uid,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            )
            .map_err(io::Error::other)?;
            Ok(())
        })();
        if let Some(unit) = temporary_unit {
            let stopped = systemctl(&["stop", &unit])?;
            if !stopped.status.success() || service_state(&unit)? != "inactive" {
                return Err(io::Error::other(
                    "temporary recovery daemon could not be stopped",
                ));
            }
            record
                .checkpoints
                .push(checkpoint("recovery-validation-stopped", unit));
            store.update(&record)?;
        }
        validation?;
        record.checkpoints.push(checkpoint(
            "recovery-live-compatibility",
            format!(
                "authenticated live evidence; approval {}",
                plan.approved_digest
            ),
        ));
        store.update(&record)?;
    }
    if registry_digest()? != *expected_registry_digest
        || fs::read_link("/usr/lib/pico2-kes-agent/current")? != *expected_current_link
        || recovery_service_observation(current.role, &record, &previous)?
            != *expected_service_state
    {
        return Err(io::Error::other("host changed during recovery validation"));
    }
    let mut effects = false;
    if needs_live && service_state("pico2-kes-agentd.service")? == "active" {
        record.checkpoints.push(checkpoint(
            "recovery-service-stopping",
            plan.approved_digest.clone(),
        ));
        store.update(&record)?;
        if recovery_service_observation(current.role, &record, &previous)?
            != *expected_service_state
        {
            return Err(io::Error::other("service changed before recovery stop"));
        }
        if !systemctl(&["stop", "pico2-kes-agentd.service"])?
            .status
            .success()
            || service_state("pico2-kes-agentd.service")? != "inactive"
        {
            return Err(io::Error::other("recovery service stop failed"));
        }
        effects = true;
        record.checkpoints.push(checkpoint(
            "recovery-service-quiesced",
            plan.approved_digest.clone(),
        ));
        store.update(&record)?;
    }
    if !deployment.is_empty() {
        restore_recovery_deployment(&deployment, plan, store, &mut record)?;
    }
    let root = Path::new("/usr/lib/pico2-kes-agent");
    let temporary = root.join(format!(".recovery-{}", plan.plan_id));
    std::os::unix::fs::symlink(&old_link, &temporary)?;
    fs::rename(&temporary, root.join("current"))?;
    File::open(root)?.sync_all()?;
    record.checkpoints.push(checkpoint(
        "recovery-activated",
        format!("restored {}", old_link.display()),
    ));
    store.update(&record)?;
    for entry in current.files {
        if !prior.files.iter().any(|old| old.path == entry.path) {
            prior.files.push(entry);
        }
    }
    let data = serde_json::to_vec_pretty(&prior).map_err(io::Error::other)?;
    if data.len() > 1024 * 1024 {
        return Err(io::Error::other("restored registry exceeds limit"));
    }
    let temporary = Path::new("/var/lib/p2kesup").join(format!(".recovery-{}", plan.plan_id));
    crate::files::publish_no_clobber(&temporary, &data, 0o644)?;
    fs::rename(&temporary, INSTALLATION_REGISTRY)?;
    File::open("/var/lib/p2kesup")?.sync_all()?;
    verify_component_versions(&previous)?;
    let old_active = record
        .previous_service_state
        .as_deref()
        .is_some_and(|s| s.starts_with("state=active;"));
    if needs_live && old_active {
        let state = observed_service_state(false)?;
        run_service(ServiceAction::Start, &state, &mut effects)?;
    }
    if prior.role == InstallationRole::Primary {
        record.post_observations.push(final_service_observation(
            record
                .previous_service_state
                .as_deref()
                .ok_or_else(|| io::Error::other("original service state missing"))?,
        )?);
    }
    record.checkpoints.push(checkpoint(
        "post-check",
        format!(
            "explicit binary fallback approved by {}",
            plan.approved_digest
        ),
    ));
    record.outcome = "failed-known".into();
    store.update(&record)
}

fn recovery_deployment_assets(
    prior: &InstallationRegistry,
    previous: &super::model::ReleaseSelection,
    target: &super::model::ReleaseSelection,
) -> io::Result<Vec<(ManagedFile, ManagedFile, PathBuf)>> {
    let old = previous
        .components
        .iter()
        .find(|c| c.component == "deployment")
        .ok_or_else(|| io::Error::other("original deployment missing"))?;
    let new = target
        .components
        .iter()
        .find(|c| c.component == "deployment")
        .ok_or_else(|| io::Error::other("target deployment missing"))?;
    if old.digest == new.digest && old.manifest_digest == new.manifest_digest {
        return Ok(Vec::new());
    }
    let source_path =
        Path::new("/usr/lib/pico2-kes-agent/sources").join(new.manifest_digest.to_string());
    let source =
        super::release::verify_bundle(&source_path, super::release::Admission::AttendedCandidate)?;
    let signed = source
        .selection()
        .components
        .iter()
        .find(|c| c.component == "deployment")
        .ok_or_else(|| io::Error::other("signed target deployment missing"))?;
    if signed.digest != new.digest
        || signed.entrypoint_digest != new.entrypoint_digest
        || signed.manifest_digest != new.manifest_digest
        || signed.version != new.version
        || signed.build_id != new.build_id
        || signed.source_commit != new.source_commit
    {
        return Err(io::Error::other(
            "target deployment differs from original approval",
        ));
    }
    let mut assets = Vec::new();
    for (name, destination) in [
        (
            "pico2-kes-agent-host-check",
            "/usr/libexec/pico2-kes-agent-host-check",
        ),
        (
            "pico2-kes-agentd.service",
            "/usr/lib/systemd/system/pico2-kes-agentd.service",
        ),
        (
            "70-pico2-kes-agent.rules",
            "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules",
        ),
    ] {
        let old_entry = prior
            .files
            .iter()
            .find(|e| e.path == Path::new(destination))
            .ok_or_else(|| io::Error::other("original deployment asset missing"))?
            .clone();
        let artifact_path = format!("deploy/{name}");
        let artifact = source
            .manifest()
            .artifacts
            .iter()
            .find(|a| a.path == artifact_path)
            .ok_or_else(|| io::Error::other("signed target deployment asset missing"))?;
        let mut new_entry = old_entry.clone();
        new_entry.digest = Digest32::parse_hex(&artifact.sha256)
            .map_err(|_| io::Error::other("invalid signed deployment digest"))?;
        new_entry.mode = artifact.mode;
        let old_source = Path::new("/usr/lib/pico2-kes-agent/components/deployment")
            .join(old.digest.to_string())
            .join(name);
        let mut old_source_entry = old_entry.clone();
        old_source_entry.path = old_source.clone();
        trusted_ancestry(&old_source)?;
        check_owned_file(&old_source, Some(&old_source_entry))?;
        trusted_ancestry(&old_entry.path)?;
        if check_owned_file(&old_entry.path, Some(&old_entry)).is_err()
            && check_owned_file(&new_entry.path, Some(&new_entry)).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "deployment asset {} is neither original nor signed target",
                    old_entry.path.display()
                ),
            ));
        }
        assets.push((old_entry, new_entry, old_source));
    }
    Ok(assets)
}

fn restore_recovery_deployment(
    assets: &[(ManagedFile, ManagedFile, PathBuf)],
    plan: &HostPlan,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
) -> io::Result<()> {
    for (old, new, source) in assets {
        if check_owned_file(&old.path, Some(old)).is_ok() {
            continue;
        }
        check_owned_file(&new.path, Some(new))?;
        record.checkpoints.push(checkpoint(
            "recovery-deployment-restoring",
            format!("{}; approval {}", old.path.display(), plan.approved_digest),
        ));
        store.update(record)?;
        let temp = old.path.with_file_name(format!(
            ".p2kesup-recovery-{}-{}",
            plan.plan_id,
            old.path.file_name().unwrap().to_string_lossy()
        ));
        write_immutable(source, &temp, old.mode)?;
        let mut temp_entry = old.clone();
        temp_entry.path = temp.clone();
        check_owned_file(&temp, Some(&temp_entry))?;
        check_owned_file(&new.path, Some(new))?;
        fs::rename(&temp, &old.path)?;
        File::open(old.path.parent().unwrap())?.sync_all()?;
        check_owned_file(&old.path, Some(old))?;
        record.checkpoints.push(checkpoint(
            "recovery-deployment-restored",
            old.path.display().to_string(),
        ));
        store.update(record)?;
    }
    if !systemctl(&["daemon-reload"])?.status.success() {
        return Err(io::Error::other("recovery systemd reload failed"));
    }
    record.checkpoints.push(checkpoint(
        "recovery-systemd-reload",
        plan.approved_digest.clone(),
    ));
    store.update(record)?;
    let udev = if Path::new("/usr/bin/udevadm").exists() {
        "/usr/bin/udevadm"
    } else {
        "/usr/sbin/udevadm"
    };
    fixed_command(udev, &["control", "--reload-rules"])?;
    record.checkpoints.push(checkpoint(
        "recovery-udev-reload",
        plan.approved_digest.clone(),
    ));
    store.update(record)
}

fn service_change_allowed(active: bool, disruptive: bool, stop_approved: bool) -> bool {
    !active || !disruptive || stop_approved
}

fn start_recovery_validation(unit: &str, daemon: &Path) -> io::Result<()> {
    let program = Path::new("/usr/bin/systemd-run");
    trusted_ancestry(program)?;
    trusted_ancestry(&fs::canonicalize(program)?)?;
    let meta = fs::metadata(program)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe systemd-run"));
    }
    let status = Command::new(program)
        .env_clear()
        .args([
            "--quiet",
            "--unit",
            unit,
            "--property=Type=exec",
            "--property=RuntimeMaxSec=60",
            "--property=TimeoutStopSec=15",
            "--property=User=pico2-kes-agent",
            "--property=Group=pico2-kes-agent",
            "--property=RuntimeDirectory=pico2-kes-agent",
            "--property=RuntimeDirectoryMode=0750",
            "--property=StateDirectory=pico2-kes-agent",
            "--property=StateDirectoryMode=0700",
            "--property=UMask=0007",
            "--property=ExecStartPre=/usr/libexec/pico2-kes-agent-host-check",
            "--property=LimitCORE=0",
            "--property=LimitMEMLOCK=268435456",
            "--property=MemorySwapMax=0",
            "--property=NoNewPrivileges=yes",
            "--property=CapabilityBoundingSet=",
            "--property=AmbientCapabilities=",
            "--property=DevicePolicy=closed",
            "--property=DeviceAllow=char-usb_device rw",
            "--property=PrivateDevices=no",
            "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=ProtectHostname=yes",
            "--property=SystemCallFilter=~@clock",
            "--property=SystemCallErrorNumber=EPERM",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectKernelLogs=yes",
            "--property=ProtectControlGroups=yes",
            "--property=ProtectProc=invisible",
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=RestrictNamespaces=yes",
            "--property=SystemCallArchitectures=native",
            "--property=ProcSubset=pid",
            "--property=BindReadOnlyPaths=/proc/swaps:/run/pico2-kes-agent/host-swaps",
            "--property=Environment=PICO2_KES_PROC_SWAPS=/run/pico2-kes-agent/host-swaps",
            "--property=LockPersonality=yes",
            "--property=MemoryDenyWriteExecute=yes",
            "--property=RestrictRealtime=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=RemoveIPC=yes",
            "--property=ReadWritePaths=/run/pico2-kes-agent /var/lib/pico2-kes-agent",
            "--",
        ])
        .arg(daemon)
        .args(["--config", "/etc/pico2-kes-agent/config.json"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(
            "temporary recovery daemon failed to start",
        ));
    }
    Ok(())
}

fn recovery_validation_allowed(needs_live: bool, state: &str, temporary: bool, stop: bool) -> bool {
    !needs_live || (stop && (state == "active" || (state == "inactive" && temporary)))
}

fn deployment_restore_allowed(changed: bool, approved: bool) -> bool {
    !changed || approved
}

fn service_state_matches(expected: &str, actual: &str) -> bool {
    (expected.starts_with("state=active;") && actual == "active")
        || (expected.starts_with("state=inactive;") && actual == "inactive")
        || (expected.starts_with("state=failed;") && actual == "failed")
}

fn final_service_observation(expected: &str) -> io::Result<String> {
    let state = service_state("pico2-kes-agentd.service")?;
    if !service_state_matches(expected, &state) {
        return Err(io::Error::other(format!(
            "service state {state} does not match original state"
        )));
    }
    if state == "active" {
        let observation = authenticated_running_daemon_observation()?;
        if service_state("pico2-kes-agentd.service")? != "active" {
            return Err(io::Error::other("running daemon build not proven"));
        }
        Ok(observation)
    } else {
        Ok(format!("service state: {state}"))
    }
}

fn transfer_flushed(
    value: &serde_json::Value,
    operation_id: &str,
    serial: &str,
    image: Option<&str>,
) -> bool {
    value["schema_version"] == 1
        && value["action"] == "update"
        && value["operation_id"] == operation_id
        && value["serial"] == serial
        && image.is_some()
        && value["uf2_sha256"].as_str() == image
        && value["checkpoints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "flush-complete"))
}

#[cfg(test)]
mod update_boundary_tests {
    use super::*;

    #[test]
    fn stop_is_only_required_for_disruptive_active_update() {
        assert!(service_change_allowed(true, false, false));
        assert!(service_change_allowed(false, true, false));
        assert!(!service_change_allowed(true, true, false));
        assert!(service_change_allowed(true, true, true));
    }

    #[test]
    fn recovery_stopped_validation_requires_explicit_approval() {
        assert!(!recovery_validation_allowed(true, "inactive", false, true));
        assert!(recovery_validation_allowed(true, "inactive", true, true));
        assert!(!recovery_validation_allowed(true, "failed", true, true));
        assert!(!recovery_validation_allowed(true, "active", true, false));
        assert!(recovery_validation_allowed(false, "inactive", false, false));
    }

    #[test]
    fn update_completion_requires_original_service_state() {
        assert!(service_state_matches("state=active;pid=12", "active"));
        assert!(!service_state_matches("state=active;pid=12", "inactive"));
        assert!(service_state_matches("state=inactive;pid=0", "inactive"));
        assert!(!service_state_matches("state=inactive;pid=0", "failed"));
    }

    #[test]
    fn deployment_restore_requires_approval_for_target_bytes() {
        assert!(deployment_restore_allowed(false, false));
        assert!(!deployment_restore_allowed(true, false));
        assert!(deployment_restore_allowed(true, true));
    }

    #[test]
    fn recovery_requires_exact_original_durable_flush() {
        let mut record = serde_json::json!({"schema_version":1,"action":"update","operation_id":"op","serial":"serial","uf2_sha256":"hash","checkpoints":["transfer-complete"]});
        assert!(!transfer_flushed(&record, "op", "serial", Some("hash")));
        record["checkpoints"] = serde_json::json!(["transfer-complete", "flush-complete"]);
        assert!(transfer_flushed(&record, "op", "serial", Some("hash")));
        assert!(!transfer_flushed(&record, "other", "serial", Some("hash")));
        assert!(!transfer_flushed(&record, "op", "serial", None));
    }

    #[test]
    fn component_inventory_paths_preserve_ownership_boundaries() {
        assert_eq!(
            component_artifact("bin/p2kesup"),
            Some(("manager", "p2kesup".into()))
        );
        assert_eq!(
            component_artifact("runtime/libusb.so"),
            Some(("tool", "runtime/libusb.so".into()))
        );
        assert_eq!(
            component_artifact("deploy/install.sh"),
            Some(("deployment", "install.sh".into()))
        );
        assert_eq!(component_artifact("bin/unknown"), None);
        assert_eq!(component_artifact("distribution.json"), None);
    }
}
#[cfg(test)]
mod runtime_directory_tests {
    use super::*;

    #[test]
    fn stopped_or_rebooted_runtime_is_recreated_without_adopting_external_state() {
        let base =
            std::env::temp_dir().join(format!("p2kesup-runtime-test-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let path = base.join("runtime");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let mut effects = false;
        assert!(ensure_runtime_at(&path, uid, gid, &mut effects).unwrap());
        assert!(!ensure_runtime_at(&path, uid, gid, &mut effects).unwrap());
        fs::remove_dir(&path).unwrap();
        assert!(ensure_runtime_at(&path, uid, gid, &mut effects).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_runtime_at(&path, uid, gid, &mut effects).is_err());
        fs::remove_dir(&path).unwrap();
        fs::remove_dir(&base).unwrap();
    }
}
#[cfg(test)]
mod recovery_scope_tests {
    use super::*;

    #[test]
    fn unresolved_transfer_allows_only_exact_original_observation_work() {
        let id = "a".repeat(32);
        let action = HostAction::CommissionService {
            start: true,
            expected_state: "reviewed".into(),
            recovery_operation: Some(id.clone()),
        };
        assert!(recovery_scope_permits(&action, &id));
        assert!(!recovery_scope_permits(&action, &"b".repeat(32)));
        assert!(!recovery_scope_permits(
            &HostAction::Service {
                operation: ServiceAction::Start,
                expected_state: "reviewed".into()
            },
            &id
        ));
        let normal = HostAction::Config {
            candidate: "/tmp/input".into(),
            candidate_digest: "b".repeat(64),
            expected_current_digest: None,
            commissioning: false,
            inputs: Vec::new(),
            recovery_operation: Some(id.clone()),
        };
        assert!(!recovery_scope_permits(&normal, &id));
        assert!(HostPlan::new(normal).unwrap().validate().is_err());
        assert!(recovery_scope_permits(
            &HostAction::ReconcileFirstInstall {
                operation_id: id.clone(),
                serial: "0123456789abcdef".into(),
                expected_service_state: "reviewed".into()
            },
            &id
        ));
    }
}
#[cfg(test)]
mod first_install_postcheck_tests {
    use super::*;

    #[test]
    fn original_transfer_needs_matching_blank_postcheck_before_commissioning() {
        let digest = "a".repeat(64);
        let unrelated = vec![checkpoint("staged-authenticated", digest.clone())];
        assert!(!matching_blank_postcheck(
            &unrelated,
            "0123456789abcdef",
            &digest
        ));
        let report = serde_json::json!({"serial":"0123456789abcdef", "manifest_digest":digest});
        let checkpoints = vec![checkpoint("application-blank-attended", report.to_string())];
        assert!(matching_blank_postcheck(
            &checkpoints,
            "0123456789abcdef",
            &"a".repeat(64)
        ));
        assert!(!matching_blank_postcheck(
            &checkpoints,
            "ffffffffffffffff",
            &"a".repeat(64)
        ));
        assert!(!matching_blank_postcheck(
            &checkpoints,
            "0123456789abcdef",
            &"b".repeat(64)
        ));
    }
}

fn resolved_service_outcome(started: bool, state: &str) -> Option<&'static str> {
    match state {
        "active" if started => Some("completed"),
        "inactive" if !started => Some("completed"),
        "active" | "inactive" | "failed" => Some("failed-known"),
        _ => None,
    }
}

fn host_reconcile_observation(action: &HostAction) -> io::Result<(String, &'static str)> {
    fn field<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
        token.split(';').find_map(|part| part.strip_prefix(prefix))
    }
    match action {
        HostAction::Service {
            operation,
            expected_state,
        } => {
            let token = observed_service_state(false)?;
            let state = token
                .split(';')
                .next()
                .and_then(|s| s.strip_prefix("state="))
                .ok_or_else(|| io::Error::other("service state unavailable"))?;
            if state == "active" {
                authenticated_running_daemon_observation()?;
            }
            if ["registry=", "unit="].iter().any(|prefix| {
                field(expected_state, prefix).is_none()
                    || field(expected_state, prefix) != field(&token, prefix)
            }) {
                return Err(io::Error::other(
                    "original service ownership changed; outcome remains unresolved",
                ));
            }
            let mut outcome = resolved_service_outcome(*operation != ServiceAction::Stop, state)
                .ok_or_else(|| io::Error::other("service transition remains unresolved"))?;
            if *operation == ServiceAction::Restart && outcome == "completed" {
                outcome = resolved_restart_invocation(
                    field(expected_state, "invocation="),
                    field(&token, "invocation="),
                )
                .ok_or_else(|| {
                    io::Error::other(
                        "original restart invocation is unavailable; restart remains unproven",
                    )
                })?;
                return Ok((
                    format!(
                        "{token};restart readback compares systemd invocation identity, not the cause of any observed transition"
                    ),
                    outcome,
                ));
            }
            Ok((token, outcome))
        }
        HostAction::CommissionService { start, .. } => {
            let token = observed_service_state(true)?;
            let state = token
                .split(';')
                .next()
                .and_then(|s| s.strip_prefix("state="))
                .ok_or_else(|| io::Error::other("restricted service state unavailable"))?;
            if state == "active" {
                restricted_daemon_identity()?;
            }
            let mut outcome = resolved_service_outcome(*start, state).ok_or_else(|| {
                io::Error::other("restricted service transition remains unresolved")
            })?;
            if !start {
                match fs::symlink_metadata("/run/systemd/system/pico2-kes-agent-commission.service")
                {
                    Ok(_) => {
                        verify_commissioning_file(&commissioning_unit()?)?;
                        outcome = "failed-known";
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            Ok((token, outcome))
        }
        HostAction::Config {
            candidate_digest,
            expected_current_digest,
            commissioning,
            inputs,
            ..
        } => {
            let current = super::setup::current_config_review()?.map(|(digest, _)| digest);
            let observation = configuration_recovery_observation()?;
            if current.as_deref() == Some(candidate_digest) {
                let metadata = fs::symlink_metadata("/etc/pico2-kes-agent/config.json")?;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "configuration ownership is unresolved",
                    ));
                }
                let validation = super::setup::verify_public_inputs(inputs).and_then(|()| {
                    check_configuration_as_service(
                        Path::new("/etc/pico2-kes-agent/config.json"),
                        *commissioning,
                    )
                });
                match validation {
                    Ok(()) => Ok((
                        format!(
                            "{observation}; service-identity validation passed; restart not implied"
                        ),
                        "completed",
                    )),
                    Err(error) => Ok((
                        format!(
                            "{observation}; validation failed: {error}; working bytes were not changed by reconciliation"
                        ),
                        "failed-known",
                    )),
                }
            } else if &current == expected_current_digest {
                Ok((
                    format!("{observation}; original replacement not observed"),
                    "failed-known",
                ))
            } else {
                Err(io::Error::other(
                    "configuration differs from both reviewed original and candidate; retain uncertainty",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "this action needs its dedicated original-operation recovery",
        )),
    }
}

fn reconcile_host_operation(plan: &HostPlan, store: &RecordStore) -> io::Result<()> {
    let HostAction::HostReconcile {
        operation_id,
        original_plan_digest,
    } = &plan.action
    else {
        return Err(io::Error::other("not a host reconciliation"));
    };
    check_other_pending_records(store, &plan.action)?;
    let id = OperationId::parse_hex(operation_id)
        .map_err(|_| io::Error::other("invalid original operation"))?;
    let mut record = store.load(&id)?.supported()?;
    if record.plan_digest.to_string() != *original_plan_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original plan digest differs",
        ));
    }
    let original: HostAction = serde_json::from_str(
        record
            .approved_scope
            .first()
            .ok_or_else(|| io::Error::other("original approved scope missing"))?,
    )
    .map_err(io::Error::other)?;
    let observed = host_reconcile_observation(&original)?;
    let digest = format!(
        "{:x}",
        Sha256::digest(format!(
            "{operation_id};{original_plan_digest};{};{}",
            observed.0, observed.1
        ))
    );
    println!(
        "Original operation {operation_id}; prior outcome {}",
        record.outcome.escape_default()
    );
    println!("Current public evidence: {}", observed.0.escape_default());
    println!(
        "Reconciliation outcome: {}; no service command or configuration replacement is performed.",
        observed.1
    );
    print!("Type {digest} to accept this readback and retain the original history: ");
    io::stdout().flush()?;
    let answer = read_confirmation(io::stdin().lock())?;
    if answer.trim() != digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "readback not approved",
        ));
    }
    if host_reconcile_observation(&original)? != observed {
        return Err(io::Error::other(
            "host state changed during reconciliation review",
        ));
    }
    record.checkpoints.push(checkpoint(
        "original-host-reconciliation",
        format!(
            "approval {}; previous outcome {}; current {}",
            plan.approved_digest, record.outcome, observed.0
        ),
    ));
    record.post_observations.push(observed.0);
    record.outcome = observed.1.into();
    store.update(&record)
}

fn recover_provisioning(plan: &HostPlan, store: &RecordStore) -> io::Result<()> {
    let HostAction::Provisioning { request } = &plan.action else {
        return Err(io::Error::other("not provisioning recovery"));
    };
    let id = OperationId::parse_hex(
        request
            .original_operation
            .as_deref()
            .ok_or_else(|| io::Error::other("original provisioning operation required"))?,
    )
    .map_err(|_| io::Error::other("invalid original provisioning operation"))?;
    check_other_pending_records(store, &plan.action)?;
    let mut original = store.load(&id)?.supported()?;
    if !super::provisioning::recovery_matches(request, &original)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provisioning recovery does not match original evidence",
        ));
    }
    let prior = original.outcome.clone();
    original.checkpoints.push(checkpoint(
        "recovery-approval",
        plan.approved_digest.clone(),
    ));
    store.update(&original)?;
    match super::provisioning::apply(request, store, &mut original) {
        Ok(evidence) => {
            println!("{}", evidence.escape_default());
            original.post_observations.push(evidence);
            original.outcome = if request.action == super::provisioning::Action::Resume {
                "completed".into()
            } else {
                prior
            };
            store.update(&original)
        }
        Err(error) => {
            original.post_observations.push(error.to_string());
            original.outcome = "uncertain".into();
            store.update(&original)?;
            Err(error)
        }
    }
}

fn original_recovery_permits(action: &HostAction, record: &MaintenanceRecord) -> io::Result<bool> {
    Ok(match action {
        HostAction::UpgradeRecovery { operation_id, original_plan_digest, .. } => {
            record.action == "upgrade" && record.operation_id.to_string() == *operation_id
                && record.plan_digest.to_string() == *original_plan_digest
        }
        HostAction::HostReconcile {
            operation_id,
            original_plan_digest,
        } => {
            matches!(
                record.action.as_str(),
                "service" | "commission_service" | "config"
            ) && record.operation_id.to_string() == *operation_id
                && record.plan_digest.to_string() == *original_plan_digest
        }
        HostAction::ProducerRecovery {
            operation_id,
            original_plan_digest,
            ..
        } => {
            record.action == "producer-hardening"
                && record.operation_id.to_string() == *operation_id
                && record.plan_digest.to_string() == *original_plan_digest
        }
        HostAction::UninstallRecovery {
            operation_id,
            original_plan_digest,
            ..
        } => {
            record.action == "uninstall"
                && record.operation_id.to_string() == *operation_id
                && record.plan_digest.to_string() == *original_plan_digest
        }
        HostAction::Provisioning { request } => {
            super::provisioning::recovery_matches(request, record)?
        }
        _ => false,
    })
}

#[test]
fn service_readback_resolves_failed_start_without_claiming_health() {
    assert_eq!(
        resolved_service_outcome(true, "failed"),
        Some("failed-known")
    );
    assert_eq!(
        resolved_service_outcome(false, "inactive"),
        Some("completed")
    );
    assert_eq!(
        resolved_service_outcome(false, "active"),
        Some("failed-known")
    );
    assert_eq!(resolved_service_outcome(true, "activating"), None);
    assert_eq!(resolved_service_outcome(false, "unknown"), None);
}

#[test]
fn privileged_confirmation_stops_at_a_bounded_line() {
    let mut input = io::Cursor::new(b"approved\nunconsumed");
    assert_eq!(read_confirmation(&mut input).unwrap(), "approved\n");
    assert_eq!(input.position(), 9);
    let mut long = io::Cursor::new(vec![b'a'; 10_000]);
    assert_eq!(
        read_confirmation(&mut long).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(long.position(), 257);
    assert!(read_confirmation(io::Cursor::new([0xff, b'\n'])).is_err());
}

#[test]
fn group_lookup_distinguishes_absence_from_failure() {
    for rc in [0, libc::ENOENT, libc::ESRCH] {
        assert_eq!(group_lookup_result(rc, None).unwrap(), None);
    }
    assert_eq!(group_lookup_result(0, Some(0)).unwrap(), Some(0));
    assert_eq!(group_lookup_result(0, Some(989)).unwrap(), Some(989));
    for rc in [
        libc::EACCES, libc::EPERM, libc::EIO, libc::EMFILE,
        libc::ENOMEM, libc::ERANGE, libc::EAGAIN,
    ] {
        assert_eq!(group_lookup_result(rc, None).unwrap_err().raw_os_error(), Some(rc));
    }
    assert_eq!(
        group_lookup_result(libc::ENOENT, Some(989)).unwrap_err().raw_os_error(),
        Some(libc::ENOENT),
    );
}

fn resolved_restart_invocation(before: Option<&str>, after: Option<&str>) -> Option<&'static str> {
    let (Some(before), Some(after)) = (before, after) else {
        return None;
    };
    if after.is_empty() {
        None
    } else if before == after {
        Some("failed-known")
    } else {
        Some("completed")
    }
}

#[test]
fn active_unchanged_invocation_does_not_prove_restart() {
    assert_eq!(
        resolved_restart_invocation(Some("original"), Some("original")),
        Some("failed-known")
    );
    assert_eq!(
        resolved_restart_invocation(Some("original"), Some("new")),
        Some("completed")
    );
    assert_eq!(resolved_restart_invocation(None, Some("new")), None);
    assert_eq!(
        resolved_restart_invocation(Some("original"), Some("")),
        None
    );
}
