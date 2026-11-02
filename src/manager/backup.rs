//! Isolated backup-host admission and foreground command construction.

use super::{
    host,
    lifecycle::TrustedCli,
    model::{INSTALLATION_REGISTRY, InstallationRegistry, InstallationRole, MaintenanceRecord},
    records::RecordStore,
};
use kes_core::identity::{Digest32, OperationId};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::Command,
};

const PRIMARY_PATHS: &[&str] = &[
    "/etc/pico2-kes-agent",
    "/var/lib/pico2-kes-agent",
    "/run/pico2-kes-agent",
    "/usr/lib/systemd/system/pico2-kes-agentd.service",
    "/etc/systemd/system/pico2-kes-agentd.service",
    "/run/systemd/system/pico2-kes-agentd.service",
    "/etc/systemd/system/pico2-kes-agentd.service.d",
    "/run/systemd/system/pico2-kes-agentd.service.d",
    "/usr/lib/systemd/system/pico2-kes-agent-commission.service",
    "/etc/systemd/system/pico2-kes-agent-commission.service",
    "/run/systemd/system/pico2-kes-agent-commission.service",
    "/usr/lib/systemd/system/pico2-kes-agent-commission.service.d",
    "/etc/systemd/system/pico2-kes-agent-commission.service.d",
    "/run/systemd/system/pico2-kes-agent-commission.service.d",
    "/etc/systemd/system/multi-user.target.wants/pico2-kes-agentd.service",
    "/etc/systemd/system/default.target.wants/pico2-kes-agentd.service",
];
const UNITS: &[&str] = &[
    "pico2-kes-agentd.service",
    "pico2-kes-agent-commission.service",
];

fn denied(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("backup role not admitted: {message}"),
    )
}

fn inspect(
    role: io::Result<Option<InstallationRole>>,
    mut exists: impl FnMut(&str) -> io::Result<bool>,
    mut unit_absent: impl FnMut(&str) -> io::Result<bool>,
) -> io::Result<()> {
    match role.map_err(denied)? {
        Some(InstallationRole::Primary) => return Err(denied("primary installation registry")),
        Some(InstallationRole::Backup) | None => {}
    }
    for path in PRIMARY_PATHS {
        if exists(path).map_err(denied)? {
            return Err(denied(format!("primary evidence at {path}")));
        }
    }
    for unit in UNITS {
        if !unit_absent(unit).map_err(denied)? {
            return Err(denied(format!("service {unit} is configured or active")));
        }
    }
    Ok(())
}

fn registry_role() -> io::Result<Option<InstallationRole>> {
    for parent in ["/var", "/var/lib", "/var/lib/p2kesup"] {
        match fs::symlink_metadata(parent) {
            Ok(meta) if meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0 => {}
            Ok(_) => return Err(denied("unsafe registry ancestry")),
            Err(e) if e.kind() == io::ErrorKind::NotFound && parent == "/var/lib/p2kesup" => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(INSTALLATION_REGISTRY)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 1024 * 1024
    {
        return Err(denied("unsafe installation registry"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(denied("oversized installation registry"));
    }
    let registry: InstallationRegistry =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if registry.schema_version != 1 {
        return Err(denied("unknown registry schema"));
    }
    Ok(Some(registry.role))
}

fn exists(path: &str) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn unit_absent(unit: &str) -> io::Result<bool> {
    let output = Command::new("/usr/bin/systemctl")
        .env_clear()
        .args([
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
        ])
        .output()?;
    if !output.status.success() {
        return Err(denied("systemd service state unavailable"));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(io::Error::other)?;
    let mut load = None;
    let mut active = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            if load.replace(value).is_some() {
                return Err(denied("ambiguous service state"));
            }
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            if active.replace(value).is_some() {
                return Err(denied("ambiguous service state"));
            }
        } else {
            return Err(denied("unexpected service state"));
        }
    }
    match (load, active) {
        (Some("not-found"), Some("inactive")) => Ok(true),
        (Some(_), Some(_)) => Ok(false),
        _ => Err(denied("incomplete service state")),
    }
}

fn no_running_daemon() -> io::Result<()> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let process = entry.path();
        match fs::read_link(process.join("exe")) {
            Ok(executable) => {
                if daemon_path(&executable) {
                    return Err(denied("running daemon process"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn daemon_path(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_bytes().starts_with(b"pico2-kes-agentd"))
}

/// Checks local registry, socket and systemd evidence; no runtime inspection.
pub fn admit_local(socket: &Path) -> io::Result<()> {
    if !socket.is_absolute() {
        return Err(denied("socket path is not absolute"));
    }
    let socket = socket
        .to_str()
        .ok_or_else(|| denied("socket path is not UTF-8"))?;
    if exists(socket).map_err(denied)? {
        return Err(denied("configured management socket exists"));
    }
    inspect(registry_role(), exists, unit_absent)
}

/// Root-only finite role inspection; no daemon, device or socket connection.
pub fn admit(socket: &Path) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(denied("privileged runtime inspection required"));
    }
    admit_local(socket)?;
    no_running_daemon().map_err(denied)
}

pub fn record_intent(
    action: &str,
    scope: Vec<String>,
) -> io::Result<(RecordStore, MaintenanceRecord)> {
    let store = RecordStore::open_backup()?;
    let mut id = [0; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut id)?;
    let digest = Digest32::from_bytes(
        Sha256::digest(serde_json::to_vec(&(action, &scope)).map_err(io::Error::other)?).into(),
    );
    let record = MaintenanceRecord {
        schema_version: 1,
        operation_id: OperationId::from_bytes(id),
        action: action.into(),
        plan_digest: digest,
        selected: None,
        approved_scope: scope,
        previous_service_state: None,
        pre_observations: Vec::new(),
        checkpoints: vec![host::checkpoint("intent-durable", digest.to_string())],
        post_observations: Vec::new(),
        outcome: "intent-durable".into(),
        bundle_digest: None,
        image_digest: None,
        physical_selection: None,
    };
    store.create(&record)?;
    Ok((store, record))
}

pub fn record_outcome(
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    outcome: &str,
    evidence: &str,
) -> io::Result<()> {
    record
        .checkpoints
        .push(host::checkpoint(outcome, evidence.into()));
    record.outcome = outcome.into();
    store.update(record)
}

pub enum Action {
    Create {
        private: String,
        public: String,
    },
    Restore {
        device: String,
        pool: String,
        incarnation: String,
        generation: String,
        verification_key: String,
        identity: String,
        artifact: String,
        recipient: String,
        output: String,
    },
}

impl Action {
    pub fn command(&self, cli: &TrustedCli) -> Command {
        let mut command = cli.command();
        match self {
            Self::Create { private, public } => {
                command.args([
                    "recipient",
                    "create",
                    "--out",
                    private,
                    "--public-out",
                    public,
                ]);
            }
            Self::Restore {
                device,
                pool,
                incarnation,
                generation,
                verification_key,
                identity,
                artifact,
                recipient,
                output,
            } => {
                command.args([
                    "restore",
                    "--device",
                    device,
                    "--pool",
                    pool,
                    "--incarnation",
                    incarnation,
                    "--generation",
                    generation,
                    "--verification-key",
                    verification_key,
                    "--device-identity",
                    identity,
                    "--artifact",
                    artifact,
                    "--recipient-key",
                    recipient,
                    "--out",
                    output,
                ]);
            }
        }
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primary_or_inaccessible_evidence_denies() {
        assert!(
            inspect(
                Ok(Some(InstallationRole::Primary)),
                |_| Ok(false),
                |_| Ok(true)
            )
            .is_err()
        );
        assert!(
            inspect(
                Ok(Some(InstallationRole::Backup)),
                |_| Ok(true),
                |_| Ok(true)
            )
            .is_err()
        );
        assert!(inspect(Ok(None), |_| Ok(false), |_| Ok(false)).is_err());
        assert!(
            inspect(
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "registry")),
                |_| Ok(false),
                |_| Ok(true)
            )
            .is_err()
        );
        assert!(
            inspect(
                Ok(None),
                |_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "path")),
                |_| Ok(true)
            )
            .is_err()
        );
        assert!(
            inspect(
                Ok(None),
                |_| Ok(false),
                |_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "service"))
            )
            .is_err()
        );
    }
    #[test]
    fn binaries_alone_do_not_deny_isolated_host() {
        assert!(inspect(Ok(None), |_| Ok(false), |_| Ok(true)).is_ok());
        assert!(!PRIMARY_PATHS.iter().any(|p| p.starts_with("/usr/bin/")));
    }

    #[test]
    fn each_primary_evidence_path_denies_even_backup_registry() {
        for blocked in PRIMARY_PATHS {
            assert!(
                inspect(
                    Ok(Some(InstallationRole::Backup)),
                    |path| Ok(path == *blocked),
                    |_| Ok(true)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn production_admission_rejects_relative_socket() {
        assert!(admit_local(Path::new("relative-socket")).is_err());
        assert!(admit(Path::new("relative-socket")).is_err());
    }
}
