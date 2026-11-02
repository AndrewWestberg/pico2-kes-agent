//! Explicit public configuration review; host application must revalidate it.

use crate::config::{Config, RunMode};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInput {
    pub path: PathBuf,
    pub sha256: String,
}

/// Exact public input and provenance shown to the operator before approval.
#[derive(Clone, Debug)]
pub struct ConfigReview {
    pub source: PathBuf,
    pub sha256: String,
    pub bytes: Vec<u8>,
    pub validation: String,
    pub inputs: Vec<PublicInput>,
}

fn read_config(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration candidate must be a regular file",
        ));
    }
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds 1 MiB",
        ));
    }
    Ok(bytes)
}

/// Validate explicit configuration using the existing daemon parser, without
/// changing working configuration or inventing network or device inputs.
pub fn review_config(path: &Path, mode: RunMode) -> io::Result<ConfigReview> {
    let bytes = read_config(path)?;
    let validation = match Config::from_bytes(&bytes, mode) {
        Ok(_) => "validated as invoking user; service identity will revalidate before replacement"
            .to_owned(),
        Err(crate::config::Error::Invalid("directory ownership or permissions are unsafe")) => {
            "service-identity validation required; invoking user does not own daemon directories"
                .to_owned()
        }
        Err(crate::config::Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
            "service-identity validation required; invoking user lacks access".to_owned()
        }
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
    };
    if read_config(path)? != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration changed during review",
        ));
    }
    let digest = Sha256::digest(&bytes);
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
    let inputs = config_inputs(&bytes)?;
    Ok(ConfigReview {
        source: path.to_path_buf(),
        sha256,
        bytes,
        validation,
        inputs,
    })
}

pub(super) fn service_identity() -> io::Result<(u32, u32)> {
    let name = CString::new("pico2-kes-agent").unwrap();
    let mut result = std::ptr::null_mut();
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buffer = vec![0u8; 16384];
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "service account is unavailable",
        ));
    }
    Ok((entry.pw_uid, entry.pw_gid))
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read_regular(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe configuration input",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds 1 MiB",
        ));
    }
    Ok(bytes)
}

/// Called only inside the locked, approved privileged transaction.
pub(super) fn apply_configuration(
    candidate: &Path,
    digest: &str,
    previous: Option<&str>,
    commissioning: bool,
    inputs: &[PublicInput],
    effects: &mut bool,
    runtime_created: &mut bool,
) -> io::Result<()> {
    let bytes = read_regular(candidate)?;
    if hash(&bytes) != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "candidate changed after review",
        ));
    }
    if config_inputs(&bytes)? != inputs {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "public genesis inputs changed after review",
        ));
    }
    super::host::validate_service_input_visibility(inputs)?;
    let (_, gid) = service_identity()?;
    let dir = Path::new("/etc/pico2-kes-agent");
    super::host::trusted_ancestry(&dir.join("config.json"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let dm = directory.metadata()?;
    if !dm.is_dir() || dm.uid() != 0 || dm.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe configuration directory",
        ));
    }
    let target = dir.join("config.json");
    let old_meta = match fs::symlink_metadata(&target) {
        Ok(meta) => {
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || meta.nlink() != 1
                || previous != Some(hash(&read_regular(&target)?).as_str())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "working configuration changed or is unsafe",
                ));
            }
            Some(meta)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && previous.is_none() => None,
        Err(error) => return Err(error),
    };
    *runtime_created = super::host::ensure_service_runtime(effects)?;
    let name = format!(".p2kesup-candidate-{}", std::process::id());
    let temporary = dir.join(&name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let result = (|| {
        let owner = old_meta.as_ref().map_or(0, |m| m.uid());
        let group = old_meta.as_ref().map_or(gid, |m| m.gid());
        let mode = old_meta.as_ref().map_or(0o640, |m| m.mode() & 0o7777);
        if unsafe { libc::fchown(file.as_raw_fd(), owner, group) } != 0
            || unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        super::host::check_configuration_as_service(&temporary, commissioning)?;
        verify_public_inputs(inputs)?;
        if hash(&read_regular(&temporary)?) != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "candidate changed during validation",
            ));
        }
        match (&old_meta, fs::symlink_metadata(&target)) {
            (Some(old), Ok(now))
                if old.dev() == now.dev()
                    && old.ino() == now.ino()
                    && old.mode() == now.mode()
                    && old.uid() == now.uid()
                    && old.gid() == now.gid()
                    && previous == Some(hash(&read_regular(&target)?).as_str()) =>
            {
                *effects = true;
                fs::rename(&temporary, &target)?
            }
            (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                let source = CString::new(name.as_bytes()).unwrap();
                let dest = CString::new("config.json").unwrap();
                *effects = true;
                if unsafe {
                    libc::renameat2(
                        directory.as_raw_fd(),
                        source.as_ptr(),
                        directory.as_raw_fd(),
                        dest.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "working configuration changed during validation",
                ));
            }
        }
        directory.sync_all()
    })();
    if result.is_err() {
        match fs::remove_file(&temporary) {
            Ok(()) => {
                if directory.sync_all().is_err() {
                    *effects = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => *effects = true,
        }
    }
    result
}

/// Validate public blank and firmware evidence; unavailable is never blank.
pub fn validate_blank_observation(
    status: &serde_json::Value,
    info: &serde_json::Value,
    serial: &str,
    firmware: &super::release::Component,
    source_commit: &str,
    storage_versions: &[u64],
    security_profiles: &[String],
) -> io::Result<()> {
    let valid = serial.len() == 16
        && serial
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && status["commissioning_state"] == "blank"
        && status["health"] == "ready"
        && info["schema_version"] == 1
        && info
            .get("device_id")
            .is_some_and(serde_json::Value::is_null)
        && info["usb_serial"] == serial
        && info["version"] == firmware.version
        && info["build_id"] == firmware.build_id
        && info["source_commit"] == source_commit
        && info["protocol_major"] == 1
        && info["storage_version"]
            .as_u64()
            .is_some_and(|v| storage_versions.contains(&v))
        && info["security_profile"]
            .as_str()
            .is_some_and(|p| security_profiles.iter().any(|s| s == p));
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "blank device or selected firmware evidence unavailable or mismatched",
        ));
    }
    Ok(())
}

pub(super) fn observation(
    socket: &Path,
    action: &str,
    deadline: std::time::Instant,
    peer: (u32, u32),
) -> io::Result<serde_json::Value> {
    let request_id = "00000000000000000000000000000001";
    let request = serde_json::to_vec(
        &serde_json::json!({"version":1,"request_id":request_id,"action":action,"arguments":{}}),
    )
    .map_err(io::Error::other)?;
    let bytes = crate::cli::client::request_until_peer(socket, &request, deadline, peer.0, peer.1)
        .map_err(|e| e.into_io())?;
    kes_protocol::management::Message::decode(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid management response"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if value["request_id"] != request_id || value["outcome"] != "success" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "device observation unavailable",
        ));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing device observation"))
}

/// Freshly query the authenticated sole commissioning daemon before submitting
/// the original commissioning receipt.
pub(super) fn admit_commissioning_from_pid(
    socket: &Path,
    serial: &str,
    bundle: &super::release::VerifiedBundle,
    pid: u32,
    uid: u32,
) -> io::Result<()> {
    let peer = (pid, uid);
    let manifest = bundle.manifest();
    if !manifest
        .compatibility
        .usb_profiles
        .iter()
        .any(|p| p == "usb-protocol-1")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "selected tuple does not authorize the observed USB protocol",
        ));
    }
    let firmware = manifest
        .components
        .iter()
        .find(|c| c.name == "firmware")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "firmware missing from selected tuple",
            )
        })?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let before = observation(socket, "device.info", deadline, peer)?;
    let status = observation(socket, "device.status", deadline, peer)?;
    let after = observation(socket, "device.info", deadline, peer)?;
    if before != after {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "device changed during admission",
        ));
    }
    validate_blank_observation(
        &status,
        &after,
        serial,
        firmware,
        &manifest.release.source_commit,
        &manifest.compatibility.storage_versions,
        &manifest.compatibility.security_profiles,
    )
}

/// The approved config action binds absence or the exact current bytes.
pub fn current_config_review() -> io::Result<Option<(String, Vec<u8>)>> {
    match read_regular(Path::new("/etc/pico2-kes-agent/config.json")) {
        Ok(bytes) => {
            std::str::from_utf8(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            Ok(Some((hash(&bytes), bytes)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Refuse factory treatment when any local evidence establishes a prior target.
/// Inaccessible evidence is not absence; an existing record must be reopened.
pub fn admit_first_install(record: &Path) -> io::Result<()> {
    match fs::symlink_metadata(record) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "existing first-install record must be reopened, not replayed",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match read_regular(Path::new("/etc/pico2-kes-agent/config.json")) {
        Ok(bytes) => {
            let config: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            let device = config
                .get("device")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "device configuration unavailable",
                    )
                })?;
            if device.get("id").is_some_and(|v| !v.is_null())
                || device
                    .get("identity_public_key")
                    .is_some_and(|v| !v.is_null())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "existing device pin excludes factory first-install",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match fs::symlink_metadata("/var/lib/pico2-kes-agent/operations.journal") {
        Ok(meta) if meta.is_file() && meta.len() == 0 => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "existing or unsafe lifecycle journal excludes factory first-install",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let records = Path::new("/var/lib/p2kesup/records");
    super::host::trusted_ancestry(&records.join("record.json"))?;
    let records_meta = fs::symlink_metadata(records)?;
    if !records_meta.is_dir() || records_meta.uid() != 0 || records_meta.mode() & 0o7777 != 0o750 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "maintenance records are not protected",
        ));
    }
    match fs::read_dir(records) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry.file_name() == ".lock" {
                    continue;
                }
                let meta = fs::symlink_metadata(entry.path())?;
                if !meta.is_file()
                    || meta.uid() != 0
                    || meta.mode() & 0o7777 != 0o640
                    || meta.nlink() != 1
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "unsafe maintenance evidence",
                    ));
                }
                let bytes = read_regular(&entry.path())?;
                let record: super::model::MaintenanceRecord =
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                if record.schema_version != 1
                    || record.outcome != "completed"
                    || !matches!(
                        record.action.as_str(),
                        "install" | "config" | "service" | "commission_service"
                    )
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing maintenance evidence excludes factory first-install",
                    ));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Capture exact bytes of a public genesis input, never a guessed node value.
pub fn review_public_input(path: &Path) -> io::Result<PublicInput> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "genesis path must be absolute and normalized",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe or oversized genesis input",
        ));
    }
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 16384];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > metadata.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "genesis input changed",
            ));
        }
        hasher.update(&buffer[..n]);
    }
    if count != metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "genesis input changed",
        ));
    }
    Ok(PublicInput {
        path: path.to_path_buf(),
        sha256: hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

pub fn verify_public_inputs(inputs: &[PublicInput]) -> io::Result<()> {
    for input in inputs {
        if review_public_input(&input.path)? != *input {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "genesis input changed after review",
            ));
        }
    }
    Ok(())
}

fn config_inputs(bytes: &[u8]) -> io::Result<Vec<PublicInput>> {
    let config: serde_json::Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    let networks = config
        .get("networks")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing explicit networks"))?;
    let mut paths = std::collections::BTreeSet::new();
    for network in networks.values() {
        for field in ["byron_genesis_file", "shelley_genesis_file"] {
            let path = network
                .get(field)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing explicit genesis path")
                })?;
            paths.insert(PathBuf::from(path));
        }
    }
    paths.iter().map(|path| review_public_input(path)).collect()
}

/// Resolve the restricted daemon's configured socket without trusting a UI path.
pub(super) fn commissioning_socket(serial: &str) -> io::Result<PathBuf> {
    let bytes = read_regular(Path::new("/etc/pico2-kes-agent/config.json"))?;
    let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if config["version"] != 1
        || config["device"]["usb_serial"] != serial
        || !config["device"]["id"].is_null()
        || !config["device"]["identity_public_key"].is_null()
        || config["socket_mode"] != "0660"
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "installed commissioning configuration differs from the reviewed target",
        ));
    }
    configured_socket(&config)
}

fn configured_socket(config: &serde_json::Value) -> io::Result<PathBuf> {
    let directory = PathBuf::from(config["socket_directory"].as_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "socket directory unavailable")
    })?);
    let socket = PathBuf::from(config["management_socket"].as_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "management socket unavailable")
    })?);
    if !directory.is_absolute()
        || directory
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || socket.parent() != Some(directory.as_path())
        || socket.file_name().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe configured management socket",
        ));
    }
    Ok(socket)
}

pub(super) fn require_firmware_default_socket() -> io::Result<()> {
    let bytes = match read_regular(Path::new("/etc/pico2-kes-agent/config.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    require_default_socket(&config)
}

fn require_default_socket(config: &serde_json::Value) -> io::Result<()> {
    if configured_socket(config)? != Path::new("/run/pico2-kes-agent/management.sock") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firmware tool requires the default management socket",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    #[test]
    fn firmware_tool_rejects_custom_socket_in_either_mode() {
        let mut config = serde_json::json!({"socket_directory":"/run/pico2-kes-agent", "management_socket":"/run/pico2-kes-agent/management.sock", "device":{"id":null,"identity_public_key":null}});
        assert!(require_default_socket(&config).is_ok());
        config["management_socket"] = "/run/pico2-kes-agent/custom.sock".into();
        assert!(require_default_socket(&config).is_err());
        config["device"]["id"] = "11".repeat(16).into();
        config["device"]["identity_public_key"] = "22".repeat(32).into();
        assert!(require_default_socket(&config).is_err());
    }
}
