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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisImport {
    pub source: PublicInput,
    pub dest: PathBuf,
}

pub fn valid_genesis_destination(path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix("/etc/pico2-kes-agent/genesis") else {
        return false;
    };
    let parts: Vec<_> = relative.components().collect();
    parts.len() == 2
        && parts
            .iter()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
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
    review_config_with_imports(path, mode, &[])
}

pub fn review_config_with_imports(
    path: &Path,
    mode: RunMode,
    imports: &[GenesisImport],
) -> io::Result<ConfigReview> {
    let bytes = read_config(path)?;
    let mut validation_config: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if validation_config.get("networks").is_none() && imports.is_empty() {
        validation_config["networks"] = serde_json::json!({});
    }
    let networks = validation_config["networks"]
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing explicit networks"))?;
    for import in imports {
        if !valid_genesis_destination(&import.dest)
            || review_public_input(&import.source.path)? != import.source
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid genesis import",
            ));
        }
        let mut used = false;
        for network in networks.values_mut() {
            for field in ["byron_genesis_file", "shelley_genesis_file"] {
                if network[field].as_str().map(Path::new) == Some(import.dest.as_path()) {
                    network[field] = import.source.path.to_string_lossy().into_owned().into();
                    used = true;
                }
            }
        }
        if !used {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unused genesis import",
            ));
        }
    }
    let validation_bytes = serde_json::to_vec(&validation_config).map_err(io::Error::other)?;
    Config::inspect_bytes(&validation_bytes, mode).map_err(io::Error::other)?;
    let validation =
        "public configuration validated; root helper must validate runtime ownership and permissions as the service user before replacement"
            .to_owned();
    if read_config(path)? != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration changed during review",
        ));
    }
    let digest = Sha256::digest(&bytes);
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
    let inputs = config_inputs_with_imports(&bytes, imports)?;
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
    (inputs, imports): (&[PublicInput], &[GenesisImport]),
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
    if config_inputs_with_imports(&bytes, imports)? != inputs {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "public genesis inputs changed after review",
        ));
    }
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
    import_genesis(imports, effects)?;
    if config_inputs(&bytes)? != inputs {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "imported genesis differs from reviewed input",
        ));
    }
    super::host::validate_service_input_visibility(inputs)?;
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
                let completed_host_action = record.outcome == "completed"
                    && matches!(
                        record.action.as_str(),
                        "install" | "config" | "service" | "commission_service"
                    );
                let no_write_factory = record.action == "firmware_transfer"
                    && matches!(record.outcome.as_str(), "failed-known" | "cancelled")
                    && super::host::maintenance_record_is_resolved(&record)?;
                if record.schema_version != 1
                    || entry.file_name() != format!("{}.json", record.operation_id).as_str()
                    || !(completed_host_action
                        || no_write_factory
                        || super::host::precommission_install_recovered(&record))
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

fn config_inputs_with_imports(
    bytes: &[u8],
    imports: &[GenesisImport],
) -> io::Result<Vec<PublicInput>> {
    let config: serde_json::Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if config.get("networks").is_none() && imports.is_empty() {
        return Ok(Vec::new());
    }
    let networks = config["networks"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing explicit networks"))?;
    let mut paths = std::collections::BTreeSet::new();
    for network in networks.values() {
        for field in ["byron_genesis_file", "shelley_genesis_file"] {
            paths.insert(PathBuf::from(network[field].as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing explicit genesis path")
            })?));
        }
    }
    if imports
        .iter()
        .any(|i| !valid_genesis_destination(&i.dest) || !paths.contains(&i.dest))
        || imports
            .iter()
            .enumerate()
            .any(|(n, i)| imports[..n].iter().any(|j| j.dest == i.dest))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid or duplicate genesis import",
        ));
    }
    paths
        .iter()
        .map(|path| match imports.iter().find(|i| &i.dest == path) {
            Some(i) => {
                if review_public_input(&i.source.path)? != i.source {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "genesis source changed",
                    ));
                }
                Ok(PublicInput {
                    path: path.clone(),
                    sha256: i.source.sha256.clone(),
                })
            }
            None => review_public_input(path),
        })
        .collect()
}

fn import_genesis(imports: &[GenesisImport], effects: &mut bool) -> io::Result<()> {
    for import in imports {
        if !valid_genesis_destination(&import.dest)
            || review_public_input(&import.source.path)? != import.source
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid genesis import",
            ));
        }
        let root = Path::new("/etc/pico2-kes-agent/genesis");
        super::host::root_directory(root, 0o755)?;
        let dir = import.dest.parent().unwrap();
        super::host::root_directory(dir, 0o755)?;
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&import.source.path)?;
        let mut bytes = Vec::new();
        source.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 * 1024 || hash(&bytes) != import.source.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "genesis source changed during import",
            ));
        }
        *effects = true;
        match crate::files::publish_no_clobber(&import.dest, &bytes, 0o644) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(&import.dest)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o644
            || metadata.nlink() != 1
            || review_public_input(&import.dest)?.sha256 != import.source.sha256
            || review_public_input(&import.source.path)? != import.source
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "genesis destination or source differs from review",
            ));
        }
    }
    Ok(())
}

fn config_inputs(bytes: &[u8]) -> io::Result<Vec<PublicInput>> {
    config_inputs_with_imports(bytes, &[])
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

#[cfg(test)]
mod genesis_import_tests {
    use super::*;

    #[test]
    fn import_destination_is_confined_to_network_directory() {
        assert!(valid_genesis_destination(Path::new(
            "/etc/pico2-kes-agent/genesis/preprod/byron.json"
        )));
        for path in [
            "/etc/pico2-kes-agent/genesis/byron.json",
            "/etc/pico2-kes-agent/genesis/../config.json",
            "/tmp/preprod/byron.json",
            "/etc/pico2-kes-agent/genesis/net/sub/file.json",
        ] {
            assert!(!valid_genesis_destination(Path::new(path)));
        }
    }

    #[test]
    fn import_inputs_bind_source_digest_and_destination() {
        let source =
            std::env::temp_dir().join(format!("p2kesup-genesis-test-{}", std::process::id()));
        fs::write(&source, b"original").unwrap();
        let dest = PathBuf::from("/etc/pico2-kes-agent/genesis/test/byron.json");
        let import = GenesisImport {
            source: review_public_input(&source).unwrap(),
            dest: dest.clone(),
        };
        let config = serde_json::to_vec(&serde_json::json!({"networks":{"test":{"byron_genesis_file":dest,"shelley_genesis_file":dest}}})).unwrap();
        let inputs = config_inputs_with_imports(&config, std::slice::from_ref(&import)).unwrap();
        assert_eq!(inputs[0].sha256, import.source.sha256);
        fs::write(&source, b"changed").unwrap();
        assert!(config_inputs_with_imports(&config, std::slice::from_ref(&import)).is_err());
        fs::remove_file(source).unwrap();
    }
}
