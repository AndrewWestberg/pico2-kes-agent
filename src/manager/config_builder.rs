//! Guided builders for commissioning, normal, and pool-binding daemon configurations.
//! Never connects to or inspects a Cardano node; all genesis inputs are static operator-supplied files.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::workspace::{self, WorkspaceKind};

const MAX_DEVICE_JSON_BYTES: u64 = 64 * 1024;
const MAX_GENESIS_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_CONTEXT_AGE_MS: u64 = 30_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommissionedDevice {
    pub device_id: String,
    pub identity_public_key: String,
    pub usb_serial: String,
}

#[derive(Clone, Debug)]
pub struct CommissioningSpec {
    pub usb_serial: String,
    pub socket_directory: PathBuf,
    pub socket_group: String,
    pub management_socket: PathBuf,
    pub state_directory: PathBuf,
}

impl Default for CommissioningSpec {
    fn default() -> Self {
        Self {
            usb_serial: candidate_usb_serial().unwrap_or_default(),
            socket_directory: PathBuf::from("/run/pico2-kes-agent"),
            socket_group: "pico2-kes-agent".into(),
            management_socket: PathBuf::from("/run/pico2-kes-agent/management.sock"),
            state_directory: PathBuf::from("/var/lib/pico2-kes-agent"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NormalConfigSpec {
    pub device_id: String,
    pub identity_public_key: String,
    pub usb_serial: String,
    pub socket_directory: PathBuf,
    pub socket_group: String,
    pub management_socket: PathBuf,
    pub state_directory: PathBuf,
    pub network_name: String,
    pub byron_genesis_file: PathBuf,
    pub shelley_genesis_file: PathBuf,
    pub byron_to_shelley_epochs: u64,
    pub max_context_age_ms: u64,
}

/// Reads sysfs USB serial when exactly one Pico 2 application (`1209:4b45`) is connected.
/// Public convenience hint only; never treated as an authenticated device pin.
pub fn candidate_usb_serial() -> Option<String> {
    let entries = fs::read_dir("/sys/bus/usb/devices").ok()?;
    let mut found: Option<String> = None;
    for (index, entry) in entries.enumerate() {
        if index >= 1024 {
            return None;
        }
        let path = entry.ok()?.path();
        let vendor = read_small_trimmed(&path.join("idVendor"), 16)?;
        if vendor != "1209" {
            continue;
        }
        let product = read_small_trimmed(&path.join("idProduct"), 16)?;
        if product != "4b45" {
            continue;
        }
        let serial = read_small_trimmed(&path.join("serial"), 64)?;
        if serial.len() == 16 && serial.is_ascii() {
            if found.is_some() {
                return None;
            }
            found = Some(serial);
        }
    }
    found
}

fn read_small_trimmed(path: &Path, limit: u64) -> Option<String> {
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(limit + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > limit {
        return None;
    }
    Some(text.trim().to_owned())
}

fn read_bounded_regular(path: &Path, max_bytes: u64, label: &'static str) -> io::Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} path must be absolute"),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be a regular file"),
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} exceeds size limit"),
        ));
    }
    Ok(bytes)
}

pub fn parse_commissioned_device(path: &Path) -> io::Result<CommissionedDevice> {
    let bytes = read_bounded_regular(path, MAX_DEVICE_JSON_BYTES, "commissioned device record")?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid commissioned device JSON: {error}"),
        )
    })?;
    let field = |name: &'static str| -> io::Result<String> {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("commissioned device JSON missing {name}"),
                )
            })
    };
    Ok(CommissionedDevice {
        device_id: field("device_id")?,
        identity_public_key: field("identity_public_key")?,
        usb_serial: field("usb_serial")?,
    })
}

pub fn latest_commissioned_device_path() -> Option<PathBuf> {
    let files = workspace::list_files(WorkspaceKind::Exports).ok()?;
    files.into_iter().find(|path| {
        path.extension().and_then(|e| e.to_str()) == Some("json")
            && parse_commissioned_device(path).is_ok()
    })
}

pub fn suggested_transition_epochs(network_name: &str) -> u64 {
    match network_name.trim() {
        "mainnet" => 208,
        "preprod" => 4,
        "preview" => 0,
        _ => 0,
    }
}

pub fn compute_shelley_digest(path: &Path) -> io::Result<String> {
    let bytes = read_bounded_regular(path, MAX_GENESIS_BYTES, "Shelley genesis file")?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub fn build_commissioning_bytes(spec: &CommissioningSpec) -> io::Result<Vec<u8>> {
    if spec.usb_serial.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device.usb_serial must be 16 characters",
        ));
    }
    let config = json!({
        "version": 1,
        "device": {
            "usb_serial": spec.usb_serial,
        },
        "socket_directory": spec.socket_directory,
        "socket_group": spec.socket_group,
        "socket_mode": "0660",
        "management_socket": spec.management_socket,
        "state_directory": spec.state_directory,
        "networks": {},
        "pools": [],
    });
    let mut bytes = serde_json::to_vec_pretty(&config).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn build_normal_bytes(spec: &NormalConfigSpec, existing: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let _ = read_bounded_regular(
        &spec.byron_genesis_file,
        MAX_GENESIS_BYTES,
        "Byron genesis file",
    )?;
    let genesis_digest = compute_shelley_digest(&spec.shelley_genesis_file)?;

    let mut networks = Map::new();
    let mut pools = Vec::new();
    if let Some(raw) = existing
        && let Ok(Value::Object(prev)) = serde_json::from_slice::<Value>(raw)
    {
        if let Some(Value::Object(prev_nets)) = prev.get("networks") {
            networks = prev_nets.clone();
        }
        if let Some(Value::Array(prev_pools)) = prev.get("pools") {
            pools = prev_pools.clone();
        }
    }

    networks.insert(
        spec.network_name.clone(),
        json!({
            "byron_genesis_file": spec.byron_genesis_file,
            "shelley_genesis_file": spec.shelley_genesis_file,
            "byron_to_shelley_epochs": spec.byron_to_shelley_epochs,
            "genesis_digest": genesis_digest,
            "max_context_age_ms": spec.max_context_age_ms,
        }),
    );

    let config = json!({
        "version": 1,
        "device": {
            "id": spec.device_id,
            "identity_public_key": spec.identity_public_key,
            "usb_serial": spec.usb_serial,
        },
        "socket_directory": spec.socket_directory,
        "socket_group": spec.socket_group,
        "socket_mode": "0660",
        "management_socket": spec.management_socket,
        "state_directory": spec.state_directory,
        "networks": Value::Object(networks),
        "pools": Value::Array(pools),
    });
    let mut bytes = serde_json::to_vec_pretty(&config).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn configured_networks(config_bytes: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<Value>(config_bytes) else {
        return Vec::new();
    };
    let Some(networks) = value.get("networks").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut names: Vec<String> = networks.keys().cloned().collect();
    names.sort();
    names
}

pub fn default_pool_socket_path(config_bytes: &[u8], pool_id: &str) -> PathBuf {
    let base = serde_json::from_slice::<Value>(config_bytes)
        .ok()
        .and_then(|v| {
            v.get("socket_directory")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("/run/pico2-kes-agent"));
    base.join(format!("{pool_id}.sock"))
}

pub fn bind_pool_bytes(
    current_bytes: &[u8],
    pool_id: &str,
    incarnation_id: &str,
    network: &str,
    socket_path: &Path,
) -> io::Result<Vec<u8>> {
    let mut root: Value = serde_json::from_slice(current_bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("working configuration is not valid JSON: {error}"),
        )
    })?;
    let obj = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration must be a JSON object",
        )
    })?;
    let has_network = obj
        .get("networks")
        .and_then(Value::as_object)
        .is_some_and(|nets| nets.contains_key(network));
    if !has_network {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("network '{network}' is not defined in configuration"),
        ));
    }
    let entry = json!({
        "pool_id": pool_id,
        "incarnation_id": incarnation_id,
        "socket_path": socket_path,
        "network": network,
    });
    let pools = obj
        .entry("pools")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pools must be a JSON array"))?;

    if let Some(existing) = pools
        .iter_mut()
        .find(|item| item.get("pool_id").and_then(Value::as_str) == Some(pool_id))
    {
        *existing = entry;
    } else {
        if pools.len() >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configuration already contains the maximum of 64 pools",
            ));
        }
        pools.push(entry);
    }
    let mut bytes = serde_json::to_vec_pretty(&root).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn publish_candidate(stem: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let path = workspace::next_path(WorkspaceKind::Candidates, stem, "json")?;
    crate::files::publish_no_clobber(&path, bytes, 0o600)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RunMode};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn builds_valid_commissioning_and_bound_normal_configs() {
        let dir = std::env::temp_dir().join(format!("p2kesup-cfg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let sock_dir = dir.join("sockets");
        let state_dir = dir.join("state");
        fs::create_dir_all(&sock_dir).unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let group_name = current_group_name();
        let comm_bytes = build_commissioning_bytes(&CommissioningSpec {
            usb_serial: "0123456789abcdef".into(),
            socket_directory: sock_dir.clone(),
            socket_group: group_name.clone(),
            management_socket: sock_dir.join("management.sock"),
            state_directory: state_dir.clone(),
        })
        .unwrap();
        Config::from_bytes(&comm_bytes, RunMode::Commissioning).unwrap();

        let byron = dir.join("byron.json");
        let shelley = dir.join("shelley.json");
        fs::write(
            &byron,
            br#"{"startTime":1506203091,"protocolConsts":{"k":2160,"protocolMagic":764824073},"blockVersionData":{"slotDuration":"20000"}}"#,
        )
        .unwrap();
        fs::write(
            &shelley,
            br#"{"networkMagic":764824073,"slotLength":1,"slotsPerKESPeriod":129600,"maxKESEvolutions":62}"#,
        )
        .unwrap();

        let dev_file = dir.join("device.json");
        fs::write(
            &dev_file,
            serde_json::to_vec(&json!({
                "kind": "commissioned",
                "device_id": "11".repeat(16),
                "identity_public_key": "22".repeat(32),
                "usb_serial": "0123456789abcdef",
            }))
            .unwrap(),
        )
        .unwrap();
        let parsed = parse_commissioned_device(&dev_file).unwrap();
        assert_eq!(parsed.usb_serial, "0123456789abcdef");

        let normal_bytes = build_normal_bytes(
            &NormalConfigSpec {
                device_id: parsed.device_id,
                identity_public_key: parsed.identity_public_key,
                usb_serial: parsed.usb_serial,
                socket_directory: sock_dir.clone(),
                socket_group: group_name,
                management_socket: sock_dir.join("management.sock"),
                state_directory: state_dir,
                network_name: "mainnet".into(),
                byron_genesis_file: byron,
                shelley_genesis_file: shelley,
                byron_to_shelley_epochs: 208,
                max_context_age_ms: DEFAULT_MAX_CONTEXT_AGE_MS,
            },
            None,
        )
        .unwrap();
        Config::from_bytes(&normal_bytes, RunMode::Normal).unwrap();

        let pool_id = "aa".repeat(28);
        let inc_id = "bb".repeat(16);
        let sock_path = default_pool_socket_path(&normal_bytes, &pool_id);
        let bound_bytes =
            bind_pool_bytes(&normal_bytes, &pool_id, &inc_id, "mainnet", &sock_path).unwrap();
        let validated = Config::from_bytes(&bound_bytes, RunMode::Normal).unwrap();
        assert_eq!(validated.pools.len(), 1);
        assert_eq!(configured_networks(&bound_bytes), vec!["mainnet"]);

        let _ = fs::remove_dir_all(&dir);
    }

    fn current_group_name() -> String {
        let gid = rustix::process::getegid().as_raw();
        let text = fs::read_to_string("/etc/group").unwrap_or_default();
        for line in text.lines() {
            let mut parts = line.split(':');
            if let (Some(name), Some(_), Some(id_str)) = (parts.next(), parts.next(), parts.next())
                && id_str.parse::<u32>().ok() == Some(gid)
            {
                return name.to_owned();
            }
        }
        "root".into()
    }
}
