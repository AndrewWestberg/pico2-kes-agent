//! Strict version-1 daemon configuration validation.

use crate::daemon::{
    context::{EraSegment, NetworkConfig, NetworkSelector, validate_network_config},
    usb::{IdentityPin, UsbSelection},
};
use kes_core::identity::{DeviceId, Digest32, IncarnationId, NetworkBinding, PoolId};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::Duration,
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunMode {
    Normal,
    Commissioning,
}

#[derive(Clone, Debug)]
pub struct PoolBinding {
    pub pool: PoolId,
    pub incarnation: IncarnationId,
    pub socket_path: PathBuf,
    pub network: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: RunMode,
    pub pin: Option<IdentityPin>,
    pub selected_serial: UsbSelection,
    pub socket_directory: PathBuf,
    pub socket_group: String,
    pub socket_gid: u32,
    pub management_socket: PathBuf,
    pub state_directory: PathBuf,
    pub networks: HashMap<String, NetworkConfig>,
    pub pools: Vec<PoolBinding>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "configuration I/O: {error}"),
            Self::Json(error) => write!(formatter, "configuration JSON: {error}"),
            Self::Invalid(reason) => write!(formatter, "invalid configuration: {reason}"),
            Self::InvalidField { field, reason } => write!(formatter, "invalid {field}: {reason}"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u8,
    device: RawDevice,
    socket_directory: PathBuf,
    socket_group: String,
    socket_mode: String,
    management_socket: PathBuf,
    state_directory: PathBuf,
    networks: HashMap<String, RawNetwork>,
    #[serde(default)]
    pools: Vec<RawPool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDevice {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    identity_public_key: Option<String>,
    usb_serial: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    genesis_file: PathBuf,
    genesis_digest: String,
    network_magic: u32,
    #[serde(default)]
    mainnet: bool,
    node_socket: PathBuf,
    cardano_cli: PathBuf,
    era_history: PathBuf,
    slots_per_kes_period: u64,
    kes_lifetime: u8,
    max_context_age_ms: u64,
    #[serde(default = "default_query_timeout_ms")]
    query_timeout_ms: u64,
}
fn default_query_timeout_ms() -> u64 {
    5_000
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPool {
    pool_id: String,
    incarnation_id: String,
    socket_path: PathBuf,
    network: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEra {
    start_slot: u64,
    start_time_us: u64,
    slot_length_us: u64,
}

impl Config {
    /// Read and validate without creating directories, sockets, locks, or USB
    /// handles. Public genesis and era-history files are read-only inputs.
    pub fn load(path: &Path, mode: RunMode) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        if file.metadata()?.len() > MAX_CONFIG_BYTES {
            return Err(Error::Invalid("configuration exceeds 1 MiB"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let raw: RawConfig = serde_json::from_slice(&bytes)?;
        if raw.version != 1 {
            return Err(Error::InvalidField {
                field: "version",
                reason: "only version 1 is supported",
            });
        }
        if raw.socket_mode != "0660" {
            return Err(Error::InvalidField {
                field: "socket_mode",
                reason: "must be exactly 0660",
            });
        }
        validate_absolute_directory(&raw.socket_directory, false)?;
        validate_absolute_directory(&raw.state_directory, true)?;
        let management_socket = checked_socket_path(&raw.socket_directory, &raw.management_socket)?;
        let socket_gid = resolve_group(&raw.socket_group)?;
        let selected_serial =
            UsbSelection::new(raw.device.usb_serial.as_bytes()).map_err(|_| {
                Error::InvalidField {
                    field: "device.usb_serial",
                    reason: "must be the 16-byte firmware USB serial",
                }
            })?;
        let pin = match mode {
            RunMode::Normal => {
                let device = raw.device.id.as_deref().ok_or(Error::InvalidField {
                    field: "device.id",
                    reason: "required in normal mode",
                })?;
                let public_key =
                    raw.device
                        .identity_public_key
                        .as_deref()
                        .ok_or(Error::InvalidField {
                            field: "device.identity_public_key",
                            reason: "required in normal mode",
                        })?;
                Some(IdentityPin {
                    device: DeviceId::parse_hex(device).map_err(|_| Error::InvalidField {
                        field: "device.id",
                        reason: "expected 32 lowercase hexadecimal characters",
                    })?,
                    public_key: parse_hex::<32>(public_key, "device.identity_public_key")?,
                    serial: selected_serial,
                })
            }
            RunMode::Commissioning => {
                if raw.device.id.is_some() || raw.device.identity_public_key.is_some() {
                    return Err(Error::Invalid(
                        "commissioning device config contains an installed identity pin",
                    ));
                }
                if !raw.pools.is_empty() {
                    return Err(Error::Invalid(
                        "commissioning mode requires an empty pool list",
                    ));
                }
                None
            }
        };

        let mut networks = HashMap::new();
        for (name, raw_network) in raw.networks {
            validate_name(&name)?;
            let digest = Digest32::parse_hex(&raw_network.genesis_digest).map_err(|_| {
                Error::InvalidField {
                    field: "networks.genesis_digest",
                    reason: "expected 64 lowercase hexadecimal characters",
                }
            })?;
            verify_file_digest(&raw_network.genesis_file, digest)?;
            let era_history = read_era_history(&raw_network.era_history)?;
            let binding = NetworkBinding::new(
                digest,
                raw_network.network_magic,
                raw_network.slots_per_kes_period,
                raw_network.kes_lifetime,
            )
            .map_err(|_| Error::InvalidField {
                field: "networks",
                reason: "invalid slots-per-period or KES lifetime",
            })?;
            let selector = if raw_network.mainnet {
                if raw_network.network_magic != 764_824_073 {
                    return Err(Error::InvalidField {
                        field: "networks.network_magic",
                        reason: "mainnet requires magic 764824073",
                    });
                }
                NetworkSelector::Mainnet
            } else {
                NetworkSelector::Testnet(raw_network.network_magic)
            };
            let network = NetworkConfig {
                cardano_cli: checked_executable(&raw_network.cardano_cli)?,
                node_socket: checked_absolute(&raw_network.node_socket, "networks.node_socket")?,
                genesis_file: checked_absolute(&raw_network.genesis_file, "networks.genesis_file")?,
                expected_genesis_digest: digest,
                selector,
                binding,
                era_history,
                max_age: Duration::from_millis(raw_network.max_context_age_ms),
                query_timeout: Duration::from_millis(raw_network.query_timeout_ms),
            };
            validate_network_config(&network).map_err(|_| Error::InvalidField {
                field: "networks.era_history",
                reason: "invalid bounds or non-contiguous era history",
            })?;
            if networks.insert(name, network).is_some() {
                return Err(Error::Invalid("duplicate network"));
            }
        }
        if networks.is_empty() && mode == RunMode::Normal {
            return Err(Error::Invalid("normal mode requires at least one network"));
        }

        let mut pools = Vec::with_capacity(raw.pools.len());
        let mut pool_ids = HashSet::new();
        let mut socket_paths = HashSet::new();
        for raw_pool in raw.pools {
            if !networks.contains_key(&raw_pool.network) {
                return Err(Error::InvalidField {
                    field: "pools.network",
                    reason: "unknown network",
                });
            }
            let pool = PoolId::parse_hex(&raw_pool.pool_id).map_err(|_| Error::InvalidField {
                field: "pools.pool_id",
                reason: "invalid pool identity",
            })?;
            let incarnation = IncarnationId::parse_hex(&raw_pool.incarnation_id).map_err(|_| {
                Error::InvalidField {
                    field: "pools.incarnation_id",
                    reason: "invalid incarnation identity",
                }
            })?;
            let socket_path = checked_socket_path(&raw.socket_directory, &raw_pool.socket_path)?;
            if socket_path == management_socket
                || !pool_ids.insert(pool)
                || !socket_paths.insert(socket_path.clone())
            {
                return Err(Error::Invalid("duplicate/conflicting pool socket binding"));
            }
            pools.push(PoolBinding {
                pool,
                incarnation,
                socket_path,
                network: raw_pool.network,
            });
        }
        if pools.len() > 64 {
            return Err(Error::Invalid("more than 64 pool bindings"));
        }

        Ok(Self {
            mode,
            pin,
            selected_serial,
            socket_directory: raw.socket_directory,
            socket_group: raw.socket_group,
            socket_gid,
            management_socket,
            state_directory: raw.state_directory,
            networks,
            pools,
        })
    }
}

fn checked_absolute(path: &Path, field: &'static str) -> Result<PathBuf, Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(Error::InvalidField {
            field,
            reason: "must be an absolute normalized path",
        });
    }
    Ok(path.to_path_buf())
}

fn validate_absolute_directory(path: &Path, private: bool) -> Result<(), Error> {
    checked_absolute(path, "directory")?;
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o002 != 0
        || (private && metadata.mode() & 0o077 != 0)
    {
        return Err(Error::Invalid(
            "directory ownership or permissions are unsafe",
        ));
    }
    Ok(())
}

fn checked_socket_path(directory: &Path, path: &Path) -> Result<PathBuf, Error> {
    let path = checked_absolute(path, "socket path")?;
    if path.parent() != Some(directory) || path.file_name().is_none() {
        return Err(Error::InvalidField {
            field: "socket path",
            reason: "must be a direct child of socket_directory",
        });
    }
    Ok(path)
}

fn checked_executable(path: &Path) -> Result<PathBuf, Error> {
    let path = checked_absolute(path, "networks.cardano_cli")?;
    let metadata = std::fs::metadata(&path)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o022 != 0 {
        return Err(Error::InvalidField {
            field: "networks.cardano_cli",
            reason: "must be a non-writable executable regular file",
        });
    }
    Ok(path)
}

fn verify_file_digest(path: &Path, expected: Digest32) -> Result<(), Error> {
    let path = checked_absolute(path, "networks.genesis_file")?;
    let mut file = File::open(path)?;
    if file.metadata()?.len() > MAX_CONFIG_BYTES {
        return Err(Error::Invalid("genesis file exceeds 1 MiB"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let actual = Digest32::from_bytes(Sha256::digest(bytes).into());
    if actual != expected {
        return Err(Error::InvalidField {
            field: "networks.genesis_digest",
            reason: "does not match genesis file",
        });
    }
    Ok(())
}

fn read_era_history(path: &Path) -> Result<Vec<EraSegment>, Error> {
    let path = checked_absolute(path, "networks.era_history")?;
    let mut file = File::open(path)?;
    if file.metadata()?.len() > MAX_CONFIG_BYTES {
        return Err(Error::Invalid("era history exceeds 1 MiB"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let eras: Vec<RawEra> = serde_json::from_slice(&bytes)?;
    if eras.is_empty() || eras.len() > 32 {
        return Err(Error::Invalid("era history must contain 1..=32 segments"));
    }
    Ok(eras
        .into_iter()
        .map(|era| EraSegment {
            start_slot: era.start_slot,
            start_time_us: era.start_time_us,
            slot_length_us: era.slot_length_us,
        })
        .collect())
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::InvalidField {
            field: "network name",
            reason: "must be 1..=64 ASCII alphanumeric, '-' or '_'",
        });
    }
    Ok(())
}

fn resolve_group(name: &str) -> Result<u32, Error> {
    if name.is_empty() || name.contains(':') || name.contains('\n') {
        return Err(Error::InvalidField {
            field: "socket_group",
            reason: "invalid group name",
        });
    }
    let groups = std::fs::read_to_string("/etc/group")?;
    groups
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            if fields.next()? != name {
                return None;
            }
            fields.next()?;
            fields.next()?.parse().ok()
        })
        .ok_or(Error::InvalidField {
            field: "socket_group",
            reason: "group does not exist",
        })
}

fn parse_hex<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], Error> {
    if value.len() != N * 2 {
        return Err(Error::InvalidField {
            field,
            reason: "wrong hexadecimal width",
        });
    }
    let mut output = [0; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        let nibble = |value| match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        };
        output[index] = (nibble(pair[0]).ok_or(Error::InvalidField {
            field,
            reason: "expected lowercase hexadecimal",
        })? << 4)
            | nibble(pair[1]).ok_or(Error::InvalidField {
                field,
                reason: "expected lowercase hexadecimal",
            })?;
    }
    Ok(output)
}
