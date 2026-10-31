//! Strict version-1 daemon configuration validation.

use crate::daemon::{
    context::{NetworkConfig, SlotTiming, validate_network_config},
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
const MAX_GENESIS_BYTES: u64 = 16 * 1024 * 1024;

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
    byron_genesis_file: PathBuf,
    shelley_genesis_file: PathBuf,
    byron_to_shelley_epochs: u64,
    genesis_digest: String,
    max_context_age_ms: u64,
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
#[serde(rename_all = "camelCase")]
struct ByronGenesis {
    start_time: u64,
    protocol_consts: ByronProtocolConsts,
    block_version_data: ByronBlockVersionData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ByronProtocolConsts {
    k: u64,
    protocol_magic: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ByronBlockVersionData {
    slot_duration: ByronSlotDuration,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ByronSlotDuration {
    Number(u64),
    String(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShelleyGenesis {
    network_magic: u32,
    slot_length: serde_json::Number,
    #[serde(rename = "slotsPerKESPeriod")]
    slots_per_kes_period: u64,
    #[serde(rename = "maxKESEvolutions")]
    max_kes_evolutions: u8,
}

impl Config {
    /// Read and validate without creating directories, sockets, locks, or USB
    /// handles. Genesis files are read-only inputs.
    pub fn load(path: &Path, mode: RunMode) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(Error::Invalid("configuration exceeds 1 MiB"));
        }
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
            let network = load_network(raw_network)?;
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

fn read_genesis(path: &Path, field: &'static str) -> Result<Vec<u8>, Error> {
    let path = checked_absolute(path, field)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_GENESIS_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_GENESIS_BYTES {
        return Err(Error::Invalid("genesis file exceeds 16 MiB"));
    }
    Ok(bytes)
}

fn load_network(raw: RawNetwork) -> Result<NetworkConfig, Error> {
    let digest = Digest32::parse_hex(&raw.genesis_digest).map_err(|_| Error::InvalidField {
        field: "networks.genesis_digest",
        reason: "expected 64 lowercase hexadecimal characters",
    })?;
    let byron_bytes = read_genesis(&raw.byron_genesis_file, "networks.byron_genesis_file")?;
    let shelley_bytes = read_genesis(&raw.shelley_genesis_file, "networks.shelley_genesis_file")?;
    if Digest32::from_bytes(Sha256::digest(&shelley_bytes).into()) != digest {
        return Err(Error::InvalidField {
            field: "networks.genesis_digest",
            reason: "does not match Shelley genesis file",
        });
    }
    let byron: ByronGenesis = serde_json::from_slice(&byron_bytes)?;
    let shelley: ShelleyGenesis = serde_json::from_slice(&shelley_bytes)?;
    if byron.protocol_consts.protocol_magic != shelley.network_magic {
        return Err(Error::Invalid("genesis network magic mismatch"));
    }
    let byron_slot_ms = match byron.block_version_data.slot_duration {
        ByronSlotDuration::Number(value) => value,
        ByronSlotDuration::String(value) => {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Invalid("invalid Byron slot duration"));
            }
            value
                .parse()
                .map_err(|_| Error::Invalid("invalid Byron slot duration"))?
        }
    };
    if byron.protocol_consts.k == 0 || byron_slot_ms == 0 {
        return Err(Error::Invalid("Byron k and slot duration must be positive"));
    }
    let start_slot = byron
        .protocol_consts
        .k
        .checked_mul(10)
        .and_then(|slots| slots.checked_mul(raw.byron_to_shelley_epochs))
        .ok_or(Error::Invalid("genesis timing overflow"))?;
    let start_time_us = byron
        .start_time
        .checked_mul(1_000_000)
        .and_then(|start| {
            start_slot
                .checked_mul(byron_slot_ms)
                .and_then(|elapsed| elapsed.checked_mul(1_000))
                .and_then(|elapsed| start.checked_add(elapsed))
        })
        .ok_or(Error::Invalid("genesis timing overflow"))?;
    let binding = NetworkBinding::new(
        digest,
        shelley.network_magic,
        shelley.slots_per_kes_period,
        shelley.max_kes_evolutions,
    )
    .map_err(|_| Error::Invalid("invalid slots-per-period or KES lifetime"))?;
    // shortcut: assumes constant post-Shelley slot duration, extend the timing model before supporting a later slot-duration change
    let network = NetworkConfig {
        binding,
        timing: SlotTiming {
            start_slot,
            start_time_us,
            slot_length_us: decimal_microseconds(&shelley.slot_length)?,
        },
        max_age: Duration::from_millis(raw.max_context_age_ms),
    };
    validate_network_config(&network)
        .map_err(|_| Error::Invalid("invalid network timing or context lease"))?;
    Ok(network)
}

fn decimal_microseconds(number: &serde_json::Number) -> Result<u64, Error> {
    let invalid = || {
        Error::Invalid(
            "Shelley slot length must be positive and exactly representable in microseconds",
        )
    };
    let text = number.as_str();
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().map_err(|_| invalid())?),
        None => (text, 0),
    };
    if mantissa.starts_with('-') {
        return Err(invalid());
    }
    let fraction_len = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let significant = mantissa.trim_end_matches(['0', '.']);
    let trailing = mantissa[significant.len()..]
        .bytes()
        .filter(|b| *b != b'.')
        .count();
    let trailing = i64::try_from(trailing).map_err(|_| invalid())?;
    let fraction_len = i64::try_from(fraction_len).map_err(|_| invalid())?;
    let scale = exponent
        .checked_add(6)
        .and_then(|e| e.checked_sub(fraction_len))
        .and_then(|e| e.checked_add(trailing))
        .ok_or_else(invalid)?;
    if !(0..=19).contains(&scale) {
        return Err(invalid());
    }
    let coefficient = significant
        .bytes()
        .filter(|b| *b != b'.')
        .try_fold(0_u64, |value, digit| {
            value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
        })
        .ok_or_else(invalid)?;
    coefficient
        .checked_mul(10_u64.checked_pow(scale as u32).ok_or_else(invalid)?)
        .filter(|value| *value > 0)
        .ok_or_else(invalid)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "kes-config-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn network(&self, byron: &str, shelley: &str, epochs: u64) -> RawNetwork {
            let byron_path = self.0.join("byron.json");
            let shelley_path = self.0.join("shelley.json");
            std::fs::write(&byron_path, byron).unwrap();
            std::fs::write(&shelley_path, shelley).unwrap();
            RawNetwork {
                byron_genesis_file: byron_path,
                shelley_genesis_file: shelley_path,
                byron_to_shelley_epochs: epochs,
                genesis_digest: Sha256::digest(shelley.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                max_context_age_ms: 30_000,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn byron(start: &str, k: &str, magic: &str, duration: &str) -> String {
        format!(
            r#"{{"startTime":{start},"protocolConsts":{{"k":{k},"protocolMagic":{magic}}},"blockVersionData":{{"slotDuration":{duration}}}}}"#
        )
    }

    fn shelley(magic: &str, length: &str, period: &str, lifetime: &str) -> String {
        format!(
            r#"{{"networkMagic":{magic},"slotLength":{length},"slotsPerKESPeriod":{period},"maxKESEvolutions":{lifetime}}}"#
        )
    }

    #[test]
    fn genesis_anchor_mainnet_and_transition_variants() {
        let fixture = Fixture::new();
        let s = shelley("764824073", "1", "129600", "62");
        let b = byron("1506203091", "2160", "764824073", r#""20000""#);
        let network = load_network(fixture.network(&b, &s, 208)).unwrap();
        assert_eq!(network.timing.start_slot, 4_492_800);
        assert_eq!(network.timing.start_time_us, 1_596_059_091_000_000);
        assert_eq!(network.timing.slot_length_us, 1_000_000);
        assert_eq!(network.binding.slots_per_period(), 129_600);
        assert_eq!(
            network.timing.start_slot / network.binding.slots_per_period(),
            34
        );
        assert_eq!(
            (35 * 129_600 - network.timing.start_slot) * network.timing.slot_length_us,
            43_200_000_000
        );
        let slot = network.timing.start_slot
            + (1_793_404_800_000_000 - network.timing.start_time_us)
                / network.timing.slot_length_us;
        assert_eq!(slot, 201_838_509);
        assert_eq!(slot / network.binding.slots_per_period(), 1557);

        let zero = load_network(fixture.network(&b, &s, 0)).unwrap();
        assert_eq!(
            (zero.timing.start_slot, zero.timing.start_time_us),
            (0, 1_506_203_091_000_000)
        );
        let custom = byron("10", "3", "42", "100");
        let custom_s = shelley("42", "0.125", "100", "64");
        let four = load_network(fixture.network(&custom, &custom_s, 4)).unwrap();
        assert_eq!(
            (
                four.timing.start_slot,
                four.timing.start_time_us,
                four.timing.slot_length_us
            ),
            (120, 22_000_000, 125_000)
        );
        let fractional = byron("10", "1", "42", r#""125""#);
        let n = load_network(fixture.network(&fractional, &custom_s, 1)).unwrap();
        assert_eq!(
            (n.timing.start_slot, n.timing.start_time_us),
            (10, 11_250_000)
        );
        let scientific = shelley("42", "1.25e-1", "100", "64");
        let n = load_network(fixture.network(&custom, &scientific, 4)).unwrap();
        assert_eq!(n.timing.slot_length_us, 125_000);
    }

    #[test]
    fn shelley_decimal_microseconds_are_exact() {
        for (input, expected) in [
            ("1", 1_000_000),
            ("0.000001", 1),
            ("1.25e-1", 125_000),
            ("1000000e-6", 1_000_000),
            ("18446744073709.551615", u64::MAX),
        ] {
            let n: serde_json::Number = serde_json::from_str(input).unwrap();
            assert_eq!(decimal_microseconds(&n).unwrap(), expected, "{input}");
        }
        for input in [
            "0",
            "-1",
            "1e-7",
            "0.0000011",
            "18446744073709.551616",
            "1e100",
            "1e-100",
        ] {
            let n: serde_json::Number = serde_json::from_str(input).unwrap();
            assert!(decimal_microseconds(&n).is_err(), "{input}");
        }
    }

    #[test]
    fn genesis_trust_boundaries_fail_closed() {
        let fixture = Fixture::new();
        let good_b = byron("1", "1", "42", r#""100""#);
        let good_s = shelley("42", "1", "100", "64");
        let bad_byron = [
            byron("-1", "1", "42", "100"),
            byron("1", "0", "42", "100"),
            byron("1", "1", "43", "100"),
            byron("1", "1", "42", r#""1.5""#),
            byron("1", "1", "42", r#""+100""#),
            byron("1", "1", "42", "0"),
            byron("1", "1", "42", "1.5"),
            byron("18446744073709551615", "1", "42", "100"),
            byron("1", "18446744073709551615", "42", "100"),
        ];
        for b in bad_byron {
            assert!(
                load_network(fixture.network(&b, &good_s, 1)).is_err(),
                "{b}"
            );
        }
        for s in [
            shelley("42", "0", "100", "64"),
            shelley("42", "1e-7", "100", "64"),
            shelley("42", "1", "0", "64"),
            shelley("42", "1", "100", "65"),
        ] {
            assert!(
                load_network(fixture.network(&good_b, &s, 1)).is_err(),
                "{s}"
            );
        }
        assert!(load_network(fixture.network(&good_b, &good_s, u64::MAX)).is_err());
        let mut raw = fixture.network(&good_b, &good_s, 1);
        raw.genesis_digest = "00".repeat(32);
        assert!(load_network(raw).is_err());
        let mut raw = fixture.network(&good_b, &good_s, 1);
        raw.max_context_age_ms = 999;
        assert!(load_network(raw).is_err());
        let mut raw = fixture.network(&good_b, &good_s, 1);
        raw.max_context_age_ms = 30_999;
        assert!(load_network(raw).is_ok());
        let mut raw = fixture.network(&good_b, &good_s, 1);
        raw.max_context_age_ms = 31_000;
        assert!(load_network(raw).is_err());
        let raw = fixture.network(&good_b, &good_s, 1);
        std::fs::write(
            &raw.byron_genesis_file,
            vec![b' '; MAX_GENESIS_BYTES as usize + 1],
        )
        .unwrap();
        assert!(load_network(raw).is_err());
        let raw = fixture.network(&good_b, &good_s, 1);
        std::fs::write(
            &raw.shelley_genesis_file,
            vec![b' '; MAX_GENESIS_BYTES as usize + 1],
        )
        .unwrap();
        assert!(load_network(raw).is_err());
    }

    #[test]
    fn network_schema_requires_transition_and_rejects_obsolete_fields() {
        let base = r#"{"byron_genesis_file":"/b","shelley_genesis_file":"/s","genesis_digest":"00","max_context_age_ms":30000"#;
        assert!(
            serde_json::from_str::<RawNetwork>(&format!(r#"{base},"byron_to_shelley_epochs":0}}"#))
                .is_ok()
        );
        assert!(serde_json::from_str::<RawNetwork>(&format!("{base}}}")).is_err());
        assert!(
            serde_json::from_str::<RawNetwork>(&format!(
                r#"{base},"byron_to_shelley_epochs":-1}}"#
            ))
            .is_err()
        );
        for field in [
            "genesis_file",
            "cardano_cli",
            "node_socket",
            "query_timeout_ms",
            "era_history",
            "mainnet",
            "network_magic",
            "slots_per_kes_period",
            "kes_lifetime",
        ] {
            assert!(
                serde_json::from_str::<RawNetwork>(&format!(
                    r#"{base},"byron_to_shelley_epochs":0,"{field}":null}}"#
                ))
                .is_err(),
                "{field}"
            );
        }
    }
}
