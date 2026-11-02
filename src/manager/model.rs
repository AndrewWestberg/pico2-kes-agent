//! Public manager observations and durable record data. These types do not contain secrets.

use std::{path::PathBuf, time::Duration};

use kes_core::{
    identity::{DeviceId, Digest32, GenerationId, OperationId},
    operation::{GenerationTarget, PoolTarget},
};
use serde::{Deserialize, Serialize};

pub const MANAGER_SCHEMA_VERSION: u64 = 1;
pub const INSTALLATION_REGISTRY: &str = "/var/lib/p2kesup/installation.json";
pub const MAX_DEVICE_POOLS: usize = 64;
pub const MAX_CONFIGURED_BINDINGS: usize = 64;
pub const MAX_EFFECTIVE_BINDINGS: usize = 64;
pub const MAX_GENERATION_SLOTS: usize = 128;
pub const MAX_JOINED_IDENTITIES: usize = 192;
pub const MAX_BINDINGS_PER_PAGE: usize = 16;
pub const MAX_MAINTENANCE_RECORD_BYTES: u64 = 1024 * 1024;
pub const MAX_MAINTENANCE_STORE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MAX_ARTIFACTS: usize = 256;
pub const MAX_ARTIFACT_PATH_BYTES: usize = 240;
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_RELEASE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Fresh,
    Stale,
    Unavailable,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Observation<T> {
    pub source: String,
    pub value: Option<T>,
    pub observed_at_unix_us: Option<u64>,
    pub age: Option<Duration>,
    pub state: ObservationState,
    pub public_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMode {
    Application,
    Bootloader,
    Absent,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationRole {
    Primary,
    Backup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Managed,
    External,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct ManagedInstallation {
    pub os: String,
    pub architecture: String,
    pub libc: String,
    pub role: InstallationRole,
    pub components: Vec<ComponentObservation>,
    pub selected: Option<ReleaseSelection>,
    pub account: Option<String>,
    pub group: Option<String>,
    pub service: Option<String>,
    pub config_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ComponentBuild {
    pub version: String,
    pub build_id: String,
    pub digest: Option<Digest32>,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct RunningComponent {
    pub build: ComponentBuild,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ComponentObservation {
    pub component: String,
    pub ownership: Ownership,
    pub installed: Observation<ComponentBuild>,
    pub running: Observation<RunningComponent>,
    pub selected: Option<ComponentBuild>,
    pub provenance: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolIdentity {
    pub device: DeviceId,
    pub target: PoolTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationIdentity {
    pub device: DeviceId,
    pub target: GenerationTarget,
}

#[derive(Clone, Debug)]
pub struct DeviceObservation {
    pub pin: Option<crate::daemon::usb::IdentityPin>,
    pub device_id: Option<DeviceId>,
    pub identity_public_key: Option<[u8; 32]>,
    pub serial: Option<String>,
    pub mode: DeviceMode,
    pub firmware_version: Option<String>,
    pub build_id: Option<String>,
    pub source_commit: Option<String>,
    pub protocol_major: Option<u64>,
    pub storage_version: Option<u64>,
    pub capacity: Option<u64>,
    pub capabilities: Option<u64>,
    pub security_report: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MembershipEntry {
    pub target: PoolTarget,
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub struct MembershipSnapshot {
    pub device: DeviceId,
    pub revision: u64,
    pub complete: bool,
    pub entries: Vec<MembershipEntry>,
}

#[derive(Clone, Debug)]
pub struct HostBinding {
    pub binding: crate::config::PoolBinding,
    pub configured: bool,
    pub effective: bool,
    pub retired: bool,
    pub conflicting: bool,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct HostBindingSnapshot {
    pub snapshot_id: String,
    pub config_identity: Digest32,
    pub journal_position: u64,
    pub bindings: Vec<HostBinding>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationRole {
    Active,
    Staged,
}

#[derive(Clone, Debug)]
pub struct GenerationObservation {
    pub identity: GenerationIdentity,
    pub revision: u64,
    pub role: GenerationRole,
    pub artifact_digest: Option<Digest32>,
    pub certificate_present: bool,
    pub certificate_start: Option<u64>,
    pub certificate_lifetime: Option<u64>,
    pub certificate_expiry_exclusive: Option<u64>,
    pub absolute_period: Option<u64>,
    pub relative_period: Option<u64>,
    pub remaining_periods: Option<u64>,
    pub health: String,
    pub readiness: String,
    pub publication: String,
    pub explanation: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PoolObservation {
    pub identity: PoolIdentity,
    pub revision: u64,
    pub membership: Option<bool>,
    pub configured: Option<bool>,
    pub effective: Option<bool>,
    pub active: Option<GenerationObservation>,
    pub staged: Option<GenerationObservation>,
    pub publication: Option<String>,
    pub accepted_period_floor: Option<u64>,
    pub context_source: Option<String>,
    pub context_age: Option<Duration>,
    pub context_valid: Option<bool>,
    pub health: String,
    pub failure: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Qualification {
    Candidate,
    Qualified,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedComponent {
    pub component: String,
    pub version: String,
    pub build_id: String,
    #[serde(with = "digest_hex")]
    pub digest: Digest32,
    #[serde(with = "digest_hex")]
    pub entrypoint_digest: Digest32,
    pub source_commit: String,
    #[serde(with = "digest_hex")]
    pub manifest_digest: Digest32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSelection {
    pub tag: String,
    pub version: String,
    pub source_commit: String,
    pub channel: String,
    pub qualification: Qualification,
    pub platform: String,
    pub components: Vec<SelectedComponent>,
    #[serde(with = "digest_hex")]
    pub manifest_digest: Digest32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFile {
    pub path: PathBuf,
    #[serde(with = "digest_hex")]
    pub digest: Digest32,
    pub mode: u32,
    pub owner: u32,
    pub group: u32,
    pub component: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRegistry {
    pub schema_version: u64,
    pub role: InstallationRole,
    pub files: Vec<ManagedFile>,
    pub current: Option<ReleaseSelection>,
    pub preserved_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceCheckpoint {
    pub name: String,
    pub observed_at_unix_us: u64,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRecord {
    pub schema_version: u64,
    #[serde(with = "operation_hex")]
    pub operation_id: OperationId,
    pub action: String,
    #[serde(with = "digest_hex")]
    pub plan_digest: Digest32,
    pub selected: Option<ReleaseSelection>,
    pub approved_scope: Vec<String>,
    pub previous_service_state: Option<String>,
    pub pre_observations: Vec<String>,
    pub checkpoints: Vec<MaintenanceCheckpoint>,
    pub post_observations: Vec<String>,
    pub outcome: String,
    pub bundle_digest: Option<String>,
    pub image_digest: Option<String>,
    pub physical_selection: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ArtifactReference {
    pub kind: String,
    pub path: PathBuf,
    pub digest: Option<Digest32>,
    pub device: Option<DeviceId>,
    pub pool: Option<PoolTarget>,
    pub generation: Option<GenerationId>,
    pub recipient: Option<Digest32>,
    pub destination_owner: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct LifecycleReceiptReference {
    pub path: PathBuf,
    pub receipt: crate::cli::receipt::PublicReceipt,
    pub reconciliation: Option<String>,
}

/// Unknown schema versions may be displayed, but must not authorize mutations.
pub fn require_supported_schema(schema_version: u64) -> Result<(), &'static str> {
    if schema_version == MANAGER_SCHEMA_VERSION {
        Ok(())
    } else {
        Err("unknown manager schema; read-only diagnostics only")
    }
}

macro_rules! hex_serde {
    ($module:ident, $ty:ty) => {
        mod $module {
            use serde::{Deserialize, Deserializer, Serializer, de::Error};

            pub fn serialize<S: Serializer>(value: &$ty, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(value)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$ty, D::Error> {
                let value = String::deserialize(deserializer)?;
                <$ty>::parse_hex(&value).map_err(|_| D::Error::custom("invalid identifier"))
            }
        }
    };
}
hex_serde!(digest_hex, kes_core::identity::Digest32);
hex_serde!(operation_hex, kes_core::identity::OperationId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_gate_and_serialized_states() {
        assert!(require_supported_schema(1).is_ok());
        assert!(require_supported_schema(2).is_err());
        assert_eq!(
            serde_json::to_string(&ObservationState::Unavailable).unwrap(),
            "\"unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&DeviceMode::Bootloader).unwrap(),
            "\"bootloader\""
        );
    }
}
