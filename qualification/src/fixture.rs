//! Parsing is deliberately separate from prerequisite checks and campaign execution.
//! Fixture documents contain public identifiers and paths, never credential contents.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

pub const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum FixtureError {
    TooLarge,
    Malformed,
    Invalid(&'static str),
    Prerequisite(&'static str),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("fixture exceeds size limit"),
            Self::Malformed => f.write_str("malformed fixture"),
            Self::Invalid(reason) => write!(f, "invalid fixture: {reason}"),
            Self::Prerequisite(reason) => write!(f, "fixture prerequisite unavailable: {reason}"),
        }
    }
}

impl std::error::Error for FixtureError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub candidate_sha256: String,
    pub source_sha256: String,
    pub device_pin: String,
    pub fitted_part_record: String,
    pub firmware: PinnedFile,
    pub daemon: PinnedFile,
    pub cli: PinnedFile,
    pub decoder: PinnedFile,
    pub peer: PinnedFile,
    pub pools: Vec<Pool>,
    pub network: Network,
    pub recipient_host: String,
    pub power_controller: String,
    pub evidence_directory: String,
    #[serde(default)]
    pub attended: Option<Attended>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub public_identity: String,
    pub cold_key_path: String,
    pub vrf_key_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub name: String,
    pub isolated: bool,
    pub disposable_credentials: bool,
    pub genesis: String,
    pub node_socket: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attended {
    pub management_socket: String,
    pub commissioning_config: String,
    pub normal_config: String,
    pub hardware_report: String,
    pub usb_hub_label: String,
    pub cut_plan: Vec<CutStep>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutStep {
    pub operation: String,
    pub receipt: Option<String>,
    pub expected_outcome: String,
}

/// Reject malformed, oversized and semantically invalid documents without I/O.
pub fn parse_fixture(input: &[u8]) -> Result<Fixture, FixtureError> {
    if input.len() > MAX_FIXTURE_BYTES {
        return Err(FixtureError::TooLarge);
    }
    let fixture: Fixture = serde_json::from_slice(input).map_err(|_| FixtureError::Malformed)?;
    fixture.validate()?;
    Ok(fixture)
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= MAX_TEXT_BYTES
        && !value.chars().any(char::is_control)
        && !value
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| {
                word.eq_ignore_ascii_case("production")
                    || word.eq_ignore_ascii_case("prod")
                    || word.eq_ignore_ascii_case("mainnet")
            })
}

fn path(value: &str) -> bool {
    text(value)
        && Path::new(value).is_absolute()
        && value[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Fixture {
    fn validate(&self) -> Result<(), FixtureError> {
        if !hash(&self.candidate_sha256) || !hash(&self.source_sha256) {
            return Err(FixtureError::Invalid("candidate or source SHA-256"));
        }
        if !text(&self.device_pin) || !path(&self.fitted_part_record) {
            return Err(FixtureError::Invalid(
                "device identity or fitted-part record",
            ));
        }
        for pinned in [
            &self.firmware,
            &self.daemon,
            &self.cli,
            &self.decoder,
            &self.peer,
        ] {
            if !path(&pinned.path) || !hash(&pinned.sha256) {
                return Err(FixtureError::Invalid("pinned file path or SHA-256"));
            }
        }
        if self.pools.len() != 64 {
            return Err(FixtureError::Invalid("exactly 64 pools are required"));
        }
        let mut identities = HashSet::with_capacity(self.pools.len());
        for pool in &self.pools {
            if !text(&pool.public_identity)
                || !path(&pool.cold_key_path)
                || !path(&pool.vrf_key_path)
                || !identities.insert(&pool.public_identity)
            {
                return Err(FixtureError::Invalid("pool identity or credential path"));
            }
        }
        if !text(&self.network.name)
            || !self.network.isolated
            || !self.network.disposable_credentials
            || !path(&self.network.genesis)
            || !path(&self.network.node_socket)
        {
            return Err(FixtureError::Invalid("isolated disposable network"));
        }
        if !text(&self.recipient_host)
            || !text(&self.power_controller)
            || !path(&self.evidence_directory)
        {
            return Err(FixtureError::Invalid(
                "campaign endpoint or evidence directory",
            ));
        }
        if let Some(attended) = &self.attended {
            if !path(&attended.management_socket)
                || !path(&attended.commissioning_config)
                || !path(&attended.normal_config)
                || !path(&attended.hardware_report)
                || !text(&attended.usb_hub_label)
                || attended.cut_plan.len() != 10
            {
                return Err(FixtureError::Invalid("attended campaign configuration"));
            }
            let mut required = HashSet::new();
            for step in &attended.cut_plan {
                if !matches!(
                    step.operation.as_str(),
                    "generation"
                        | "certification"
                        | "evolution"
                        | "activation"
                        | "discard"
                        | "deletion"
                        | "cleanup"
                ) || !matches!(step.expected_outcome.as_str(), "success" | "rejected")
                    || step
                        .receipt
                        .as_deref()
                        .is_some_and(|receipt| !path(receipt))
                {
                    return Err(FixtureError::Invalid("attended cut plan"));
                }
                required.insert(step.operation.as_str());
            }
            if required.len() != 7 {
                return Err(FixtureError::Invalid(
                    "cut plan must cover every required operation",
                ));
            }
        }
        Ok(())
    }

    /// Check local prerequisites only after complete semantic validation. This
    /// neither starts programs nor opens devices, sockets, or credential files.
    pub fn validate_prerequisites(&self) -> Result<(), FixtureError> {
        self.validate()?;
        regular_file(&self.fitted_part_record, false)?;
        regular_file(&self.network.genesis, false)?;
        for pool in &self.pools {
            protected_file(&pool.cold_key_path)?;
            protected_file(&pool.vrf_key_path)?;
        }
        let socket = fs::metadata(&self.network.node_socket)
            .map_err(|_| FixtureError::Prerequisite("node socket"))?;
        if !socket.file_type().is_socket() {
            return Err(FixtureError::Prerequisite("node socket"));
        }
        if !fs::metadata(&self.evidence_directory)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            return Err(FixtureError::Prerequisite("evidence directory"));
        }
        for (pinned, executable) in [
            (&self.firmware, false),
            (&self.daemon, true),
            (&self.cli, true),
            (&self.decoder, true),
            (&self.peer, true),
        ] {
            regular_file(&pinned.path, executable)?;
            let mut file =
                File::open(&pinned.path).map_err(|_| FixtureError::Prerequisite("pinned file"))?;
            let mut digest = Sha256::new();
            let mut buffer = [0u8; 8192];
            loop {
                let n = file
                    .read(&mut buffer)
                    .map_err(|_| FixtureError::Prerequisite("pinned file"))?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
            let actual = format!("{:x}", digest.finalize());
            if !actual.eq_ignore_ascii_case(&pinned.sha256) {
                return Err(FixtureError::Prerequisite("pinned file digest"));
            }
        }
        if let Some(attended) = &self.attended {
            regular_file(&attended.commissioning_config, false)?;
            regular_file(&attended.normal_config, false)?;
            regular_file(&attended.hardware_report, false)?;
            let socket = fs::metadata(&attended.management_socket)
                .map_err(|_| FixtureError::Prerequisite("management socket"))?;
            if !socket.file_type().is_socket() {
                return Err(FixtureError::Prerequisite("management socket"));
            }
        }
        Ok(())
    }
}

fn regular_file(path: &str, executable: bool) -> Result<(), FixtureError> {
    let metadata = fs::metadata(path).map_err(|_| FixtureError::Prerequisite("regular file"))?;
    if !metadata.is_file() || (executable && metadata.permissions().mode() & 0o111 == 0) {
        return Err(FixtureError::Prerequisite("regular executable or file"));
    }
    Ok(())
}

fn protected_file(path: &str) -> Result<(), FixtureError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| FixtureError::Prerequisite("protected credential file"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(FixtureError::Prerequisite("protected credential file"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn document() -> Value {
        let pinned = json!({"path":"/qualification/binary", "sha256":"00".repeat(32)});
        let pools: Vec<_> = (0..64)
            .map(|n| {
                json!({
                    "public_identity": format!("pool-{n}"),
                    "cold_key_path": format!("/qualification/cold-{n}"),
                    "vrf_key_path": format!("/qualification/vrf-{n}")
                })
            })
            .collect();
        json!({
            "candidate_sha256":"ab".repeat(32), "source_sha256":"cd".repeat(32),
            "device_pin":"public-device-pin", "fitted_part_record":"/qualification/part",
            "firmware":pinned, "daemon":pinned, "cli":pinned, "decoder":pinned, "peer":pinned,
            "pools":pools, "network":{"name":"disposable", "isolated":true,
                "disposable_credentials":true, "genesis":"/qualification/genesis",
                "node_socket":"/qualification/node.socket"},
            "recipient_host":"recipient.example:1234", "power_controller":"controller",
            "evidence_directory":"/qualification/evidence"
        })
    }

    fn parse(value: &Value) -> Result<Fixture, FixtureError> {
        parse_fixture(&serde_json::to_vec(value).unwrap())
    }

    fn attended() -> Value {
        let operations = [
            "generation",
            "certification",
            "evolution",
            "activation",
            "discard",
            "deletion",
            "cleanup",
            "generation",
            "evolution",
            "cleanup",
        ];
        json!({
            "management_socket":"/qualification/management.socket",
            "commissioning_config":"/qualification/commission.json",
            "normal_config":"/qualification/normal.json",
            "hardware_report":"/qualification/hardware.json",
            "usb_hub_label":"bench-hub",
            "cut_plan": operations.iter().enumerate().map(|(index, operation)| json!({
                "operation": operation,
                "receipt": (!matches!(*operation, "evolution" | "activation" | "cleanup"))
                    .then(|| format!("/qualification/receipt-{index}.json")),
                "expected_outcome":"success"
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn attended_plan_requires_ten_cuts_covering_every_operation_class() {
        let mut value = document();
        value["attended"] = attended();
        assert!(parse(&value).is_ok());

        value["attended"]["cut_plan"][5]["operation"] = json!("generation");
        assert!(matches!(
            parse(&value),
            Err(FixtureError::Invalid(
                "cut plan must cover every required operation"
            ))
        ));
    }

    #[test]
    fn prerequisite_check_revalidates_before_any_filesystem_check() {
        let mut fixture = parse(&document()).unwrap();
        fixture.network.isolated = false;
        fixture.fitted_part_record = "/nonexistent-fixture-prerequisite".into();
        assert_eq!(
            fixture.validate_prerequisites(),
            Err(FixtureError::Invalid("isolated disposable network"))
        );
    }

    #[test]
    fn valid_public_document_parses_without_prerequisites() {
        assert!(parse(&document()).is_ok());
        assert!(matches!(
            parse(&document()).unwrap().validate_prerequisites(),
            Err(FixtureError::Prerequisite(_))
        ));
    }

    #[test]
    fn rejects_syntax_unknown_duplicate_and_oversized_input() {
        assert!(matches!(parse_fixture(b"{"), Err(FixtureError::Malformed)));
        assert!(matches!(
            parse_fixture(b"{\"device_pin\":\"a\",\"device_pin\":\"b\"}"),
            Err(FixtureError::Malformed)
        ));
        let mut value = document();
        value["unexpected"] = json!(true);
        assert!(matches!(parse(&value), Err(FixtureError::Malformed)));
        assert!(matches!(
            parse_fixture(&vec![b' '; MAX_FIXTURE_BYTES + 1]),
            Err(FixtureError::TooLarge)
        ));
    }

    #[test]
    fn rejects_semantic_errors_before_campaign_callback() {
        let mut cases = Vec::new();
        let mut value = document();
        value["pools"].as_array_mut().unwrap().pop();
        cases.push(value);
        let mut value = document();
        value["pools"][1]["public_identity"] = value["pools"][0]["public_identity"].clone();
        cases.push(value);
        let mut value = document();
        value["network"]["isolated"] = json!(false);
        cases.push(value);
        let mut value = document();
        value["network"]["disposable_credentials"] = json!(false);
        cases.push(value);
        let mut value = document();
        value["firmware"]["sha256"] = json!("invalid");
        cases.push(value);
        let mut value = document();
        value["pools"][0]["cold_key_path"] = json!("relative");
        cases.push(value);
        let mut value = document();
        value["pools"][0]["cold_key_path"] = json!("/production/key");
        cases.push(value);
        let mut value = document();
        value["network"]["name"] = json!("mainnet");
        cases.push(value);
        let mut value = document();
        value["source_sha256"] = json!("AB".repeat(32));
        cases.push(value);
        let mut value = document();
        value["network"]["genesis"] = json!("/qualification/../genesis");
        cases.push(value);
        let mut value = document();
        value["recipient_host"] = json!("x".repeat(MAX_TEXT_BYTES + 1));
        cases.push(value);
        for value in cases {
            let mut called = false;
            if parse(&value).is_ok() {
                called = true;
            }
            assert!(!called);
        }
    }
}
