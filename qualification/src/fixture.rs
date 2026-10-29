//! Fixture documents contain public identifiers and paths, never credential contents.

use serde::Deserialize;
use std::{collections::HashSet, fmt, path::Path};

pub const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum FixtureError {
    TooLarge,
    Malformed,
    Invalid(&'static str),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("fixture exceeds size limit"),
            Self::Malformed => f.write_str("malformed fixture"),
            Self::Invalid(reason) => write!(f, "invalid fixture: {reason}"),
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
    pub evidence_directory: String,
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
        if !text(&self.recipient_host) || !path(&self.evidence_directory) {
            return Err(FixtureError::Invalid(
                "recipient endpoint or evidence directory",
            ));
        }
        Ok(())
    }
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
            "recipient_host":"recipient.example:1234",
            "evidence_directory":"/qualification/evidence"
        })
    }

    fn parse(value: &Value) -> Result<Fixture, FixtureError> {
        parse_fixture(&serde_json::to_vec(value).unwrap())
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
