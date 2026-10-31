//! Validation of operator-collected, public security qualification observations.
//! This is separate from the hardware gate and performs no device operations.
use crate::evidence;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

const LIMIT: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    Pass,
    Fail,
    NotObserved,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check<T> {
    outcome: Outcome,
    observations: Vec<T>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    commit: String,
    dirty: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chip {
    chip_revision: u8,
    rom_version: u8,
    usb_serial: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tools {
    picotool: String,
    firmware: String,
    host: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    signed_uf2_sha256: String,
    signed_elf_sha256: String,
    bundle_sha256: String,
    bootkey_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Device {
    usb_serial: String,
    device_id: String,
    identity_public_key: String,
    profile: String,
    bootkey_sha256: String,
    critical: u32,
    boot_flags0: u32,
    boot_flags1: u32,
    page2_lock0: u8,
    page2_lock1: u8,
    page63_lock0: u8,
    page63_lock1: u8,
    debugen: u32,
    debugen_lock: u32,
    redundancy_ok: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootObservation {
    description: String,
    image_sha256: String,
    booted: bool,
    device_serial: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectionObservation {
    description: String,
    image_sha256: String,
    signing_key_sha256: String,
    structurally_valid: bool,
    usb_write_completed: bool,
    executed: bool,
    restored_signed_image_booted: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceObservation {
    description: String,
    msd_present: bool,
    picoboot_present: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugObservation {
    description: String,
    debug_fuses_set: bool,
    runtime_locks_set: bool,
    external_swd_denial_observed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryObservation {
    description: String,
    physical_bootsel: bool,
    full_signed_uf2_copied: bool,
    same_device_booted: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pool {
    pool_id: String,
    incarnation: String,
    recipient: String,
    active_generation: String,
    staged_generation: String,
    active_verification_key: String,
    staged_verification_key: String,
    active_certificate_sha256: String,
    staged_certificate_sha256: String,
    active_artifact_sha256: String,
    staged_artifact_sha256: String,
    period_floor: u64,
    pool_revision: u64,
    relative_period: u64,
    publication_revision: u64,
    publication_timestamp_us: u64,
    publication_high_water_us: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activated {
    pool_id: String,
    incarnation: String,
    generation: String,
    verification_key: String,
    certificate_sha256: String,
    activation_period: u64,
    usable: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservationObservation {
    scenario: String,
    from_version: String,
    to_version: String,
    from_commit: String,
    to_commit: String,
    from_image_sha256: String,
    to_image_sha256: String,
    storage_version: u32,
    period: u64,
    before: Vec<Pool>,
    after: Vec<Pool>,
    current_kes_equal: bool,
    staged_activated: bool,
    activated: Vec<Activated>,
    description: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checks {
    signed_boot: Check<BootObservation>,
    wrong_key_rejected: Check<RejectionObservation>,
    tampered_image_rejected: Check<RejectionObservation>,
    picoboot_disabled: Check<InterfaceObservation>,
    debug_fuses_and_runtime_locks: Check<DebugObservation>,
    msd_recovery: Check<RecoveryObservation>,
    state_preserving_update: Check<PreservationObservation>,
    compatible_downgrade: Check<PreservationObservation>,
    interrupted_update_recovery: Check<PreservationObservation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u8,
    candidate: Candidate,
    chip: Chip,
    tools: Tools,
    artifacts: Artifacts,
    pre_device: Option<Device>,
    post_device: Option<Device>,
    checks: Checks,
}

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
// Input and output are public evidence. Do not accept multiline/raw command output.
fn label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
fn locked_policy(d: &Device) -> bool {
    const REQUIRED: u32 =
        0x20_0000 | 0x08_0000 | 0x04_0000 | 0x01_0000 | 0x8000 | 0x2000 | 0x100 | 0x80;
    const FORBIDDEN: u32 = 0x02_0000 | 0x4000 | 0x1000 | 0x800 | 0x40;
    fn locks(lock0: u8, lock1: u8) -> bool {
        lock0 == 0
            && lock1 & 0xc0 == 0
            && lock1 & 3 == 1
            && matches!((lock1 >> 2) & 3, 1 | 3)
            && matches!((lock1 >> 4) & 3, 1 | 3)
    }
    d.critical & 0x1000f == 7
        && d.boot_flags0 & REQUIRED == REQUIRED
        && d.boot_flags0 & FORBIDDEN == 0
        && d.boot_flags1 & 0xf0f == 0xe01
        && locks(d.page2_lock0, d.page2_lock1)
        && locks(d.page63_lock0, d.page63_lock1)
        && d.debugen & 0x10f == 0
        && d.debugen_lock & 0x10f == 0x10f
        && d.redundancy_ok
}
fn public_values(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => label(s),
        serde_json::Value::Array(items) => items.len() <= 16 && items.iter().all(public_values),
        serde_json::Value::Object(items) => items.values().all(public_values),
        _ => true,
    }
}
fn device_valid(d: &Device, serial: &str) -> bool {
    d.usb_serial == serial
        && hex(&d.device_id, 32)
        && hex(&d.identity_public_key, 64)
        && hex(&d.bootkey_sha256, 64)
        && matches!(
            d.profile.as_str(),
            "unlocked" | "incomplete" | "rp2350-signed-msd-v1"
        )
}
fn pool_valid(p: &Pool) -> bool {
    hex(&p.pool_id, 56)
        && hex(&p.incarnation, 32)
        && hex(&p.recipient, 64)
        && hex(&p.active_generation, 32)
        && hex(&p.staged_generation, 32)
        && hex(&p.active_verification_key, 64)
        && hex(&p.staged_verification_key, 64)
        && hex(&p.active_certificate_sha256, 64)
        && hex(&p.staged_certificate_sha256, 64)
        && hex(&p.active_artifact_sha256, 64)
        && hex(&p.staged_artifact_sha256, 64)
        && p.publication_revision <= p.pool_revision
        && p.publication_timestamp_us <= p.publication_high_water_us
}
fn preservation_valid(p: &PreservationObservation, scenario: &str) -> bool {
    p.scenario == scenario
        && label(&p.description)
        && label(&p.from_version)
        && label(&p.to_version)
        && (scenario.starts_with("interrupted_")
            || (p.from_version != p.to_version
                && p.from_commit != p.to_commit
                && p.from_image_sha256 != p.to_image_sha256))
        && p.current_kes_equal
        && p.staged_activated
        && p.before.len() >= 2
        && p.before.len() <= 16
        && p.before == p.after
        && p.before.iter().all(|pool| {
            pool_valid(pool)
                && pool.active_generation != pool.staged_generation
                && pool.period_floor == p.period
        })
        && p.before.iter().enumerate().all(|(i, pool)| {
            p.before[..i]
                .iter()
                .all(|other| pool.pool_id != other.pool_id)
        })
        && p.activated.len() == p.before.len()
        && p.before.iter().all(|pool| {
            p.activated
                .iter()
                .filter(|a| {
                    a.pool_id == pool.pool_id
                        && a.incarnation == pool.incarnation
                        && a.generation == pool.staged_generation
                        && a.verification_key == pool.staged_verification_key
                        && a.certificate_sha256 == pool.staged_certificate_sha256
                        && a.usable
                        && a.activation_period >= p.period
                })
                .count()
                == 1
        })
}
trait PublicObservation {
    fn public_valid(&self) -> bool;
}
impl PublicObservation for BootObservation {
    fn public_valid(&self) -> bool {
        label(&self.description) && hex(&self.image_sha256, 64) && hex(&self.device_serial, 16)
    }
}
impl PublicObservation for RejectionObservation {
    fn public_valid(&self) -> bool {
        label(&self.description) && hex(&self.image_sha256, 64) && hex(&self.signing_key_sha256, 64)
    }
}
impl PublicObservation for InterfaceObservation {
    fn public_valid(&self) -> bool {
        label(&self.description)
    }
}
impl PublicObservation for DebugObservation {
    fn public_valid(&self) -> bool {
        label(&self.description)
    }
}
impl PublicObservation for RecoveryObservation {
    fn public_valid(&self) -> bool {
        label(&self.description)
    }
}
impl PublicObservation for PreservationObservation {
    fn public_valid(&self) -> bool {
        matches!(
            self.scenario.as_str(),
            "upgrade"
                | "downgrade"
                | "interrupted_beginning"
                | "interrupted_middle"
                | "interrupted_end"
        ) && label(&self.description)
            && label(&self.from_version)
            && label(&self.to_version)
            && matches!(self.from_commit.len(), 40 | 64)
            && hex(&self.from_commit, self.from_commit.len())
            && matches!(self.to_commit.len(), 40 | 64)
            && hex(&self.to_commit, self.to_commit.len())
            && hex(&self.from_image_sha256, 64)
            && hex(&self.to_image_sha256, 64)
            && self.storage_version == 2
            && self.before.len() <= 16
            && self.after.len() <= 16
            && self.before.iter().chain(&self.after).all(pool_valid)
            && self.activated.len() <= 16
            && self.activated.iter().all(|a| {
                hex(&a.pool_id, 56)
                    && hex(&a.incarnation, 32)
                    && hex(&a.generation, 32)
                    && hex(&a.verification_key, 64)
                    && hex(&a.certificate_sha256, 64)
            })
    }
}
fn check<T: PublicObservation>(c: &Check<T>, valid: impl Fn(&[T]) -> bool) -> bool {
    c.observations.len() <= 16
        && c.observations.iter().all(PublicObservation::public_valid)
        && match c.outcome {
            Outcome::Pass => valid(&c.observations),
            Outcome::Fail => !c.observations.is_empty(),
            Outcome::NotObserved => c.observations.is_empty(),
        }
}
fn validate(input: &Input, revision: &str, dirty: &str) -> Result<bool, &'static str> {
    if !serde_json::to_value(input)
        .ok()
        .is_some_and(|v| public_values(&v))
        || input.schema_version != 1
        || input.candidate.commit != revision
        || input.candidate.dirty != dirty
        || !hex(&input.chip.usb_serial, 16)
        || !matches!(input.chip.rom_version, 2 | 4)
        || ![
            &input.tools.picotool,
            &input.tools.firmware,
            &input.tools.host,
        ]
        .into_iter()
        .all(|s| label(s))
        || ![
            &input.artifacts.signed_uf2_sha256,
            &input.artifacts.signed_elf_sha256,
            &input.artifacts.bundle_sha256,
            &input.artifacts.bootkey_sha256,
        ]
        .into_iter()
        .all(|s| hex(s, 64))
        || input
            .pre_device
            .as_ref()
            .is_some_and(|d| !device_valid(d, &input.chip.usb_serial))
        || input
            .post_device
            .as_ref()
            .is_some_and(|d| !device_valid(d, &input.chip.usb_serial))
    {
        return Err("invalid candidate or public metadata");
    }
    let c = &input.checks;
    let valid = check(&c.signed_boot, |v| {
        !v.is_empty()
            && v.iter().all(|o| {
                label(&o.description)
                    && o.booted
                    && o.image_sha256 == input.artifacts.signed_uf2_sha256
                    && o.device_serial == input.chip.usb_serial
            })
    }) && check(&c.wrong_key_rejected, |v| {
        !v.is_empty()
            && v.iter().all(|o| {
                label(&o.description)
                    && hex(&o.image_sha256, 64)
                    && hex(&o.signing_key_sha256, 64)
                    && o.signing_key_sha256 != input.artifacts.bootkey_sha256
                    && o.structurally_valid
                    && o.usb_write_completed
                    && !o.executed
                    && o.restored_signed_image_booted
            })
    }) && check(&c.tampered_image_rejected, |v| {
        !v.is_empty()
            && v.iter().all(|o| {
                label(&o.description)
                    && hex(&o.image_sha256, 64)
                    && o.image_sha256 != input.artifacts.signed_uf2_sha256
                    && o.signing_key_sha256 == input.artifacts.bootkey_sha256
                    && o.structurally_valid
                    && o.usb_write_completed
                    && !o.executed
                    && o.restored_signed_image_booted
            })
    }) && check(&c.picoboot_disabled, |v| {
        !v.is_empty()
            && v.iter()
                .all(|o| label(&o.description) && o.msd_present && !o.picoboot_present)
    }) && check(&c.debug_fuses_and_runtime_locks, |v| {
        !v.is_empty()
            && v.iter()
                .all(|o| label(&o.description) && o.debug_fuses_set && o.runtime_locks_set)
    }) && check(&c.msd_recovery, |v| {
        !v.is_empty()
            && v.iter().all(|o| {
                label(&o.description)
                    && o.physical_bootsel
                    && o.full_signed_uf2_copied
                    && o.same_device_booted
            })
    }) && check(&c.state_preserving_update, |v| {
        v.len() == 1 && preservation_valid(&v[0], "upgrade")
    }) && check(&c.compatible_downgrade, |v| {
        v.len() == 1 && preservation_valid(&v[0], "downgrade")
    }) && check(&c.interrupted_update_recovery, |v| {
        v.len() == 3
            && [
                "interrupted_beginning",
                "interrupted_middle",
                "interrupted_end",
            ]
            .iter()
            .all(|scenario| v.iter().filter(|o| preservation_valid(o, scenario)).count() == 1)
    });
    if !valid {
        return Err("invalid check observations");
    }
    let outcomes = [
        c.signed_boot.outcome,
        c.wrong_key_rejected.outcome,
        c.tampered_image_rejected.outcome,
        c.picoboot_disabled.outcome,
        c.debug_fuses_and_runtime_locks.outcome,
        c.msd_recovery.outcome,
        c.state_preserving_update.outcome,
        c.compatible_downgrade.outcome,
        c.interrupted_update_recovery.outcome,
    ];
    let all_pass = outcomes.iter().all(|o| *o == Outcome::Pass);
    if all_pass {
        let authority =
            kes_protocol::security::AUTHORIZED_BOOTKEY.ok_or("authorized boot key unavailable")?;
        let authority_hex: String = authority.iter().map(|byte| format!("{byte:02x}")).collect();
        if input.artifacts.bootkey_sha256 != authority_hex {
            return Err("boot key is not the authorized authority");
        }
        let (Some(pre), Some(post)) = (&input.pre_device, &input.post_device) else {
            return Err("passing evidence requires pre and post device records");
        };
        if pre.device_id != post.device_id
            || pre.identity_public_key != post.identity_public_key
            || post.bootkey_sha256 != input.artifacts.bootkey_sha256
            || post.profile != "rp2350-signed-msd-v1"
            || !locked_policy(post)
        {
            return Err("device identity or security report mismatch");
        }
    }
    Ok(all_pass)
}
fn stepping_verdicts(rom: u8, observed: Outcome) -> (Outcome, Outcome) {
    if rom == 2 {
        (observed, Outcome::NotObserved)
    } else {
        (Outcome::NotObserved, observed)
    }
}

pub fn run(args: &[String]) -> i32 {
    let [flag, file] = args else {
        eprintln!("usage: qualification security --input FILE");
        return 2;
    };
    if flag != "--input" {
        eprintln!("usage: qualification security --input FILE");
        return 2;
    }
    match execute(Path::new(file)) {
        Ok((path, passed)) => {
            println!("security evidence: {}", path.display());
            if passed { 0 } else { 1 }
        }
        Err(error) => {
            eprintln!("security evidence: {error}");
            1
        }
    }
}
fn execute(path: &Path) -> Result<(std::path::PathBuf, bool), String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("input exceeds 1 MiB".into());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "invalid public evidence schema at {}:{}",
            e.line(),
            e.column()
        )
    })?;
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let passed = validate(&input, &revision, &dirty).map_err(str::to_owned)?;
    let observed = if passed {
        Outcome::Pass
    } else if [
        &input.checks.signed_boot.outcome,
        &input.checks.wrong_key_rejected.outcome,
        &input.checks.tampered_image_rejected.outcome,
        &input.checks.picoboot_disabled.outcome,
        &input.checks.debug_fuses_and_runtime_locks.outcome,
        &input.checks.msd_recovery.outcome,
        &input.checks.state_preserving_update.outcome,
        &input.checks.compatible_downgrade.outcome,
        &input.checks.interrupted_update_recovery.outcome,
    ]
    .contains(&&Outcome::Fail)
    {
        Outcome::Fail
    } else {
        Outcome::NotObserved
    };
    let (a2, a4) = stepping_verdicts(input.chip.rom_version, observed);
    let report = serde_json::json!({"schema_version": 1, "a2": a2, "a4": a4, "evidence": input});
    let output = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("repository path unavailable")?
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("security/report.json");
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    evidence::atomic_write(&output, &bytes).map_err(|e| e.to_string())?;
    Ok((output, passed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(id: &str) -> Pool {
        Pool {
            pool_id: id.repeat(56),
            incarnation: "1".repeat(32),
            recipient: "2".repeat(64),
            active_generation: "3".repeat(32),
            staged_generation: "4".repeat(32),
            active_verification_key: "5".repeat(64),
            staged_verification_key: "6".repeat(64),
            active_certificate_sha256: "7".repeat(64),
            staged_certificate_sha256: "8".repeat(64),
            active_artifact_sha256: "a".repeat(64),
            staged_artifact_sha256: "b".repeat(64),
            period_floor: 8,
            pool_revision: 5,
            relative_period: 2,
            publication_revision: 4,
            publication_timestamp_us: 10,
            publication_high_water_us: 10,
        }
    }

    #[test]
    fn pool_observation_requires_complete_publication() {
        let mut value = serde_json::to_value(pool("a")).unwrap();
        for field in [
            "pool_revision",
            "relative_period",
            "publication_revision",
            "publication_timestamp_us",
            "publication_high_water_us",
        ] {
            let removed = value.as_object_mut().unwrap().remove(field).unwrap();
            assert!(serde_json::from_value::<Pool>(value.clone()).is_err());
            value.as_object_mut().unwrap().insert(field.into(), removed);
        }
    }

    #[test]
    fn pass_needs_observations() {
        let c = Check::<BootObservation> {
            outcome: Outcome::Pass,
            observations: vec![],
        };
        assert!(!check(&c, |v| !v.is_empty()));
        let c = Check::<BootObservation> {
            outcome: Outcome::NotObserved,
            observations: vec![],
        };
        assert!(check(&c, |v| !v.is_empty()));
    }

    #[test]
    fn failed_observations_still_require_public_field_shapes() {
        let c = Check {
            outcome: Outcome::Fail,
            observations: vec![BootObservation {
                description: "boot did not start".into(),
                image_sha256: "not a digest".into(),
                booted: false,
                device_serial: "00afd9003906a634".into(),
            }],
        };
        assert!(!check(&c, |_| true));
    }

    #[test]
    fn preservation_rejects_mismatch_and_unequal_key_bytes() {
        let before = vec![pool("a"), pool("b")];
        let mut obs = PreservationObservation {
            scenario: "upgrade".into(),
            from_version: "v1".into(),
            to_version: "v2".into(),
            from_commit: "a".repeat(40),
            to_commit: "b".repeat(40),
            from_image_sha256: "a".repeat(64),
            to_image_sha256: "b".repeat(64),
            storage_version: 2,
            period: 8,
            after: before.clone(),
            before,
            current_kes_equal: true,
            staged_activated: true,
            activated: ["a", "b"]
                .into_iter()
                .map(|id| Activated {
                    pool_id: id.repeat(56),
                    incarnation: "1".repeat(32),
                    generation: "4".repeat(32),
                    verification_key: "6".repeat(64),
                    certificate_sha256: "8".repeat(64),
                    activation_period: 9,
                    usable: true,
                })
                .collect(),
            description: "observed upgrade".into(),
        };
        assert!(preservation_valid(&obs, "upgrade"));
        obs.current_kes_equal = false;
        assert!(!preservation_valid(&obs, "upgrade"));
        obs.current_kes_equal = true;
        obs.after[1].period_floor = 7;
        assert!(!preservation_valid(&obs, "upgrade"));
        obs.after[1].period_floor = 8;
        obs.after[0].publication_timestamp_us += 1;
        assert!(!preservation_valid(&obs, "upgrade"));
        obs.after[0].publication_timestamp_us -= 1;
        obs.after[0].publication_revision += 1;
        assert!(!preservation_valid(&obs, "upgrade"));
    }

    #[test]
    fn a2_results_never_imply_a4_observation() {
        assert_eq!(
            stepping_verdicts(2, Outcome::Pass),
            (Outcome::Pass, Outcome::NotObserved)
        );
        assert_eq!(
            stepping_verdicts(2, Outcome::Fail),
            (Outcome::Fail, Outcome::NotObserved)
        );
    }

    #[test]
    fn duplicate_and_unknown_fields_are_rejected() {
        assert!(
            serde_json::from_str::<Check<BootObservation>>(
                r#"{"outcome":"pass","outcome":"fail","observations":[]}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Check<BootObservation>>(
                r#"{"outcome":"not-observed","observations":[],"success":true}"#
            )
            .is_err()
        );
    }
}
