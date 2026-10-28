use crate::evidence;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const HORIZON_SECONDS: u64 = 157_852_800;
const HORIZON_DAYS: u64 = 1_827;
const MONTHLY_EVENTS: u64 = 61;
const POOLS: u64 = 64;
const SECTORS: usize = 1_024;
const IMAGE_LIMIT: u64 = 1_048_576;
const SRAM_BYTES: u64 = 520 * 1_024;
const OWNED_RAM_BUDGET: u64 = 128 * 1_024;
const REQUIRED_SPARE_RAM: u64 = 32 * 1_024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalInput {
    fitted_part: String,
    rating_source: String,
    rating_conditions: String,
    guaranteed_erase_cycles: u64,
    prior_wear_by_sector: Vec<u64>,
    network_profiles: Vec<NetworkProfile>,
    costs_by_sector: Vec<SectorCosts>,
    measured_flash_stall_us: u64,
    measured_stack_runtime_high_water_bytes: u64,
    measured_framework_overhead_bytes: u64,
    entropy_assessment: Value,
    erase_verification: Value,
    state_preserving_installation: Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkProfile {
    period_duration_seconds: u64,
    minimum_generation_lifetime: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SectorCosts {
    sector: usize,
    device_commissioning: u64,
    pool_enrollment: u64,
    initial_generation: u64,
    evolution_boundary: u64,
    rotation_workflow: u64,
    discard_workflow: u64,
    recipient_change: u64,
    delete_reenroll: u64,
    interrupted_recovery: u64,
    background_poll: u64,
}

#[derive(Serialize)]
struct Projection {
    period_boundaries: u64,
    network_rotations: u64,
    counts: WorkloadCounts,
    limiting_sector: usize,
    prior_wear: u64,
    projected_erases: u64,
    guaranteed_rating: u64,
    remaining_cycles: u64,
    minimum_margin_ratio: f64,
    verdict: &'static str,
}

#[derive(Serialize)]
struct WorkloadCounts {
    device_commissioning: u64,
    pool_enrollment: u64,
    initial_generation: u64,
    evolution_boundary: u64,
    rotation_workflow: u64,
    discard_workflow: u64,
    recipient_change: u64,
    delete_reenroll: u64,
    interrupted_recovery: u64,
    background_poll: u64,
}

pub fn run(arguments: &[String]) -> i32 {
    if let [flag, path] = arguments
        && flag == "--write-template"
    {
        return match write_template(Path::new(path)) {
            Ok(()) => {
                println!("{path}");
                0
            }
            Err(error) => {
                eprintln!("hardware qualification: {error}");
                1
            }
        };
    }
    let input_path = match arguments {
        [] => None,
        [flag, path] if flag == "--input" => Some(Path::new(path)),
        _ => {
            eprintln!(
                "usage: qualification hardware [--input PHYSICAL_INPUT.json] | --write-template PATH"
            );
            return 2;
        }
    };
    match execute(input_path) {
        Ok((path, verdict)) => {
            println!("{}", path.display());
            if verdict == "pass" { 0 } else { 1 }
        }
        Err(error) => {
            eprintln!("hardware qualification: {error}");
            1
        }
    }
}

fn write_template(path: &Path) -> Result<(), String> {
    let costs_by_sector = (0..SECTORS)
        .map(|sector| SectorCosts {
            sector,
            device_commissioning: 0,
            pool_enrollment: 0,
            initial_generation: 0,
            evolution_boundary: 0,
            rotation_workflow: 0,
            discard_workflow: 0,
            recipient_change: 0,
            delete_reenroll: 0,
            interrupted_recovery: 0,
            background_poll: 0,
        })
        .collect();
    let template = PhysicalInput {
        fitted_part: String::new(),
        rating_source: String::new(),
        rating_conditions: String::new(),
        guaranteed_erase_cycles: 0,
        prior_wear_by_sector: vec![0; SECTORS],
        network_profiles: (0..POOLS)
            .map(|_| NetworkProfile {
                period_duration_seconds: 0,
                minimum_generation_lifetime: 0,
            })
            .collect(),
        costs_by_sector,
        measured_flash_stall_us: 0,
        measured_stack_runtime_high_water_bytes: 0,
        measured_framework_overhead_bytes: 0,
        entropy_assessment: json!({"status":"incomplete","evidence":null}),
        erase_verification: json!({"status":"incomplete","evidence":null}),
        state_preserving_installation: json!({"status":"incomplete","evidence":null}),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create input template without overwrite: {error}"))?;
    serde_json::to_writer_pretty(&mut file, &template)
        .map_err(|error| format!("cannot encode input template: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("cannot finish input template: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync input template: {error}"))
}

fn execute(input_path: Option<&Path>) -> Result<(PathBuf, &'static str), String> {
    let repository = Path::new(ROOT)
        .parent()
        .ok_or("repository path unavailable")?;
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let build = Command::new("cargo")
        .args([
            "build",
            "--offline",
            "--release",
            "-p",
            "pico2-kes-firmware",
            "--target",
            "thumbv8m.main-none-eabihf",
        ])
        .current_dir(repository)
        .status()
        .map_err(|error| format!("cannot run firmware build: {error}"))?;
    if !build.success() {
        return Err("firmware release build failed".to_owned());
    }
    let elf = repository.join("target/thumbv8m.main-none-eabihf/release/pico2-kes-firmware");
    let size = measure_size(&elf)?;
    let image_bytes = size
        .text
        .checked_add(size.data)
        .ok_or("image-size overflow")?;
    let linked_static_ram = size.data.checked_add(size.bss).ok_or("RAM-size overflow")?;

    let (physical, input_error) = match input_path {
        Some(path) => match read_physical(path) {
            Ok(input) => (Some(input), None),
            Err(error) => (None, Some(error)),
        },
        None => (
            None,
            Some("no physical measurement input supplied".to_owned()),
        ),
    };
    let projection = physical.as_ref().and_then(|input| project(input).ok());
    let physical_complete = physical.as_ref().is_some_and(|input| {
        input
            .measured_stack_runtime_high_water_bytes
            .checked_add(input.measured_framework_overhead_bytes)
            .and_then(|runtime| runtime.checked_add(OWNED_RAM_BUDGET))
            .is_some_and(|used| SRAM_BYTES.saturating_sub(used) >= REQUIRED_SPARE_RAM)
            && !input.fitted_part.is_empty()
            && !input.rating_source.is_empty()
            && !input.rating_conditions.is_empty()
            && input.measured_flash_stall_us > 0
            && assessment_passes(&input.entropy_assessment)
            && assessment_passes(&input.erase_verification)
            && assessment_passes(&input.state_preserving_installation)
    });
    let definition_approved = evidence::approved_definition();
    let verdict = if definition_approved
        && image_bytes <= IMAGE_LIMIT
        && physical_complete
        && projection
            .as_ref()
            .is_some_and(|value| value.verdict == "pass")
    {
        "pass"
    } else if image_bytes > IMAGE_LIMIT
        || projection
            .as_ref()
            .is_some_and(|value| value.verdict == "fail")
    {
        "fail"
    } else {
        "inconclusive"
    };
    let mut missing = if physical_complete {
        Vec::<&str>::new()
    } else {
        vec![
            "direct fitted-part JEDEC/SFDP identity and applicable rating conditions",
            "per-sector prior-wear upper bounds",
            "measured per-sector workflow erase costs and 64 deployment network profiles",
            "stack/runtime high-water and framework RAM overhead",
            "flash-stall and erase/read-verification observations",
            "entropy assessment and fault-injection observations",
            "state-preserving attended installation observation",
        ]
    };
    if !definition_approved {
        missing.push("approval of the current storage-contract digest");
    }
    let report = json!({
        "schema_version": 1,
        "candidate": { "revision": revision, "dirty_sha256": dirty },
        "gate": {
            "name": "hardware",
            "definition_sha256": evidence::APPROVED_DIGEST,
            "definition_and_storage_approved": definition_approved,
            "scope": "T043 preliminary implemented-scope resource and endurance qualification"
        },
        "command": "cargo run --locked -p qualification -- hardware [--input PHYSICAL_INPUT.json]",
        "environment": {
            "rustc": tool_version("rustc"),
            "cargo": tool_version("cargo"),
            "size": tool_version("size"),
            "target": "thumbv8m.main-none-eabihf"
        },
        "measurements": {
            "firmware": {
                "elf": elf,
                "text_bytes": size.text,
                "data_bytes": size.data,
                "bss_bytes": size.bss,
                "image_bytes": image_bytes,
                "image_limit_bytes": IMAGE_LIMIT,
                "passes_image_limit": image_bytes <= IMAGE_LIMIT,
                "linked_static_ram_bytes": linked_static_ram
            },
            "encoding_bounds": {
                "configuration_payload_bytes": 7400,
                "configuration_bank_capacity_bytes": 7408,
                "operation_handoff_max_payload_bytes": 6144,
                "operation_handoff_bank_bytes": 8192,
                "pool_snapshot_payload_capacity_bytes": 3312,
                "two_canonical_kes_states_bytes": 1216,
                "public_object_bytes": 8192,
                "tree_bytes": 4064,
                "artifact_max_bytes": 2048,
                "identity_integrity_overhead_bytes": 2080,
                "allocated_state_start": 1048576,
                "allocated_state_end": 3178496,
                "pool_count": 64
            },
            "ram_budget": {
                "total_sram_bytes": SRAM_BYTES,
                "owned_budget_bytes": OWNED_RAM_BUDGET,
                "required_spare_bytes": REQUIRED_SPARE_RAM,
                "measured_stack_runtime_high_water_bytes": physical.as_ref().map(|v| v.measured_stack_runtime_high_water_bytes),
                "measured_framework_overhead_bytes": physical.as_ref().map(|v| v.measured_framework_overhead_bytes)
            },
            "physical": physical.as_ref().map(public_physical),
            "endurance_projection": projection,
        },
        "endurance_policy": {
            "horizon_days": HORIZON_DAYS,
            "horizon_seconds": HORIZON_SECONDS,
            "monthly_events": MONTHLY_EVENTS,
            "margin_rule": "2 * (prior wear + projected service erases) <= guaranteed minimum rating for every sector",
            "arithmetic": "checked u128 intermediate arithmetic; no sector averaging"
        },
        "input_error": input_error,
        "missing_prerequisites": missing,
        "exclusions": [
            "No simulated flash operation is treated as physical evidence.",
            "The preliminary result does not include later lifecycle costs required by T093.",
            "No commissioning, erase, flash programming, or irreversible device action is performed by this command."
        ],
        "oracle": {
            "image": "text plus data <= 1 MiB",
            "ram": "128-KiB owned budget plus measured framework/runtime leaves >=32 KiB SRAM",
            "endurance": "every physical sector satisfies the five-year 2x rule",
            "missing_input": "inconclusive and enrollment blocked"
        },
        "verdict": verdict,
        "enrollment_acceptance": if verdict == "pass" { "eligible for T044 physical commissioning" } else { "blocked" }
    });
    let path = repository
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("hardware/report.json");
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    evidence::atomic_write(&path, &bytes).map_err(|error| error.to_string())?;
    Ok((path, verdict))
}

fn assessment_passes(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.get("status").and_then(Value::as_str) == Some("pass"))
        && value
            .get("evidence")
            .is_some_and(|evidence| !evidence.is_null())
}

#[derive(Clone, Copy)]
struct Size {
    text: u64,
    data: u64,
    bss: u64,
}

fn measure_size(elf: &Path) -> Result<Size, String> {
    let output = Command::new("size")
        .arg(elf)
        .output()
        .map_err(|error| format!("cannot execute size: {error}"))?;
    if !output.status.success() {
        return Err("size rejected firmware ELF".to_owned());
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| "size output is not UTF-8")?;
    let row = stdout.lines().nth(1).ok_or("size output has no data row")?;
    let mut columns = row.split_whitespace();
    let text = columns
        .next()
        .ok_or("size text missing")?
        .parse()
        .map_err(|_| "invalid text size")?;
    let data = columns
        .next()
        .ok_or("size data missing")?
        .parse()
        .map_err(|_| "invalid data size")?;
    let bss = columns
        .next()
        .ok_or("size bss missing")?
        .parse()
        .map_err(|_| "invalid bss size")?;
    Ok(Size { text, data, bss })
}

fn read_physical(path: &Path) -> Result<PhysicalInput, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err("physical input must be a regular non-symlink file <=1 MiB".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid physical input: {error}"))
}

fn project(input: &PhysicalInput) -> Result<Projection, &'static str> {
    if input.guaranteed_erase_cycles == 0
        || input.prior_wear_by_sector.len() != SECTORS
        || input.network_profiles.len() != POOLS as usize
        || input.costs_by_sector.len() != SECTORS
    {
        return Err("physical input dimensions are incomplete");
    }
    let mut period_boundaries = 0_u64;
    let mut network_rotations = 0_u64;
    for profile in &input.network_profiles {
        if profile.period_duration_seconds == 0
            || !(1..=64).contains(&profile.minimum_generation_lifetime)
        {
            return Err("invalid network profile");
        }
        let periods = checked_ceil(HORIZON_SECONDS, profile.period_duration_seconds)?
            .checked_add(1)
            .ok_or("period count overflow")?;
        period_boundaries = period_boundaries
            .checked_add(periods)
            .ok_or("period sum overflow")?;
        network_rotations = network_rotations
            .checked_add(
                checked_ceil(periods, profile.minimum_generation_lifetime)?
                    .checked_add(1)
                    .ok_or("rotation overflow")?,
            )
            .ok_or("rotation sum overflow")?;
    }
    let counts = WorkloadCounts {
        device_commissioning: 1,
        pool_enrollment: POOLS,
        initial_generation: POOLS.checked_mul(2).ok_or("count overflow")?,
        evolution_boundary: period_boundaries.checked_mul(2).ok_or("count overflow")?,
        rotation_workflow: network_rotations
            .checked_add(POOLS.checked_mul(MONTHLY_EVENTS).ok_or("count overflow")?)
            .ok_or("count overflow")?,
        discard_workflow: POOLS.checked_mul(MONTHLY_EVENTS).ok_or("count overflow")?,
        recipient_change: MONTHLY_EVENTS,
        delete_reenroll: MONTHLY_EVENTS,
        interrupted_recovery: HORIZON_DAYS,
        background_poll: checked_ceil(HORIZON_SECONDS, 5)?
            .checked_add(1)
            .ok_or("poll overflow")?
            .checked_mul(POOLS)
            .ok_or("poll overflow")?,
    };
    let mut limiting = None;
    let mut all_pass = true;
    for (sector, prior) in input.prior_wear_by_sector.iter().copied().enumerate() {
        let cost = input
            .costs_by_sector
            .iter()
            .find(|cost| cost.sector == sector)
            .ok_or("sector cost missing")?;
        let projected = sector_projection(cost, &counts)?;
        let total = prior.checked_add(projected).ok_or("wear overflow")?;
        let doubled = total.checked_mul(2).ok_or("margin overflow")?;
        all_pass &= doubled <= input.guaranteed_erase_cycles;
        if limiting
            .as_ref()
            .is_none_or(|(_, _, _, current_total): &(usize, u64, u64, u64)| total > *current_total)
        {
            limiting = Some((sector, prior, projected, total));
        }
    }
    let (limiting_sector, prior_wear, projected_erases, total) = limiting.ok_or("no sectors")?;
    Ok(Projection {
        period_boundaries,
        network_rotations,
        counts,
        limiting_sector,
        prior_wear,
        projected_erases,
        guaranteed_rating: input.guaranteed_erase_cycles,
        remaining_cycles: input.guaranteed_erase_cycles.saturating_sub(total),
        minimum_margin_ratio: input.guaranteed_erase_cycles as f64 / total.max(1) as f64,
        verdict: if all_pass { "pass" } else { "fail" },
    })
}

fn sector_projection(cost: &SectorCosts, count: &WorkloadCounts) -> Result<u64, &'static str> {
    let terms = [
        (cost.device_commissioning, count.device_commissioning),
        (cost.pool_enrollment, count.pool_enrollment),
        (cost.initial_generation, count.initial_generation),
        (cost.evolution_boundary, count.evolution_boundary),
        (cost.rotation_workflow, count.rotation_workflow),
        (cost.discard_workflow, count.discard_workflow),
        (cost.recipient_change, count.recipient_change),
        (cost.delete_reenroll, count.delete_reenroll),
        (cost.interrupted_recovery, count.interrupted_recovery),
        (cost.background_poll, count.background_poll),
    ];
    let total = terms
        .into_iter()
        .try_fold(0_u128, |sum, (cost, count)| {
            sum.checked_add(u128::from(cost).checked_mul(u128::from(count))?)
        })
        .ok_or("projection overflow")?;
    u64::try_from(total).map_err(|_| "projection overflow")
}

fn checked_ceil(numerator: u64, denominator: u64) -> Result<u64, &'static str> {
    if denominator == 0 {
        return Err("division by zero");
    }
    numerator
        .checked_add(denominator - 1)
        .ok_or("ceiling overflow")
        .map(|value| value / denominator)
}

fn public_physical(input: &PhysicalInput) -> Value {
    json!({
        "fitted_part": input.fitted_part,
        "rating_source": input.rating_source,
        "rating_conditions": input.rating_conditions,
        "guaranteed_erase_cycles": input.guaranteed_erase_cycles,
        "measured_flash_stall_us": input.measured_flash_stall_us,
        "measured_stack_runtime_high_water_bytes": input.measured_stack_runtime_high_water_bytes,
        "measured_framework_overhead_bytes": input.measured_framework_overhead_bytes,
        "entropy_assessment": input.entropy_assessment,
        "erase_verification": input.erase_verification,
        "state_preserving_installation": input.state_preserving_installation,
    })
}

fn tool_version(program: &str) -> Option<String> {
    let output = Command::new(program).arg("--version").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_assessments_require_explicit_pass_with_evidence() {
        assert!(!assessment_passes(&json!({})));
        assert!(!assessment_passes(
            &json!({"status":"incomplete","evidence":"log"})
        ));
        assert!(!assessment_passes(
            &json!({"status":"pass","evidence":null})
        ));
        assert!(assessment_passes(
            &json!({"status":"pass","evidence":"measurement-log-sha256"})
        ));
    }

    #[test]
    fn endurance_accepts_equality_and_rejects_one_over_budget_sector() {
        let counts = WorkloadCounts {
            device_commissioning: 1,
            pool_enrollment: 0,
            initial_generation: 0,
            evolution_boundary: 0,
            rotation_workflow: 0,
            discard_workflow: 0,
            recipient_change: 0,
            delete_reenroll: 0,
            interrupted_recovery: 0,
            background_poll: 0,
        };
        let mut cost = SectorCosts {
            sector: 0,
            device_commissioning: 50,
            pool_enrollment: 0,
            initial_generation: 0,
            evolution_boundary: 0,
            rotation_workflow: 0,
            discard_workflow: 0,
            recipient_change: 0,
            delete_reenroll: 0,
            interrupted_recovery: 0,
            background_poll: 0,
        };
        assert_eq!(sector_projection(&cost, &counts), Ok(50));
        assert!(2_u64.checked_mul(50).is_some_and(|wear| wear <= 100));
        cost.device_commissioning = 51;
        assert!(
            2_u64
                .checked_mul(sector_projection(&cost, &counts).unwrap())
                .is_some_and(|wear| wear > 100)
        );
    }

    #[test]
    fn five_year_counts_include_phase_uncertainty() {
        assert_eq!(checked_ceil(HORIZON_SECONDS, 86_400).unwrap() + 1, 1_828);
        assert_eq!(MONTHLY_EVENTS, 61);
    }
}
