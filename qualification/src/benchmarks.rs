use crate::evidence;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const MANIFEST_LIMIT: usize = 1024 * 1024;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    runs_per_revision: usize,
    sample_size: usize,
    warm_up_seconds: u64,
    measurement_seconds: u64,
    ratio_threshold: f64,
    combined_budget_seconds: u64,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    id: String,
    criterion_directory: String,
    status: String,
    input: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Target {
    package: String,
    bench: String,
    workloads: Vec<Workload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    revision: String,
    source_tree: String,
    workload_sha256: String,
    approved_by: String,
    approved_date: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u64,
    purpose: String,
    settings: Settings,
    approved_baselines: Vec<Baseline>,
    targets: Vec<Target>,
}

#[derive(Clone, Copy, Deserialize, serde::Serialize)]
struct ConfidenceInterval {
    lower_bound: f64,
    upper_bound: f64,
}

#[derive(Deserialize)]
struct Mean {
    confidence_interval: ConfidenceInterval,
}

#[derive(Deserialize)]
struct Estimates {
    mean: Mean,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn load() -> Result<(Manifest, String), &'static str> {
    let path = Path::new(ROOT).join("qualification/benchmarks.json");
    let metadata = fs::symlink_metadata(&path).map_err(|_| "benchmark manifest unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() > MANIFEST_LIMIT as u64 {
        return Err("benchmark manifest invalid");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|_| "benchmark manifest unavailable")?
        .take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "benchmark manifest unreadable")?;
    if bytes.len() > MANIFEST_LIMIT {
        return Err("benchmark manifest too large");
    }
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| "benchmark manifest invalid")?;
    if manifest.schema_version != 1
        || manifest.purpose.is_empty()
        || manifest.settings.runs_per_revision != 3
        || manifest.settings.sample_size != 100
        || manifest.settings.warm_up_seconds != 5
        || manifest.settings.measurement_seconds != 10
        || manifest.settings.ratio_threshold != 1.05
        || manifest.settings.combined_budget_seconds != 1_800
        || manifest.targets.len() != 2
    {
        return Err("benchmark settings mismatch");
    }
    let workload = serde_json::to_vec(&(&manifest.settings, &manifest.targets))
        .map_err(|_| "benchmark manifest invalid")?;
    Ok((manifest, hex(&Sha256::digest(workload))))
}

fn public_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn validate_inventory(manifest: &Manifest) -> Result<(), &'static str> {
    let mut names = std::collections::BTreeSet::new();
    for target in &manifest.targets {
        if !public_token(&target.package, 64)
            || !public_token(&target.bench, 64)
            || target.workloads.is_empty()
        {
            return Err("benchmark target invalid");
        }
        for workload in &target.workloads {
            if !public_token(&workload.id, 64)
                || !public_token(&workload.criterion_directory, 128)
                || workload.input.is_empty()
                || workload.input.len() > 256
                || !names.insert((target.bench.as_str(), workload.id.as_str()))
            {
                return Err("benchmark workload invalid");
            }
            if workload.status != "active" {
                return Err("required benchmark workload pending");
            }
        }
    }
    Ok(())
}

fn command_output(program: &str, args: &[&str], directory: &Path) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn validate_baseline<'a>(
    manifest: &'a Manifest,
    revision: &str,
    workload_sha256: &str,
) -> Result<&'a Baseline, &'static str> {
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("baseline revision invalid");
    }
    let baseline = manifest
        .approved_baselines
        .iter()
        .find(|baseline| baseline.revision == revision)
        .ok_or("baseline is not approved")?;
    if baseline.workload_sha256 != workload_sha256
        || baseline.source_tree.len() != 40
        || baseline.approved_by.is_empty()
        || baseline.approved_date.is_empty()
    {
        return Err("baseline approval stale or invalid");
    }
    let object = command_output(
        "git",
        &["rev-parse", &format!("{revision}^{{commit}}")],
        Path::new(ROOT),
    )
    .ok_or("baseline revision unavailable")?;
    let tree = command_output(
        "git",
        &["rev-parse", &format!("{revision}^{{tree}}")],
        Path::new(ROOT),
    )
    .ok_or("baseline tree unavailable")?;
    if object != revision || tree != baseline.source_tree {
        return Err("baseline source identity mismatch");
    }
    Ok(baseline)
}

fn report_path() -> Result<(PathBuf, String, String), &'static str> {
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let path = Path::new(ROOT)
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("P0/report.json");
    Ok((path, revision, dirty))
}

fn publish_preflight(baseline: &str, reason: &'static str) -> i32 {
    let Ok((path, revision, dirty)) = report_path() else {
        eprintln!("benchmark qualification unavailable");
        return 1;
    };
    let report = json!({
        "schema_version": 1,
        "candidate": {"revision": revision, "dirty_sha256": dirty},
        "gate": "P0",
        "baseline_revision": baseline,
        "required_targets": ["kes-core/lifecycle", "pico2-kes-agent/host"],
        "executions": 0,
        "verdict": "inconclusive",
        "reason": reason,
        "acceptance_claim": false,
    });
    let bytes = serde_json::to_vec(&report).unwrap_or_default();
    if bytes.is_empty() || evidence::atomic_write(&path, &bytes).is_err() {
        eprintln!("benchmark qualification unavailable");
        return 1;
    }
    println!(
        "{}",
        json!({"verdict":"inconclusive", "reason":reason, "report":path})
    );
    1
}

struct Worktree {
    path: PathBuf,
}

impl Drop for Worktree {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .current_dir(ROOT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn checkout(revision: &str) -> Result<Worktree, &'static str> {
    let root = std::env::temp_dir().join(format!(
        "pico2-kes-benchmark-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| "system clock unavailable")?
            .as_nanos()
    ));
    let status = Command::new("git")
        .args(["worktree", "add", "--detach"])
        .arg(&root)
        .arg(revision)
        .current_dir(ROOT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "cannot create baseline worktree")?;
    if !status.success() {
        return Err("cannot create baseline worktree");
    }
    Ok(Worktree { path: root })
}

fn execute_bench(
    source: &Path,
    target_dir: &Path,
    target: &Target,
    label: &str,
    deadline: Instant,
) -> bool {
    let mut command = Command::new("cargo");
    command
        .args(["bench", "--locked", "-p"])
        .arg(&target.package)
        .args(["--bench"])
        .arg(&target.bench)
        .args(["--target-dir"])
        .arg(target_dir)
        .args(["--", "--noplot", "--save-baseline", label])
        .current_dir(source)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let pid = child.id() as i32;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            _ => {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn read_interval(path: &Path) -> Result<ConfidenceInterval, &'static str> {
    let bytes = fs::read(path).map_err(|_| "benchmark estimate missing")?;
    if bytes.len() > MANIFEST_LIMIT {
        return Err("benchmark estimate too large");
    }
    let estimate: Estimates =
        serde_json::from_slice(&bytes).map_err(|_| "benchmark estimate invalid")?;
    let interval = estimate.mean.confidence_interval;
    if !interval.lower_bound.is_finite()
        || !interval.upper_bound.is_finite()
        || interval.lower_bound <= 0.0
        || interval.lower_bound > interval.upper_bound
    {
        return Err("benchmark confidence interval invalid");
    }
    Ok(interval)
}

fn classify(
    baseline: &[ConfidenceInterval],
    candidate: &[ConfidenceInterval],
    threshold: f64,
) -> Result<(f64, f64, &'static str), &'static str> {
    if baseline.len() != 3 || candidate.len() != 3 {
        return Err("benchmark run count incomplete");
    }
    let mut lower = f64::INFINITY;
    let mut upper = 0.0_f64;
    for (baseline, candidate) in baseline.iter().zip(candidate) {
        lower = lower.min(candidate.lower_bound / baseline.upper_bound);
        upper = upper.max(candidate.upper_bound / baseline.lower_bound);
    }
    let verdict = if upper <= threshold {
        "pass"
    } else if lower > threshold {
        "fail"
    } else {
        "inconclusive"
    };
    Ok((lower, upper, verdict))
}

fn copy_estimate(source: &Path, destination: &Path) -> Result<(), &'static str> {
    let parent = destination.parent().ok_or("raw result path invalid")?;
    fs::create_dir_all(parent).map_err(|_| "cannot create raw result directory")?;
    let bytes = fs::read(source).map_err(|_| "benchmark estimate missing")?;
    let mut file = File::create(destination).map_err(|_| "cannot retain raw estimate")?;
    file.write_all(&bytes)
        .map_err(|_| "cannot retain raw estimate")?;
    file.sync_all().map_err(|_| "cannot retain raw estimate")
}

fn execute(
    manifest: &Manifest,
    baseline: &Baseline,
    baseline_revision: &str,
) -> Result<(Value, bool), &'static str> {
    let (report, revision, dirty) = report_path()?;
    let evidence_root = report.parent().ok_or("evidence path invalid")?;
    let worktree = checkout(baseline_revision)?;
    let temporary =
        std::env::temp_dir().join(format!("pico2-kes-benchmark-target-{}", std::process::id()));
    if temporary.exists() {
        return Err("benchmark target path already exists");
    }
    fs::create_dir(&temporary).map_err(|_| "cannot create benchmark target path")?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temporary.clone());
    let started = Instant::now();
    let deadline = started + Duration::from_secs(manifest.settings.combined_budget_seconds);
    let mut intervals: BTreeMap<(String, String, String), Vec<ConfidenceInterval>> =
        BTreeMap::new();

    for (side, source) in [
        ("baseline", worktree.path.as_path()),
        ("candidate", Path::new(ROOT)),
    ] {
        let target_dir = temporary.join(side);
        for target in &manifest.targets {
            for run in 1..=manifest.settings.runs_per_revision {
                let label = format!("{side}-{}-{run}", target.bench);
                if !execute_bench(source, &target_dir, target, &label, deadline) {
                    return Err("benchmark command failed or exceeded budget");
                }
                for workload in &target.workloads {
                    let estimate = target_dir
                        .join("criterion")
                        .join(&workload.criterion_directory)
                        .join(&label)
                        .join("estimates.json");
                    let interval = read_interval(&estimate)?;
                    intervals
                        .entry((side.to_owned(), target.bench.clone(), workload.id.clone()))
                        .or_default()
                        .push(interval);
                    let retained = evidence_root
                        .join("raw")
                        .join(side)
                        .join(&target.bench)
                        .join(format!("run-{run}"))
                        .join(format!("{}.json", workload.id));
                    copy_estimate(&estimate, &retained)?;
                }
            }
        }
    }

    let mut results = Vec::new();
    let mut all_passed = true;
    for target in &manifest.targets {
        for workload in &target.workloads {
            let baseline_runs = intervals
                .get(&(
                    "baseline".to_owned(),
                    target.bench.clone(),
                    workload.id.clone(),
                ))
                .ok_or("baseline workload result missing")?;
            let candidate_runs = intervals
                .get(&(
                    "candidate".to_owned(),
                    target.bench.clone(),
                    workload.id.clone(),
                ))
                .ok_or("candidate workload result missing")?;
            let (lower, upper, verdict) = classify(
                baseline_runs,
                candidate_runs,
                manifest.settings.ratio_threshold,
            )?;
            all_passed &= verdict == "pass";
            results.push(json!({
                "target": format!("{}/{}", target.package, target.bench),
                "workload": workload.id,
                "input": workload.input,
                "ratio_95_lower": lower,
                "ratio_95_upper": upper,
                "threshold": manifest.settings.ratio_threshold,
                "verdict": verdict,
                "baseline_runs": baseline_runs,
                "candidate_runs": candidate_runs,
            }));
        }
    }
    if started.elapsed() > Duration::from_secs(manifest.settings.combined_budget_seconds) {
        return Err("benchmark combined budget exceeded");
    }
    let value = json!({
        "schema_version": 1,
        "candidate": {"revision": revision, "dirty_sha256": dirty},
        "gate": "P0",
        "baseline": {
            "revision": baseline_revision,
            "source_tree": baseline.source_tree,
            "approved_by": baseline.approved_by,
            "approved_date": baseline.approved_date,
        },
        "settings": manifest.settings,
        "environment": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "fixed_environment_required": true,
        },
        "elapsed_seconds": started.elapsed().as_secs_f64(),
        "workloads": results,
        "verdict": if all_passed { "pass" } else { "failed-or-inconclusive" },
        "acceptance_claim": all_passed,
    });
    Ok((value, all_passed))
}

pub fn run(baseline_revision: &str) -> i32 {
    let (manifest, workload_sha256) = match load() {
        Ok(value) => value,
        Err(reason) => return publish_preflight(baseline_revision, reason),
    };
    if let Err(reason) = validate_inventory(&manifest) {
        return publish_preflight(baseline_revision, reason);
    }
    let baseline = match validate_baseline(&manifest, baseline_revision, &workload_sha256) {
        Ok(baseline) => baseline,
        Err(reason) => return publish_preflight(baseline_revision, reason),
    };
    let (report_path, _, _) = match report_path() {
        Ok(value) => value,
        Err(reason) => return publish_preflight(baseline_revision, reason),
    };
    let (report, passed) = match execute(&manifest, baseline, baseline_revision) {
        Ok(result) => result,
        Err(reason) => return publish_preflight(baseline_revision, reason),
    };
    let Ok(bytes) = serde_json::to_vec(&report) else {
        return publish_preflight(baseline_revision, "cannot encode benchmark report");
    };
    if evidence::atomic_write(&report_path, &bytes).is_err() {
        return publish_preflight(baseline_revision, "cannot publish benchmark report");
    }
    println!(
        "{}",
        json!({"verdict":report["verdict"], "report":report_path})
    );
    if passed { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_classification_uses_all_three_retained_intervals() {
        let baseline = [
            ConfidenceInterval {
                lower_bound: 9.8,
                upper_bound: 10.2,
            },
            ConfidenceInterval {
                lower_bound: 9.9,
                upper_bound: 10.1,
            },
            ConfidenceInterval {
                lower_bound: 9.7,
                upper_bound: 10.3,
            },
        ];
        let fast = [ConfidenceInterval {
            lower_bound: 9.0,
            upper_bound: 9.5,
        }; 3];
        let slow = [ConfidenceInterval {
            lower_bound: 11.0,
            upper_bound: 11.2,
        }; 3];
        let crossing = [ConfidenceInterval {
            lower_bound: 9.9,
            upper_bound: 10.7,
        }; 3];
        assert_eq!(classify(&baseline, &fast, 1.05).unwrap().2, "pass");
        assert_eq!(classify(&baseline, &slow, 1.05).unwrap().2, "fail");
        assert_eq!(
            classify(&baseline, &crossing, 1.05).unwrap().2,
            "inconclusive"
        );
        assert!(classify(&baseline[..2], &fast, 1.05).is_err());
    }

    #[test]
    fn current_inventory_is_explicitly_pending() {
        let (manifest, _) = load().unwrap();
        assert_eq!(
            validate_inventory(&manifest),
            Err("required benchmark workload pending")
        );
    }
}
