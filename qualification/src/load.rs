use crate::evidence;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const CAMPAIGN_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize)]
struct Candidate<'a> {
    revision: &'a str,
    dirty_sha256: &'a str,
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    expected: &'static str,
    observed: &'static str,
    executions: u64,
    elapsed_seconds: f64,
    passed: bool,
}

#[derive(Serialize)]
struct Report<'a> {
    schema_version: u64,
    candidate: Candidate<'a>,
    scope: &'static str,
    checks: &'a [Check],
    verdict: &'static str,
    acceptance_claim: bool,
}

pub fn run() -> i32 {
    match execute() {
        Ok((true, path)) => {
            println!("load qualification passed: {}", path.display());
            0
        }
        Ok((false, path)) => {
            eprintln!("load qualification failed: {}", path.display());
            1
        }
        Err(error) => {
            eprintln!("load qualification error: {error}");
            1
        }
    }
}

fn execute() -> Result<(bool, PathBuf), String> {
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let capacity = command(&[
        "test",
        "--locked",
        "-p",
        "kes-core",
        "--test",
        "recovery",
        "full_capacity_keeps_pool_delivery_isolated_and_recovers_within_budget",
        "--",
        "--exact",
    ])?;
    let isolation = command(&[
        "test",
        "--locked",
        "--test",
        "operator_cli",
        "stalled_and_malformed_clients_do_not_block_valid_requests",
        "--",
        "--exact",
    ])?;
    let checks = [
        Check {
            name: "full-capacity-pool-isolation",
            expected: "64 active plus 64 staged; pool-correct requests under 10s; enrollment 65 rejected; recovery under 60s",
            observed: if capacity.0 {
                "all assertions passed"
            } else {
                "test failed or timed out"
            },
            executions: 1,
            elapsed_seconds: capacity.1.as_secs_f64(),
            passed: capacity.0,
        },
        Check {
            name: "client-isolation",
            expected: "stalled and malformed clients do not delay valid requests beyond 10s",
            observed: if isolation.0 {
                "all assertions passed"
            } else {
                "test failed or timed out"
            },
            executions: 1,
            elapsed_seconds: isolation.1.as_secs_f64(),
            passed: isolation.0,
        },
    ];
    let passed = checks.iter().all(|check| check.passed);
    let path = Path::new(ROOT)
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("load/report.json");
    let report = Report {
        schema_version: 1,
        candidate: Candidate {
            revision: &revision,
            dirty_sha256: &dirty,
        },
        scope: "SC-001/SC-003/SC-004 full-capacity and client-isolation qualification",
        checks: &checks,
        verdict: if passed { "pass" } else { "failed" },
        acceptance_claim: passed,
    };
    let bytes = serde_json::to_vec_pretty(&report).map_err(|_| "cannot encode load report")?;
    evidence::atomic_write(&path, &bytes).map_err(|error| error.to_string())?;
    Ok((passed, path))
}

fn command(arguments: &[&str]) -> Result<(bool, Duration), String> {
    let started = Instant::now();
    let mut child = Command::new("cargo")
        .args(arguments)
        .current_dir(ROOT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start cargo: {error}"))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status.success(), started.elapsed())),
            Ok(None) if started.elapsed() < CAMPAIGN_TIMEOUT => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok((false, started.elapsed()));
            }
            Err(error) => return Err(format!("cannot observe cargo: {error}")),
        }
    }
}
