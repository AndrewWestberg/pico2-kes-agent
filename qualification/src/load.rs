use crate::evidence;
use serde::Serialize;
use std::path::{Path, PathBuf};
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
    let capacity_name = "full_capacity_keeps_pool_delivery_isolated_and_recovers_within_budget";
    let capacity = command(
        &[
            "test",
            "--locked",
            "-p",
            "kes-core",
            "--test",
            "recovery",
            capacity_name,
            "--",
            "--exact",
            "--format",
            "pretty",
            "--color",
            "never",
        ],
        capacity_name,
    );
    let isolation_name = "stalled_and_malformed_clients_do_not_block_valid_requests";
    let isolation = command(
        &[
            "test",
            "--locked",
            "--test",
            "operator_cli",
            isolation_name,
            "--",
            "--exact",
            "--format",
            "pretty",
            "--color",
            "never",
        ],
        isolation_name,
    );
    let checks = [
        Check {
            name: "full-capacity-pool-isolation",
            expected: "64 active plus 64 staged; pool-correct requests under 10s; enrollment 65 rejected; recovery under 60s",
            observed: if capacity.0 {
                "all assertions passed"
            } else {
                "test failed or timed out"
            },
            executions: capacity.1,
            elapsed_seconds: capacity.2.as_secs_f64(),
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
            executions: isolation.1,
            elapsed_seconds: isolation.2.as_secs_f64(),
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

fn selected_result(success: bool, output: &[u8], name: &str) -> (bool, u64) {
    let Ok(output) = std::str::from_utf8(output) else {
        return (false, 0);
    };
    let passed = format!("test {name} ... ok");
    let failed = format!("test {name} ... FAILED");
    let mut lines = output
        .lines()
        .filter(|line| *line == passed || *line == failed);
    let first = lines.next();
    let exactly_one = first.is_some() && lines.next().is_none();
    (
        success && exactly_one && first == Some(passed.as_str()),
        u64::from(exactly_one),
    )
}

fn command(arguments: &[&str], name: &str) -> (bool, u64, Duration) {
    let started = Instant::now();
    let (passed, executions) = evidence::command("cargo", arguments, CAMPAIGN_TIMEOUT)
        .map(|(success, output)| selected_result(success, &output, name))
        .unwrap_or((false, 0));
    (passed, executions, started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_test_requires_exact_success_record() {
        let name = "selected";
        assert_eq!(
            selected_result(true, b"running 1 test\ntest selected ... ok\n", name),
            (true, 1)
        );
        assert_eq!(
            selected_result(false, b"test selected ... ok\n", name),
            (false, 1)
        );
        assert_eq!(
            selected_result(true, b"test selected ... FAILED\n", name),
            (false, 1)
        );
        assert_eq!(
            selected_result(true, b"running 0 tests\n", name),
            (false, 0)
        );
        assert_eq!(
            selected_result(true, b"test selected ... ignored\n", name),
            (false, 0)
        );
        assert_eq!(
            selected_result(true, b"test other_selected ... ok\n", name),
            (false, 0)
        );
        assert_eq!(
            selected_result(true, b"test selected ... ok\ntest selected ... ok\n", name),
            (false, 0)
        );
    }
}
