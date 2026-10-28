use crate::evidence;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const REPORT_LIMIT: usize = 16 * 1024 * 1024;

struct CheckCommand {
    label: &'static str,
    program: String,
    args: Vec<String>,
    directory: PathBuf,
    timeout: Duration,
}

#[derive(Serialize)]
struct Candidate<'a> {
    revision: &'a str,
    dirty_sha256: &'a str,
}

#[derive(Serialize)]
struct DispatchCheck<'a> {
    name: &'a str,
    expected: &'static str,
    observed: &'static str,
    executions: u64,
    passed: bool,
}

#[derive(Serialize)]
struct DispatchReport<'a> {
    schema_version: u64,
    candidate: Candidate<'a>,
    definition_sha256: &'static str,
    scope: &'a str,
    required_scope: [&'a str; 1],
    checks: &'a [DispatchCheck<'a>],
    verdict: &'static str,
    acceptance_claim: bool,
}

fn command(
    label: &'static str,
    program: &str,
    args: &[&str],
    directory: &Path,
    seconds: u64,
) -> CheckCommand {
    CheckCommand {
        label,
        program: program.to_owned(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        directory: directory.to_owned(),
        timeout: Duration::from_secs(seconds),
    }
}

fn fixed_commands(scope: &str) -> Result<Vec<CheckCommand>, &'static str> {
    let root = Path::new(ROOT);
    match scope {
        "host" => Ok(vec![
            command(
                "rust-format",
                "cargo",
                &["fmt", "--all", "--check"],
                root,
                300,
            ),
            command("host-check", "cargo", &["check", "--locked"], root, 1_800),
            command("host-tests", "cargo", &["test", "--locked"], root, 1_800),
            command(
                "host-clippy",
                "cargo",
                &["clippy", "--all-targets", "--", "-D", "warnings"],
                root,
                1_800,
            ),
            command(
                "core-no-std",
                "cargo",
                &[
                    "check",
                    "--locked",
                    "-p",
                    "kes-core",
                    "--no-default-features",
                ],
                root,
                1_800,
            ),
            command(
                "protocol-no-std",
                "cargo",
                &[
                    "check",
                    "--locked",
                    "-p",
                    "kes-protocol",
                    "--no-default-features",
                ],
                root,
                1_800,
            ),
            command("dependency-audit", "cargo", &["audit"], root, 1_800),
            command(
                "dependency-policy",
                "cargo",
                &["deny", "check"],
                root,
                1_800,
            ),
        ]),
        "firmware" => Ok(vec![
            command(
                "firmware-check",
                "cargo",
                &[
                    "check",
                    "--locked",
                    "-p",
                    "pico2-kes-firmware",
                    "--target",
                    "thumbv8m.main-none-eabihf",
                ],
                root,
                1_800,
            ),
            command(
                "firmware-release",
                "cargo",
                &[
                    "build",
                    "--locked",
                    "-p",
                    "pico2-kes-firmware",
                    "--release",
                    "--target",
                    "thumbv8m.main-none-eabihf",
                ],
                root,
                1_800,
            ),
            command(
                "firmware-clippy",
                "cargo",
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "pico2-kes-firmware",
                    "--target",
                    "thumbv8m.main-none-eabihf",
                    "--",
                    "-D",
                    "warnings",
                ],
                root,
                1_800,
            ),
        ]),
        "native" => native_commands(),
        _ => Err("unknown executable scope"),
    }
}

fn native_commands() -> Result<Vec<CheckCommand>, &'static str> {
    let pins = fs::read(Path::new(ROOT).join("qualification/native/pins.json"))
        .map_err(|_| "native pin record unavailable")?;
    if pins.len() > REPORT_LIMIT {
        return Err("native pin record too large");
    }
    let pins: Value = serde_json::from_slice(&pins).map_err(|_| "native pin record invalid")?;
    let cli = pins
        .pointer("/cli_resolved_plan/source")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .ok_or("pinned CLI source unavailable")?;
    Ok(vec![
        command(
            "native-oracle-build",
            "cabal",
            &["build", "all"],
            &Path::new(ROOT).join("qualification/native"),
            7_200,
        ),
        command(
            "cardano-cli-build",
            "cabal",
            &["build", "exe:cardano-cli"],
            &cli,
            7_200,
        ),
    ])
}

fn execute(spec: &CheckCommand) -> bool {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.directory)
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
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if started.elapsed() < spec.timeout => {
                thread::sleep(Duration::from_millis(50))
            }
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

fn write_dispatch(scope: &str, checks: &[DispatchCheck<'_>]) -> Result<PathBuf, &'static str> {
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    if !evidence::approved_definition() {
        return Err("gate definition approval unavailable");
    }
    let report = DispatchReport {
        schema_version: 1,
        candidate: Candidate {
            revision: &revision,
            dirty_sha256: &dirty,
        },
        definition_sha256: evidence::APPROVED_DIGEST,
        scope,
        required_scope: [scope],
        checks,
        verdict: if checks.iter().all(|check| check.passed) {
            "pass-for-dispatch-scope"
        } else {
            "failed"
        },
        acceptance_claim: false,
    };
    let bytes = serde_json::to_vec(&report).map_err(|_| "cannot encode dispatch report")?;
    let path = Path::new(ROOT)
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("dispatch")
        .join(format!("{scope}.json"));
    evidence::atomic_write(&path, &bytes).map_err(|_| "cannot publish dispatch report")?;
    Ok(path)
}

fn run_scope(scope: &str) -> i32 {
    if scope == "foundation" {
        return run_foundation();
    }
    if matches!(
        scope,
        "smoke" | "interop" | "power-loss" | "node" | "operator" | "load"
    ) {
        eprintln!("gate scope pending: implementation and nonempty workload required");
        return 1;
    }
    let commands = match fixed_commands(scope) {
        Ok(commands) => commands,
        Err(error) => {
            eprintln!("gate dispatch error: {error}");
            return 1;
        }
    };
    let mut checks = Vec::with_capacity(commands.len());
    for command in &commands {
        let passed = execute(command);
        checks.push(DispatchCheck {
            name: command.label,
            expected: "command exits successfully",
            observed: if passed {
                "successful exit"
            } else {
                "failed exit"
            },
            executions: 1,
            passed,
        });
        if !passed {
            break;
        }
    }
    let path = match write_dispatch(scope, &checks) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("gate dispatch error: {error}");
            return 1;
        }
    };
    println!(
        "{}",
        serde_json::json!({
            "scope": scope,
            "verdict": if checks.len() == commands.len() && checks.iter().all(|check| check.passed) { "pass-for-dispatch-scope" } else { "failed" },
            "acceptance_claim": false,
            "report": path,
        })
    );
    if checks.len() == commands.len() && checks.iter().all(|check| check.passed) {
        0
    } else {
        1
    }
}

fn run_foundation() -> i32 {
    let Ok(executable) = std::env::current_exe() else {
        eprintln!("foundation dispatch unavailable");
        return 1;
    };
    let Ok(output) = Command::new(executable)
        .arg("foundation")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
    else {
        eprintln!("foundation dispatch unavailable");
        return 1;
    };
    if !output.status.success() || output.stdout.len() > 16 * 1024 {
        eprintln!("foundation dispatch failed");
        return 1;
    }
    let Ok(summary) = serde_json::from_slice::<Value>(&output.stdout) else {
        eprintln!("foundation summary invalid");
        return 1;
    };
    let Some(path) = summary.get("report").and_then(Value::as_str) else {
        eprintln!("foundation report path missing");
        return 1;
    };
    match validate(Path::new(path), "foundation") {
        Ok(()) => {
            println!(
                "{}",
                serde_json::json!({"scope":"foundation", "verdict":"pass-for-foundation-scope", "acceptance_claim":false, "report":path})
            );
            0
        }
        Err(error) => {
            eprintln!("foundation report rejected: {error}");
            1
        }
    }
}

fn read_report(path: &Path) -> Result<Value, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "report unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > REPORT_LIMIT as u64
    {
        return Err("report path or size invalid");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|_| "report unavailable")?
        .take((REPORT_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "report read failed")?;
    if bytes.len() > REPORT_LIMIT {
        return Err("report too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "report JSON invalid")
}

fn validate_value(
    report: &Value,
    required: &str,
    current: (&str, &str),
) -> Result<(), &'static str> {
    if report.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("unsupported report schema");
    }
    if report
        .pointer("/candidate/revision")
        .and_then(Value::as_str)
        != Some(current.0)
        || report
            .pointer("/candidate/dirty_sha256")
            .and_then(Value::as_str)
            != Some(current.1)
    {
        return Err("stale candidate identity");
    }
    let definition = report
        .pointer("/gate/definition_sha256")
        .or_else(|| report.get("definition_sha256"))
        .and_then(Value::as_str);
    if definition != Some(evidence::APPROVED_DIGEST) {
        return Err("stale gate definition");
    }
    let checks = report
        .get("checks")
        .and_then(Value::as_array)
        .filter(|checks| !checks.is_empty())
        .ok_or("empty report")?;
    if checks.iter().any(|check| {
        check.get("executions").and_then(Value::as_u64).unwrap_or(0) == 0
            || check.get("passed").and_then(Value::as_bool) != Some(true)
    }) {
        return Err("failed or unexecuted check");
    }
    let verdict = report
        .get("verdict")
        .and_then(Value::as_str)
        .ok_or("missing verdict")?;
    if required == "foundation" {
        if report.get("command").and_then(Value::as_str)
            != Some("cargo run --locked -p qualification -- foundation")
            || verdict != "pass-for-foundation-scope"
        {
            return Err("foundation scope or verdict mismatch");
        }
    } else {
        if report.get("scope").and_then(Value::as_str) != Some(required)
            || !report
                .get("required_scope")
                .and_then(Value::as_array)
                .is_some_and(|scopes| scopes.iter().any(|scope| scope.as_str() == Some(required)))
            || verdict != "pass-for-dispatch-scope"
            || report.get("acceptance_claim").and_then(Value::as_bool) != Some(false)
        {
            return Err("dispatch scope or verdict mismatch");
        }
    }
    Ok(())
}

fn validate(path: &Path, required: &str) -> Result<(), &'static str> {
    let report = read_report(path)?;
    let current = evidence::candidate().ok_or("candidate identity unavailable")?;
    if !evidence::approved_definition() {
        return Err("gate definition approval unavailable");
    }
    validate_value(&report, required, (&current.0, &current.1))
}

pub fn run(args: &[String]) -> i32 {
    match args {
        [action, scope] if action == "run" => run_scope(scope),
        [action, path, flag, scope] if action == "validate" && flag == "--require" => {
            match validate(Path::new(path), scope) {
                Ok(()) => {
                    println!(
                        "{}",
                        serde_json::json!({"report":path, "required_scope":scope, "valid":true})
                    );
                    0
                }
                Err(error) => {
                    eprintln!("gate report rejected: {error}");
                    1
                }
            }
        }
        _ => {
            eprintln!(
                "usage: qualification gates run SCOPE | gates validate REPORT --require SCOPE"
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(verdict: &str, checks: Value) -> Value {
        serde_json::json!({
            "schema_version": 1,
            "candidate": {"revision": "revision", "dirty_sha256": "dirty"},
            "gate": {"definition_sha256": evidence::APPROVED_DIGEST},
            "command": "cargo run --locked -p qualification -- foundation",
            "checks": checks,
            "verdict": verdict,
        })
    }

    #[test]
    fn validity_rejects_empty_failed_inconclusive_and_stale_reports() {
        let good = serde_json::json!([{"executions":1,"passed":true}]);
        assert!(
            validate_value(
                &report("pass-for-foundation-scope", good.clone()),
                "foundation",
                ("revision", "dirty")
            )
            .is_ok()
        );
        assert_eq!(
            validate_value(
                &report("pass-for-foundation-scope", serde_json::json!([])),
                "foundation",
                ("revision", "dirty")
            ),
            Err("empty report")
        );
        assert_eq!(
            validate_value(
                &report("failed", good.clone()),
                "foundation",
                ("revision", "dirty")
            ),
            Err("foundation scope or verdict mismatch")
        );
        assert_eq!(
            validate_value(
                &report("inconclusive", good.clone()),
                "foundation",
                ("revision", "dirty")
            ),
            Err("foundation scope or verdict mismatch")
        );
        assert_eq!(
            validate_value(
                &report("pass-for-foundation-scope", good),
                "foundation",
                ("other", "dirty")
            ),
            Err("stale candidate identity")
        );
    }

    #[test]
    fn pending_hardware_scopes_are_not_executable() {
        for scope in ["smoke", "interop", "power-loss", "node", "operator", "load"] {
            assert_eq!(run_scope(scope), 1);
        }
    }
}
