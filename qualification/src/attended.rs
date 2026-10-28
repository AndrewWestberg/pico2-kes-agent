use crate::{evidence, fixture};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const RECOVERY_LIMIT: Duration = Duration::from_secs(60);
const OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Serialize)]
struct Observation {
    operation: String,
    expected_outcome: String,
    before_revision: u64,
    after_revision: u64,
    before_status_sha256: String,
    after_status_sha256: String,
    reconciliation_outcome: Option<String>,
    passed: bool,
}

struct Status {
    device_id: String,
    revision: u64,
    bytes: Vec<u8>,
}

pub fn run(arguments: &[String]) -> i32 {
    let (fixture_path, cuts) = match arguments {
        [fixture_flag, fixture_path, cuts_flag, cuts]
            if fixture_flag == "--fixture" && cuts_flag == "--cuts" =>
        {
            let Ok(cuts) = cuts.parse::<usize>() else {
                eprintln!("attended cuts: --cuts must be 10");
                return 2;
            };
            (Path::new(fixture_path), cuts)
        }
        _ => {
            eprintln!("usage: qualification attended-cuts --fixture FIXTURE --cuts 10");
            return 2;
        }
    };
    if cuts != 10 {
        eprintln!("attended cuts: the approved campaign requires exactly 10 cuts");
        return 2;
    }
    match execute(fixture_path) {
        Ok(report) => {
            println!("{}", report.display());
            0
        }
        Err(error) => {
            eprintln!("attended cuts: {error}");
            1
        }
    }
}

fn execute(fixture_path: &Path) -> Result<PathBuf, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("an attached operator terminal is required".to_owned());
    }
    let fixture_bytes = bounded_file(fixture_path)?;
    let fixture = fixture::parse_fixture(&fixture_bytes).map_err(|error| error.to_string())?;
    fixture
        .validate_prerequisites()
        .map_err(|error| error.to_string())?;
    let attended = fixture
        .attended
        .as_ref()
        .ok_or("fixture has no attended campaign configuration")?;
    if !fixture
        .power_controller
        .eq_ignore_ascii_case("manual-usb-hub")
    {
        return Err(
            "power_controller must be manual-usb-hub; no automated cut is permitted".into(),
        );
    }
    validate_hardware_report(Path::new(&attended.hardware_report))?;
    check_config(&fixture.daemon.path, &attended.commissioning_config, true)?;
    check_config(&fixture.daemon.path, &attended.normal_config, false)?;

    println!(
        "Attended 10-cut campaign on hub '{}'. The runner never controls power.",
        attended.usb_hub_label
    );
    println!("Use only the disposable fixture named by the validated document.");
    confirm("Type READY and press Enter to start: ", "READY")?;

    let mut baseline = status(&fixture.cli.path, &attended.management_socket)?;
    let device_id = baseline.device_id.clone();
    let mut observations = Vec::with_capacity(10);
    for (index, step) in attended.cut_plan.iter().enumerate() {
        if let Some(receipt) = &step.receipt
            && Path::new(receipt).exists()
        {
            return Err(format!("cut {} receipt already exists", index + 1));
        }
        println!("\nCut {}/10: {}", index + 1, step.operation);
        println!(
            "In the operation terminal, start the predeclared {} action{}.",
            step.operation,
            step.receipt
                .as_ref()
                .map_or(String::new(), |path| format!(" using receipt {path}"))
        );
        confirm(
            "When the operation has started, type ARMED and press Enter: ",
            "ARMED",
        )?;
        confirm(
            "Press the USB-hub power button OFF, then type OFF and press Enter: ",
            "OFF",
        )?;
        confirm(
            "Press the USB-hub power button ON, then type ON and press Enter: ",
            "ON",
        )?;

        let recovered =
            wait_for_status(&fixture.cli.path, &attended.management_socket, &device_id)?;
        if recovered.revision < baseline.revision {
            return Err(format!(
                "cut {} rolled the device revision backward",
                index + 1
            ));
        }
        let reconciliation_outcome = step
            .receipt
            .as_ref()
            .map(|receipt| {
                reconcile(
                    &fixture.cli.path,
                    &attended.management_socket,
                    receipt,
                    &step.expected_outcome,
                )
            })
            .transpose()?;
        observations.push(Observation {
            operation: step.operation.clone(),
            expected_outcome: step.expected_outcome.clone(),
            before_revision: baseline.revision,
            after_revision: recovered.revision,
            before_status_sha256: digest(&baseline.bytes),
            after_status_sha256: digest(&recovered.bytes),
            reconciliation_outcome,
            passed: true,
        });
        baseline = recovered;
    }

    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let report = serde_json::json!({
        "schema_version": 1,
        "candidate": { "revision": revision, "dirty_sha256": dirty },
        "gate": {
            "definition_sha256": evidence::APPROVED_DIGEST,
            "scope": "ten attended physical USB-hub cuts"
        },
        "command": "cargo run --locked -p qualification -- attended-cuts --fixture <validated> --cuts 10",
        "power_control": "operator pressed the physical USB-hub button; no automated controller",
        "device_id": device_id,
        "cuts": observations,
        "cut_count": observations.len(),
        "verdict": "pass-for-attended-cut-scope",
        "acceptance_claim": false,
        "remaining_evidence": [
            "software persistent-boundary campaign",
            "operation-specific signing and publication oracles",
            "obsolete-region erase/read verification",
            "same-candidate G8 aggregation"
        ]
    });
    let path = Path::new(ROOT)
        .parent()
        .ok_or("repository path unavailable")?
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("G8/attended-cuts.json");
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    evidence::atomic_write(&path, &bytes).map_err(|error| error.to_string())?;
    Ok(path)
}

fn validate_hardware_report(path: &Path) -> Result<(), String> {
    let bytes = bounded_file(path)?;
    let report: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid hardware report")?;
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    if report["verdict"] != "pass"
        || report["enrollment_acceptance"] != "eligible for T044 physical commissioning"
        || report["gate"]["definition_sha256"] != evidence::APPROVED_DIGEST
        || report["gate"]["definition_and_storage_approved"] != true
        || report["candidate"]["revision"] != revision
        || report["candidate"]["dirty_sha256"] != dirty
    {
        return Err("hardware report is not a passing reading for the current candidate".into());
    }
    Ok(())
}

fn check_config(daemon: &str, config: &str, commissioning: bool) -> Result<(), String> {
    let mut command = Command::new(daemon);
    command.args(["--config", config, "--check-config"]);
    if commissioning {
        command.arg("--commission");
    }
    let status = command
        .status()
        .map_err(|error| format!("cannot check daemon configuration: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("daemon configuration check failed".into())
    }
}

fn status(cli: &str, socket: &str) -> Result<Status, String> {
    let output = Command::new(cli)
        .args(["--socket", socket, "--json", "status"])
        .output()
        .map_err(|error| format!("cannot execute status command: {error}"))?;
    if !output.status.success() || output.stdout.len() > OUTPUT_LIMIT {
        return Err("device status unavailable".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "status command returned invalid JSON")?;
    if value["outcome"] != "success" {
        return Err("status command did not report success".into());
    }
    let result = &value["result"];
    let device_id = result["device_id"]
        .as_str()
        .filter(|value| value.len() == 32)
        .ok_or("status has no valid device identity")?
        .to_owned();
    let revision = result["revision"]
        .as_u64()
        .ok_or("status has no device revision")?;
    Ok(Status {
        device_id,
        revision,
        bytes: output.stdout,
    })
}

fn wait_for_status(cli: &str, socket: &str, device_id: &str) -> Result<Status, String> {
    let deadline = Instant::now() + RECOVERY_LIMIT;
    loop {
        if let Ok(status) = status(cli, socket) {
            if status.device_id != device_id {
                return Err("a different device appeared after the cut".into());
            }
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("device did not recover within 60 seconds".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn reconcile(cli: &str, socket: &str, receipt: &str, expected: &str) -> Result<String, String> {
    let output = Command::new(cli)
        .args([
            "--socket",
            socket,
            "--json",
            "operation",
            "reconcile",
            "--receipt",
            receipt,
        ])
        .output()
        .map_err(|error| format!("cannot reconcile operation: {error}"))?;
    if output.stdout.len() > OUTPUT_LIMIT {
        return Err("reconciliation output exceeds limit".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "reconciliation returned invalid JSON")?;
    let observed = value["outcome"]
        .as_str()
        .ok_or("reconciliation has no outcome")?;
    let expected_exit = if expected == "success" { 0 } else { 5 };
    if observed != expected || output.status.code() != Some(expected_exit) {
        return Err(format!(
            "reconciliation outcome mismatch: expected {expected}, observed {observed}"
        ));
    }
    Ok(observed.to_owned())
}

fn bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err("input must be a regular non-symlink file no larger than 1 MiB".into());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn confirm(prompt: &str, expected: &str) -> Result<(), String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    if response.trim() == expected {
        Ok(())
    } else {
        Err(format!("expected explicit operator response {expected}"))
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
