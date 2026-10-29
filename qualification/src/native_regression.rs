use crate::evidence;
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

#[derive(Deserialize)]
struct Inventory {
    sources: Sources,
}

#[derive(Deserialize)]
struct Sources {
    cardano_node: Source,
    ouroboros_consensus: Source,
}

#[derive(Deserialize)]
struct Source {
    root: String,
    revision: String,
}

pub fn run() -> i32 {
    match execute() {
        Ok((true, report)) => {
            println!("native compatibility passed: {}", report.display());
            0
        }
        Ok((false, report)) => {
            eprintln!("native compatibility failed: {}", report.display());
            1
        }
        Err(error) => {
            eprintln!("native compatibility error: {error}");
            1
        }
    }
}

fn execute() -> Result<(bool, PathBuf), String> {
    let inventory_bytes = fs::read(Path::new(ROOT).join("qualification/native-sources.json"))
        .map_err(|error| format!("cannot read native inventory: {error}"))?;
    let inventory: Inventory =
        serde_json::from_slice(&inventory_bytes).map_err(|_| "invalid native inventory")?;
    let node_root = Path::new(&inventory.sources.cardano_node.root);
    let consensus_root = Path::new(&inventory.sources.ouroboros_consensus.root);
    let node_pinned =
        revision(node_root).as_deref() == Some(inventory.sources.cardano_node.revision.as_str());
    let consensus_pinned = revision(consensus_root).as_deref()
        == Some(inventory.sources.ouroboros_consensus.revision.as_str());

    let build_started = Instant::now();
    let native_build = node_pinned
        && consensus_pinned
        && status(
            "cabal",
            &["build", "--offline", "cardano-node:exe:cardano-node"],
            node_root,
        );
    let build_elapsed = build_started.elapsed().as_secs_f64();
    let service_started = Instant::now();
    let service_protocol = status(
        "cargo",
        &["test", "--locked", "--test", "node_service"],
        Path::new(ROOT),
    );
    let service_elapsed = service_started.elapsed().as_secs_f64();
    let passed = native_build && service_protocol;
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let report = json!({
        "schema_version": 1,
        "candidate": {"revision": revision, "dirty_sha256": dirty},
        "scope": "pinned native build and node-service V2 compatibility",
        "checks": [
            {
                "name": "pinned-native-node-build",
                "executions": 1,
                "pinned_node_source": node_pinned,
                "pinned_consensus_source": consensus_pinned,
                "elapsed_seconds": build_elapsed,
                "passed": native_build
            },
            {
                "name": "node-service-protocol-regressions",
                "executions": 1,
                "elapsed_seconds": service_elapsed,
                "passed": service_protocol
            }
        ],
        "verdict": if passed {"pass"} else {"failed"},
        "acceptance_claim": passed,
        "limitations": "Compilation and protocol regressions do not claim peer-accepted blocks or a supplied-leadership campaign."
    });
    let path = Path::new(ROOT)
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("native/report.json");
    let bytes = serde_json::to_vec_pretty(&report).map_err(|_| "cannot encode native report")?;
    evidence::atomic_write(&path, &bytes).map_err(|error| error.to_string())?;
    Ok((passed, path))
}

fn status(program: &str, arguments: &[&str], directory: &Path) -> bool {
    Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn revision(directory: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(directory)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}
