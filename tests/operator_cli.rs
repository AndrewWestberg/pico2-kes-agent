mod support;

use serde_json::Value;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
use support::TestRig;

fn cli(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pico2-kes-agent-cli"))
        .args(arguments)
        .output()
        .unwrap()
}

fn strings(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).to_owned()).collect()
}

fn temporary(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pico2-kes-agent-{name}-{}", std::process::id()))
}

#[test]
fn executable_rejects_direct_usb_without_contacting_a_device() {
    let output = cli(&strings(&["--help"]));
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());

    let rejected = cli(&strings(&[
        "status",
        "--direct-usb",
        "/dev/bus/usb/001/001",
    ]));
    assert_eq!(rejected.status.code(), Some(2));
    assert!(!rejected.status.success());
}

#[test]
fn stalled_and_malformed_clients_do_not_block_valid_requests() {
    let rig = TestRig::certified_pool();
    let mut stalled = UnixStream::connect(rig.management_socket()).unwrap();
    stalled.write_all(&[0, 0]).unwrap();

    let started = Instant::now();
    let first = cli(&[
        "--socket".into(),
        rig.management_socket().display().to_string(),
        "--json".into(),
        "pool".into(),
        "list".into(),
    ]);
    assert!(first.status.success());
    assert!(started.elapsed() < Duration::from_secs(10));

    let mut malformed = UnixStream::connect(rig.management_socket()).unwrap();
    malformed.write_all(&u32::MAX.to_be_bytes()).unwrap();
    let started = Instant::now();
    let second = cli(&[
        "--socket".into(),
        rig.management_socket().display().to_string(),
        "--json".into(),
        "pool".into(),
        "list".into(),
    ]);
    assert!(second.status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn executable_reports_permission_unavailable_and_local_failure_exit_classes() {
    let missing = temporary("missing.sock");
    let unavailable = cli(&[
        "--socket".into(),
        missing.display().to_string(),
        "status".into(),
    ]);
    assert_eq!(unavailable.status.code(), Some(4));

    let receipt_directory = temporary("before-admission");
    let _ = fs::remove_dir_all(&receipt_directory);
    fs::create_dir(&receipt_directory).unwrap();
    fs::set_permissions(&receipt_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let receipt = receipt_directory.join("operation.json");
    let mutation_unavailable = cli(&[
        "--socket".into(),
        missing.display().to_string(),
        "key".into(),
        "generate".into(),
        "--pool".into(),
        "11".repeat(28),
        "--incarnation".into(),
        "22".repeat(16),
        "--operation-id".into(),
        "33".repeat(16),
        "--expected-revision".into(),
        "1".into(),
        "--receipt".into(),
        receipt.display().to_string(),
    ]);
    assert_eq!(mutation_unavailable.status.code(), Some(4));
    assert!(receipt.is_file());
    fs::remove_dir_all(receipt_directory).unwrap();

    let directory = temporary("denied");
    let socket = directory.join("management.sock");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o000)).unwrap();
    let denied = cli(&[
        "--socket".into(),
        socket.display().to_string(),
        "status".into(),
    ]);
    assert_eq!(denied.status.code(), Some(3));
    drop(listener);
    let _ = fs::remove_dir_all(&directory);

    let failed = cli(&strings(&[
        "restore",
        "--device",
        "00000000000000000000000000000000",
        "--pool",
        "00000000000000000000000000000000000000000000000000000000",
        "--incarnation",
        "00000000000000000000000000000000",
        "--generation",
        "00000000000000000000000000000000",
        "--verification-key",
        "/definitely/missing/pico2-kes.vkey",
        "--device-identity",
        "/definitely/missing/device.json",
        "--artifact",
        "/definitely/missing/artifact.bin",
        "--recipient-key",
        "/definitely/missing/recipient.key",
        "--out",
        "/definitely/missing/restored.skey",
    ]));
    assert_eq!(failed.status.code(), Some(7));
}

#[test]
fn executable_json_paginates_rejects_and_preserves_uncertain_receipt() {
    let mut rig = TestRig::commissioned_pool();
    let socket = rig.management_socket().display().to_string();
    let list = cli(&[
        "--socket".into(),
        socket.clone(),
        "--json".into(),
        "pool".into(),
        "list".into(),
        "--page-size".into(),
        "1".into(),
    ]);
    assert_eq!(list.status.code(), Some(0));
    assert!(list.stderr.is_empty());
    let listed: Value = serde_json::from_slice(&list.stdout).unwrap();
    let pool = &listed["result"]["pools"][0];
    let pool_id = pool["pool_id"].as_str().unwrap().to_owned();
    let incarnation = pool["incarnation_id"].as_str().unwrap().to_owned();

    let rejected_output = temporary("rejected-artifact.bin");
    let _ = fs::remove_file(&rejected_output);
    let unknown = cli(&[
        "--socket".into(),
        socket.clone(),
        "--json".into(),
        "key".into(),
        "export".into(),
        "--pool".into(),
        pool_id.clone(),
        "--incarnation".into(),
        incarnation.clone(),
        "--generation".into(),
        "00".repeat(16),
        "--out".into(),
        rejected_output.display().to_string(),
    ]);
    assert_eq!(unknown.status.code(), Some(5));
    let rejected: Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(rejected["outcome"], "rejected");
    assert!(!rejected_output.exists());

    let status = cli(&[
        "--socket".into(),
        socket.clone(),
        "--json".into(),
        "pool".into(),
        "status".into(),
        "--pool".into(),
        pool_id.clone(),
    ]);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    let revision = status["result"]["revision"].as_u64().unwrap().to_string();
    let receipt_directory = temporary("uncertain");
    let _ = fs::remove_dir_all(&receipt_directory);
    fs::create_dir(&receipt_directory).unwrap();
    fs::set_permissions(&receipt_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let receipt = receipt_directory.join("receipt.json");
    rig.timeout_next_usb_reply();
    let uncertain = cli(&[
        "--socket".into(),
        socket,
        "--json".into(),
        "key".into(),
        "generate".into(),
        "--pool".into(),
        pool_id,
        "--incarnation".into(),
        incarnation,
        "--operation-id".into(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        "--expected-revision".into(),
        revision,
        "--receipt".into(),
        receipt.display().to_string(),
    ]);
    assert_eq!(
        uncertain.status.code(),
        Some(6),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&uncertain.stdout),
        String::from_utf8_lossy(&uncertain.stderr)
    );
    assert!(receipt.is_file());
    assert!(String::from_utf8_lossy(&uncertain.stderr).contains("operation reconcile"));
    fs::remove_dir_all(receipt_directory).unwrap();
}

#[test]
fn destructive_commands_name_target_and_require_confirmation_before_contact() {
    let receipt = temporary("unused-receipt.json");
    let output = cli(&[
        "--socket".into(),
        "/definitely/missing/socket".into(),
        "key".into(),
        "discard".into(),
        "--pool".into(),
        "11".repeat(28),
        "--incarnation".into(),
        "22".repeat(16),
        "--generation".into(),
        "33".repeat(16),
        "--operation-id".into(),
        "44".repeat(16),
        "--expected-revision".into(),
        "1".into(),
        "--receipt".into(),
        receipt.display().to_string(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(&"33".repeat(16)));
    assert!(error.contains("external copies are unaffected"));
    assert!(error.contains("--yes"));
    assert!(!Path::new(&receipt).exists());
}
