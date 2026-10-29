mod support;

use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
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

#[test]
fn security_command_reports_observed_state_and_disallows_mutation_flags() {
    for mut rig in [
        TestRig::blank_commissioning("attended-board01"),
        TestRig::commissioned_pool(),
    ] {
        let socket = rig.management_socket().display().to_string();
        let args = ["--socket", &socket, "--json", "device", "security"];
        let output = cli(&strings(&args));
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        kes_protocol::management::Message::decode(&output.stdout).unwrap();
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["result"]["profile"], "unlocked");
        assert_eq!(response["result"]["stepping"], "A2");
        assert_eq!(response["result"]["usb_serial"], "00afd9003906a634");

        let mut report = rig.security_report();
        report.critical = 1;
        rig.set_security_report(Some(report));
        let output = cli(&strings(&args));
        assert_eq!(output.status.code(), Some(0));
        kes_protocol::management::Message::decode(&output.stdout).unwrap();
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["result"]["profile"], "incomplete");

        report.usb_serial[0] = b'G';
        rig.set_security_report(Some(report));
        assert!(!cli(&strings(&args)).status.success());
        rig.set_security_report(None);
        assert!(!cli(&strings(&args)).status.success());

        for (flag, value) in [
            ("--operation-id", "00000000000000000000000000000000"),
            ("--expected-revision", "0"),
            ("--receipt", "/tmp/not-created-security-receipt"),
            ("--usb-serial", "00afd9003906a634"),
        ] {
            let mut arguments = strings(&args);
            arguments.extend(strings(&[flag, value]));
            assert_eq!(cli(&arguments).status.code(), Some(2));
        }
    }
}

#[test]
fn executable_rejects_forged_or_malformed_security_replies() {
    let rig = TestRig::commissioned_pool();
    let output = cli(&strings(&[
        "--socket",
        rig.management_socket().to_str().unwrap(),
        "--json",
        "device",
        "security",
    ]));
    assert!(output.status.success());
    let baseline: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, (field, value)) in [
        ("profile", Value::String("rp2350-signed-msd-v1".into())),
        ("stepping", Value::String("A4".into())),
        ("bootkey0", Value::String("00".into())),
        ("critical", Value::from(0x1_0000_0000u64)),
        ("redundancy_ok", Value::from(1)),
        ("usb_serial", Value::String("00AFD9003906A634".into())),
        ("unexpected", Value::Bool(true)),
    ]
    .into_iter()
    .enumerate()
    {
        let path = temporary(&format!("forged-security-{index}.sock"));
        let listener = UnixListener::bind(&path).unwrap();
        let mut forged = baseline.clone();
        forged["result"][field] = value;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).unwrap();
            let request: Value = serde_json::from_slice(&request).unwrap();
            forged["request_id"] = request["request_id"].clone();
            let bytes = serde_json::to_vec(&forged).unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
        });
        let output = cli(&strings(&[
            "--socket",
            path.to_str().unwrap(),
            "--json",
            "device",
            "security",
        ]));
        assert_eq!(output.status.code(), Some(7), "malformed field {field}");
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }
}
