mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;
use support::TestRig;

fn p2kes(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_p2kes"))
        .args(args)
        .output()
        .expect("spawn p2kes")
}

#[test]
fn help_and_version_work_standalone() {
    let help = p2kes(&["--help"]);
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("status"));
    assert!(stdout.contains("rotate"));
    assert!(stdout.contains("reconcile"));

    let ver = p2kes(&["--version", "--json"]);
    assert!(ver.status.success());
    let v: Value = serde_json::from_slice(&ver.stdout).unwrap();
    assert!(v.get("version").is_some());
}

#[test]
fn status_json_reports_device_and_pools() {
    let rig = TestRig::commissioned_pool();
    let res = rig.status_cli();
    assert_eq!(res.exit_code, 0, "{}", String::from_utf8_lossy(&res.stderr));
    let v: Value = serde_json::from_slice(&res.stdout).unwrap();
    assert!(v.get("revision").is_some());
    assert_eq!(v["pools"].as_array().unwrap().len(), 1);
}

#[test]
fn key_rotate_writes_vkey_and_backup_and_refuses_clobber() {
    let rig = TestRig::commissioned_pool();
    let status: Value = serde_json::from_slice(&rig.status_cli().stdout).unwrap();
    let pool_id = status["pools"][0]["pool_id"].as_str().unwrap().to_owned();
    let dir = rig.receipt_path().parent().unwrap();
    let vkey = dir.join("op-vkey");
    let backup = dir.join("op-backup");
    let _ = std::fs::remove_file(&vkey);
    let _ = std::fs::remove_file(&backup);

    let res = rig.run_cli(vec![
        "key".into(),
        "rotate".into(),
        pool_id.clone(),
        "--vkey-out".into(),
        vkey.display().to_string(),
        "--backup-out".into(),
        backup.display().to_string(),
    ]);
    assert_eq!(res.exit_code, 0, "{}", String::from_utf8_lossy(&res.stderr));
    assert!(vkey.exists());
    assert!(backup.exists());

    let res2 = rig.run_cli(vec![
        "key".into(),
        "rotate".into(),
        pool_id,
        "--vkey-out".into(),
        vkey.display().to_string(),
        "--backup-out".into(),
        backup.display().to_string(),
    ]);
    assert_ne!(res2.exit_code, 0);
}

#[test]
fn destructive_commands_require_confirmation() {
    let rig = TestRig::commissioned_pool();
    let status: Value = serde_json::from_slice(&rig.status_cli().stdout).unwrap();
    let pool_id = status["pools"][0]["pool_id"].as_str().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_p2kes"))
        .args([
            "--socket",
            rig.management_socket().to_str().unwrap(),
            "pool",
            "rm",
            pool_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let after: Value = serde_json::from_slice(&rig.status_cli().stdout).unwrap();
    assert_eq!(after["pools"].as_array().unwrap().len(), 1);
}

#[test]
fn missing_socket_and_unknown_command_fail_closed() {
    let missing = p2kes(&["--socket", "/nonexistent/p2kes.sock", "status"]);
    assert!(!missing.status.success());

    let unknown = p2kes(&["--socket", "/nonexistent/p2kes.sock", "bogus-cmd"]);
    assert!(!unknown.status.success());
}
