//! Single-pool lifecycle tests exercising `p2kes` against a daemon backed by
//! disposable, faultable persistent storage.
mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;
use support::TestRig;

fn json_out(res: support::CliResult) -> Value {
    assert_eq!(
        res.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    serde_json::from_slice(&res.stdout).unwrap()
}

#[test]
fn status_reports_commissioned_pool_and_revision() {
    let rig = TestRig::commissioned_pool();
    let v = json_out(rig.status_cli());
    assert!(v.get("revision").is_some());
    let pools = v["pools"].as_array().unwrap();
    assert_eq!(pools.len(), 1);
    assert!(pools[0].get("pool_id").is_some());
    assert!(pools[0].get("incarnation_id").is_some());
}
fn key_rotate_writes_vkey_and_backup() {
    let rig = TestRig::commissioned_pool();
    let status = json_out(rig.status_cli());
    let pool_id = status["pools"][0]["pool_id"].as_str().unwrap().to_owned();
    let dir = rig.receipt_path().parent().unwrap();
    let vkey = dir.join("sp-vkey");
    let backup = dir.join("sp-backup");
    let _ = std::fs::remove_file(&vkey);
    let _ = std::fs::remove_file(&backup);

    let rot = json_out(rig.run_cli(vec![
        "key".into(),
        "rotate".into(),
        pool_id,
        "--vkey-out".into(),
        vkey.display().to_string(),
        "--backup-out".into(),
        backup.display().to_string(),
    ]));
    assert!(rot.get("generation_id").is_some());
    assert!(vkey.exists());
    assert!(backup.exists());
}
#[test]
fn pool_rm_removes_pool_after_confirmation() {
    let rig = TestRig::commissioned_pool();
    let status = json_out(rig.status_cli());
    let pool_id = status["pools"][0]["pool_id"].as_str().unwrap().to_owned();

    let mut child = Command::new(env!("CARGO_BIN_EXE_p2kes"))
        .args([
            "--socket",
            rig.management_socket().to_str().unwrap(),
            "pool",
            "rm",
            &pool_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = json_out(rig.status_cli());
    assert_eq!(after["pools"].as_array().unwrap().len(), 0);
}

#[test]
fn reconcile_is_noop_when_idle() {
    let rig = TestRig::commissioned_pool();
    let res = json_out(rig.reconcile_cli());
    assert_eq!(res["reconciled"], false);
}
