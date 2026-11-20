mod support;

use pico2_kes_agent::cli::client;
use serde_json::Value;
use support::{CliResult, TestRig};

const OPERATION: &str = "00112233445566778899aabbccddeeff";

fn success(result: CliResult) -> Value {
    assert_eq!(
        result.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}


#[test]
fn absent_device_does_not_admit_an_intent_and_reconcile_is_noop() {
    let mut rig = TestRig::commissioned_pool();
    let before = rig.journal_state();
    rig.disconnect_device();
    assert_ne!(rig.generate_cli(OPERATION).exit_code, 0);
    assert_eq!(rig.journal_state(), before);
    rig.reopen_journal();
    assert_eq!(rig.journal_state(), before);
    rig.reconnect_device();
    let result = success(rig.reconcile_cli());
    assert_eq!(result["reconciled"], false);
    assert_eq!(rig.generation_count(), 0);
    assert_eq!(rig.journal_state(), before);
}

#[test]
fn restart_before_usb_dispatch_recovers_both_durable_write_boundaries() {
    for include_device_request in [false, true] {
        let mut rig = TestRig::commissioned_pool();
        let before = rig.journal_state().0;
        rig.stage_unsent_generation(OPERATION, include_device_request);
        assert_eq!(rig.journal_state(), (before, true));
        assert_eq!(rig.generation_count(), 0);
        let recovered = rig.reconcile_pending_unattended().unwrap().unwrap();
        assert_eq!(recovered["outcome"]["result"]["kind"], "generated");
        assert_eq!(recovered["sequence"], before);
        assert_eq!(rig.journal_state(), (before + 1, false));
        let result = success(rig.reconcile_cli());
        assert_eq!(result["reconciled"], false);
        assert_eq!(rig.generation_count(), 1);
    }
}

#[test]
fn lost_pending_response_reconciles_original_generation_instead_of_readmitting() {
    let mut rig = TestRig::commissioned_pool();
    let before = rig.journal_state().0;
    rig.timeout_next_usb_reply();
    assert_ne!(rig.generate_cli(OPERATION).exit_code, 0);
    assert_eq!(rig.generation_count(), 1);
    rig.reopen_journal();
    rig.timeout_next_ack_reply();
    assert_ne!(rig.reconcile_cli().exit_code, 0);
    assert_eq!(rig.journal_state(), (before, true));
    let recovered = success(rig.reconcile_cli());
    assert_eq!(rig.generation_count(), 1);
    assert_eq!(rig.journal_state(), (before + 1, false));
}

#[test]
fn export_never_overwrites_existing_artifact() {
    let mut rig = TestRig::commissioned_pool();
    let status = success(rig.status_cli());
    let pool_id = status["pools"][0]["pool_id"].as_str().unwrap().to_owned();
    let vkey_path = rig.receipt_path().with_file_name("retained-vkey");
    let backup_path = rig.receipt_path().with_file_name("retained-backup");
    let _ = std::fs::remove_file(&vkey_path);
    let _ = std::fs::remove_file(&backup_path);
    let res = rig.run_cli(vec![
        "key".into(),
        "rotate".into(),
        pool_id.clone(),
        "--vkey-out".into(),
        vkey_path.display().to_string(),
        "--backup-out".into(),
        backup_path.display().to_string(),
    ]);
    assert_eq!(res.exit_code, 0, "{}", String::from_utf8_lossy(&res.stderr));
    let original = std::fs::read(&backup_path).unwrap();
    let res2 = rig.run_cli(vec![
        "key".into(),
        "rotate".into(),
        pool_id,
        "--vkey-out".into(),
        vkey_path.display().to_string(),
        "--backup-out".into(),
        backup_path.display().to_string(),
    ]);
    assert_ne!(res2.exit_code, 0);
    assert_eq!(std::fs::read(&backup_path).unwrap(), original);
}
#[test]
fn admitted_generation_resumes_before_and_after_device_commit() {
    for after_commit in [false, true] {
        let mut rig = TestRig::commissioned_pool();
        let before = rig.journal_state().0;
        rig.cut_mutation(after_commit);
        assert_ne!(rig.generate_cli(OPERATION).exit_code, 0);
        assert_eq!(rig.generation_count(), usize::from(after_commit));
        rig.reboot_device();
        let result = success(rig.reconcile_cli());
        assert_eq!(rig.generation_count(), 1);
        assert_eq!(rig.journal_state(), (before + 1, false));
    }
}

#[test]
fn failed_ack_persistence_cannot_be_mistaken_for_a_durable_ack() {
    let mut rig = TestRig::commissioned_pool();
    let before = rig.journal_state().0;
    rig.fail_next_ack_persistence();
    assert_ne!(rig.generate_cli(OPERATION).exit_code, 0);
    assert!(rig.journal_state().1);
    assert_ne!(rig.reconcile_cli().exit_code, 0);
    assert_eq!(rig.journal_state(), (before, true));
    rig.reboot_device();
    let result = success(rig.reconcile_cli());
    assert_eq!(rig.generation_count(), 1);
    assert_eq!(rig.journal_state(), (before + 1, false));
}

#[test]
fn operation_id_cannot_be_reused_with_changed_revision_action_or_target() {
    for pending in [false, true] {
        let mut rig = TestRig::commissioned_pool();
        let status = success(rig.status_cli());
        let pool = &status["pools"][0];
        let base_request = serde_json::json!({
            "version": 1,
            "request_id": "11111111111111111111111111111111",
            "action": "generation.create",
            "expected_revision": pool["revision"],
            "operation_id": OPERATION,
            "arguments": {
                "pool_id": pool["pool_id"],
                "incarnation_id": pool["incarnation_id"],
            }
        });
        if pending {
            rig.timeout_next_usb_reply();
            let _ = client::request(rig.management_socket(), &serde_json::to_vec(&base_request).unwrap()).unwrap();
        } else {
            let first: Value = serde_json::from_slice(
                &client::request(rig.management_socket(), &serde_json::to_vec(&base_request).unwrap()).unwrap(),
            ).unwrap();
            assert_eq!(first["outcome"], "success", "{first}");
        }
        let before = rig.journal_state();
        for changed in ["revision", "action", "target"] {
            let mut request = base_request.clone();
            match changed {
                "revision" => request["expected_revision"] = 99.into(),
                "action" => {
                    request["action"] = "pool.delete".into();
                }
                "target" => {
                    request["arguments"]["incarnation_id"] = "22".repeat(16).into();
                }
                _ => unreachable!(),
            }
            let response: Value = serde_json::from_slice(
                &client::request(
                    rig.management_socket(),
                    &serde_json::to_vec(&request).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                response["error"]["code"], "operation_conflict",
                "{changed}: {response}"
            );
            assert_eq!(rig.journal_state(), before);
            assert_eq!(rig.generation_count(), 1);
        }
        if pending {
            let recovered = success(rig.reconcile_cli());
        }
    }
}
