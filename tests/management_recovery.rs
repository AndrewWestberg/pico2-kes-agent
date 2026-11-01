mod support;

use pico2_kes_agent::cli::{client, receipt};
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

fn lose_management_response(rig: &TestRig) {
    let mut saved = receipt::load(rig.receipt_path()).unwrap();
    saved.response = None;
    std::fs::write(rig.receipt_path(), serde_json::to_vec(&saved).unwrap()).unwrap();
}

#[test]
fn absent_device_does_not_admit_an_intent_and_same_receipt_can_be_retried() {
    let mut rig = TestRig::commissioned_pool();
    let before = rig.journal_state();
    rig.disconnect_device();
    assert_eq!(rig.generate_cli(OPERATION).exit_code, 4);
    assert_eq!(rig.journal_state(), before);
    rig.reopen_journal();
    assert_eq!(rig.journal_state(), before);
    rig.reconnect_device();
    let result = success(rig.reconcile_cli());
    assert_eq!(result["result"]["kind"], "generated");
    assert_eq!(rig.generation_count(), 1);
    assert_eq!(rig.journal_state(), (before.0 + 1, false));
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
        assert_eq!(
            result["result"]["generation_id"],
            recovered["outcome"]["result"]["generation_id"]
        );
        assert_eq!(rig.generation_count(), 1);
    }
}

#[test]
fn lost_completed_response_replays_original_result_after_restart_without_usb() {
    let rig = TestRig::commissioned_pool();
    let original = success(rig.generate_cli(OPERATION));
    let after = rig.journal_state();
    lose_management_response(&rig);
    rig.reopen_journal();
    rig.disconnect_device();
    let recovered = success(rig.reconcile_cli());
    assert_eq!(recovered["result"], original["result"]);
    assert_eq!(rig.journal_state(), after);

    let mut request = receipt::load(rig.receipt_path()).unwrap().request;
    request["request_id"] = "11111111111111111111111111111111".into();
    let replay: Value = serde_json::from_slice(
        &client::request(
            rig.management_socket(),
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(replay["request_id"], request["request_id"]);
    assert_eq!(replay["result"], original["result"]);
    assert_eq!(rig.journal_state(), after);
}

#[test]
fn lost_pending_response_reconciles_original_generation_instead_of_readmitting() {
    let mut rig = TestRig::commissioned_pool();
    let before = rig.journal_state().0;
    rig.timeout_next_usb_reply();
    assert_eq!(rig.generate_cli(OPERATION).exit_code, 6);
    assert_eq!(rig.generation_count(), 1);
    lose_management_response(&rig);
    rig.reopen_journal();
    rig.timeout_next_ack_reply();
    assert_eq!(rig.reconcile_cli().exit_code, 6);
    assert_eq!(rig.journal_state(), (before, true));
    let recovered = success(rig.reconcile_cli());
    assert_eq!(recovered["result"]["kind"], "generated");
    assert_eq!(recovered["result"]["sequence"], before);
    assert_eq!(rig.generation_count(), 1);
    assert_eq!(rig.journal_state(), (before + 1, false));
}

#[test]
fn admitted_generation_resumes_before_and_after_device_commit() {
    for after_commit in [false, true] {
        let mut rig = TestRig::commissioned_pool();
        let before = rig.journal_state().0;
        rig.cut_mutation(after_commit);
        assert_eq!(rig.generate_cli(OPERATION).exit_code, 6);
        assert_eq!(rig.generation_count(), usize::from(after_commit));
        rig.reboot_device();
        let result = success(rig.reconcile_cli());
        assert_eq!(result["result"]["kind"], "generated");
        assert_eq!(rig.generation_count(), 1);
        assert_eq!(rig.journal_state(), (before + 1, false));
    }
}

#[test]
fn failed_ack_persistence_cannot_be_mistaken_for_a_durable_ack() {
    let mut rig = TestRig::commissioned_pool();
    let before = rig.journal_state().0;
    rig.fail_next_ack_persistence();
    assert_eq!(rig.generate_cli(OPERATION).exit_code, 6);
    assert!(rig.journal_state().1);
    assert_ne!(rig.reconcile_cli().exit_code, 0);
    assert_eq!(rig.journal_state(), (before, true));
    rig.reboot_device();
    let result = success(rig.reconcile_cli());
    assert_eq!(result["result"]["kind"], "generated");
    assert_eq!(rig.generation_count(), 1);
    assert_eq!(rig.journal_state(), (before + 1, false));
}

#[test]
fn operation_id_cannot_be_reused_with_changed_revision_action_or_target() {
    for pending in [false, true] {
        let mut rig = TestRig::commissioned_pool();
        if pending {
            rig.timeout_next_usb_reply();
        }
        let first = rig.generate_cli(OPERATION);
        assert_eq!(first.exit_code, if pending { 6 } else { 0 });
        let saved = receipt::load(rig.receipt_path()).unwrap();
        let before = rig.journal_state();
        for changed in ["revision", "action", "target"] {
            let mut request = saved.request.clone();
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
        let recovered = success(rig.reconcile_cli());
        assert_eq!(recovered["result"]["kind"], "generated");
    }
}
