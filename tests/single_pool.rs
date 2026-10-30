//! Public management/CLI regressions against a daemon backed by disposable,
//! faultable persistent storage. The driver must execute real device and host
//! paths, not synthesize management replies.
mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use kes_protocol::management::{FrameDecoder, MAX_FRAME, Message};
use pico2_kes_agent::backup::{recipient, recover};
use serde_json::{Value, json};
use support::{Cut, TestRig};

const ID: &str = "00112233445566778899aabbccddeeff";

struct RecipientEntropy(u8);

impl recipient::Entropy for RecipientEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), recipient::Error> {
        for byte in output {
            self.0 = self.0.wrapping_mul(17).wrapping_add(29);
            *byte = self.0;
        }
        Ok(())
    }
}

fn management(rig: &TestRig, request: Value) -> Value {
    let json = serde_json::to_vec(&request).unwrap();
    let msg = Message::decode(&json).unwrap();
    let mut frame = [0; MAX_FRAME + 4];
    let n = msg.encode_frame(&mut frame).unwrap();
    let mut socket = UnixStream::connect(rig.management_socket()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for byte in &frame[..n] {
        socket.write_all(&[*byte]).unwrap();
    }
    let mut decoder = FrameDecoder::new();
    while decoder.frame().is_none() {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(decoder.feed(&byte).unwrap(), 1);
    }
    let bytes = decoder.frame().unwrap();
    Message::decode(bytes).unwrap();
    serde_json::from_slice(bytes).unwrap()
}

fn status(rig: &TestRig) -> Value {
    management(
        rig,
        json!({"version":1,"request_id":ID,"action":"device.status","arguments":{}}),
    )
}

#[test]
fn attended_commissioning_publishes_pin_and_normal_restart_authenticates_it() {
    let mut rig = TestRig::blank_commissioning("attended-board01");
    let blank = status(&rig);
    assert_eq!(blank["result"]["commissioning_state"], "blank");
    assert_eq!(blank["result"]["health"], "ready");
    assert!(blank["result"].get("device_id").is_none());
    assert!(blank["result"].get("revision").is_none());
    let cli = rig.status_cli();
    assert_eq!(cli.exit_code, 0);
    let cli_status: Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(cli_status["result"]["commissioning_state"], "blank");
    assert!(rig.pool_sockets().is_empty());
    let response = rig.commission_cli("attended-board01", ID);
    assert_eq!(response.exit_code, 0);
    let committed = status(&rig);
    assert_eq!(committed["result"]["commissioning_state"], "committed");
    assert!(committed["result"].get("device_id").is_some());
    assert!(committed["result"].get("revision").is_some());
    let pin_bytes = std::fs::read(rig.pin_record_path()).unwrap();
    let record: Value = serde_json::from_slice(&pin_bytes).unwrap();
    assert_eq!(record["version"], 1);
    assert_eq!(record["usb_serial"], "attended-board01");
    assert_eq!(record["operation_id"], ID);
    for (field, size) in [
        ("device_id", 32),
        ("identity_public_key", 64),
        ("identity_fingerprint", 64),
        ("request_digest", 64),
    ] {
        let value = record[field].as_str().unwrap();
        assert_eq!(value.len(), size, "{field}");
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
    assert!(record.get("private_key").is_none());
    assert!(record.get("storage_key").is_none());
    rig.restart_normal_with_pin().unwrap();
    assert_eq!(status(&rig)["outcome"], "success");
    rig.replace_connected_device_with_different_identity();
    assert_eq!(status(&rig)["error"]["code"], "wrong_device");
    assert_eq!(
        std::fs::read(rig.pin_record_path()).unwrap(),
        pin_bytes,
        "installed pin must never be silently replaced"
    );
}

#[test]
fn commissioning_lost_reply_reconciles_original_identity_and_no_clobber() {
    for cut in [
        Cut::AfterCommit,
        Cut::AfterCleanBeforeUsbReply,
        Cut::BeforePinPublication,
    ] {
        let mut rig = TestRig::blank_commissioning("attended-board01");
        rig.cut_next_commission(cut);
        let interrupted = rig.commission_cli("attended-board01", ID);
        assert!(matches!(interrupted.exit_code, 6 | 7));
        assert!(rig.receipt_path().exists());
        rig.restart_commissioning().unwrap();
        let reconciled = rig.reconcile_cli();
        assert_eq!(reconciled.exit_code, 0, "cut {cut:?}");
        let first = std::fs::read(rig.pin_record_path()).unwrap();
        let record: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(record["operation_id"], ID);
        assert_eq!(
            rig.reconcile_cli().exit_code,
            7,
            "existing output is no-clobber"
        );
        assert_eq!(std::fs::read(rig.pin_record_path()).unwrap(), first);
        assert_eq!(
            rig.commission_cli("attended-board01", "ffeeddccbbaa99887766554433221100")
                .exit_code,
            5
        );
        assert_eq!(std::fs::read(rig.pin_record_path()).unwrap(), first);
    }
}

#[test]
fn commissioning_rejects_wrong_selection_and_nonblank_partial_state() {
    let mut rig = TestRig::blank_commissioning("attended-board01");
    assert_eq!(rig.commission_cli("other-board", ID).exit_code, 5);
    assert!(!rig.pin_record_path().exists());
    drop(rig);
    let mut rig = TestRig::blank_commissioning("attended-board01");
    rig.cut_next_commission(Cut::PartialFirstWrite);
    assert_ne!(rig.commission_cli("attended-board01", ID).exit_code, 0);
    rig.restart_commissioning().unwrap();
    assert_ne!(rig.reconcile_cli().exit_code, 0);
    assert_ne!(status(&rig)["result"]["commissioning_state"], "blank");
    assert!(!rig.pin_record_path().exists());
}

#[test]
fn commissioning_status_fails_closed_on_bad_hello_and_disconnect() {
    let rig = TestRig::blank_commissioning("attended-board01");
    rig.stale_hello();
    assert_ne!(status(&rig)["outcome"], "success");

    let rig = TestRig::blank_commissioning("attended-board01");
    rig.malformed_hello();
    assert_ne!(status(&rig)["outcome"], "success");

    let rig = TestRig::blank_commissioning("attended-board01");
    rig.disconnect_device();
    let disconnected = status(&rig);
    assert_eq!(disconnected["result"]["health"], "disconnected");
    assert_ne!(disconnected["result"]["commissioning_state"], "blank");

    let rig = TestRig::blank_commissioning("attended-board01");
    rig.timeout_hello();
    let timeout = status(&rig);
    assert_eq!(timeout["result"]["health"], "disconnected");
    assert_ne!(timeout["result"]["commissioning_state"], "blank");
}

#[test]
fn status_distinguishes_disconnected_and_recovering_without_secret_fields() {
    let rig = TestRig::commissioned_pool();
    rig.disconnect_device();
    let disconnected = status(&rig);
    assert_eq!(disconnected["outcome"], "success");
    assert_eq!(disconnected["result"]["health"], "disconnected");
    assert!(disconnected["result"].get("state").is_none());

    let mut recovering_rig = TestRig::commissioned_pool();
    recovering_rig.timeout_next_usb_reply();
    assert_eq!(recovering_rig.generate_cli(ID).exit_code, 6);
    let recovering = status(&recovering_rig);
    assert_eq!(recovering["outcome"], "success");
    assert_eq!(recovering["result"]["health"], "recovering");
    assert!(recovering["result"].get("state").is_none());
}

#[test]
fn dispatched_timeout_is_uncertain_and_reconciles_same_generation() {
    let mut rig = TestRig::commissioned_pool();
    rig.timeout_next_usb_reply();
    let result = rig.generate_cli(ID);
    assert_eq!(result.exit_code, 6);
    assert!(rig.receipt_path().exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("operation reconcile"));
    let reconciled = rig.reconcile_cli();
    assert_eq!(reconciled.exit_code, 0);
    let first: Value = serde_json::from_slice(&reconciled.stdout).unwrap();
    let again: Value = serde_json::from_slice(&rig.reconcile_cli().stdout).unwrap();
    assert_eq!(
        first["result"]["generation_id"],
        again["result"]["generation_id"]
    );
    assert_eq!(rig.staged_generation_count(), 1);
}

#[test]
fn unattended_recovery_reconciles_pending_result_before_resuming() {
    let mut rig = TestRig::commissioned_pool();
    rig.timeout_next_usb_reply();
    assert_eq!(rig.generate_cli(ID).exit_code, 6);
    assert!(rig.journal_state().1);

    let reconciled = rig.reconcile_pending_unattended().unwrap().unwrap();
    assert_eq!(reconciled["outcome"]["result"]["kind"], "generated");
    assert!(!rig.journal_state().1);
    assert_eq!(rig.staged_generation_count(), 1);
}

#[test]
fn lost_acknowledgment_reply_reconciles_completed_mutation() {
    let mut rig = TestRig::commissioned_pool();
    rig.timeout_next_ack_reply();
    let interrupted = rig.generate_cli(ID);
    assert_eq!(interrupted.exit_code, 6);
    assert!(rig.receipt_path().exists());

    let reconciled = rig.reconcile_cli();
    assert_eq!(reconciled.exit_code, 0);
    assert_eq!(rig.staged_generation_count(), 1);
}

#[test]
fn lost_generation_and_activation_replies_reconcile_with_stable_export() {
    let mut rig = TestRig::commissioned_pool();
    rig.timeout_next_usb_reply();
    assert_eq!(rig.generate_cli(ID).exit_code, 6);
    let generated: Value = serde_json::from_slice(&rig.reconcile_cli().stdout).unwrap();
    let generation_id = generated["result"]["generation_id"].as_str().unwrap();
    let generation = rig.generation_from_id(generation_id);
    assert_eq!(rig.staged_generation_count(), 1);

    let first_export = rig.export_cli(&generation, "artifact-first.bin");
    assert_eq!(first_export.exit_code, 0);
    let retried_export = rig.export_cli(&generation, "artifact-retried.bin");
    assert_eq!(retried_export.exit_code, 0);
    assert_eq!(
        rig.read_file("artifact-first.bin"),
        rig.read_file("artifact-retried.bin")
    );

    let certificate = rig.certificate_for(&generation);
    rig.timeout_next_usb_reply();
    assert_eq!(
        rig.install_certificate_cli(&generation.id, &certificate)
            .exit_code,
        6
    );
    let receipt = rig.certificate_receipt_path();
    assert_eq!(rig.reconcile_receipt_cli(&receipt).exit_code, 0);
    rig.refresh_context().unwrap();
    assert_eq!(rig.current_usb_generation(), generation.id);

    rig.restart_device_and_refresh_context().unwrap();
    assert_eq!(rig.current_usb_generation(), generation.id);
}

#[test]
fn generate_after_staged_activation_preserves_current_and_exports() {
    use kes_protocol::usb::{CurrentResult, decode_current_response};

    let mut rig = TestRig::commissioned_pool();
    let a = rig
        .generate_with_operation("11111111111111111111111111111111")
        .unwrap();
    let certificate_a = rig.certificate_for(&a);
    assert_eq!(
        rig.install_certificate_cli(&a.id, &certificate_a).exit_code,
        0
    );
    rig.refresh_context().unwrap();
    assert_eq!(rig.current_usb_generation(), a.id);

    rig.remove_receipt();
    let b = rig
        .generate_with_operation("22222222222222222222222222222222")
        .unwrap();
    let certificate_b = rig.certificate_for(&b);
    assert_eq!(
        rig.install_certificate_cli(&b.id, &certificate_b).exit_code,
        0
    );
    // The fixture derives context sequence from period; start a fresh lease
    // before refreshing at the same period.
    rig.disconnect_usb();
    rig.refresh_context().unwrap();
    assert_eq!(rig.current_usb_generation(), b.id);

    assert_eq!(rig.export_cli(&b, "active-before.bin").exit_code, 0);
    let active_before = rig.read_file("active-before.bin");
    let current_payload = rig.current_usb_payload();
    let current_before = decode_current_response(&current_payload).unwrap();
    let (generation_before, period_before, state_before, certificate_before) =
        match current_before.result {
            CurrentResult::Key {
                generation,
                period,
                state,
                certificate,
            } => (generation, period, state, certificate),
            _ => panic!("current key unavailable"),
        };
    assert_eq!(generation_before.to_string(), b.id);

    rig.remove_receipt();
    let journal_before = rig.journal_state();
    assert!(!journal_before.1);
    let generated = rig.generate_cli("33333333333333333333333333333333");
    assert_eq!(
        generated.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&generated.stdout),
        String::from_utf8_lossy(&generated.stderr)
    );
    let response: Value = serde_json::from_slice(&generated.stdout).unwrap();
    let id = response["result"]["generation_id"].as_str().unwrap();
    assert_ne!(id, a.id);
    assert_ne!(id, b.id);
    let c = rig.generation_from_id(id);
    assert_eq!(rig.journal_state(), (journal_before.0 + 1, false));

    let payload_after = rig.current_usb_payload();
    let current_after = decode_current_response(&payload_after).unwrap();
    assert_eq!(current_after.target, current_before.target);
    assert_eq!(current_after.publication, current_before.publication);
    match current_after.result {
        CurrentResult::Key {
            generation,
            period,
            state,
            certificate,
        } => {
            assert_eq!(generation, generation_before);
            assert_eq!(period, period_before);
            assert_eq!(state, state_before);
            assert_eq!(certificate, certificate_before);
        }
        _ => panic!("current key unavailable after generation"),
    }
    assert_eq!(rig.export_cli(&b, "active-after.bin").exit_code, 0);
    assert_eq!(rig.read_file("active-after.bin"), active_before);
    assert_eq!(
        rig.export_cli(&c, "replacement-before-reboot.bin")
            .exit_code,
        0
    );
    let replacement_before = rig.read_file("replacement-before-reboot.bin");

    rig.restart_device_and_refresh_context().unwrap();
    let payload_rebooted = rig.current_usb_payload();
    let current_rebooted = decode_current_response(&payload_rebooted).unwrap();
    assert_eq!(current_rebooted.target, current_before.target);
    match current_rebooted.result {
        CurrentResult::Key {
            generation,
            period,
            state,
            certificate,
        } => {
            assert_eq!(generation, generation_before);
            assert_eq!(period, period_before);
            assert_eq!(state, state_before);
            assert_eq!(certificate, certificate_before);
        }
        _ => panic!("current key unavailable after reboot"),
    }
    assert_eq!(rig.export_cli(&b, "active-after-reboot.bin").exit_code, 0);
    assert_eq!(rig.read_file("active-after-reboot.bin"), active_before);
    assert_eq!(
        rig.export_cli(&c, "replacement-after-reboot.bin").exit_code,
        0
    );
    assert_eq!(
        rig.read_file("replacement-after-reboot.bin"),
        replacement_before
    );
}

#[test]
fn pre_admission_rejection_does_not_require_device_acknowledgment() {
    let rig = TestRig::commissioned_pool();
    let before = rig.journal_state();
    let rejected = rig.generate_cli_expected(ID, u64::MAX);
    assert_eq!(rejected.exit_code, 5);
    assert_eq!(rig.journal_state(), before);
    rig.remove_receipt();

    let accepted = rig.generate_cli("ffeeddccbbaa99887766554433221100");
    assert_eq!(
        accepted.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );
}

#[test]
fn retained_artifact_is_stable_and_retirement_is_distinct_from_unknown_generation() {
    let mut rig = TestRig::commissioned_pool();
    let generation = rig.generate_with_cli().unwrap();

    let first = rig.export_cli(&generation, "artifact-first.bin");
    let second = rig.export_cli(&generation, "artifact-second.bin");
    assert_eq!(
        first.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(second.exit_code, 0);
    assert_eq!(
        rig.read_file("artifact-first.bin"),
        rig.read_file("artifact-second.bin")
    );

    rig.remove_receipt();
    let replacement = rig.generate_cli("ffeeddccbbaa99887766554433221100");
    assert_eq!(
        replacement.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&replacement.stdout),
        String::from_utf8_lossy(&replacement.stderr)
    );
    let replacement_value: Value = serde_json::from_slice(&replacement.stdout).unwrap();
    let replacement_id = replacement_value["result"]["generation_id"]
        .as_str()
        .unwrap();
    let discarded = rig.discard_id_cli(replacement_id);
    assert_eq!(
        discarded.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&discarded.stdout),
        String::from_utf8_lossy(&discarded.stderr)
    );

    let retired = rig.export_id_cli(replacement_id, "artifact-retired.bin");
    assert_eq!(retired.exit_code, 5);
    assert!(String::from_utf8_lossy(&retired.stdout).contains("artifact_retired"));
    assert_eq!(
        rig.export_cli(&generation, "artifact-active.bin").exit_code,
        0
    );

    let unknown = rig.export_id_cli("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "artifact-unknown.bin");
    assert_eq!(unknown.exit_code, 5);
    assert!(String::from_utf8_lossy(&unknown.stdout).contains("generation_mismatch"));
}

#[test]
fn recipient_rotation_is_future_only_and_private_keys_stay_off_primary() {
    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    let mut rig = TestRig::commissioned_pool();
    let (public_a, private_a) = recipient::create(PASSPHRASE, &mut RecipientEntropy(7)).unwrap();
    let (public_b, private_b) = recipient::create(PASSPHRASE, &mut RecipientEntropy(173)).unwrap();

    let set_a = rig.set_recipient_cli(
        &public_a.json().unwrap(),
        "10000000000000000000000000000001",
    );
    assert_eq!(
        set_a.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&set_a.stdout),
        String::from_utf8_lossy(&set_a.stderr)
    );
    let generation_a = rig
        .generate_with_operation("20000000000000000000000000000001")
        .unwrap();
    assert_eq!(
        rig.export_cli(&generation_a, "artifact-a-before.bin")
            .exit_code,
        0
    );
    let artifact_a_before = rig.read_file("artifact-a-before.bin");
    let expected_a = rig.backup_expectations(&generation_a);

    let set_b = rig.set_recipient_cli(
        &public_b.json().unwrap(),
        "10000000000000000000000000000002",
    );
    assert_eq!(
        set_b.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&set_b.stdout),
        String::from_utf8_lossy(&set_b.stderr)
    );
    assert_eq!(rig.recipient_public_key(), public_b.public_key);
    assert_eq!(
        rig.export_cli(&generation_a, "artifact-a-after.bin")
            .exit_code,
        0
    );
    assert_eq!(artifact_a_before, rig.read_file("artifact-a-after.bin"));

    rig.remove_receipt();
    let generation_b = rig
        .generate_with_operation("20000000000000000000000000000002")
        .unwrap();
    assert_eq!(rig.export_cli(&generation_b, "artifact-b.bin").exit_code, 0);
    let artifact_b = rig.read_file("artifact-b.bin");
    let expected_b = rig.backup_expectations(&generation_b);

    assert!(recover::recover(&artifact_a_before, &private_a, PASSPHRASE, expected_a).is_ok());
    assert!(matches!(
        recover::recover(&artifact_a_before, &private_b, PASSPHRASE, expected_a),
        Err(recover::Error::WrongRecipient)
    ));
    assert!(recover::recover(&artifact_b, &private_b, PASSPHRASE, expected_b).is_ok());
    assert!(matches!(
        recover::recover(&artifact_b, &private_a, PASSPHRASE, expected_b),
        Err(recover::Error::WrongRecipient)
    ));

    for persisted in rig.persisted_files() {
        assert!(
            !persisted
                .windows(private_a.encoded().len())
                .any(|bytes| bytes == private_a.encoded())
        );
        assert!(
            !persisted
                .windows(private_b.encoded().len())
                .any(|bytes| bytes == private_b.encoded())
        );
    }
}

#[test]
fn generation_is_not_delivered_until_matching_certificate_and_fresh_context() {
    let mut rig = TestRig::commissioned_pool();
    let generation = rig.generate_with_cli().unwrap();
    assert_eq!(rig.pool_status()["generation_id"], generation.id);
    assert_eq!(rig.current_usb_result(), "unavailable");
    let wrong_certificate = rig.certificate_for_other_generation();
    assert_eq!(
        rig.install_certificate_cli(&generation.id, &wrong_certificate)
            .exit_code,
        5
    );
    assert_eq!(rig.current_usb_result(), "unavailable");
    let certificate = rig.certificate_for(&generation);
    assert_eq!(
        rig.install_certificate_cli(&generation.id, &certificate)
            .exit_code,
        0
    );
    assert_eq!(rig.current_usb_result(), "unavailable");
    rig.refresh_context().unwrap();
    assert_eq!(rig.current_usb_result(), "key");
    assert_eq!(rig.current_usb_generation(), generation.id);
    assert_eq!(rig.current_usb_certificate(), certificate);
}

#[test]
fn normal_mode_never_commissions_a_blank_device() {
    let mut rig = TestRig::blank_commissioning("attended-board01");
    rig.restart_normal_without_pin().unwrap();
    let result = status(&rig);
    assert_eq!(result["error"]["code"], "uncommissioned");
    assert!(!rig.pin_record_path().exists());
    rig.restart_commissioning().unwrap();
    assert_eq!(status(&rig)["result"]["commissioning_state"], "blank");
}

#[test]
fn commissioning_mode_rejects_pool_mutations() {
    let rig = TestRig::blank_commissioning("attended-board01");
    let response = management(
        &rig,
        json!({
            "version":1, "request_id":ID, "action":"pool.enroll",
            "arguments":{"cold_verification_key":"0101010101010101010101010101010101010101010101010101010101010101", "network":"test"},
            "operation_id":ID, "expected_revision":0
        }),
    );
    assert_eq!(response["outcome"], "rejected");
    assert_eq!(status(&rig)["result"]["commissioning_state"], "blank");
    assert!(rig.pool_sockets().is_empty());
}
