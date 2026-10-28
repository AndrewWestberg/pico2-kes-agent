//! Public management/CLI regressions against a daemon backed by disposable,
//! faultable persistent storage. The driver must execute real device and host
//! paths, not synthesize management replies.
mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use kes_protocol::management::{FrameDecoder, MAX_FRAME, Message};
use serde_json::{Value, json};
use support::{Cut, TestRig};

const ID: &str = "00112233445566778899aabbccddeeff";

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
    assert_eq!(status(&rig)["result"]["commissioning_state"], "blank");
    assert!(rig.pool_sockets().is_empty());
    let response = rig.commission_cli("attended-board01", ID);
    assert_eq!(response.exit_code, 0);
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
    assert_eq!(status(&rig)["result"]["commissioning_state"], "unavailable");
    assert!(!rig.pin_record_path().exists());
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
