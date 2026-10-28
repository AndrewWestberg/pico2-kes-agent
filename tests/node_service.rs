//! V2 consumer tests. The driver runs the real daemon and device state machine
//! over a disposable faultable flash/USB transport; it is not a protocol peer.
mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use kes_protocol::usb::{CurrentResult, decode_current_response};
use support::{Cut, TestRig};

fn service() -> [u8; 32] {
    let mut id = [0; 32];
    id[..11].copy_from_slice(b"Service:2.0");
    id
}
const BUNDLE_LEN: usize = 608 + 4 + 32 + 8 + 8 + 64;

fn connect(rig: &TestRig) -> UnixStream {
    let mut s = UnixStream::connect(rig.pool_socket()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut offer = [0; 36];
    s.read_exact(&mut offer).unwrap();
    assert_eq!(&offer[..4], &1u32.to_be_bytes());
    assert_eq!(&offer[4..], &service());
    // Split the boolean and identifier into individual writes.
    for byte in std::iter::once(&1u8).chain(service().iter()) {
        s.write_all(&[*byte]).unwrap();
    }
    let mut selected = [0; 32];
    s.read_exact(&mut selected).unwrap();
    assert_eq!(selected, service());
    s
}

fn key(s: &mut UnixStream) -> (u64, Vec<u8>) {
    let mut header = [0; 9];
    s.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 0, "expected key, not Drop");
    let mut bundle = vec![0; BUNDLE_LEN];
    s.read_exact(&mut bundle).unwrap();
    (u64::from_be_bytes(header[1..].try_into().unwrap()), bundle)
}

fn assert_matches_usb(rig: &TestRig, wire: &(u64, Vec<u8>)) {
    let payload = rig.current_usb_payload();
    let current = decode_current_response(&payload).unwrap();
    assert_eq!(wire.0, current.publication.timestamp_us);
    match current.result {
        CurrentResult::Key {
            period,
            state,
            certificate,
            ..
        } => {
            assert_eq!(certificate.len(), 112);
            assert_eq!(&wire.1[..608], state);
            assert_eq!(
                &wire.1[608..612],
                &u32::try_from(period).unwrap().to_be_bytes()
            );
            assert_eq!(&wire.1[612..], certificate);
        }
        _ => panic!("device did not return a clean current key"),
    }
}

fn no_bytes(s: &mut UnixStream) {
    s.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut byte = [0];
    let e = s.read(&mut byte).unwrap_err();
    assert!(matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
}

#[test]
fn fragmented_handshake_and_exact_four_byte_confirmation_gate_updates() {
    let mut rig = TestRig::certified_pool();
    let mut s = connect(&rig);
    let first = key(&mut s);
    assert_matches_usb(&rig, &first);
    rig.advance_period(1, 10_000).unwrap();
    // Three bytes are not a complete confirmation. A one-byte enum codec would
    // incorrectly allow the second publication through here.
    s.write_all(&[0, 0, 0]).unwrap();
    no_bytes(&mut s);
    s.write_all(&[0]).unwrap();
    let second = key(&mut s);
    assert!(second.0 > first.0);
    assert_matches_usb(&rig, &second);
    assert_ne!(first.1, second.1);
}

#[test]
fn unsupported_version_choice_is_not_a_service_session() {
    let rig = TestRig::certified_pool();
    let mut s = UnixStream::connect(rig.pool_socket()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut offer = [0; 36];
    s.read_exact(&mut offer).unwrap();
    let mut choice = [0; 33];
    choice[0] = 1;
    choice[1..12].copy_from_slice(b"Service:9.0");
    s.write_all(&choice).unwrap();
    let mut b = [0];
    assert_eq!(s.read(&mut b).unwrap(), 0);
}

#[test]
fn committed_publication_reuses_timestamp_and_bundle_across_cuts() {
    for cut in [Cut::AfterCommit, Cut::AfterCleanBeforeUsbReply] {
        let mut rig = TestRig::certified_pool();
        let mut s = connect(&rig);
        let original = key(&mut s);
        s.write_all(&0u32.to_be_bytes()).unwrap();
        rig.cut_next_publication(cut);
        rig.advance_period(1, original.0 + 100).unwrap_err();
        rig.restart_device_and_refresh_context().unwrap();
        let recovered = key(&mut connect(&rig));
        assert_matches_usb(&rig, &recovered);
        assert!(recovered.0 > original.0);
        let repeated = key(&mut connect(&rig));
        assert_eq!(
            recovered, repeated,
            "cut {cut:?} changed committed publication"
        );
    }
}

#[test]
fn lost_confirmation_and_metadata_commits_do_not_republish() {
    let mut rig = TestRig::certified_pool();
    let mut first_socket = connect(&rig);
    let first = key(&mut first_socket);
    drop(first_socket); // sent, but confirmation was lost
    rig.refresh_same_period().unwrap();
    rig.commit_metadata_only().unwrap();
    rig.poll_status().unwrap();
    let repeated = key(&mut connect(&rig));
    assert_eq!(repeated, first);
    assert_matches_usb(&rig, &repeated);
    rig.advance_period(1, first.0).unwrap();
    let later = key(&mut connect(&rig));
    assert_eq!(later.0, first.0 + 1);
    assert_matches_usb(&rig, &later);
}

#[test]
fn reconnect_requires_fresh_context_and_unavailability_never_sends_drop() {
    let mut rig = TestRig::certified_pool();
    let mut s = connect(&rig);
    let first = key(&mut s);
    s.write_all(&0u32.to_be_bytes()).unwrap();
    rig.disconnect_usb();
    no_bytes(&mut s);
    rig.reconnect_usb_without_context().unwrap();
    let mut next = connect(&rig);
    no_bytes(&mut next);
    rig.refresh_context().unwrap();
    let delivered = key(&mut next);
    assert_eq!(delivered, first);
}

#[test]
fn overflow_is_rejected_without_wrapping_or_drop() {
    let mut rig = TestRig::certified_pool_at(u64::MAX);
    let mut s = connect(&rig);
    let last = key(&mut s);
    assert_eq!(last.0, u64::MAX);
    s.write_all(&0u32.to_be_bytes()).unwrap();
    assert_eq!(
        rig.advance_period(1, u64::MAX).unwrap_err().code(),
        "storage_failure"
    );
    no_bytes(&mut s);
    assert_eq!(key(&mut connect(&rig)), last);
}

#[test]
fn uncommitted_candidate_never_consumes_a_publication() {
    let mut rig = TestRig::certified_pool();
    let before = key(&mut connect(&rig));
    rig.cut_next_publication(Cut::BeforeCommit);
    rig.advance_period(1, before.0 + 50).unwrap_err();
    rig.restart_device_and_refresh_context().unwrap();
    let recovered = key(&mut connect(&rig));
    assert_eq!(recovered, before);
    assert_matches_usb(&rig, &recovered);
}

#[test]
fn durable_expiry_sends_one_drop_with_device_timestamp() {
    let mut rig = TestRig::certified_pool();
    let mut s = connect(&rig);
    let before = key(&mut s);
    s.write_all(&0u32.to_be_bytes()).unwrap();
    rig.expire_generation(before.0 + 10).unwrap();
    let mut drop_wire = [0; 9];
    s.read_exact(&mut drop_wire).unwrap();
    assert_eq!(drop_wire[0], 1);
    let timestamp = u64::from_be_bytes(drop_wire[1..].try_into().unwrap());
    assert!(timestamp > before.0);
    let payload = rig.current_usb_payload();
    let current = decode_current_response(&payload).unwrap();
    assert_eq!(timestamp, current.publication.timestamp_us);
    assert!(matches!(current.result, CurrentResult::Drop));
    s.write_all(&0u32.to_be_bytes()).unwrap();
    no_bytes(&mut s);
    let mut reconnect = connect(&rig);
    let mut repeated = [0; 9];
    reconnect.read_exact(&mut repeated).unwrap();
    assert_eq!(repeated, drop_wire);
}

#[test]
fn v2_confirmation_codec_uses_rawutil_u32_not_enum_ordinals() {
    use kes_protocol::node_service::{Confirmation, decode_confirmation, encode_confirmation};
    for (result, bytes) in [
        (Confirmation::Ok, [0, 0, 0, 0]),
        (Confirmation::Outdated, [0, 0, 0, 1]),
        (Confirmation::InvalidCertificate, [0, 0, 0, 2]),
        (Confirmation::NoKey, [0, 0, 0, 3]),
        (Confirmation::Unsupported, [0, 0, 0, 4]),
        (Confirmation::Unknown, [0, 0, 0xff, 0xff]),
    ] {
        assert_eq!(encode_confirmation(result), bytes);
        assert_eq!(decode_confirmation(&bytes).unwrap(), result);
    }
    assert_eq!(
        decode_confirmation(&[0, 0, 0, 5]).unwrap(),
        Confirmation::Unknown
    );
    assert!(decode_confirmation(&[0, 0, 0]).is_err());
}
