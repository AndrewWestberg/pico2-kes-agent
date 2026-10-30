use kes_protocol::usb::{self, Decoder, Error, HEADER_LEN, Kind, MAX_FRAME};

fn frame(kind: Kind, request: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = [0; MAX_FRAME];
    let n = usb::encode(kind, request, payload, &mut out).unwrap();
    out[..n].to_vec()
}

#[test]
fn fragments_and_connection_reset() {
    let bytes = frame(Kind::Hello, 42, &[0xa1, 0x01, 0x01]);
    let mut decoder = Decoder::new();
    for &byte in &bytes[..bytes.len() - 1] {
        let (used, frame) = decoder.feed(&[byte]).unwrap();
        assert_eq!(used, 1);
        assert!(frame.is_none());
    }
    let (used, result) = decoder.feed(&bytes[bytes.len() - 1..]).unwrap();
    assert_eq!(used, 1);
    let result = result.unwrap();
    assert_eq!(result.kind, Kind::Hello);
    assert_eq!(result.request_number, 42);
    assert_eq!(result.payload, &[0xa1, 0x01, 0x01]);
    decoder.reconnect();
    decoder.feed(&bytes[..9]).unwrap();
    decoder.reconnect();
    let (_, result) = decoder.feed(&bytes).unwrap();
    assert!(result.is_some());
}

#[test]
fn rejects_declared_oversize_before_body() {
    let mut header = [0; HEADER_LEN];
    header[..4].copy_from_slice(b"PKA1");
    header[4..6].copy_from_slice(&1u16.to_be_bytes());
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    header[16..20].copy_from_slice(&4097u32.to_be_bytes());
    let mut decoder = Decoder::new();
    assert!(matches!(decoder.feed(&header), Err(Error::Length)));
    assert_eq!(decoder.buffered_len(), HEADER_LEN);
    assert!(matches!(decoder.feed(&[0; 10]), Err(Error::Poisoned)));
    decoder.reconnect();
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn bad_crc_and_header_are_rejected_without_resynchronizing() {
    let mut bytes = frame(Kind::Hello, 1, &[0xa0]);
    *bytes.last_mut().unwrap() ^= 1;
    let mut d = Decoder::new();
    assert!(matches!(d.feed(&bytes), Err(Error::Crc)));
    assert!(matches!(
        d.feed(&frame(Kind::Hello, 2, &[0xa0])),
        Err(Error::Poisoned)
    ));
    d.reconnect();
    bytes[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(matches!(d.feed(&bytes), Err(Error::Major)));
    d.reconnect();
    bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&12u16.to_be_bytes());
    assert!(matches!(d.feed(&bytes), Err(Error::Kind)));
}

#[test]
fn canonical_cbor_rejections() {
    for payload in [
        &[0x18, 0x01][..],      // non-shortest integer
        &[0xbf, 0xff],          // indefinite map
        &[0xa2, 1, 0, 1, 0],    // duplicate
        &[0xa2, 2, 0, 1, 0],    // unordered
        &[0xa0, 0],             // trailing item
        &[0x61, 0xff],          // invalid UTF-8
        &[0x5a, 0, 0, 0, 1, 0], // non-shortest length
    ] {
        assert_eq!(usb::validate_cbor(payload), Err(Error::Cbor));
    }
}

#[test]
fn all_kinds_and_surplus_input() {
    for n in 1..=11 {
        let kind = Kind::try_from(n).unwrap();
        let bytes = frame(kind, u64::from(n), &[0xa0]);
        let mut combined = bytes.clone();
        combined.extend_from_slice(&bytes);
        let mut d = Decoder::new();
        let (used, result) = d.feed(&combined).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(result.unwrap().kind, kind);
        let (used, result) = d.feed(&combined[used..]).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(result.unwrap().request_number, u64::from(n));
    }
}

#[test]
fn context_diagnostics_roundtrip_and_schema() {
    use kes_core::{
        identity::{IncarnationId, PoolId},
        operation::PoolTarget,
        platform::EntropyFailure,
        storage::{StorageError, StorageFailure, StorageStage},
    };
    use usb::{ContextDiagnostics, ContextPhase, ContextResponse, Response};

    let target = PoolTarget {
        pool: PoolId::from_bytes([2; 28]),
        incarnation: IncarnationId::from_bytes([3; 16]),
    };
    let diagnostics = ContextDiagnostics {
        phase: ContextPhase::CatchUp,
        storage: Some(StorageFailure {
            stage: StorageStage::PoolDecode,
            error: StorageError::Geometry,
        }),
        entropy: Some(EntropyFailure::Timeout),
    };
    let response = ContextResponse {
        target,
        session: 2,
        sequence: 3,
        floor: 4,
        result: Err(9),
        diagnostics: Some(diagnostics),
    };
    let mut output = [0; 4096];
    let (_, n) = usb::encode_response(&Response::Context(response), &mut output).unwrap();
    match usb::decode_response(Kind::Context, &output[..n]).unwrap() {
        Response::Context(decoded) => assert_eq!(decoded, response),
        _ => panic!("wrong response kind"),
    }
    let empty = ContextResponse {
        diagnostics: Some(ContextDiagnostics {
            phase: ContextPhase::ReadFloor,
            storage: None,
            entropy: None,
        }),
        ..response
    };
    let (_, n) = usb::encode_response(&Response::Context(empty), &mut output).unwrap();
    assert!(matches!(usb::decode_response(Kind::Context, &output[..n]),
        Ok(Response::Context(value)) if value == empty));

    let old = ContextResponse {
        diagnostics: None,
        ..response
    };
    let (_, old_len) = usb::encode_response(&Response::Context(old), &mut output).unwrap();
    assert_eq!(output[0], 0xa5);
    assert!(
        matches!(usb::decode_response(Kind::Context, &output[..old_len]),
        Ok(Response::Context(value)) if value == old)
    );

    let invalid_success = ContextResponse {
        result: Ok(()),
        diagnostics: Some(diagnostics),
        ..response
    };
    assert!(usb::encode_response(&Response::Context(invalid_success), &mut output).is_err());
    let success = ContextResponse {
        result: Ok(()),
        diagnostics: None,
        ..response
    };
    let (_, success_len) = usb::encode_response(&Response::Context(success), &mut output).unwrap();
    let mut payload = output[..success_len].to_vec();
    payload[0] = 0xa6;
    payload.extend_from_slice(&[6, 0xa3, 1, 1, 2, 0xf6, 3, 0xf6]);
    assert!(usb::decode_response(Kind::Context, &payload).is_err());

    let (_, old_len) = usb::encode_response(&Response::Context(old), &mut output).unwrap();
    let mut prefix = output[..old_len].to_vec();
    prefix[0] = 0xa6;
    for suffix in [
        &b"\x06\xa3\x01\x00\x02\xf6\x03\xf6"[..],
        &b"\x06\xa3\x01\x06\x02\xf6\x03\xf6"[..],
        &b"\x06\xa3\x01\x01\x02\x82\x00\x08\x03\xf6"[..],
        &b"\x06\xa3\x01\x01\x02\x82\x01\x00\x03\xf6"[..],
        &b"\x06\xa3\x01\x01\x02\xf6\x03\x00"[..],
        &b"\x06\xa3\x01\x01\x02\x81\x01\x03\xf6"[..],
        &b"\x06\xa3\x01\x01\x02\x00\x03\xf6"[..],
        &b"\x06\xa2\x01\x01\x02\xf6"[..],
        &b"\x06\xa3\x01\x01\x02\xf6\x03\x80"[..],
    ] {
        let mut malformed = prefix.clone();
        malformed.extend_from_slice(suffix);
        assert!(
            usb::decode_response(Kind::Context, &malformed).is_err(),
            "{suffix:?}"
        );
    }
}

#[test]
fn security_status_roundtrip_and_schema_rejection() {
    use kes_protocol::{
        security::SecurityStatus,
        usb::{Request, Response},
    };
    let status = SecurityStatus {
        chip_revision: 2,
        rom_version: 2,
        critical: 7,
        boot_flags0: 0x2da180,
        boot_flags1: 0xe01,
        bootkey0: [7; 32],
        page2_lock0: 0,
        page2_lock1: 0x15,
        page63_lock0: 0,
        page63_lock1: 0x15,
        debugen: 0,
        debugen_lock: 0x10f,
        redundancy_ok: true,
        jedec_id: [0xef, 0x40, 0x16],
        sfdp_header: [
            0x53, 0x46, 0x44, 0x50, 0x0a, 1, 0, 0xff, 0, 8, 1, 0x17, 0x80, 0, 0, 0xff,
        ],
        density_bits_minus_one: 0x1ff_ffff,
        usb_serial: *b"0123456789abcdef",
        storage_blank_at_boot: true,
    };
    let mut locked = status;
    locked.boot_flags0 = 0x200000 | 0x80000 | 0x40000 | 0x10000 | 0x8000 | 0x2000 | 0x100 | 0x80;
    assert_eq!(locked.profile(Some(&[7; 32])), "rp2350-signed-msd-v1");
    assert_eq!(locked.profile(None), "incomplete");
    assert_eq!(locked.profile(Some(&[8; 32])), "incomplete");
    for bit in [
        0x200000, 0x80000, 0x40000, 0x10000, 0x8000, 0x2000, 0x100, 0x80,
    ] {
        let mut v = locked;
        v.boot_flags0 &= !bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    for bit in [0x20000, 0x4000, 0x1000, 0x800, 0x40] {
        let mut v = locked;
        v.boot_flags0 |= bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    for bit in [2, 4] {
        let mut v = locked;
        v.critical &= !bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    for bit in [8, 0x10000] {
        let mut v = locked;
        v.critical |= bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    for bit in [1, 2, 4, 8, 0x100, 0x200, 0x400, 0x800] {
        let mut v = locked;
        v.boot_flags1 ^= bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    for lock in [0, 2, 3, 0x14, 0x19, 0x25, 0x95] {
        let mut v = locked;
        v.page2_lock1 = lock;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
        v = locked;
        v.page63_lock1 = lock;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    for lock in [0x1d, 0x35, 0x3d] {
        let mut v = locked;
        v.page2_lock1 = lock;
        v.page63_lock1 = lock;
        assert_eq!(v.profile(Some(&[7; 32])), "rp2350-signed-msd-v1");
    }
    for bit in [1, 2, 4, 8, 0x100] {
        let mut v = locked;
        v.debugen |= bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
        v = locked;
        v.debugen_lock &= !bit;
        assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    }
    let mut v = locked;
    v.page2_lock0 = 1;
    assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    v = locked;
    v.jedec_id[0] ^= 1;
    assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    v = locked;
    v.sfdp_header[0] ^= 1;
    assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    v = locked;
    v.density_bits_minus_one ^= 1;
    assert_eq!(v.profile(Some(&[7; 32])), "incomplete");
    let mut bad_policy = locked;
    bad_policy.boot_flags0 |= 0x20000;
    assert_eq!(bad_policy.profile(Some(&[7; 32])), "incomplete");
    bad_policy = locked;
    bad_policy.page63_lock0 = 0x80;
    assert_eq!(bad_policy.profile(Some(&[7; 32])), "incomplete");
    bad_policy = locked;
    bad_policy.redundancy_ok = false;
    assert_eq!(bad_policy.profile(Some(&[7; 32])), "incomplete");
    bad_policy = locked;
    bad_policy.critical = 0;
    assert_eq!(bad_policy.profile(Some(&[7; 32])), "unlocked");
    bad_policy = locked;
    bad_policy.rom_version = 4;
    assert_eq!(bad_policy.stepping(), "A4");
    assert_eq!(bad_policy.profile(Some(&[7; 32])), "rp2350-signed-msd-v1");
    bad_policy.rom_version = 3;
    assert_eq!(bad_policy.stepping(), "unsupported");
    assert_eq!(bad_policy.profile(Some(&[7; 32])), "incomplete");
    let mut out = [0; 4096];
    let (kind, n) = usb::encode_request(&Request::SecurityStatus, &mut out).unwrap();
    assert_eq!((kind, &out[..n]), (Kind::SecurityStatus, &[0xa0][..]));
    assert!(matches!(
        usb::decode_request(kind, &out[..n]),
        Ok(Request::SecurityStatus)
    ));
    assert!(usb::decode_request(kind, &[0xa1, 1, 0]).is_err());
    let (kind, n) = usb::encode_response(&Response::SecurityStatus(status), &mut out).unwrap();
    assert!(
        matches!(usb::decode_response(kind, &out[..n]), Ok(Response::SecurityStatus(v)) if v == status)
    );
    assert!(usb::decode_response(kind, &out[..n - 1]).is_err());
    let mut bad = out[..n].to_vec();
    bad[1] = 2; // missing key 1 and duplicate key 2
    assert!(usb::decode_response(kind, &bad).is_err());
    let mut bad = out[..n].to_vec();
    let key = bad.windows(3).position(|v| v == [6, 0x58, 0x20]).unwrap();
    bad[key + 2] = 31;
    assert!(usb::decode_response(kind, &bad).is_err());
    let mut bad = out[..n].to_vec();
    let boolean = bad.windows(2).position(|v| v == [13, 0xf5]).unwrap();
    bad[boolean + 1] = 1;
    assert!(usb::decode_response(kind, &bad).is_err());
    let mut bad = out[..n].to_vec();
    bad.push(0);
    assert!(usb::decode_response(kind, &bad).is_err());
}

#[test]
fn crc32c_known_vector() {
    assert_eq!(usb::crc32c(b"123456789"), 0xe3069283);
}

#[test]
fn request_binding_and_digest_are_checked() {
    use kes_core::identity::{DeviceId, IncarnationId, OperationId, PoolId};
    use kes_core::operation::{Action, Mutation, PoolTarget};
    use kes_protocol::usb::{Request, decode_request, encode_request};
    let target = PoolTarget {
        pool: PoolId::from_bytes([3; 28]),
        incarnation: IncarnationId::from_bytes([4; 16]),
    };
    let operation = OperationId::from_bytes([5; 16]);
    let mutation = Mutation::managed(
        DeviceId::from_bytes([6; 16]),
        9,
        operation,
        7,
        Action::Delete {
            target,
            publication_time_us: Some(12345),
        },
    )
    .unwrap();
    let mut payload = [0; 4096];
    let (kind, n) = encode_request(&Request::Mutate(mutation), &mut payload).unwrap();
    match decode_request(kind, &payload[..n]).unwrap() {
        Request::Mutate(actual) => assert_eq!(actual, mutation),
        _ => panic!("wrong request"),
    }
    // Changing a target leaves well-formed CBOR, but invalidates the core USB digest.
    let index = payload[..n].windows(28).position(|w| w == [3; 28]).unwrap();
    payload[index] ^= 1;
    assert!(matches!(
        decode_request(kind, &payload[..n]),
        Err(Error::Schema)
    ));
    let wire = frame(kind, 88, &payload[..n]);
    let mut d = Decoder::new();
    let (_, decoded) = d.feed(&wire).unwrap();
    assert_eq!(decoded.unwrap().request_number, 88);
    assert_ne!(&88u64.to_be_bytes()[..], operation.as_bytes());
}

#[test]
fn context_exact_target_and_publication_sample_round_trip() {
    use kes_core::identity::{Digest32, IncarnationId, NetworkBinding, PoolId};
    use kes_core::operation::PoolTarget;
    use kes_protocol::usb::{Request, decode_request, encode_request};
    let target = PoolTarget {
        pool: PoolId::from_bytes([1; 28]),
        incarnation: IncarnationId::from_bytes([2; 16]),
    };
    let network = NetworkBinding::new(Digest32::from_bytes([3; 32]), 42, 129600, 62).unwrap();
    let request = Request::Context {
        target,
        network,
        period: 77,
        session: 12,
        sequence: 13,
        lease_seconds: 30,
        publication_time_us: 987654321,
    };
    let mut bytes = [0; 4096];
    let (kind, n) = encode_request(&request, &mut bytes).unwrap();
    match decode_request(kind, &bytes[..n]).unwrap() {
        Request::Context {
            target: actual,
            network: actual_network,
            period,
            session,
            sequence,
            lease_seconds,
            publication_time_us,
        } => {
            assert_eq!(actual, target);
            assert_eq!(actual_network, network);
            assert_eq!(
                (
                    period,
                    session,
                    sequence,
                    lease_seconds,
                    publication_time_us
                ),
                (77, 12, 13, 30, 987654321)
            );
        }
        _ => panic!("wrong request"),
    }
}

#[test]
fn unknown_request_fields_are_rejected() {
    use kes_protocol::usb::decode_request;
    assert!(matches!(
        decode_request(Kind::Status, &[0xa1, 0x02, 0xf6]),
        Err(Error::Schema)
    ));
    assert!(matches!(
        decode_request(Kind::Status, &[0xa2, 0x01, 0xf6, 0x02, 0xf6]),
        Err(Error::Schema)
    ));
}

#[test]
fn commission_serial_and_sequence_bind_digest() {
    use kes_core::identity::OperationId;
    use kes_core::operation::{Mutation, UsbSerial};
    use kes_protocol::usb::{Request, decode_request, encode_request};
    let mutation = Mutation::commission(
        UsbSerial::new(b"selected-device").unwrap(),
        OperationId::from_bytes([7; 16]),
        0,
    )
    .unwrap();
    let mut bytes = [0; 4096];
    let (kind, n) = encode_request(&Request::Commission(mutation), &mut bytes).unwrap();
    match decode_request(kind, &bytes[..n]).unwrap() {
        Request::Commission(actual) => assert_eq!(actual, mutation),
        _ => panic!("wrong request"),
    }
    let serial = bytes[..n]
        .windows(15)
        .position(|w| w == b"selected-device")
        .unwrap();
    bytes[serial] ^= 1;
    assert!(matches!(
        decode_request(kind, &bytes[..n]),
        Err(Error::Schema)
    ));
}

#[test]
fn stored_publication_and_current_bundle_match() {
    use kes_core::identity::{Digest32, GenerationId, IncarnationId, PoolId};
    use kes_core::operation::PoolTarget;
    use kes_protocol::usb::{
        CurrentResponse, CurrentResult, Publication, PublicationKind, decode_current_response,
        encode_current_response,
    };
    let target = PoolTarget {
        pool: PoolId::from_bytes([1; 28]),
        incarnation: IncarnationId::from_bytes([2; 16]),
    };
    let generation = GenerationId::from_bytes([3; 16]);
    let publication = Publication {
        revision: 12,
        timestamp_us: 4000,
        high_water_us: 4000,
        kind: PublicationKind::Key {
            generation,
            period: 4,
            certificate_digest: Digest32::from_bytes([5; 32]),
        },
    };
    let state = [6; 608];
    let response = CurrentResponse {
        target,
        snapshot_revision: 15,
        publication,
        result: CurrentResult::Key {
            generation,
            period: 4,
            state: &state,
            certificate: b"certificate",
        },
    };
    let mut bytes = [0; 4096];
    let n = encode_current_response(&response, &mut bytes).unwrap();
    let decoded = decode_current_response(&bytes[..n]).unwrap();
    assert_eq!(decoded.target, target);
    assert_eq!(decoded.publication, publication);
    match decoded.result {
        CurrentResult::Key {
            generation: g,
            period,
            state: s,
            certificate,
        } => {
            assert_eq!(g, generation);
            assert_eq!(period, 4);
            assert_eq!(s, &state);
            assert_eq!(certificate, b"certificate");
        }
        _ => panic!("wrong current result"),
    }
}

#[test]
fn deletion_receipt_preserves_old_target_and_high_water() {
    use kes_core::identity::{IncarnationId, PoolId};
    use kes_core::operation::{DeletionPublication, PoolTarget};
    use kes_protocol::usb::{decode_deletion_publication, encode_deletion_publication};
    let target = PoolTarget {
        pool: PoolId::from_bytes([9; 28]),
        incarnation: IncarnationId::from_bytes([10; 16]),
    };
    let receipt = DeletionPublication::new(target, 18, Some(123456), 123456).unwrap();
    let mut bytes = [0; 4096];
    let n = encode_deletion_publication(&receipt, &mut bytes).unwrap();
    assert_eq!(decode_deletion_publication(&bytes[..n]).unwrap(), receipt);
}

#[test]
fn enrollment_floor_is_bound_into_usb_digest() {
    use kes_core::identity::{DeviceId, Digest32, NetworkBinding, OperationId};
    use kes_core::operation::{Action, Mutation};
    use kes_protocol::usb::{Request, decode_request, encode_request};
    let network = NetworkBinding::new(Digest32::from_bytes([1; 32]), 42, 20, 10).unwrap();
    let make = |floor| {
        Mutation::managed(
            DeviceId::from_bytes([2; 16]),
            1,
            OperationId::from_bytes([3; 16]),
            4,
            Action::Enroll {
                cold_key: [4; 32],
                network,
                publication_floor_us: floor,
            },
        )
        .unwrap()
    };
    let a = make(33);
    let b = make(34);
    assert_eq!(a.cli_digest(), b.cli_digest());
    assert_ne!(a.usb_digest(), b.usb_digest());
    let mut payload = [0; 4096];
    let (kind, n) = encode_request(&Request::Mutate(a), &mut payload).unwrap();
    match decode_request(kind, &payload[..n]).unwrap() {
        Request::Mutate(m) => assert_eq!(m, a),
        _ => panic!("wrong request"),
    }
}

#[test]
fn artifact_response_is_targeted_and_bounded() {
    use kes_core::identity::{Digest32, GenerationId, IncarnationId, PoolId};
    use kes_core::operation::{GenerationTarget, PoolTarget};
    use kes_protocol::usb::{
        ArtifactResponse, ArtifactResult, decode_artifact_response, encode_artifact_response,
    };
    let target = GenerationTarget {
        pool: PoolTarget {
            pool: PoolId::from_bytes([1; 28]),
            incarnation: IncarnationId::from_bytes([2; 16]),
        },
        generation: GenerationId::from_bytes([3; 16]),
    };
    let data = [7u8; 2048];
    let value = ArtifactResponse {
        target,
        result: ArtifactResult::Retained {
            artifact: &data,
            digest: Digest32::from_bytes([4; 32]),
            retention_policy: 1,
        },
    };
    let mut bytes = [0; 4096];
    let n = encode_artifact_response(&value, &mut bytes).unwrap();
    let decoded = decode_artifact_response(&bytes[..n]).unwrap();
    assert_eq!(decoded.target, target);
    match decoded.result {
        ArtifactResult::Retained {
            artifact,
            digest,
            retention_policy,
        } => {
            assert_eq!(artifact, &data);
            assert_eq!(digest, Digest32::from_bytes([4; 32]));
            assert_eq!(retention_policy, 1);
        }
        _ => panic!("wrong artifact result"),
    }
    let too_large = [7u8; 2049];
    let value = ArtifactResponse {
        target,
        result: ArtifactResult::Retained {
            artifact: &too_large,
            digest: Digest32::from_bytes([4; 32]),
            retention_policy: 1,
        },
    };
    assert!(matches!(
        encode_artifact_response(&value, &mut bytes),
        Err(Error::Length)
    ));
}

#[test]
fn every_response_kind_round_trips_and_rejects_unknown_fields() {
    use kes_core::identity::{
        DeviceId, Digest32, GenerationId, IncarnationId, OperationId, PoolId,
    };
    use kes_core::operation::{
        CommissioningRecord, CommittedResult, DeletionPublication, GenerationTarget, LiveTarget,
        PoolTarget, UsbSerial,
    };
    use kes_protocol::usb::*;
    let device = DeviceId::from_bytes([1; 16]);
    let target = PoolTarget {
        pool: PoolId::from_bytes([2; 28]),
        incarnation: IncarnationId::from_bytes([3; 16]),
    };
    let generation = GenerationId::from_bytes([4; 16]);
    let generation_target = GenerationTarget {
        pool: target,
        generation,
    };
    let serial = UsbSerial::new(b"serial").unwrap();
    let operation_id = OperationId::from_bytes([5; 16]);
    let request_digest = kes_core::operation::Mutation::commission(serial, operation_id, 0)
        .unwrap()
        .usb_digest();
    let result_digest = Digest32::from_bytes([7; 32]);
    let record = CommissioningRecord::new(
        device,
        [8; 32],
        serial,
        1,
        2,
        0,
        operation_id,
        request_digest,
    );
    let commission = PublicReceipt {
        sequence: 0,
        operation_id,
        request_digest,
        binding: ReceiptBinding::Serial(serial),
        target: None,
        outcome: PublicOutcome::Committed {
            result: CommittedResult::Commissioned(record),
            result_digest,
        },
    };
    let deletion = DeletionPublication::new(target, 11, Some(1234), 1234).unwrap();
    let receipt = PublicReceipt {
        sequence: 2,
        operation_id,
        request_digest,
        binding: ReceiptBinding::Device(device),
        target: Some(LiveTarget::Pool(target)),
        outcome: PublicOutcome::Committed {
            result: CommittedResult::Deleted(deletion),
            result_digest,
        },
    };
    let publication = Publication {
        revision: 9,
        timestamp_us: 1234,
        high_water_us: 1234,
        kind: PublicationKind::Drop,
    };
    let responses = [
        Response::Hello(HelloResponse {
            nonce: [10; 32],
            state: HelloState::Committed(HelloIdentity {
                device,
                public_key: [8; 32],
                serial,
                protocol_version: 1,
                storage_version: 2,
                capacity: 64,
                commissioning_state: 1,
                signature: [11; 64],
            }),
        }),
        Response::Status(StatusResponse {
            device,
            revision: 3,
            health: 1,
            commissioning_state: 1,
            receipt_pending: true,
            pool: Some(PoolStatus {
                target,
                revision: 11,
                health: 0,
                active: Some(GenerationStatus {
                    generation,
                    revision: 10,
                    role: 1,
                    period: 2,
                    health: 0,
                    artifact_digest: result_digest,
                }),
                staged: None,
                publication,
            }),
            next_pool: None,
        }),
        Response::Context(ContextResponse {
            target,
            session: 2,
            sequence: 3,
            floor: 4,
            result: Ok(()),
            diagnostics: None,
        }),
        Response::Mutate(receipt),
        Response::Reconcile(receipt),
        Response::ReceiptAck(ReceiptAckResponse {
            sequence: 2,
            result_digest,
            result: Ok(()),
        }),
        Response::Current(CurrentResponse {
            target,
            snapshot_revision: 11,
            publication,
            result: CurrentResult::Drop,
        }),
        Response::Artifact(ArtifactResponse {
            target: generation_target,
            result: ArtifactResult::Retained {
                artifact: b"encrypted",
                digest: result_digest,
                retention_policy: 1,
            },
        }),
        Response::PublicKey(PublicKeyResponse {
            target: generation_target,
            result: PublicKeyResult::Available {
                verification_key: [12; 32],
                revision: 10,
                artifact_digest: result_digest,
            },
        }),
        Response::Commission(commission),
    ];
    for response in &responses {
        let mut bytes = [0; 4096];
        let (kind, n) = encode_response(response, &mut bytes).unwrap();
        let decoded = decode_response(kind, &bytes[..n]).unwrap();
        let mut roundtrip = [0; 4096];
        let (decoded_kind, m) = encode_response(&decoded, &mut roundtrip).unwrap();
        assert_eq!(kind, decoded_kind);
        assert_eq!(&bytes[..n], &roundtrip[..m]);
        bytes[0] += 1;
        bytes[n..n + 3].copy_from_slice(&[0x18, 0x7f, 0xf6]);
        assert!(decode_response(kind, &bytes[..n + 3]).is_err());
    }
    let blank = Response::Hello(HelloResponse {
        nonce: [42; 32],
        state: HelloState::Uncommissioned,
    });
    let mut bytes = [0; 4096];
    let (kind, n) = encode_response(&blank, &mut bytes).unwrap();
    assert!(matches!(
        decode_response(kind, &bytes[..n]),
        Ok(Response::Hello(HelloResponse {
            state: HelloState::Uncommissioned,
            ..
        }))
    ));
    assert!(
        encode_hello_signing(
            &HelloResponse {
                nonce: [42; 32],
                state: HelloState::Uncommissioned
            },
            &mut bytes
        )
        .is_err()
    );
}

#[test]
fn hello_signature_transcript_includes_nonce_not_signature() {
    use kes_core::identity::DeviceId;
    use kes_core::operation::UsbSerial;
    use kes_protocol::usb::*;
    let mut hello = HelloResponse {
        nonce: [1; 32],
        state: HelloState::Committed(HelloIdentity {
            device: DeviceId::from_bytes([2; 16]),
            public_key: [3; 32],
            serial: UsbSerial::new(b"serial").unwrap(),
            protocol_version: 1,
            storage_version: 1,
            capacity: 64,
            commissioning_state: 1,
            signature: [4; 64],
        }),
    };
    let mut a = [0; 4096];
    let n = encode_hello_signing(&hello, &mut a).unwrap();
    if let HelloState::Committed(identity) = &mut hello.state {
        identity.signature = [5; 64];
    }
    let mut b = [0; 4096];
    let m = encode_hello_signing(&hello, &mut b).unwrap();
    assert_eq!(&a[..n], &b[..m]);
    hello.nonce[0] ^= 1;
    let m = encode_hello_signing(&hello, &mut b).unwrap();
    assert_ne!(&a[..n], &b[..m]);
}

#[test]
fn every_request_kind_round_trips() {
    use kes_core::identity::{
        DeviceId, Digest32, GenerationId, IncarnationId, NetworkBinding, OperationId, PoolId,
    };
    use kes_core::operation::{Action, GenerationTarget, Mutation, PoolTarget, UsbSerial};
    use kes_protocol::usb::*;
    let target = PoolTarget {
        pool: PoolId::from_bytes([1; 28]),
        incarnation: IncarnationId::from_bytes([2; 16]),
    };
    let generation = GenerationTarget {
        pool: target,
        generation: GenerationId::from_bytes([3; 16]),
    };
    let op = OperationId::from_bytes([4; 16]);
    let device = DeviceId::from_bytes([5; 16]);
    let digest = Digest32::from_bytes([6; 32]);
    let serial = UsbSerial::new(b"serial").unwrap();
    let network = NetworkBinding::new(digest, 42, 100, 10).unwrap();
    let managed = Mutation::managed(device, 1, op, 2, Action::Generate { target }).unwrap();
    let commission = Mutation::commission(serial, op, 0).unwrap();
    let requests = [
        Request::Hello { nonce: [1; 32] },
        Request::Status {
            pool: Some(target.pool),
        },
        Request::Context {
            target,
            network,
            period: 7,
            session: 8,
            sequence: 9,
            lease_seconds: 30,
            publication_time_us: 10,
        },
        Request::Mutate(managed),
        Request::Reconcile {
            sequence: 0,
            operation_id: op,
            digest: commission.usb_digest(),
            binding: ReconcileBinding::Serial(serial),
        },
        Request::ReceiptAck {
            sequence: 1,
            result_digest: digest,
        },
        Request::Current { target },
        Request::Artifact { target: generation },
        Request::PublicKey { target: generation },
        Request::Commission(commission),
    ];
    for request in &requests {
        let mut bytes = [0; 4096];
        let (kind, n) = encode_request(request, &mut bytes).unwrap();
        let decoded = decode_request(kind, &bytes[..n]).unwrap();
        let mut output = [0; 4096];
        let (other_kind, m) = encode_request(&decoded, &mut output).unwrap();
        assert_eq!(kind, other_kind);
        assert_eq!(&bytes[..n], &output[..m]);
    }
}
