use kes_protocol::management::{Action, Error, FrameDecoder, Kind, MAX_FRAME, Message};

const ID: &str = "00112233445566778899aabbccddeeff";
const POOL: &str = "00112233445566778899aabbccddeeff00112233445566778899aabb";
const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
fn request(action: &str, arguments: &str, mutation: bool) -> String {
    let extra = if mutation {
        format!(",\"operation_id\":\"{ID}\",\"expected_revision\":0")
    } else {
        String::new()
    };
    format!(
        "{{\"version\":1,\"request_id\":\"{ID}\",\"action\":\"{action}\",\"arguments\":{arguments}{extra}}}"
    )
}
fn response(outcome: &str, result: &str, error: &str) -> String {
    format!(
        "{{\"version\":1,\"request_id\":\"{ID}\",\"outcome\":\"{outcome}\",\"result\":{result},\"error\":{error}}}"
    )
}
#[test]
fn framing_fragmentation_limits_and_next_frame() {
    let json = request("device.status", "{}", false);
    let message = Message::decode(json.as_bytes()).unwrap();
    let mut encoded = [0; MAX_FRAME + 4];
    let n = message.encode_frame(&mut encoded).unwrap();
    let mut decoder = FrameDecoder::new();
    for byte in &encoded[..n - 1] {
        assert_eq!(decoder.feed(core::slice::from_ref(byte)), Ok(1));
        assert!(decoder.frame().is_none());
    }
    assert_eq!(decoder.feed(&encoded[n - 1..n]), Ok(1));
    assert_eq!(decoder.frame(), Some(json.as_bytes()));
    assert_eq!(decoder.feed(&encoded[..n]), Ok(0));
    decoder.reset();
    let joined = [encoded[..n].as_ref(), encoded[..n].as_ref()].concat();
    assert_eq!(decoder.feed(&joined), Ok(n));
    decoder.reset();
    assert_eq!(
        decoder.feed(&((MAX_FRAME as u32 + 1).to_be_bytes())),
        Err(Error::Oversized)
    );
}
#[test]
fn every_action_and_exact_argument_schema() {
    let pool = format!("\"pool_id\":\"{POOL}\"");
    let target = format!("{pool},\"incarnation_id\":\"{ID}\"");
    let generation = format!("{target},\"generation_id\":\"{ID}\"");
    let cases = [
        ("device.status", "{}".into(), false, Action::DeviceStatus),
        (
            "device.commission",
            "{\"usb_serial\":\"board\"}".into(),
            true,
            Action::DeviceCommission,
        ),
        (
            "pool.list",
            "{\"page_size\":16,\"cursor\":\"next\"}".into(),
            false,
            Action::PoolList,
        ),
        (
            "pool.status",
            format!("{{{pool}}}"),
            false,
            Action::PoolStatus,
        ),
        (
            "pool.enroll",
            format!("{{\"cold_verification_key\":\"{KEY}\",\"network\":\"mainnet\"}}"),
            true,
            Action::PoolEnroll,
        ),
        (
            "generation.create",
            format!("{{{target}}}"),
            true,
            Action::GenerationCreate,
        ),
        (
            "generation.public_key",
            format!("{{{generation}}}"),
            false,
            Action::GenerationPublicKey,
        ),
        (
            "generation.artifact",
            format!("{{{generation}}}"),
            false,
            Action::GenerationArtifact,
        ),
        (
            "generation.certificate",
            format!("{{{generation},\"certificate\":\"00ff\"}}"),
            true,
            Action::GenerationCertificate,
        ),
        (
            "generation.discard",
            format!("{{{generation}}}"),
            true,
            Action::GenerationDiscard,
        ),
        (
            "recipient.set",
            format!("{{\"public_key\":\"{KEY}\"}}"),
            true,
            Action::RecipientSet,
        ),
        (
            "pool.delete",
            format!("{{{target}}}"),
            true,
            Action::PoolDelete,
        ),
        (
            "operation.reconcile",
            format!("{{\"operation_id\":\"{ID}\",\"request_digest\":\"{KEY}\"}}"),
            false,
            Action::OperationReconcile,
        ),
    ];
    for (name, args, mutation, action) in cases {
        let input = request(name, &args, mutation);
        assert!(
            matches!(Message::decode(input.as_bytes()).unwrap().kind(), Kind::Request { action: a, .. } if a == action)
        );
        let extra = if args == "{}" {
            "{\"unexpected\":1}".into()
        } else {
            format!("{},\"unexpected\":1}}", &args[..args.len() - 1])
        };
        assert!(Message::decode(request(name, &extra, mutation).as_bytes()).is_err());
        if mutation {
            assert!(Message::decode(request(name, &args, false).as_bytes()).is_err());
        }
    }
    assert!(Message::decode(request("pool.status", "{}", false).as_bytes()).is_err());
    assert!(Message::decode(request("device.status", "{}", true).as_bytes()).is_err());
    assert!(Message::decode(request("other", "{}", false).as_bytes()).is_err());
}
#[test]
fn strict_json_duplicate_escaping_and_numbers() {
    let input = request("device.status", "{}", false);
    for bad in [
        input.replace("\"version\":1", "\"version\":1,\"ver\\u0073ion\":1"),
        input.replace("{}", "{\"pool_id\":1,\"pool_id\":2}"),
        input.replace("\"version\":1", "\"version\":01"),
        input.replace("\"version\":1", "\"version\":1.0"),
        input.replace("\"version\":1", "\"version\":-1"),
        input.replace("\"version\":1", "\"version\":18446744073709551616"),
        format!("{input} null"),
        input.replace("device.status", "device.\\qstatus"),
        input.replace("device.status", "device.\\ud800status"),
        input.replace("\"version\":1", "\"version\":2"),
    ] {
        assert!(Message::decode(bad.as_bytes()).is_err(), "{bad}");
    }
    let good = input.replace("device.status", "device.\\u0073tatus");
    assert!(Message::decode(good.as_bytes()).is_ok());
    let duplicate = request(
        "pool.status",
        &format!("{{\"pool_id\":\"{POOL}\",\"pool_\\u0069d\":\"{POOL}\"}}"),
        false,
    );
    assert_eq!(
        Message::decode(duplicate.as_bytes()).unwrap_err(),
        Error::DuplicateField
    );
    assert!(Message::decode(&[0xff]).is_err());
}
#[test]
fn ids_hex_and_integer_bounds() {
    for bad in [ID.to_uppercase(), ID[..30].into(), format!("{ID}00")] {
        assert!(
            Message::decode(
                request("device.status", "{}", false)
                    .replace(ID, &bad)
                    .as_bytes()
            )
            .is_err()
        );
    }
    for bad in ["0", "17", "18446744073709551616", "1e0"] {
        assert!(
            Message::decode(
                request("pool.list", &format!("{{\"page_size\":{bad}}}"), false).as_bytes()
            )
            .is_err()
        );
    }
    assert!(
        Message::decode(
            request(
                "recipient.set",
                &format!("{{\"public_key\":\"{}\"}}", KEY.to_uppercase()),
                true
            )
            .as_bytes()
        )
        .is_err()
    );
    let commissioned = request("device.commission", "{\"usb_serial\":\"x\"}", true)
        .replace("\"expected_revision\":0", "\"expected_revision\":1");
    assert!(Message::decode(commissioned.as_bytes()).is_err());
}
#[test]
fn outcomes_are_exclusive_and_secrets_not_fields() {
    let reject = "{\"code\":\"revision_conflict\",\"message\":\"stale\",\"reconciliation_advice\":\"reconcile\"}";
    let unknown = "{\"code\":\"outcome_unknown\",\"message\":\"reconcile\"}";
    for (o, r, e) in [
        ("success", "{}", "null"),
        ("rejected", "null", reject),
        ("pending", "null", unknown),
        ("uncertain", "null", unknown),
    ] {
        assert!(Message::decode(response(o, r, e).as_bytes()).is_ok());
    }
    for (o, r, e) in [
        ("success", "{}", reject),
        ("success", "null", "null"),
        ("rejected", "null", unknown),
        ("pending", "null", reject),
        ("uncertain", "{}", "null"),
        (
            "rejected",
            "null",
            "{\"code\":\"not_real\",\"message\":\"x\"}",
        ),
    ] {
        assert!(Message::decode(response(o, r, e).as_bytes()).is_err());
    }
    for secret in [
        "secret",
        "operational_key",
        "current_key",
        "signing_key",
        "private_key",
        "key_state",
    ] {
        let result = format!("{{\"{secret}\":\"00\"}}");
        assert!(Message::decode(response("success", &result, "null").as_bytes()).is_err());
    }
}

#[test]
fn bounded_artifact_and_revision() {
    let artifact = "ab".repeat(2048);
    assert!(
        Message::decode(
            response(
                "success",
                &format!("{{\"artifact\":\"{artifact}\",\"revision\":18446744073709551615}}"),
                "null"
            )
            .as_bytes()
        )
        .is_ok()
    );
    let too_large = "ab".repeat(2049);
    assert!(
        Message::decode(
            response(
                "success",
                &format!("{{\"artifact\":\"{too_large}\"}}"),
                "null"
            )
            .as_bytes()
        )
        .is_err()
    );
    assert!(
        Message::decode(response("success", "{\"artifact\":\"AB\"}", "null").as_bytes()).is_err()
    );
}
