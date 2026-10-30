use kes_core::identity::{DeviceId, Digest32, IncarnationId, NetworkBinding, PoolId};
use kes_core::operation::PoolTarget;
use kes_protocol::usb::{ContextResponse, Kind, Request, Response};
use pico2_kes_agent::daemon::usb::{IdentityPin, Mode, Transport, UsbSelection};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[path = "context_evidence.rs"]
mod context_evidence;
use context_evidence::ContextEvidence;

#[path = "physical_security.rs"]
mod physical_security;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    device_id: String,
    identity_public_key: String,
    usb_serial: String,
    pool_id: String,
    incarnation_id: String,
    genesis_digest: String,
    network_magic: u32,
    slots_per_period: u64,
    lifetime: u8,
    period: u64,
    session: u64,
    sequence: u64,
    lease_seconds: u8,
    publication_time_us: u64,
}

pub fn run(arguments: &[String]) -> i32 {
    if let [flag, input, path] = arguments
        && flag == "--preserve-update"
        && input == "--input"
    {
        return match physical_security::execute(Path::new(path)) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("physical preservation: {error}");
                1
            }
        };
    }
    let [flag, path] = arguments else {
        eprintln!("usage: qualification physical-context --input INPUT.json");
        return 2;
    };
    if flag != "--input" {
        eprintln!("usage: qualification physical-context --input INPUT.json");
        return 2;
    }
    match execute(Path::new(path)) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("physical context: {error}");
            1
        }
    }
}

fn execute(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("input exceeds 16 KiB".into());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let pin = IdentityPin {
        device: DeviceId::parse_hex(&input.device_id).map_err(|_| "invalid device_id")?,
        public_key: parse_hex(&input.identity_public_key)?,
        serial: UsbSelection::new(input.usb_serial.as_bytes())
            .map_err(|error| error.to_string())?,
    };
    let target = PoolTarget {
        pool: PoolId::parse_hex(&input.pool_id).map_err(|_| "invalid pool_id")?,
        incarnation: IncarnationId::parse_hex(&input.incarnation_id)
            .map_err(|_| "invalid incarnation_id")?,
    };
    let network = NetworkBinding::new(
        Digest32::parse_hex(&input.genesis_digest).map_err(|_| "invalid genesis_digest")?,
        input.network_magic,
        input.slots_per_period,
        input.lifetime,
    )
    .map_err(|_| "invalid network binding")?;
    let mut transport = Transport::connect(Mode::Normal { pin }, Duration::from_secs(10))
        .map_err(|error| format!("connect: {error}"))?;
    let status = transport
        .request(&Request::Status {
            pool: Some(target.pool),
        })
        .map_err(|error| format!("status request: {error}"))?;
    let Response::Status(status) = status
        .decode()
        .map_err(|error| format!("status decode: {error}"))?
    else {
        return Err("device returned the wrong status response kind".into());
    };
    println!("pre-context pool status: {:?}", status.pool);
    let evidence = context_evidence_path(path, None, input.session, input.sequence);
    let response = request_context(
        &mut transport,
        &evidence,
        Request::Context {
            target,
            network,
            period: input.period,
            session: input.session,
            sequence: input.sequence,
            lease_seconds: input.lease_seconds,
            publication_time_us: input.publication_time_us,
        },
        None,
    )?;
    println!(
        "accepted pool={} incarnation={} period={} floor={}",
        input.pool_id, input.incarnation_id, input.period, response.floor
    );
    Ok(())
}

fn context_evidence_path(base: &Path, step: Option<u64>, session: u64, sequence: u64) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    match step {
        Some(step) => name.push(format!(".context-{step}-{session}-{sequence}.jsonl")),
        None => name.push(format!(".context-{session}-{sequence}.jsonl")),
    }
    PathBuf::from(name)
}

fn request_context(
    transport: &mut Transport,
    path: &Path,
    request: Request,
    expected_floor: Option<u64>,
) -> Result<ContextResponse, String> {
    let Request::Context {
        target,
        network,
        period,
        session,
        sequence,
        lease_seconds,
        publication_time_us,
    } = request
    else {
        return Err("context evidence requires a Context request".into());
    };
    let location = path.display();
    let intent = json!({
        "event": "intent", "pool_id": target.pool.to_string(),
        "incarnation_id": target.incarnation.to_string(),
        "genesis_digest": network.genesis().to_string(), "network_magic": network.magic(),
        "slots_per_period": network.slots_per_period(), "lifetime": network.lifetime(),
        "period": period, "session": session, "sequence": sequence,
        "lease_seconds": lease_seconds, "publication_time_us": publication_time_us
    });
    let mut evidence = ContextEvidence::reserve(path, &intent)?;
    let reply = match transport.request(&request) {
        Ok(reply) => reply,
        Err(error) => {
            let message = format!("context transport: {error}");
            evidence
                .event(&json!({"event":"transport_error","error":message}))
                .map_err(|e| format!("{message}; cannot persist error in {location}: {e}"))?;
            return Err(format!("{message}; evidence: {location}"));
        }
    };
    evidence.reply(reply.kind, reply.payload())?;
    if reply.kind != Kind::Context {
        let message = "device returned the wrong context response kind";
        evidence
            .event(&json!({"event":"decode_error","error":message}))
            .map_err(|e| format!("{message}; cannot persist error in {location}: {e}"))?;
        return Err(format!("{message}; evidence: {location}"));
    }
    let response = match reply.decode() {
        Ok(Response::Context(response)) => response,
        Ok(_) => {
            let message = "device returned the wrong context response kind";
            evidence
                .event(&json!({"event":"decode_error","error":message}))
                .map_err(|e| format!("{message}; cannot persist error in {location}: {e}"))?;
            return Err(format!("{message}; evidence: {location}"));
        }
        Err(error) => {
            let message = format!("context decode: {error}");
            evidence
                .event(&json!({"event":"decode_error","error":message}))
                .map_err(|e| format!("{message}; cannot persist error in {location}: {e}"))?;
            return Err(format!("{message}; evidence: {location}"));
        }
    };
    let decoded = format!("{response:?}");
    let failure = if response.target != target
        || response.session != session
        || response.sequence != sequence
    {
        Some("mismatched context binding")
    } else if response.result.is_err() {
        Some("device rejected context")
    } else if expected_floor.is_some_and(|floor| response.floor != floor) {
        Some("context period floor mismatch")
    } else {
        None
    };
    evidence
        .event(&json!({"event":"decoded","response":decoded,"failure":failure}))
        .map_err(|error| {
            format!("cannot persist decoded context {location}: {error}; response: {decoded}")
        })?;
    if let Some(failure) = failure {
        return Err(format!(
            "{failure}; response: {decoded}; evidence: {location}"
        ));
    }
    Ok(response)
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err("invalid hexadecimal length".into());
    }
    let mut output = [0; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        output[index] = (nibble(pair[0]).ok_or("invalid hexadecimal input")? << 4)
            | nibble(pair[1]).ok_or("invalid hexadecimal input")?;
    }
    Ok(output)
}
