use kes_core::identity::{DeviceId, Digest32, IncarnationId, NetworkBinding, PoolId};
use kes_core::operation::PoolTarget;
use kes_protocol::usb::{Request, Response};
use pico2_kes_agent::daemon::usb::{IdentityPin, Mode, Transport, UsbSelection};
use serde::Deserialize;
use std::{fs, path::Path, time::Duration};

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
    let reply = transport
        .request(&Request::Context {
            target,
            network,
            period: input.period,
            session: input.session,
            sequence: input.sequence,
            lease_seconds: input.lease_seconds,
            publication_time_us: input.publication_time_us,
        })
        .map_err(|error| format!("request: {error}"))?;
    let Response::Context(response) = reply.decode().map_err(|error| format!("decode: {error}"))?
    else {
        return Err("device returned the wrong response kind".into());
    };
    if response.target != target
        || response.session != input.session
        || response.sequence != input.sequence
    {
        return Err("device returned a mismatched context binding".into());
    }
    response
        .result
        .map_err(|code| format!("device rejected context with code {code}"))?;
    println!(
        "accepted pool={} incarnation={} period={} floor={}",
        input.pool_id, input.incarnation_id, input.period, response.floor
    );
    Ok(())
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
