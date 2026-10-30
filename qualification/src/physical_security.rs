//! Attended public observations; current KES material never leaves zeroizing memory.
use super::parse_hex;
use crate::evidence;
use kes_core::{
    certificate::OperationalCertificate,
    identity::{DeviceId, Digest32, IncarnationId, NetworkBinding, PoolId},
    operation::{GenerationTarget, PoolTarget},
};
use kes_protocol::usb::{
    ArtifactResult, CurrentResult, PublicKeyResult, PublicationKind, Request, Response,
};
use pico2_kes_agent::memory::{SecretBuffer, protect_process};
use pico2_kes_agent::{
    backup::recover::{Expectations, artifact_recipient},
    daemon::usb::{IdentityPin, Mode, Transport, UsbSelection},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    device_id: String,
    identity_public_key: String,
    usb_serial: String,
    recipient_public_key: String,
    genesis_digest: String,
    network_magic: u32,
    slots_per_period: u64,
    lifetime: u8,
    period: u64,
    session: u64,
    sequence: u64,
    lease_seconds: u8,
    publication_time_us: u64,
    scenario: String,
    before_bundle: PathBuf,
    after_bundle: PathBuf,
    output: PathBuf,
    pools: Vec<PoolInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolInput {
    pool_id: String,
    incarnation_id: String,
    active_certificate: PathBuf,
    staged_certificate: PathBuf,
}
struct Capture {
    public: Value,
    state: SecretBuffer,
    target: PoolTarget,
    staged: kes_core::identity::GenerationId,
    staged_key: [u8; 32],
    staged_certificate: [u8; 112],
    staged_start: u64,
    floor: u64,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("input file is not a bounded regular file".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}
fn bundle(path: &Path) -> Result<(String, String, String, String), String> {
    // The checked-out verifier is trusted, not the verifier inside the bundle.
    let status = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/firmware.py"))
        .arg("verify")
        .arg("--bundle")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("bundle verifier: {e}"))?;
    if !status.success() {
        return Err("bundle verification failed".into());
    }
    let bytes = read_bounded(&path.join("release.json"), 65536)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid release manifest")?;
    let commit = value
        .get("commit")
        .and_then(Value::as_str)
        .ok_or("missing release commit")?;
    let tag = value
        .get("tag")
        .and_then(Value::as_str)
        .ok_or("missing release tag")?;
    let image = value
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or("missing artifacts")?
        .iter()
        .find(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("pico2-kes-firmware.signed.uf2")
        })
        .and_then(|entry| entry.get("sha256"))
        .and_then(Value::as_str)
        .ok_or("missing signed UF2 digest")?;
    Ok((
        hex(&Sha256::digest(&bytes)),
        commit.to_owned(),
        tag.to_owned(),
        image.to_owned(),
    ))
}
fn certificate(path: &Path, pool: PoolId) -> Result<OperationalCertificate, String> {
    let bytes = read_bounded(path, 154)?;
    let c = OperationalCertificate::decode(&bytes)
        .map_err(|_| "invalid public operational certificate")?;
    if PoolId::from_cold_verification_key(c.cold_verification_key()) != pool {
        return Err("certificate cold key does not identify pool".into());
    }
    c.certificate()
        .verify(c.cold_verification_key())
        .map_err(|_| "invalid certificate signature")?;
    Ok(c)
}
fn context(
    transport: &mut Transport,
    input: &Input,
    target: PoolTarget,
    network: NetworkBinding,
    period: u64,
    offset: u64,
) -> Result<u64, String> {
    let sequence = input
        .sequence
        .checked_add(offset)
        .ok_or("sequence overflow")?;
    let session = input
        .session
        .checked_add(offset)
        .ok_or("session overflow")?;
    let time = input
        .publication_time_us
        .checked_add(offset)
        .ok_or("publication time overflow")?;
    let reply = transport
        .request(&Request::Context {
            target,
            network,
            period,
            session,
            sequence,
            lease_seconds: input.lease_seconds,
            publication_time_us: time,
        })
        .map_err(|e| format!("context: {e}"))?;
    let Response::Context(response) = reply.decode().map_err(|e| e.to_string())? else {
        return Err("wrong context response".into());
    };
    if response.target != target
        || response.session != session
        || response.sequence != sequence
        || response.result.is_err()
        || response.floor != period
    {
        return Err("context rejected or period floor mismatch".into());
    }
    Ok(response.floor)
}
fn key(
    transport: &mut Transport,
    target: GenerationTarget,
    digest: Digest32,
) -> Result<[u8; 32], String> {
    let reply = transport
        .request(&Request::PublicKey { target })
        .map_err(|e| e.to_string())?;
    let Response::PublicKey(response) = reply.decode().map_err(|e| e.to_string())? else {
        return Err("wrong public-key response".into());
    };
    match response.result {
        PublicKeyResult::Available {
            verification_key,
            artifact_digest,
            ..
        } if response.target == target && artifact_digest == digest => Ok(verification_key),
        _ => Err("public key unavailable or binding mismatch".into()),
    }
}
fn artifact(
    transport: &mut Transport,
    target: GenerationTarget,
    expected: Digest32,
    pin: IdentityPin,
    recipient: &[u8; 32],
    verification_key: &[u8; 32],
) -> Result<(), String> {
    let reply = transport
        .request(&Request::Artifact { target })
        .map_err(|e| e.to_string())?;
    let Response::Artifact(response) = reply.decode().map_err(|e| e.to_string())? else {
        return Err("wrong artifact response".into());
    };
    let ArtifactResult::Retained {
        artifact, digest, ..
    } = response.result
    else {
        return Err("artifact unavailable".into());
    };
    if response.target != target
        || digest != expected
        || Sha256::digest(artifact).as_slice() != digest.as_bytes()
    {
        return Err("artifact digest mismatch".into());
    }
    let actual = artifact_recipient(
        artifact,
        Expectations {
            device: *pin.device.as_bytes(),
            pool: *target.pool.pool.as_bytes(),
            incarnation: *target.pool.incarnation.as_bytes(),
            generation: *target.generation.as_bytes(),
            verification_key: *verification_key,
            identity_public_key: pin.public_key,
        },
    )
    .map_err(|_| "artifact signature or binding invalid")?;
    if &actual != recipient {
        return Err("artifact recipient mismatch".into());
    }
    Ok(())
}
fn capture(
    transport: &mut Transport,
    input: &Input,
    pool: &PoolInput,
    network: NetworkBinding,
    offset: u64,
) -> Result<Capture, String> {
    let target = PoolTarget {
        pool: PoolId::parse_hex(&pool.pool_id).map_err(|_| "invalid pool")?,
        incarnation: IncarnationId::parse_hex(&pool.incarnation_id)
            .map_err(|_| "invalid incarnation")?,
    };
    let active_cert = certificate(&pool.active_certificate, target.pool)?;
    let staged_cert = certificate(&pool.staged_certificate, target.pool)?;
    if staged_cert.certificate().start_period() <= input.period {
        return Err("staged start must follow comparison period".into());
    }
    let floor = context(transport, input, target, network, input.period, offset)?;
    let reply = transport
        .request(&Request::Status {
            pool: Some(target.pool),
        })
        .map_err(|e| e.to_string())?;
    let Response::Status(status) = reply.decode().map_err(|e| e.to_string())? else {
        return Err("wrong status response".into());
    };
    let p = status.pool.ok_or("pool unavailable")?;
    if p.target != target
        || status.device != DeviceId::parse_hex(&input.device_id).map_err(|_| "invalid device")?
    {
        return Err("identity mismatch".into());
    }
    let active = p.active.ok_or("active generation missing")?;
    let staged = p.staged.ok_or("staged generation missing")?;
    let ak = key(
        transport,
        GenerationTarget {
            pool: target,
            generation: active.generation,
        },
        active.artifact_digest,
    )?;
    let sk = key(
        transport,
        GenerationTarget {
            pool: target,
            generation: staged.generation,
        },
        staged.artifact_digest,
    )?;
    if &ak != active_cert.certificate().hot_verification_key()
        || &sk != staged_cert.certificate().hot_verification_key()
    {
        return Err("certificate verification key mismatch".into());
    }
    let pin = IdentityPin {
        device: DeviceId::parse_hex(&input.device_id).map_err(|_| "invalid device")?,
        public_key: parse_hex(&input.identity_public_key)?,
        serial: UsbSelection::new(input.usb_serial.as_bytes()).map_err(|e| e.to_string())?,
    };
    let recipient = parse_hex(&input.recipient_public_key)?;
    artifact(
        transport,
        GenerationTarget {
            pool: target,
            generation: active.generation,
        },
        active.artifact_digest,
        pin,
        &recipient,
        &ak,
    )?;
    artifact(
        transport,
        GenerationTarget {
            pool: target,
            generation: staged.generation,
        },
        staged.artifact_digest,
        pin,
        &recipient,
        &sk,
    )?;
    let reply = transport
        .request(&Request::Current { target })
        .map_err(|e| e.to_string())?;
    let Response::Current(current) = reply.decode().map_err(|e| e.to_string())? else {
        return Err("wrong current response".into());
    };
    let CurrentResult::Key {
        generation,
        period,
        state,
        certificate,
    } = current.result
    else {
        return Err("active current key unavailable".into());
    };
    let expected_cert = active_cert.certificate().direct_bytes();
    if current.target != target
        || generation != active.generation
        || active_cert.certificate().start_period().checked_add(period) != Some(input.period)
        || certificate != expected_cert
        || !matches!(current.publication.kind, PublicationKind::Key { generation: g, period: p, certificate_digest } if g == generation && p == period && certificate_digest == active_cert.certificate().digest())
    {
        return Err("active current binding mismatch".into());
    }
    if kes_core::kes::verification_key_from_state(
        state,
        u8::try_from(period).map_err(|_| "invalid current period")?,
    )
    .map_err(|_| "invalid current KES state")?
        != ak
    {
        return Err("current KES state has another verification key".into());
    }
    let saved = SecretBuffer::copy_from_slice(state)
        .map_err(|_| "cannot lock current KES comparison memory")?;
    let public = json!({"pool_id": pool.pool_id, "incarnation": pool.incarnation_id, "recipient": hex(&recipient), "active_generation": active.generation.to_string(), "staged_generation": staged.generation.to_string(), "active_verification_key": hex(&ak), "staged_verification_key": hex(&sk), "active_certificate_sha256": active_cert.certificate().digest().to_string(), "staged_certificate_sha256": staged_cert.certificate().digest().to_string(), "active_artifact_sha256": active.artifact_digest.to_string(), "staged_artifact_sha256": staged.artifact_digest.to_string(), "period_floor": floor});
    Ok(Capture {
        public,
        state: saved,
        target,
        staged: staged.generation,
        staged_key: sk,
        staged_certificate: staged_cert.certificate().direct_bytes(),
        staged_start: staged_cert.certificate().start_period(),
        floor,
    })
}
fn security(transport: &mut Transport) -> Result<Value, String> {
    let reply = transport
        .request(&Request::SecurityStatus)
        .map_err(|e| e.to_string())?;
    let Response::SecurityStatus(s) = reply.decode().map_err(|e| e.to_string())? else {
        return Err("security report unavailable".into());
    };
    if s.profile(kes_protocol::security::AUTHORIZED_BOOTKEY.as_ref()) != "rp2350-signed-msd-v1" {
        return Err("device security profile is not fully locked".into());
    }
    Ok(
        json!({"chip_revision":s.chip_revision,"rom_version":s.rom_version,"stepping":s.stepping(),"critical":s.critical,"boot_flags0":s.boot_flags0,"boot_flags1":s.boot_flags1,"bootkey0":hex(&s.bootkey0),"page2_lock0":s.page2_lock0,"page2_lock1":s.page2_lock1,"page63_lock0":s.page63_lock0,"page63_lock1":s.page63_lock1,"debugen":s.debugen,"debugen_lock":s.debugen_lock,"redundancy_ok":s.redundancy_ok,"jedec_id":hex(&s.jedec_id),"sfdp_header":hex(&s.sfdp_header),"density_bits_minus_one":s.density_bits_minus_one,"usb_serial":std::str::from_utf8(&s.usb_serial).map_err(|_| "invalid security serial")?,"storage_blank_at_boot":s.storage_blank_at_boot}),
    )
}
pub(super) fn execute(path: &Path) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("preservation requires an attended terminal".into());
    }
    protect_process().map_err(|_| "cannot disable process dumps")?;
    let input: Input = serde_json::from_slice(&read_bounded(path, 65536)?).map_err(|e| {
        format!(
            "invalid public fixture schema at {}:{}",
            e.line(),
            e.column()
        )
    })?;
    if input.output == path {
        return Err("output must not replace input".into());
    }
    match execute_attended(&input) {
        Ok(()) => Ok(()),
        Err(error) => {
            let candidate = evidence::candidate();
            let failure = json!({"outcome":"fail","candidate":candidate,"scenario":input.scenario,"description":"Attended preservation observation failed; see operator diagnostics."});
            let bytes = serde_json::to_vec_pretty(&failure).map_err(|e| e.to_string())?;
            evidence::atomic_write(&input.output, &bytes).map_err(|e| {
                format!("cannot write failure evidence: {e}; original error: {error}")
            })?;
            Err(error)
        }
    }
}
fn validate_bundle_transition(
    scenario: &str,
    before: (&str, &str, &str, &str),
    after: (&str, &str, &str, &str),
) -> Result<(), String> {
    if scenario == "reinstall" {
        if before != after {
            return Err("reinstall requires identical verified bundles".into());
        }
    } else if before.0 == after.0
        || before.1 == after.1
        || before.2 == after.2
        || before.3 == after.3
    {
        return Err(
            "distinct verified versions, source commits, manifests and firmware images required"
                .into(),
        );
    }
    Ok(())
}

fn execute_attended(input: &Input) -> Result<(), String> {
    if input.pools.len() < 2
        || input.pools.len() > 16
        || !matches!(
            input.scenario.as_str(),
            "upgrade"
                | "reinstall"
                | "downgrade"
                | "interrupted_beginning"
                | "interrupted_middle"
                | "interrupted_end"
        )
    {
        return Err("invalid scenario or pool count".into());
    }
    let mut ids = std::collections::HashSet::new();
    if input.pools.iter().any(|p| !ids.insert(&p.pool_id)) {
        return Err("duplicate pool".into());
    }
    let before_bundle = bundle(&input.before_bundle)?;
    let after_bundle = bundle(&input.after_bundle)?;
    validate_bundle_transition(
        &input.scenario,
        (
            &before_bundle.0,
            &before_bundle.1,
            &before_bundle.2,
            &before_bundle.3,
        ),
        (
            &after_bundle.0,
            &after_bundle.1,
            &after_bundle.2,
            &after_bundle.3,
        ),
    )?;
    let pin = IdentityPin {
        device: DeviceId::parse_hex(&input.device_id).map_err(|_| "invalid device")?,
        public_key: parse_hex(&input.identity_public_key)?,
        serial: UsbSelection::new(input.usb_serial.as_bytes()).map_err(|e| e.to_string())?,
    };
    let network = NetworkBinding::new(
        Digest32::parse_hex(&input.genesis_digest).map_err(|_| "invalid genesis")?,
        input.network_magic,
        input.slots_per_period,
        input.lifetime,
    )
    .map_err(|_| "invalid network")?;
    let candidate = evidence::candidate().ok_or("candidate identity unavailable")?;
    let mut transport = Transport::connect(Mode::Normal { pin }, Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let before_security = security(&mut transport)?;
    if before_security["usb_serial"] != input.usb_serial {
        return Err("security report serial mismatch".into());
    }
    let mut before = Vec::with_capacity(input.pools.len());
    for (i, pool) in input.pools.iter().enumerate() {
        before.push(capture(&mut transport, &input, pool, network, i as u64)?);
    }
    drop(transport);
    println!(
        "USB released. Perform {} using the verified bundle at {}. For interruption scenarios, interrupt the indicated portion and then copy the complete verified bundle. Reboot into the application, then type the exact serial {}:",
        input.scenario,
        input.after_bundle.display(),
        input.usb_serial
    );
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .map_err(|e| e.to_string())?;
    if confirmation.trim_end() != input.usb_serial {
        return Err("serial confirmation mismatch".into());
    }
    let mut transport = Transport::connect(Mode::Normal { pin }, Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let after_security = security(&mut transport)?;
    if after_security["usb_serial"] != input.usb_serial {
        return Err("security report serial mismatch".into());
    }
    let mut after = Vec::with_capacity(input.pools.len());
    for (i, pool) in input.pools.iter().enumerate() {
        after.push(capture(
            &mut transport,
            &input,
            pool,
            network,
            input.pools.len() as u64 + i as u64,
        )?);
    }
    for (a, b) in before.iter().zip(&after) {
        if a.public != b.public || a.state.as_slice() != b.state.as_slice() || a.floor != b.floor {
            return Err("state or public bindings changed after update".into());
        }
    }
    for capture in before.iter_mut().chain(after.iter_mut()) {
        capture.state.clear();
    }
    let mut activated = Vec::new();
    for (i, a) in before.iter().enumerate() {
        context(
            &mut transport,
            &input,
            a.target,
            network,
            a.staged_start,
            2 * input.pools.len() as u64 + i as u64,
        )?;
        let reply = transport
            .request(&Request::Current { target: a.target })
            .map_err(|e| e.to_string())?;
        let Response::Current(current) = reply.decode().map_err(|e| e.to_string())? else {
            return Err("wrong staged current response".into());
        };
        let CurrentResult::Key {
            generation,
            period,
            certificate,
            state,
        } = current.result
        else {
            return Err("staged generation unavailable after activation".into());
        };
        let certificate_digest = Digest32::from_bytes(Sha256::digest(&a.staged_certificate).into());
        if current.target != a.target
            || generation != a.staged
            || period != 0
            || certificate != a.staged_certificate
            || certificate[..32] != a.staged_key
            || !matches!(current.publication.kind, PublicationKind::Key { generation: g, period: 0, certificate_digest: d } if g == generation && d == certificate_digest)
        {
            return Err("activated generation binding mismatch".into());
        }
        if kes_core::kes::verification_key_from_state(state, 0)
            .map_err(|_| "invalid activated KES state")?
            != a.staged_key
        {
            return Err("activated KES state has another verification key".into());
        }
        activated.push(json!({"pool_id":a.target.pool.to_string(),"incarnation":a.target.incarnation.to_string(),"generation":generation.to_string(),"verification_key":hex(&a.staged_key),"certificate_sha256":certificate_digest.to_string(),"activation_period":a.staged_start,"usable":true}));
    }
    drop(transport);
    println!(
        "USB released. Replenish a disposable staged generation for each pool using the existing attended workflow, without changing the recipient. Stop the daemon, then type the exact serial {}:",
        input.usb_serial
    );
    io::stdout().flush().map_err(|e| e.to_string())?;
    confirmation.clear();
    io::stdin()
        .read_line(&mut confirmation)
        .map_err(|e| e.to_string())?;
    if confirmation.trim_end() != input.usb_serial {
        return Err("serial confirmation mismatch".into());
    }
    let mut transport = Transport::connect(Mode::Normal { pin }, Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let mut replenished = Vec::new();
    for a in &before {
        let reply = transport
            .request(&Request::Status {
                pool: Some(a.target.pool),
            })
            .map_err(|e| e.to_string())?;
        let Response::Status(status) = reply.decode().map_err(|e| e.to_string())? else {
            return Err("wrong replenishment status response".into());
        };
        let pool = status.pool.ok_or("replenished pool unavailable")?;
        let active = pool
            .active
            .ok_or("activated generation unavailable after replenishment")?;
        let staged = pool.staged.ok_or("new staged generation unavailable")?;
        if pool.target != a.target || active.generation != a.staged || staged.generation == a.staged
        {
            return Err("replenished generation binding mismatch".into());
        }
        let target = GenerationTarget {
            pool: a.target,
            generation: staged.generation,
        };
        let verification_key = key(&mut transport, target, staged.artifact_digest)?;
        let recipient = parse_hex(&input.recipient_public_key)?;
        artifact(
            &mut transport,
            target,
            staged.artifact_digest,
            pin,
            &recipient,
            &verification_key,
        )?;
        replenished.push(json!({"pool_id":a.target.pool.to_string(),"incarnation":a.target.incarnation.to_string(),"generation":staged.generation.to_string(),"verification_key":hex(&verification_key),"artifact_sha256":staged.artifact_digest.to_string()}));
    }
    let observation = json!({"scenario":input.scenario,"from_version":before_bundle.2,"to_version":after_bundle.2,"from_commit":before_bundle.1,"to_commit":after_bundle.1,"from_image_sha256":before_bundle.3,"to_image_sha256":after_bundle.3,"storage_version":2,"period":input.period,"before":before.iter().map(|x| &x.public).collect::<Vec<_>>(),"after":after.iter().map(|x| &x.public).collect::<Vec<_>>(),"current_kes_equal":true,"staged_activated":true,"activated":activated,"description":"Attended signed UF2 transfer; image execution is operationally inferred, not independently attested."});
    let report = json!({"outcome":"pass","candidate_commit":candidate.0,"candidate_dirty":candidate.1,"before_manifest_sha256":before_bundle.0,"after_manifest_sha256":after_bundle.0,"before_security":before_security,"after_security":after_security,"observation":observation,"replenished":replenished});
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    evidence::atomic_write(&input.output, &bytes).map_err(|e| e.to_string())?;
    println!(
        "Public preservation observation written; full security qualification requires the other independent checks."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_bundle_transition;

    #[test]
    fn reinstall_requires_all_bundle_fields_equal() {
        let before = ("manifest", "commit", "tag", "image");
        assert!(validate_bundle_transition("reinstall", before, before).is_ok());
        for after in [
            ("other", "commit", "tag", "image"),
            ("manifest", "other", "tag", "image"),
            ("manifest", "commit", "other", "image"),
            ("manifest", "commit", "tag", "other"),
        ] {
            assert!(validate_bundle_transition("reinstall", before, after).is_err());
        }
    }

    #[test]
    fn existing_scenarios_require_every_field_distinct() {
        let before = ("manifest", "commit", "tag", "image");
        let distinct = ("other-manifest", "other-commit", "other-tag", "other-image");
        for scenario in [
            "upgrade",
            "downgrade",
            "interrupted_beginning",
            "interrupted_middle",
            "interrupted_end",
        ] {
            assert!(validate_bundle_transition(scenario, before, before).is_err());
            assert!(validate_bundle_transition(scenario, before, distinct).is_ok());
            for after in [
                ("manifest", distinct.1, distinct.2, distinct.3),
                (distinct.0, "commit", distinct.2, distinct.3),
                (distinct.0, distinct.1, "tag", distinct.3),
                (distinct.0, distinct.1, distinct.2, "image"),
            ] {
                assert!(validate_bundle_transition(scenario, before, after).is_err());
            }
        }
    }
}
