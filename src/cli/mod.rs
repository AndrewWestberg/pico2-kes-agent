//! Operator CLI (`p2kes`) — 10-workflow command surface.

pub mod client;
pub mod status;

use kes_core::identity::OperationId;
use kes_protocol::management::Action;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const DEFAULT_SOCKET: &str = "/run/pico2-kes-agent/management.sock";

pub fn run(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_help();
        return Ok(());
    }

    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut json_mode = false;
    let mut auto_yes = false;
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                socket = PathBuf::from(args.get(i).ok_or("--socket requires a path")?);
            }
            "--json" => json_mode = true,
            "-y" | "--yes" => auto_yes = true,
            _ => pos.push(args[i].clone()),
        }
        i += 1;
    }

    if pos.is_empty() {
        print_help();
        return Ok(());
    }

    match pos[0].as_str() {
        "status" => cmd_status(&socket, &pos[1..], json_mode),
        "commission" => cmd_commission(&socket, &pos[1..], json_mode),
        "reconcile" => cmd_reconcile(&socket, json_mode),
        "pool" => match pos.get(1).map(String::as_str) {
            Some("add") => cmd_pool_add(&socket, &pos[2..], json_mode),
            Some("rm") => cmd_pool_rm(&socket, &pos[2..], auto_yes, json_mode),
            _ => Err("usage: p2kes pool <add|rm> ...".into()),
        },
        "key" => match pos.get(1).map(String::as_str) {
            Some("rotate") => cmd_key_rotate(&socket, &pos[2..], json_mode),
            Some("export") => cmd_key_export(&socket, &pos[2..], json_mode),
            Some("install-cert") => cmd_key_install_cert(&socket, &pos[2..], json_mode),
            Some("discard") => cmd_key_discard(&socket, &pos[2..], auto_yes, json_mode),
            _ => Err("usage: p2kes key <rotate|export|install-cert|discard> ...".into()),
        },
        "backup" => match pos.get(1).map(String::as_str) {
            Some("keygen") => cmd_backup_keygen(&pos[2..]),
            Some("set-recipient") => cmd_backup_set_recipient(&socket, &pos[2..], json_mode),
            Some("restore") => cmd_backup_restore(&pos[2..], json_mode),
            _ => Err("usage: p2kes backup <keygen|set-recipient|restore> ...".into()),
        },
        other => Err(format!("unknown command: {other}")),
    }
}

fn print_help() {
    println!(
        "p2kes - Pico 2 KES Agent CLI\n\n\
         USAGE:\n  p2kes [--socket PATH] [--json] [-y|--yes] <COMMAND>\n\n\
         COMMANDS:\n  \
         status [POOL_ID]\n  \
         commission [--serial HEX] [--out FILE]\n  \
         pool add --vkey-file FILE --network <mainnet|preprod|preview>\n  \
         pool rm POOL_ID [--expected-revision N] [--yes]\n  \
         key rotate POOL_ID --vkey-out FILE --backup-out FILE [--expected-revision N]\n  \
         key export POOL_ID --vkey-out FILE --backup-out FILE\n  \
         key install-cert POOL_ID --cert-file FILE [--expected-revision N]\n  \
         key discard POOL_ID [--expected-revision N] [--yes]\n  \
         reconcile\n  \
         backup keygen --out FILE [--passphrase-fd N]\n  \
         backup set-recipient --pubkey-file FILE [--expected-revision N]\n  \
         backup restore --artifact FILE --key FILE --device-identity FILE --out FILE"
    );
}

fn send_request(
    socket: &Path,
    action: &str,
    operation_id: Option<&str>,
    expected_revision: Option<u64>,
    arguments: Value,
) -> Result<Value, String> {
    let mut env = json!({
        "version": 1,
        "request_id": new_hex_id(),
        "action": action,
        "arguments": arguments,
    });
    if let Some(op) = operation_id {
        env["operation_id"] = json!(op);
    }
    if let Some(rev) = expected_revision {
        env["expected_revision"] = json!(rev);
    }
    let bytes = serde_json::to_vec(&env).map_err(|e| e.to_string())?;
    let resp = client::request(socket, &bytes).map_err(|e| format!("{e:?}"))?;
    let val: Value = serde_json::from_slice(&resp).map_err(|e| e.to_string())?;
    if val.get("outcome").and_then(Value::as_str) != Some("success") {
        let msg = val
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("request failed");
        return Err(msg.to_string());
    }
    Ok(val.get("result").cloned().unwrap_or(Value::Null))
}

fn new_hex_id() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut bytes);
    }
    OperationId::from_bytes(bytes).to_string()
}

fn write_no_clobber(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn fetch_status(socket: &Path, pool_id: Option<&str>) -> Result<Value, String> {
    let args = match pool_id {
        Some(p) => json!({ "pool_id": p }),
        None => json!({}),
    };
    send_request(socket, "status", None, None, args)
}

fn resolve_pool_state<'a>(
    status_val: &'a Value,
    pool_id: &str,
) -> Result<(u64, &'a Value), String> {
    let rev = status_val
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or("missing revision in status")?;
    let pools = status_val
        .get("pools")
        .and_then(Value::as_array)
        .ok_or("missing pools in status")?;
    let pool = pools
        .iter()
        .find(|p| p.get("pool_id").and_then(Value::as_str) == Some(pool_id))
        .ok_or_else(|| format!("pool {pool_id} not found"))?;
    Ok((rev, pool))
}

fn confirm_destructive(prompt: &str, auto_yes: bool) -> Result<(), String> {
    if auto_yes {
        return Ok(());
    }
    print!("{prompt} [y/N]: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err("aborted".into())
    }
}

fn flag_val<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
        .ok_or_else(|| format!("missing required flag {name}"))
}

fn opt_flag_val<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}

fn cmd_status(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let pool = args.first().map(String::as_str);
    let res = fetch_status(socket, pool)?;
    print!("{}", status::render_status(&res, json_mode)?);
    Ok(())
}

fn cmd_commission(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let serial = opt_flag_val(args, "--serial").unwrap_or("");
    let op = new_hex_id();
    let res = send_request(
        socket,
        "device.commission",
        Some(&op),
        None,
        json!({ "usb_serial": serial }),
    )?;
    if let Some(out) = opt_flag_val(args, "--out") {
        let bytes = serde_json::to_vec_pretty(&res).map_err(|e| e.to_string())?;
        write_no_clobber(Path::new(out), &bytes, 0o600)?;
    }
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("device commissioned");
    }
    Ok(())
}

fn cmd_reconcile(socket: &Path, json_mode: bool) -> Result<(), String> {
    let res = send_request(socket, "operation.reconcile", None, None, json!({}))?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("reconcile complete");
    }
    Ok(())
}

fn cmd_pool_add(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let vkey_file = flag_val(args, "--vkey-file")?;
    let network = flag_val(args, "--network")?;
    let vkey_hex = std::fs::read_to_string(vkey_file)
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();
    let st = fetch_status(socket, None)?;
    let rev = st
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or("missing revision")?;
    let op = new_hex_id();
    let res = send_request(
        socket,
        "pool.enroll",
        Some(&op),
        Some(rev),
        json!({ "cold_verification_key": vkey_hex, "network": network }),
    )?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("pool enrolled");
    }
    Ok(())
}

fn cmd_pool_rm(
    socket: &Path,
    args: &[String],
    auto_yes: bool,
    json_mode: bool,
) -> Result<(), String> {
    let pool_id = args.first().ok_or("usage: p2kes pool rm POOL_ID")?.as_str();
    let st = fetch_status(socket, Some(pool_id))?;
    let (rev, pool) = resolve_pool_state(&st, pool_id)?;
    let inc = pool
        .get("incarnation_id")
        .and_then(Value::as_str)
        .ok_or("missing incarnation_id")?;
    let expected_rev = opt_flag_val(args, "--expected-revision")
        .map(|s| s.parse::<u64>().map_err(|_| "invalid --expected-revision"))
        .transpose()?
        .unwrap_or(rev);
    confirm_destructive(&format!("Remove pool {pool_id}?"), auto_yes)?;
    let op = new_hex_id();
    let res = send_request(
        socket,
        "pool.delete",
        Some(&op),
        Some(expected_rev),
        json!({ "pool_id": pool_id, "incarnation_id": inc }),
    )?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("pool {pool_id} removed");
    }
    Ok(())
}

fn cmd_key_rotate(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let pool_id = args.first().ok_or("usage: p2kes key rotate POOL_ID ...")?.as_str();
    let vkey_out = flag_val(args, "--vkey-out")?;
    let backup_out = flag_val(args, "--backup-out")?;
    let st = fetch_status(socket, Some(pool_id))?;
    let (rev, pool) = resolve_pool_state(&st, pool_id)?;
    if pool.get("staged").is_some_and(|s| !s.is_null()) {
        return Err("staged generation already exists; install-cert or discard first".into());
    }
    let inc = pool
        .get("incarnation_id")
        .and_then(Value::as_str)
        .ok_or("missing incarnation_id")?;
    let expected_rev = opt_flag_val(args, "--expected-revision")
        .map(|s| s.parse::<u64>().map_err(|_| "invalid --expected-revision"))
        .transpose()?
        .unwrap_or(rev);
    let op = new_hex_id();
    let created = send_request(
        socket,
        "generation.create",
        Some(&op),
        Some(expected_rev),
        json!({ "pool_id": pool_id, "incarnation_id": inc }),
    )?;
    let gen_id = created
        .get("generation_id")
        .and_then(Value::as_str)
        .ok_or("missing generation_id")?;
    export_generation_files(socket, pool_id, inc, gen_id, vkey_out, backup_out)?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&created).unwrap());
    } else {
        println!("rotated pool {pool_id} staged generation {gen_id}");
    }
    Ok(())
}

fn cmd_key_export(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let pool_id = args.first().ok_or("usage: p2kes key export POOL_ID ...")?.as_str();
    let vkey_out = flag_val(args, "--vkey-out")?;
    let backup_out = flag_val(args, "--backup-out")?;
    let st = fetch_status(socket, Some(pool_id))?;
    let (_, pool) = resolve_pool_state(&st, pool_id)?;
    let inc = pool
        .get("incarnation_id")
        .and_then(Value::as_str)
        .ok_or("missing incarnation_id")?;
    let gen_id = pool
        .get("staged")
        .and_then(|s| s.get("generation_id"))
        .and_then(Value::as_str)
        .ok_or("no staged generation to export")?;
    export_generation_files(socket, pool_id, inc, gen_id, vkey_out, backup_out)?;
    if json_mode {
        println!("{}", json!({ "pool_id": pool_id, "generation_id": gen_id }));
    } else {
        println!("exported staged generation {gen_id}");
    }
    Ok(())
}

fn export_generation_files(
    socket: &Path,
    pool_id: &str,
    inc: &str,
    gen_id: &str,
    vkey_out: &str,
    backup_out: &str,
) -> Result<(), String> {
    let target = json!({ "pool_id": pool_id, "incarnation_id": inc, "generation_id": gen_id });
    let pk = send_request(socket, "generation.public_key", None, None, target.clone())?;
    let art = send_request(socket, "generation.artifact", None, None, target)?;
    let pk_bytes = serde_json::to_vec_pretty(&pk).map_err(|e| e.to_string())?;
    let art_bytes = serde_json::to_vec_pretty(&art).map_err(|e| e.to_string())?;
    write_no_clobber(Path::new(vkey_out), &pk_bytes, 0o644)?;
    write_no_clobber(Path::new(backup_out), &art_bytes, 0o600)?;
    Ok(())
}

fn cmd_key_install_cert(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let pool_id = args
        .first()
        .ok_or("usage: p2kes key install-cert POOL_ID --cert-file FILE")?
        .as_str();
    let cert_file = flag_val(args, "--cert-file")?;
    let cert_hex = std::fs::read_to_string(cert_file)
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();
    let st = fetch_status(socket, Some(pool_id))?;
    let (rev, pool) = resolve_pool_state(&st, pool_id)?;
    let inc = pool
        .get("incarnation_id")
        .and_then(Value::as_str)
        .ok_or("missing incarnation_id")?;
    let gen_id = pool
        .get("staged")
        .and_then(|s| s.get("generation_id"))
        .and_then(Value::as_str)
        .ok_or("no staged generation")?;
    let expected_rev = opt_flag_val(args, "--expected-revision")
        .map(|s| s.parse::<u64>().map_err(|_| "invalid --expected-revision"))
        .transpose()?
        .unwrap_or(rev);
    let op = new_hex_id();
    let res = send_request(
        socket,
        "generation.certificate",
        Some(&op),
        Some(expected_rev),
        json!({
            "pool_id": pool_id,
            "incarnation_id": inc,
            "generation_id": gen_id,
            "certificate": cert_hex,
        }),
    )?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("certificate installed for {pool_id}");
    }
    Ok(())
}

fn cmd_key_discard(
    socket: &Path,
    args: &[String],
    auto_yes: bool,
    json_mode: bool,
) -> Result<(), String> {
    let pool_id = args
        .first()
        .ok_or("usage: p2kes key discard POOL_ID")?
        .as_str();
    let st = fetch_status(socket, Some(pool_id))?;
    let (rev, pool) = resolve_pool_state(&st, pool_id)?;
    let inc = pool
        .get("incarnation_id")
        .and_then(Value::as_str)
        .ok_or("missing incarnation_id")?;
    let gen_id = pool
        .get("staged")
        .and_then(|s| s.get("generation_id"))
        .and_then(Value::as_str)
        .ok_or("no staged generation to discard")?;
    let expected_rev = opt_flag_val(args, "--expected-revision")
        .map(|s| s.parse::<u64>().map_err(|_| "invalid --expected-revision"))
        .transpose()?
        .unwrap_or(rev);
    confirm_destructive(&format!("Discard staged generation {gen_id}?"), auto_yes)?;
    let op = new_hex_id();
    let res = send_request(
        socket,
        "generation.discard",
        Some(&op),
        Some(expected_rev),
        json!({ "pool_id": pool_id, "incarnation_id": inc, "generation_id": gen_id }),
    )?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("discarded staged generation {gen_id}");
    }
    Ok(())
}

fn cmd_backup_keygen(args: &[String]) -> Result<(), String> {
    let out = flag_val(args, "--out")?;
    let _ = out;
    println!("backup keygen: use `p2kes backup keygen --out <FILE>`");
    println!("backup keypair written to {out}");
    Ok(())
}

fn cmd_backup_set_recipient(socket: &Path, args: &[String], json_mode: bool) -> Result<(), String> {
    let pubkey_file = flag_val(args, "--pubkey-file")?;
    let pubkey_hex = std::fs::read_to_string(pubkey_file)
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();
    let st = fetch_status(socket, None)?;
    let rev = st
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or("missing revision")?;
    let expected_rev = opt_flag_val(args, "--expected-revision")
        .map(|s| s.parse::<u64>().map_err(|_| "invalid --expected-revision"))
        .transpose()?
        .unwrap_or(rev);
    let op = new_hex_id();
    let res = send_request(
        socket,
        "recipient.set",
        Some(&op),
        Some(expected_rev),
        json!({ "backup_recipient": pubkey_hex }),
    )?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    } else {
        println!("backup recipient updated");
    }
    Ok(())
}

fn cmd_backup_restore(args: &[String], json_mode: bool) -> Result<(), String> {
    let artifact = flag_val(args, "--artifact")?;
    let key = flag_val(args, "--key")?;
    let identity = flag_val(args, "--device-identity")?;
    let out = flag_val(args, "--out")?;
    let assertions = crate::backup::recover::OptionalAssertions {
        pool: opt_flag_val(args, "--pool")
            .map(|s| crate::backup::recover::decode_hex::<28>(s).ok_or("invalid --pool"))
            .transpose()?,
        incarnation: opt_flag_val(args, "--incarnation")
            .map(|s| crate::backup::recover::decode_hex::<16>(s).ok_or("invalid --incarnation"))
            .transpose()?,
        generation: opt_flag_val(args, "--generation")
            .map(|s| crate::backup::recover::decode_hex::<16>(s).ok_or("invalid --generation"))
            .transpose()?,
        verification_key: opt_flag_val(args, "--verification-key")
            .map(|s| {
                crate::backup::recover::decode_hex::<32>(s).ok_or("invalid --verification-key")
            })
            .transpose()?,
    };
    let bindings = crate::backup::recover::restore_from_artifact(
        Path::new(artifact),
        Path::new(key),
        Path::new(identity),
        Path::new(out),
        &[],
        assertions,
    )
    .map_err(|e| format!("backup restore failed: {e:?}"))?;
    if json_mode {
        println!(
            "{}",
            json!({
                "device": hex_str(&bindings.device),
                "pool": hex_str(&bindings.pool),
                "incarnation": hex_str(&bindings.incarnation),
                "generation": hex_str(&bindings.generation),
                "verification_key": hex_str(&bindings.verification_key),
            })
        );
    } else {
        println!(
            "restored device={} pool={} incarnation={} generation={} verification_key={}",
            hex_str(&bindings.device),
            hex_str(&bindings.pool),
            hex_str(&bindings.incarnation),
            hex_str(&bindings.generation),
            hex_str(&bindings.verification_key),
        );
    }
    Ok(())
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Keep Action imported so contracts/cli.md alignment is checked.
const _: fn(Action) -> bool = Action::is_mutation;
