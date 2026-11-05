use super::{
    review,
    widgets::{ConfirmMode, pick_file, review_mode},
};
use crate::manager::{
    backup,
    discovery::files::FileKind,
    host,
    observe::Worker,
    terminal::TerminalOwner,
    workspace::{self, WorkspaceKind},
};
use serde_json::Value;
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Create,
    Restore,
    Transfer,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (
        Action::Create,
        "Create protected HPKE backup recipient keypair",
    ),
    (Action::Restore, "Emergency plaintext KES restore (local)"),
    (
        Action::Transfer,
        "Public recipient transfer & custody guidance",
    ),
];

pub(super) fn run(
    action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    _selected: Option<&PathBuf>,
) -> io::Result<()> {
    let action = ACTIONS
        .get(action)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown backup action"))?
        .0;
    // Stop any previous primary observation before entering this device-free workflow.
    if let Some(active) = worker.take() {
        active.shutdown();
    }
    backup::admit_local(socket)?;
    if matches!(action, Action::Transfer) {
        review(terminal, "Public recipient transfer guidance", vec![
            "1. Transfer ONLY the public recipient file (.json) to the primary host through your independently authenticated channel, then install it under Pools -> Install or rotate HPKE backup recipient."
                .into(),
            "2. NEVER transfer the private recipient file (.key) or passphrase to the primary host. Retain old private recipient files securely: existing .kes-backup artifacts remain encrypted to the recipient active when they were created."
                .into(),
            "3. Local role admission checks active processes and sockets, but cannot prove historical host separation—maintain physical/operational separation."
                .into(),
        ])?;
        return Ok(());
    }
    // The installed executable is accepted only through the host's authenticated registry.
    host::trusted_cli()?;
    let notice = vec![
        "Isolated backup host only: local role checks verify no primary daemon or socket is active, though historical separation remains an operator responsibility. No daemon, device, or node is contacted."
            .into(),
        "Passphrase custody: pico2-kes-agent directly owns the foreground terminal for passphrase entry; p2kesup never captures passphrases or plaintext keys."
            .into(),
        "Use backup and identity files from your independently trusted custody records; the tool checks their device, pool, generation, and verification-key bindings."
            .into(),
        "Plaintext restore warning: restoration writes unencrypted KES signing material (0600) and does not revoke other copies or extend OpCert lifetime—fence all producers before using a restored key."
            .into(),
        "Elevated role check: a read-only privileged helper (host-backup-admit) inspects local process executables and role evidence before path entry and again immediately before CLI handoff."
            .into(),
    ];
    if !review_mode(
        terminal,
        "Backup custody & host separation",
        notice,
        ConfirmMode::Enter("acknowledge custody notice & run role admission"),
    )? {
        return Ok(());
    }
    privileged_admission(terminal, socket)?;
    let (request, lines, danger) = match action {
        Action::Create => {
            let priv_path =
                workspace::next_path(WorkspaceKind::Exports, "recipient-secret", "key")?
                    .to_string_lossy()
                    .into_owned();
            let pub_path =
                workspace::next_path(WorkspaceKind::Exports, "recipient-public", "json")?
                    .to_string_lossy()
                    .into_owned();
            ensure_absent(&priv_path, 0).map_err(|(_, e)| io::Error::other(e))?;
            ensure_absent(&pub_path, 1).map_err(|(_, e)| io::Error::other(e))?;
            let lines = vec![
                format!("Private recipient key (keep off-primary) : {priv_path}"),
                format!("Public recipient record (transferable)   : {pub_path}"),
                String::new(),
                "Both outputs are created owner-only (0600) and never overwrite existing files."
                    .into(),
                "Next: terminal hands off directly to pico2-kes-agent to prompt for the encryption passphrase."
                    .into(),
            ];
            (
                backup::Action::Create {
                    private: priv_path,
                    public: pub_path,
                },
                lines,
                false,
            )
        }
        Action::Restore => {
            let Some(artifact) =
                pick_file(terminal, "Select encrypted KES backup", &[FileKind::Backup])?
            else {
                return Ok(());
            };
            let Some(identity) = pick_file(
                terminal,
                "Select independently trusted device.json",
                &[FileKind::DeviceJson],
            )?
            else {
                return Ok(());
            };
            let metadata =
                load_export_metadata(Path::new(&format!("{}.metadata.json", artifact.display())))?;
            let device = load_export_metadata(&identity)?;
            let get = |value: &Value, key: &str| -> io::Result<String> {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("Missing {key}"))
                    })
            };
            let dev = get(&device, "device_id")?;
            let pool = get(&metadata, "pool_id")?;
            let inc = get(&metadata, "incarnation_id")?;
            let generation = get(&metadata, "generation_id")?;
            if metadata.get("device_id").and_then(Value::as_str) != Some(dev.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Backup metadata does not match trusted device.json",
                ));
            }
            for (value, len, label) in [
                (&dev, 32, "Device ID"),
                (&pool, 56, "Pool ID"),
                (&inc, 32, "Incarnation ID"),
                (&generation, 32, "Generation ID"),
            ] {
                check_hex(value, len, 0, label)
                    .map_err(|(_, e)| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            let sibling = artifact.parent().unwrap_or(Path::new("/"));
            let exports = workspace::list_files(WorkspaceKind::Exports)?;
            let sibling_files: Vec<PathBuf> = std::fs::read_dir(sibling)?
                .take(1024)
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect();
            let newest = |extension: &str| {
                sibling_files
                    .iter()
                    .filter(|p| p.extension().is_some_and(|e| e == extension))
                    .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
                    .cloned()
            };
            let vkey = newest("vkey").or_else(|| {
                exports
                    .iter()
                    .find(|p| p.extension().is_some_and(|e| e == "vkey"))
                    .cloned()
            });
            let vkey = if let Some(p) = vkey {
                p
            } else {
                let Some(p) = pick_file(terminal, "Select KES verification key", &[FileKind::Any])?
                else {
                    return Ok(());
                };
                p
            };
            let recipient = newest("key").or_else(|| {
                exports
                    .iter()
                    .find(|p| p.extension().is_some_and(|e| e == "key"))
                    .cloned()
            });
            let recipient = if let Some(p) = recipient {
                p
            } else {
                let Some(p) =
                    pick_file(terminal, "Select private recipient key", &[FileKind::Any])?
                else {
                    return Ok(());
                };
                p
            };
            let output = workspace::next_path(WorkspaceKind::Exports, "restored-kes", "skey")?;
            let resolved = [
                dev,
                pool,
                inc,
                generation,
                vkey.to_string_lossy().into_owned(),
                identity.to_string_lossy().into_owned(),
                artifact.to_string_lossy().into_owned(),
                recipient.to_string_lossy().into_owned(),
                output.to_string_lossy().into_owned(),
            ];
            for path in &resolved[4..] {
                if !Path::new(path).is_absolute() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Restore paths must be absolute",
                    ));
                }
            }
            ensure_absent(&resolved[8], 0).map_err(|(_, e)| io::Error::other(e))?;
            let labels = [
                "Device ID",
                "Pool ID",
                "Incarnation ID",
                "Generation ID",
                "Verification key",
                "Device identity",
                "Encrypted artifact",
                "Private recipient",
                "Plaintext output",
            ];
            let mut lines = vec![
                "Verify every identity below against your independent custody records:".into(),
                String::new(),
            ];
            lines.extend(
                labels
                    .iter()
                    .zip(&resolved)
                    .map(|(name, value)| format!("{name:<20}: {value}")),
            );
            lines.push(String::new());
            lines.push(
                "The CLI authenticates every binding and refuses existing outputs, unsafe host memory (active swap), or invalid credentials; no plaintext is published on failure."
                    .into(),
            );
            (
                backup::Action::Restore {
                    device: resolved[0].clone(),
                    pool: resolved[1].clone(),
                    incarnation: resolved[2].clone(),
                    generation: resolved[3].clone(),
                    verification_key: resolved[4].clone(),
                    identity: resolved[5].clone(),
                    artifact: resolved[6].clone(),
                    recipient: resolved[7].clone(),
                    output: resolved[8].clone(),
                },
                lines,
                true,
            )
        }
        Action::Transfer => unreachable!(),
    };
    let confirm_mode = ConfirmMode::YesNo { danger };
    let display_lines = if let backup::Action::Restore {
        verification_key,
        identity,
        artifact,
        recipient,
        output,
        ..
    } = &request
    {
        vec![
            "Restore an unencrypted KES signing key on this isolated backup host.".into(),
            "Fence all producers before using the restored key. This does not revoke other copies or extend the certificate lifetime.".into(),
            "Select the backup for the intended pool from independently trusted custody records; the tool verifies the device and key bindings.".into(),
            format!("Encrypted backup: {artifact}"),
            format!("Trusted device identity: {identity}"),
            format!("KES verification key: {verification_key}"),
            format!("Private recipient key: {recipient}"),
            format!("Plaintext output: {output}"),
            "Existing outputs are never overwritten. If interrupted, keep any output files and check Activity before attempting another restore.".into(),
        ]
    } else {
        lines.clone()
    };
    if !review_mode(
        terminal,
        "Review backup operation",
        display_lines.clone(),
        confirm_mode,
    )? {
        return Ok(());
    }
    let cli = host::trusted_cli()?;
    let mut command = request.command(&cli);
    let operation = match action {
        Action::Create => "backup-recipient-create",
        Action::Restore => "backup-restore",
        Action::Transfer => unreachable!(),
    };
    let (store, mut record) = backup::record_intent(operation, lines.clone())?;
    backup::record_outcome(
        &store,
        &mut record,
        "uncertain",
        "Foreground handoff may have started; inspect outputs before retrying",
    )?;
    if let Err(error) = privileged_admission(terminal, socket) {
        backup::record_outcome(
            &store,
            &mut record,
            "failed-known",
            "Role admission denied before foreground handoff",
        )?;
        return Err(error);
    }
    let status = match terminal.foreground(&mut command, true) {
        Ok(status) => status,
        Err(error) => {
            backup::record_outcome(
                &store,
                &mut record,
                "uncertain",
                "Foreground handoff or terminal restoration failed; inspect outputs before retrying",
            )?;
            return Err(error);
        }
    };
    let mut outcome = display_lines;
    let summary = if status.success() {
        backup::record_outcome(
            &store,
            &mut record,
            "completed",
            "Foreground CLI reported success",
        )?;
        "Backup operation completed.".to_string()
    } else {
        backup::record_outcome(
            &store,
            &mut record,
            "uncertain",
            "Foreground CLI did not report success; inspect outputs before retrying",
        )?;
        format!(
            "Backup operation did not finish successfully ({status}). Keep any output files and check the saved operation in Activity before retrying."
        )
    };
    outcome.push(String::new());
    if status.success() && matches!(action, Action::Create) {
        outcome.push("Copy the public recipient JSON to the primary host; keep the private key and passphrase on this backup host.".into());
    }
    outcome.push(summary);
    outcome.push(format!(
        "Protected backup-local public record: {}",
        record.operation_id
    ));
    review(terminal, "Backup operation outcome", outcome)?;
    Ok(())
}

fn privileged_admission(terminal: &mut TerminalOwner, socket: &Path) -> io::Result<()> {
    backup::admit_local(socket)?;
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.arg("host-backup-admit").arg("--socket").arg(socket);
    if !terminal.foreground(&mut command, false)?.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged backup role inspection denied or unavailable",
        ));
    }
    Ok(())
}

fn check_hex(
    value: &str,
    expected_len: usize,
    field_idx: usize,
    label: &str,
) -> Result<(), (Option<usize>, String)> {
    let valid_lower_hex = value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if value.len() != expected_len || !valid_lower_hex {
        return Err((
            Some(field_idx),
            format!("{label} must be {expected_len} lowercase hex characters"),
        ));
    }
    Ok(())
}

fn ensure_absent(path: &str, field_idx: usize) -> Result<(), (Option<usize>, String)> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err((
            Some(field_idx),
            format!("Destination already exists (refusing overwrite): {path}"),
        )),
        Err(error) => Err((
            Some(field_idx),
            format!("Cannot inspect destination: {error}"),
        )),
    }
}

fn load_export_metadata(path: &Path) -> io::Result<Value> {
    let file = crate::files::open_owner_controlled_file(path)?;
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata JSON exceeds 64 KiB",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::check_hex;

    #[test]
    fn restore_ids_require_exact_lowercase_hex() {
        assert!(check_hex(&"ab".repeat(16), 32, 0, "Device ID").is_ok());
        assert!(check_hex(&"AB".repeat(16), 32, 0, "Device ID").is_err());
        assert!(check_hex("abc", 32, 0, "Device ID").is_err());
    }
}
