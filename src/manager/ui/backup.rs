use super::{
    review,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::manager::{
    backup, host,
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
        review(
            terminal,
            "Public recipient transfer guidance",
            vec![
                "1. Transfer ONLY the public recipient file (.json) to the primary host through your independently authenticated channel, then install it under Pools -> Install or rotate HPKE backup recipient."
                    .into(),
                "2. NEVER transfer the private recipient file (.key) or passphrase to the primary host. Retain old private recipient files securely: existing .kes-backup artifacts remain encrypted to the recipient active when they were created."
                    .into(),
                "3. Local role admission checks active processes and sockets, but cannot prove historical host separation—maintain physical/operational separation."
                    .into(),
            ],
            None,
        )?;
        return Ok(());
    }
    // The installed executable is accepted only through the host's authenticated registry.
    host::trusted_cli()?;
    let notice = vec![
        "Isolated backup host only: local role checks verify no primary daemon or socket is active, though historical separation remains an operator responsibility. No daemon, device, or node is contacted."
            .into(),
        "Passphrase custody: pico2-kes-agent directly owns the foreground terminal for passphrase entry; p2kesup never captures passphrases or plaintext keys."
            .into(),
        "Independent verification: verify device, pool, incarnation, generation, and verification-key bindings against your independent custody records."
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
    let (request, lines, confirm_phrase) = match action {
        Action::Create => {
            let priv_default =
                workspace::next_path(WorkspaceKind::Exports, "recipient-secret", "key")?
                    .to_string_lossy()
                    .into_owned();
            let pub_default =
                workspace::next_path(WorkspaceKind::Exports, "recipient-public", "json")?
                    .to_string_lossy()
                    .into_owned();
            let specs = [
                FieldSpec::text_hint(
                    "Private recipient key destination (0600, keep on backup host)",
                    &priv_default,
                    "Never copy this file to the primary host",
                ),
                FieldSpec::text_hint(
                    "Public recipient record destination (0600, safe to transfer)",
                    &pub_default,
                    "Copy only this public JSON file to the primary host",
                ),
            ];
            let Some((priv_path, pub_path)) =
                form_validated(terminal, "Create HPKE backup recipient", &specs, |values| {
                    let pr = values[0].trim();
                    let pu = values[1].trim();
                    if !Path::new(pr).is_absolute() {
                        return Err((
                            Some(0),
                            "Private recipient destination must be an absolute path".into(),
                        ));
                    }
                    if !Path::new(pu).is_absolute() {
                        return Err((
                            Some(1),
                            "Public recipient destination must be an absolute path".into(),
                        ));
                    }
                    if pr == pu {
                        return Err((
                            Some(1),
                            "Private and public recipient destinations must differ".into(),
                        ));
                    }
                    ensure_absent(pr, 0)?;
                    ensure_absent(pu, 1)?;
                    Ok((pr.to_owned(), pu.to_owned()))
                })?
            else {
                return Ok(());
            };
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
                None,
            )
        }
        Action::Restore => {
            let out_default = workspace::next_path(WorkspaceKind::Exports, "restored-kes", "skey")?
                .to_string_lossy()
                .into_owned();
            let specs = [
                FieldSpec::text_hint(
                    "Export metadata JSON (.kes-backup.metadata.json, optional helper)",
                    "",
                    "Optional: pre-populates any blank ID fields below for your review",
                ),
                FieldSpec::text("Independently trusted device ID (32 lowercase hex)", ""),
                FieldSpec::text("Pool ID (56 lowercase hex)", ""),
                FieldSpec::text("Incarnation ID (32 lowercase hex)", ""),
                FieldSpec::text("Generation ID (32 lowercase hex)", ""),
                FieldSpec::text("Independent verification-key file (.vkey, absolute)", ""),
                FieldSpec::text("Trusted device identity file (device.json, absolute)", ""),
                FieldSpec::text("Encrypted artifact file (.kes-backup, absolute)", ""),
                FieldSpec::text("Private recipient key file (.key, absolute)", ""),
                FieldSpec::text_hint(
                    "Plaintext KES output destination (0600, no overwrite)",
                    &out_default,
                    "Protect custody and fence producers before using restored key",
                ),
            ];
            let Some(resolved) = form_validated(
                terminal,
                "Emergency plaintext KES restore",
                &specs,
                |values| {
                    let meta_str = values[0].trim();
                    let mut dev = values[1].trim().to_owned();
                    let mut pool = values[2].trim().to_owned();
                    let mut inc = values[3].trim().to_owned();
                    let mut gn = values[4].trim().to_owned();
                    if !meta_str.is_empty() {
                        if !Path::new(meta_str).is_absolute() {
                            return Err((
                                Some(0),
                                "Metadata helper path must be absolute (or leave blank)".into(),
                            ));
                        }
                        let meta = load_export_metadata(Path::new(meta_str))
                            .map_err(|e| (Some(0), format!("Cannot read metadata JSON: {e}")))?;
                        if dev.is_empty()
                            && let Some(s) = meta.get("device_id").and_then(Value::as_str)
                        {
                            dev = s.to_owned();
                        }
                        if pool.is_empty()
                            && let Some(s) = meta.get("pool_id").and_then(Value::as_str)
                        {
                            pool = s.to_owned();
                        }
                        if inc.is_empty()
                            && let Some(s) = meta.get("incarnation_id").and_then(Value::as_str)
                        {
                            inc = s.to_owned();
                        }
                        if gn.is_empty()
                            && let Some(s) = meta.get("generation_id").and_then(Value::as_str)
                        {
                            gn = s.to_owned();
                        }
                    }
                    check_hex(&dev, 32, 1, "Device ID")?;
                    check_hex(&pool, 56, 2, "Pool ID")?;
                    check_hex(&inc, 32, 3, "Incarnation ID")?;
                    check_hex(&gn, 32, 4, "Generation ID")?;
                    for (idx, label) in [
                        (5, "Verification-key file"),
                        (6, "Device identity file"),
                        (7, "Encrypted artifact file"),
                        (8, "Private recipient file"),
                        (9, "Plaintext output destination"),
                    ] {
                        let p = values[idx].trim();
                        if !Path::new(p).is_absolute() {
                            return Err((Some(idx), format!("{label} must be an absolute path")));
                        }
                    }
                    ensure_absent(values[9].trim(), 9)?;
                    Ok([
                        dev,
                        pool,
                        inc,
                        gn,
                        values[5].trim().to_owned(),
                        values[6].trim().to_owned(),
                        values[7].trim().to_owned(),
                        values[8].trim().to_owned(),
                        values[9].trim().to_owned(),
                    ])
                },
            )?
            else {
                return Ok(());
            };
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
            let phrase = format!("RESTORE {}", workspace::short_id(&resolved[1]));
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
                Some(phrase),
            )
        }
        Action::Transfer => unreachable!(),
    };
    let confirm_mode = match &confirm_phrase {
        Some(phrase) => ConfirmMode::Phrase(phrase),
        None => ConfirmMode::Enter("hand off terminal to pico2-kes-agent"),
    };
    if !review_mode(
        terminal,
        "Review exact backup operation",
        lines.clone(),
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
    let mut outcome = lines;
    let summary = if status.success() {
        backup::record_outcome(
            &store,
            &mut record,
            "completed",
            "Foreground CLI reported success",
        )?;
        "Foreground CLI reported success.".to_string()
    } else {
        backup::record_outcome(
            &store,
            &mut record,
            "uncertain",
            "Foreground CLI did not report success; inspect outputs before retrying",
        )?;
        format!(
            "Foreground CLI did not report success ({status}); inspect the attended CLI result and outputs before retrying."
        )
    };
    outcome.push(String::new());
    outcome.push(summary);
    outcome.push(format!(
        "Protected backup-local public record: {}",
        record.operation_id
    ));
    review(terminal, "Backup operation outcome", outcome, None)?;
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
