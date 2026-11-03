use super::{public_fields, review};
use crate::manager::{backup, host, observe::Worker, terminal::TerminalOwner};
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Create,
    Restore,
    Transfer,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (Action::Create, "Create protected backup recipient"),
    (Action::Restore, "Restore encrypted backup locally"),
    (Action::Transfer, "Public recipient transfer guidance"),
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
        review(terminal, "Public recipient transfer", vec![
            "Transfer only the public recipient file to the primary through your independently authenticated channel, then explicitly install it there using recipient installation.".into(),
            "Never transfer the private recipient file or passphrase to the primary. Retain the original private file securely: old encrypted artifacts still depend on it after rotation.".into(),
            "Local admission cannot prove this machine has never been a primary; the operator must ensure historical separation.".into(),
        ], None)?;
        return Ok(());
    }
    // The installed executable is accepted only through the host's authenticated registry.
    host::trusted_cli()?;
    let notice = vec![
        "Isolated backup host only: local role checks cannot prove historical separation. No daemon, device or node is contacted.".into(),
        "The CLI directly owns the terminal and passphrase interaction; the manager does not capture private key material or passphrases.".into(),
        "Use independently trusted public identity, pool, incarnation, generation and verification key evidence; do not infer it from the artifact.".into(),
        "Restore publishes plaintext KES signing material: protect its custody and destination. Restoration does not extend the original certificate lifetime or revoke other copies; you are responsible for producer fencing and node use.".into(),
        "Only a public recipient file may be transferred to the primary; keep the private recipient and passphrase off-primary. Existing artifacts require their original private recipient.".into(),
        "Before private-path entry and again immediately before the child, authorize a read-only elevated helper to inspect local process executables and role evidence. It does not read private paths or connect to a daemon, device, socket or node.".into(),
    ];
    if !review(
        terminal,
        "Backup custody and separation",
        notice,
        Some("CONTINUE"),
    )? {
        return Ok(());
    }
    privileged_admission(terminal, socket)?;
    let (request, lines) = match action {
        Action::Create => {
            let Some(v) = public_fields(
                terminal,
                "Recipient destinations",
                &[
                    ("Private recipient destination (absolute path)", ""),
                    ("Public recipient destination (absolute path)", ""),
                ],
            )?
            else {
                return Ok(());
            };
            check_paths(&v)?;
            if v[0] == v[1] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "recipient destinations must differ",
                ));
            }
            let lines = vec![format!("Private recipient destination: {}", v[0]), format!("Public recipient destination: {}", v[1]), "Both outputs are owner-only and must not already exist. Transfer only the public file.".into()];
            (
                backup::Action::Create {
                    private: v[0].clone(),
                    public: v[1].clone(),
                },
                lines,
            )
        }
        Action::Restore => {
            let Some(v) = public_fields(
                terminal,
                "Independent restore evidence",
                &[
                    ("Independently trusted device ID (hex)", ""),
                    ("Pool ID (hex)", ""),
                    ("Incarnation ID (hex)", ""),
                    ("Generation ID (hex)", ""),
                    ("Independent verification-key file (absolute path)", ""),
                    ("Trusted device identity file (absolute path)", ""),
                    ("Encrypted artifact file (absolute path)", ""),
                    ("Private recipient file (absolute path)", ""),
                    ("Plaintext output destination (absolute path)", ""),
                ],
            )?
            else {
                return Ok(());
            };
            if v[..4].iter().any(|s| s.is_empty()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "all independent identities are required",
                ));
            }
            check_paths(&v[4..])?;
            let labels = [
                "Device",
                "Pool",
                "Incarnation",
                "Generation",
                "Verification key",
                "Device identity",
                "Encrypted artifact",
                "Private recipient path",
                "Plaintext destination",
            ];
            let mut lines: Vec<_> = labels
                .iter()
                .zip(&v)
                .map(|(name, value)| format!("{name}: {value}"))
                .collect();
            lines.push("The CLI authenticates every binding and refuses existing output, unsafe host memory or invalid credentials; no plaintext should be published on failure.".into());
            (
                backup::Action::Restore {
                    device: v[0].clone(),
                    pool: v[1].clone(),
                    incarnation: v[2].clone(),
                    generation: v[3].clone(),
                    verification_key: v[4].clone(),
                    identity: v[5].clone(),
                    artifact: v[6].clone(),
                    recipient: v[7].clone(),
                    output: v[8].clone(),
                },
                lines,
            )
        }
        Action::Transfer => unreachable!(),
    };
    if !review(
        terminal,
        "Review exact backup operation",
        lines.clone(),
        Some("RUN BACKUP"),
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

fn check_paths(values: &[String]) -> io::Result<()> {
    if values.iter().any(|value| !Path::new(value).is_absolute()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "all file paths must be absolute",
        ));
    }
    Ok(())
}
