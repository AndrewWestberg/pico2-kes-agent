use super::{
    foreground, review, setup,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::{
    files,
    manager::{
        config_builder::{CommissioningSpec, build_commissioning_bytes},
        host::{self, HostAction, ServiceAction},
        observe::{Diagnostics, Worker},
        terminal::TerminalOwner,
        workspace::{self, WorkspaceKind},
    },
};
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Start,
    Stop,
    Restart,
    Configuration,
    Edit,
    Diagnostics,
    Export,
    Inspect,
    Reconcile,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (Action::Start, "Start managed agent"),
    (Action::Stop, "Stop managed agent"),
    (Action::Restart, "Restart managed agent"),
    (
        Action::Configuration,
        "Build or install configuration candidate",
    ),
    (
        Action::Edit,
        "Edit configuration candidate in /usr/bin/editor",
    ),
    (
        Action::Diagnostics,
        "Inspect bounded public diagnostic history",
    ),
    (
        Action::Export,
        "Export public diagnostics to a protected file",
    ),
    (
        Action::Inspect,
        "Inspect original host plan and actual state",
    ),
    (
        Action::Reconcile,
        "Reconcile original service/configuration record",
    ),
];

pub(super) fn reconcile_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    operation_id: String,
    original_plan_digest: String,
) -> io::Result<()> {
    let lines = vec![
        format!("Original operation : {operation_id}"),
        format!("Original plan SHA  : {original_plan_digest}"),
        "The privileged helper will independently read current service/configuration state without replaying start/stop/restart or overwriting config."
            .into(),
    ];
    if !review_mode(
        terminal,
        "Read-only host reconciliation",
        lines,
        ConfirmMode::Enter("stage read-only reconciliation plan"),
    )? {
        return Ok(());
    }
    setup::apply(
        terminal,
        worker,
        socket,
        HostAction::HostReconcile {
            operation_id,
            original_plan_digest,
        },
        None,
    )
}

pub(super) fn run(
    index: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    diagnostics: &Diagnostics,
) -> io::Result<()> {
    let action = ACTIONS
        .get(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown service action"))?
        .0;
    match action {
        Action::Start | Action::Stop | Action::Restart => {
            let operation = match action {
                Action::Start => ServiceAction::Start,
                Action::Stop => ServiceAction::Stop,
                _ => ServiceAction::Restart,
            };
            let expected_state = host::observed_service_state(false)?;
            setup::apply(
                terminal,
                worker,
                socket,
                HostAction::Service {
                    operation,
                    expected_state,
                },
                None,
            )
        }
        Action::Configuration => {
            let Some(candidate) = setup::guided_normal_candidate(terminal)? else {
                return Ok(());
            };
            setup::configuration(terminal, worker, socket, false, candidate)
        }
        Action::Edit => {
            let suggested =
                workspace::next_path(WorkspaceKind::Candidates, "edited-config", "json")?
                    .to_string_lossy()
                    .into_owned();
            let mode_opts = [
                ("normal", "Validate edited file as normal pinned config"),
                (
                    "commissioning",
                    "Validate edited file as commissioning config",
                ),
            ];
            let specs = [
                FieldSpec::text("New candidate config path", &suggested),
                FieldSpec::select("Validation mode after editing", "normal", &mode_opts),
            ];
            let Some((candidate, commissioning)) = form_validated(
                terminal,
                "Edit public configuration candidate",
                &specs,
                |values| {
                    let p = PathBuf::from(values[0].trim());
                    if !p.is_absolute() {
                        return Err((Some(0), "Candidate path must be absolute".into()));
                    }
                    Ok((p, values[1] == "commissioning"))
                },
            )?
            else {
                return Ok(());
            };
            let seed_bytes = match crate::manager::setup::current_config_review()? {
                Some((_, bytes)) => bytes,
                None => {
                    let mut spec = CommissioningSpec::default();
                    if spec.usb_serial.len() != 16 {
                        spec.usb_serial = "0000000000000000".into();
                    }
                    build_commissioning_bytes(&spec)?
                }
            };
            let editor = Path::new("/usr/bin/editor");
            host::trusted_ancestry(editor)?;
            host::trusted_ancestry(&std::fs::canonicalize(editor)?)?;
            if !review_mode(
                terminal,
                "Open /usr/bin/editor on public candidate",
                vec![
                    format!("Candidate copy: {}", candidate.display()),
                    "Working /etc/pico2-kes-agent/config.json is untouched while editing.".into(),
                    "Never enter private keys or passphrases in configuration files.".into(),
                ],
                ConfirmMode::Enter("create candidate & open /usr/bin/editor"),
            )? {
                return Ok(());
            }
            files::publish_no_clobber(&candidate, &seed_bytes, 0o600)?;
            let status = foreground(
                terminal,
                worker,
                socket,
                Command::new(editor).arg("--").arg(&candidate),
                false,
            )?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "editor exited {status}; candidate retained at {}, working configuration unchanged",
                    candidate.display()
                )));
            }
            setup::configuration(terminal, worker, socket, commissioning, candidate)
        }
        Action::Diagnostics => {
            let mut lines = vec![
                "Bounded public observation history (application security reports are not hardware attestation):"
                    .into(),
                String::new(),
            ];
            lines.extend(diagnostics.lines().map(str::to_owned));
            review(terminal, "Public diagnostics", lines, None).map(|_| ())
        }
        Action::Export => {
            let suggested = workspace::next_path(WorkspaceKind::Exports, "diagnostics", "txt")?
                .to_string_lossy()
                .into_owned();
            let specs = [FieldSpec::text(
                "New protected diagnostics output path (0600, no overwrite)",
                &suggested,
            )];
            let Some(destination) =
                form_validated(terminal, "Export public diagnostics", &specs, |values| {
                    let p = PathBuf::from(values[0].trim());
                    if !p.is_absolute() {
                        return Err((Some(0), "Destination path must be absolute".into()));
                    }
                    Ok(p)
                })?
            else {
                return Ok(());
            };
            if !review_mode(
                terminal,
                "Review diagnostic export",
                vec![
                    format!("Output: {} (owner-only mode 0600)", destination.display()),
                    "Only bounded, escaped public observation metadata is exported. Review paths and pool IDs before sharing externally."
                        .into(),
                ],
                ConfirmMode::Enter("write diagnostic export"),
            )? {
                return Ok(());
            }
            diagnostics.export(&destination)?;
            review(
                terminal,
                "Diagnostic export published",
                vec![format!("Exported to {}", destination.display())],
                None,
            )
            .map(|_| ())
        }
        Action::Reconcile => {
            let specs = [
                FieldSpec::text("Original maintenance operation ID (32 hex)", ""),
                FieldSpec::text("Original approved plan digest (64 hex)", ""),
            ];
            let Some((op_id, digest)) = form_validated(
                terminal,
                "Original service/configuration operation",
                &specs,
                |values| {
                    let op = values[0].trim();
                    let dg = values[1].trim();
                    if op.len() != 32 || !op.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err((Some(0), "Operation ID must be 32 hex characters".into()));
                    }
                    if dg.len() != 64 || !dg.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err((Some(1), "Plan digest must be 64 hex characters".into()));
                    }
                    Ok((op.to_owned(), dg.to_owned()))
                },
            )?
            else {
                return Ok(());
            };
            reconcile_record(terminal, worker, socket, op_id, digest)
        }
        Action::Inspect => setup::run(
            1,
            terminal,
            worker,
            crate::manager::model::InstallationRole::Primary,
            socket,
            None,
        ),
    }
}
