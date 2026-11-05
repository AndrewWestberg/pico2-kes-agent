use super::{
    foreground, review, setup,
    widgets::{ConfirmMode, review_mode},
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
    io::{self, Read},
    path::Path,
    process::Command,
};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Start,
    Stop,
    Restart,
    Edit,
    Diagnostics,
    Export,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (Action::Start, "Start managed agent"),
    (Action::Stop, "Stop managed agent"),
    (Action::Restart, "Restart managed agent"),
    (Action::Edit, "Edit configuration manually (advanced)"),
    (
        Action::Diagnostics,
        "Inspect bounded public diagnostic history",
    ),
    (
        Action::Export,
        "Export public diagnostics to a protected file",
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
        "The privileged helper will independently read current service/configuration state without replaying start/stop/restart or overwriting config."
            .into(),
    ];
    if !review_mode(
        terminal,
        "Read-only host reconciliation",
        lines,
        ConfirmMode::Enter("continue to approval"),
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
        Action::Edit => {
            let candidate =
                workspace::next_path(WorkspaceKind::Candidates, "edited-config", "json")?;
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
                ConfirmMode::YesNo { danger: false },
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
            let mut edited = Vec::new();
            files::open_owner_controlled_file(&candidate)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut edited)?;
            if edited.len() > 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Edited configuration exceeds 1 MiB",
                ));
            }
            let json: serde_json::Value =
                serde_json::from_slice(&edited).map_err(io::Error::other)?;
            let commissioning = json
                .pointer("/device/id")
                .and_then(serde_json::Value::as_str)
                .is_none();
            setup::configuration(terminal, worker, socket, commissioning, candidate)
        }
        Action::Diagnostics => {
            let mut lines = vec![
                "Bounded public observation history (application security reports are not hardware attestation):"
                    .into(),
                String::new(),
            ];
            lines.extend(diagnostics.lines().map(str::to_owned));
            review(terminal, "Public diagnostics", lines).map(|_| ())
        }
        Action::Export => {
            let destination = workspace::next_path(WorkspaceKind::Exports, "diagnostics", "txt")?;
            if !review_mode(
                terminal,
                "Review diagnostic export",
                vec![
                    format!("Output: {} (owner-only mode 0600)", destination.display()),
                    "Only bounded, escaped public observation metadata is exported. Review paths and pool IDs before sharing externally."
                        .into(),
                ],
                ConfirmMode::YesNo { danger: false },
            )? {
                return Ok(());
            }
            diagnostics.export(&destination)?;
            review(
                terminal,
                "Diagnostic export published",
                vec![format!("Exported to {}", destination.display())],
            )
            .map(|_| ())
        }
    }
}
