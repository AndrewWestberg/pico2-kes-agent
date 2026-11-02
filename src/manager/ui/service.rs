use super::{foreground, public_fields, review, setup};
use crate::{
    files,
    manager::{
        host::{self, HostAction, ServiceAction},
        observe::{Diagnostics, Worker},
        terminal::TerminalOwner,
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
        "Review/validate supplied configuration candidate",
    ),
    (Action::Edit, "Edit a new public configuration candidate"),
    (
        Action::Diagnostics,
        "Inspect bounded public diagnostic history",
    ),
    (
        Action::Export,
        "Export public diagnostics to a new protected file",
    ),
    (
        Action::Inspect,
        "Inspect original host operation and actual state",
    ),
    (
        Action::Reconcile,
        "Reconcile original service/configuration outcome without replay",
    ),
];

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
            if !review(terminal, "Review managed service transition", vec![
                format!("Requested: {operation:?}; unit: pico2-kes-agentd.service"),
                format!("Reviewed service/file/PID identity: {expected_state}"),
                "Administrative approval is required. Stop/restart interrupts delivery for every served pool; this never controls a producer service.".into(),
                "Start/restart uses the unchanged installed unit and host-memory/preflight checks. Commissioning must be stopped. Invalid configuration or preflight failure is not healthy startup.".into(),
                "Only service state and the selected running daemon executable are checked here; uptime is not device, pool-delivery, node-consumption or forging evidence.".into(),
                "An interrupted operation retains its original host plan and public maintenance checkpoints; inspect those rather than assuming cancellation.".into(),
            ], Some("APPLY AGENT SERVICE ACTION"))? { return Ok(()); }
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
        Action::Configuration | Action::Edit => {
            let edit = matches!(action, Action::Edit);
            let Some(values) = public_fields(
                terminal,
                "Public configuration candidate",
                &[(
                    if edit {
                        "New absolute candidate path in your protected directory"
                    } else {
                        "Absolute supplied candidate path"
                    },
                    "",
                )],
            )?
            else {
                return Ok(());
            };
            let candidate = PathBuf::from(&values[0]);
            if !candidate.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "candidate path must be absolute",
                ));
            }
            if edit {
                let (_, bytes) =
                    crate::manager::setup::current_config_review()?.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "no working configuration; supply an explicit candidate through Setup",
                        )
                    })?;
                let editor = Path::new("/usr/bin/editor");
                host::trusted_ancestry(editor)?;
                host::trusted_ancestry(&std::fs::canonicalize(editor)?)?;
                if !review(terminal, "Edit public candidate only", vec![
                    format!("Create owner-only, no-clobber copy: {}", candidate.display()),
                    "The system editor runs unprivileged in the restored foreground terminal. Never enter private keys, passphrases or current KES traffic.".into(),
                    "Working configuration is unchanged. The candidate remains for inspection if editing or later validation fails. Exact diff and service-identity validation precede replacement; restart is separate.".into(),
                ], Some("CREATE PUBLIC CANDIDATE"))? { return Ok(()); }
                files::publish_no_clobber(&candidate, &bytes, 0o600)?;
                let status = foreground(
                    terminal,
                    worker,
                    socket,
                    Command::new(editor).arg("--").arg(&candidate),
                    false,
                )?;
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "editor exited {status}; candidate retained, working configuration unchanged"
                    )));
                }
            }
            setup::configuration(terminal, worker, socket, false, candidate)
        }
        Action::Diagnostics => {
            let mut lines = vec!["Bounded public observation history; no raw subprocess/socket streams. Application security reports are not independent attestation. No node connection/consumption/forging conclusion is implied.".into()];
            lines.extend(diagnostics.lines().map(str::to_owned));
            review(terminal, "Public diagnostics", lines, None).map(|_| ())
        }
        Action::Export => {
            let Some(values) = public_fields(
                terminal,
                "Export public diagnostics",
                &[("New absolute output in your protected directory", "")],
            )?
            else {
                return Ok(());
            };
            let destination = Path::new(&values[0]);
            if !review(terminal, "Review diagnostic export", vec![format!("Output: {}; owner-only mode 0600; no overwrite", destination.display()), "Only bounded, escaped public observation metadata is exported. Inspect before sharing; public identities and filesystem paths can still be sensitive operational information.".into()], Some("EXPORT PUBLIC DIAGNOSTICS"))? { return Ok(()); }
            diagnostics.export(destination)?;
            review(
                terminal,
                "Diagnostic export published",
                vec![destination.display().to_string()],
                None,
            )
            .map(|_| ())
        }
        Action::Reconcile => {
            let Some(values) = public_fields(
                terminal,
                "Original service/configuration operation",
                &[
                    ("Original maintenance operation ID", ""),
                    ("Original approved plan digest", ""),
                ],
            )?
            else {
                return Ok(());
            };
            if !review(terminal, "Read-only host reconciliation", vec![
                format!("Original operation: {}; plan: {}", values[0], values[1]),
                "The privileged helper will independently read current service/configuration evidence and ask for its exact digest before resolving this original record.".into(),
                "No start, stop, restart or configuration replacement is replayed. Prior failure/uncertainty remains in history. Transitional, changed or inaccessible evidence stays unresolved.".into(),
                "After a known failed outcome is retained, corrective work still requires a separate fresh review and approval.".into(),
            ], Some("RECONCILE ORIGINAL HOST OPERATION"))? { return Ok(()); }
            setup::apply(
                terminal,
                worker,
                socket,
                HostAction::HostReconcile {
                    operation_id: values[0].clone(),
                    original_plan_digest: values[1].clone(),
                },
                None,
            )
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
