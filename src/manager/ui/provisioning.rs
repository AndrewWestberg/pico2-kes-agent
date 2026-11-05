use super::{
    setup::{apply, bundle},
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::manager::{
    discovery::{files::FileKind, usb},
    host::{self, HostAction},
    observe,
    provisioning::{Action as ProvisionAction, Request},
    setup,
    terminal::TerminalOwner,
};
use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Preview,
    Prepare,
    Enable,
    Lock,
    Reopen,
    Resume,
    Reconcile,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (
        Action::Preview,
        "Check device security without changing the board",
    ),
    (
        Action::Prepare,
        "Permanently set the firmware signing authority",
    ),
    (Action::Enable, "Permanently require signed firmware"),
    (
        Action::Lock,
        "Permanently restrict debugging and recovery access",
    ),
];

pub(super) fn recover_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<observe::Worker>,
    socket: &Path,
    selected: Option<&PathBuf>,
    record: &crate::manager::model::MaintenanceRecord,
) -> io::Result<()> {
    if record.action != "provisioning" {
        return Err(io::Error::other("Not a provisioning record"));
    }
    let choices = [
        ("reopen", "Open the original record"),
        (
            "resume",
            "Continue the interrupted signing-authority preparation",
        ),
        (
            "reconcile",
            "Check the uncertain security change on the same board",
        ),
    ];
    let specs = [FieldSpec::select("Recovery action", "reopen", &choices)];
    let Some(choice) = form_validated(terminal, "Recover device security", &specs, |v| {
        Ok(v[0].clone())
    })?
    else {
        return Ok(());
    };
    let action = match choice.as_str() {
        "resume" => Action::Resume,
        "reconcile" => Action::Reconcile,
        _ => Action::Reopen,
    };
    run_action(action, terminal, worker, socket, selected, Some(record))
}

pub(super) fn run(
    action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<observe::Worker>,
    socket: &Path,
    selected: Option<&PathBuf>,
) -> io::Result<()> {
    let action = ACTIONS
        .get(action)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown device security action",
            )
        })?
        .0;
    run_action(action, terminal, worker, socket, selected, None)
}

fn run_action(
    action: Action,
    terminal: &mut TerminalOwner,
    worker: &mut Option<observe::Worker>,
    socket: &Path,
    selected: Option<&PathBuf>,
    record: Option<&crate::manager::model::MaintenanceRecord>,
) -> io::Result<()> {
    let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
        return Ok(());
    };
    let serial = if let Some(record) = record {
        let checkpoint = record
            .checkpoints
            .iter()
            .find(|c| c.name == "provisioning-original")
            .ok_or_else(|| io::Error::other("Original provisioning identity unavailable"))?;
        let path = checkpoint.evidence.split(';').next().unwrap_or("");
        Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("Invalid provisioning identity"))?
            .to_owned()
    } else {
        let boards: Vec<_> = usb::list_pico2()?
            .into_iter()
            .filter_map(|b| b.serial.map(|s| (s, b.port)))
            .collect();
        if boards.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No Pico 2 application board found",
            ));
        }
        if boards.len() == 1 {
            boards[0].0.clone()
        } else {
            let options: Vec<(&str, &str)> = boards
                .iter()
                .map(|(s, p)| (s.as_str(), p.as_str()))
                .collect();
            let specs = [FieldSpec::select("Pico 2 board", "", &options)];
            let Some(serial) =
                form_validated(terminal, "Select board", &specs, |v| Ok(v[0].clone()))?
            else {
                return Ok(());
            };
            serial
        }
    };
    let evidence = if matches!(
        action,
        Action::Prepare | Action::Enable | Action::Lock | Action::Resume
    ) {
        let kinds = [FileKind::Any];
        let specs = [FieldSpec::file(
            "Verification evidence (Space to choose)",
            "",
            &kinds,
        )];
        let Some(path) = form_validated(terminal, "Select verification evidence", &specs, |v| {
            if v[0].is_empty() {
                Err((Some(0), "Choose a verification evidence file".into()))
            } else {
                Ok(PathBuf::from(&v[0]))
            }
        })?
        else {
            return Ok(());
        };
        Some(setup::review_public_input(&path)?)
    } else {
        None
    };
    let normal = host::observed_service_state(false)?;
    let commission = host::observed_service_state(true)?;
    let resume = matches!(action, Action::Resume);
    let normal_active = normal.starts_with("state=active;");
    let commission_active = commission.starts_with("state=active;");
    if matches!(action, Action::Enable | Action::Lock) && (!commission_active || normal_active) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "To enable or lock device security, the setup service must be running and the normal agent must be stopped. Start the setup service through setup without creating a device identity first.",
        ));
    }
    let stop_normal = normal_active && !matches!(action, Action::Reopen);
    let stop_commissioning = commission_active && !resume && !matches!(action, Action::Reopen);
    let provision_action = match action {
        Action::Preview => ProvisionAction::Preview,
        Action::Prepare => ProvisionAction::Prepare,
        Action::Enable => ProvisionAction::Enable,
        Action::Lock => ProvisionAction::Lock,
        Action::Reopen => ProvisionAction::Reopen,
        Action::Resume => ProvisionAction::Resume,
        Action::Reconcile => ProvisionAction::Reconcile,
    };
    let request = Request {
        action: provision_action,
        bundle: source,
        manifest_digest: verified.selection().manifest_digest.to_string(),
        candidate_accepted: candidate,
        original_operation: record.map(|r| r.operation_id.to_string()),
        serial,
        evidence,
        normal_state: normal,
        commissioning_state: commission,
        stop_normal,
        stop_commissioning,
    };
    request.validate()?;

    let description = match action {
        Action::Preview => "Check device security without changing the board",
        Action::Prepare => "Permanently set the firmware signing authority",
        Action::Enable => "Permanently require firmware signed by the selected authority",
        Action::Lock => "Permanently restrict debugging and recovery access",
        Action::Reopen => "Open the original device-security record",
        Action::Resume => "Continue the interrupted signing-authority preparation",
        Action::Reconcile => "Check the uncertain security change on the same board",
    };
    let mut lines = vec![
        format!("{description}; Pico 2 serial: {}", request.serial),
        "Device security is optional. Setting the signing authority, requiring signed firmware, and restricting access are permanent and cannot be undone. Unlocked use remains supported.".into(),
        "Follow the firmware tool's prompts and physical instructions for the selected board.".into(),
    ];
    if stop_normal {
        lines.push(
            "The normal agent service will be stopped and will not restart automatically.".into(),
        );
    }
    if stop_commissioning {
        lines.push("The setup service will be stopped and will not restart automatically.".into());
    }
    if !review_mode(
        terminal,
        "Review optional irreversible device security",
        lines,
        ConfirmMode::Enter("continue to approval"),
    )? {
        return Ok(());
    }
    apply(
        terminal,
        worker,
        socket,
        HostAction::Provisioning { request },
        Some(&verified),
    )
}
