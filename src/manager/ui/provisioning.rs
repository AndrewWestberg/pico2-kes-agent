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
    (Action::Preview, "Read-only security preview"),
    (Action::Prepare, "Prepare one stage"),
    (Action::Enable, "Enable one stage"),
    (Action::Lock, "Lock one stage"),
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
        ("reopen", "Read original record"),
        ("resume", "Resume admitted preparation"),
        ("reconcile", "Reconcile permission uncertainty"),
    ];
    let specs = [FieldSpec::select("Recovery action", "reopen", &choices)];
    let Some(choice) = form_validated(terminal, "Provisioning recovery", &specs, |v| {
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
            "Qualification evidence (Space to choose)",
            "",
            &kinds,
        )];
        let Some(path) = form_validated(terminal, "Select qualification evidence", &specs, |v| {
            if v[0].is_empty() {
                Err((Some(0), "Choose a qualification evidence file".into()))
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
            "enable and lock require the sole restricted commissioning observation service already running for fresh blank admission; start it explicitly through setup, without commissioning",
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

    let lines = vec![
        format!("Stage: {:?}; exact serial: {}", request.action, request.serial),
        format!(
            "Authenticated distribution: {}; qualification evidence: {:?}",
            request.manifest_digest, request.evidence
        ),
        format!(
            "Normal service: {}; commissioning service: {}",
            request.normal_state, request.commissioning_state
        ),
        format!(
            "Approved service stops: normal {}; commissioning {}. No automatic restart or commissioning.",
            stop_normal, stop_commissioning
        ),
        "WARNING: OTP stages are optional and hardware-irreversible. Unlocked use remains fully supported."
            .into(),
        "The foreground firmware tool owns interactive prompts, physical transitions, and the protected record."
            .into(),
    ];
    if !review_mode(
        terminal,
        "Review optional irreversible device security",
        lines,
        ConfirmMode::YesNo { danger: true },
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
