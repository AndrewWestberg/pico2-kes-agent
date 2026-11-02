use super::{
    public_fields, review,
    setup::{apply, bundle},
};
use crate::manager::{
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
    (Action::Reopen, "Reopen original record"),
    (Action::Resume, "Admitted pre-OTP prepare resume"),
    (Action::Reconcile, "Read-only permission reconciliation"),
];

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
    let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
        return Ok(());
    };
    let recovery = matches!(action, Action::Reopen | Action::Resume | Action::Reconcile);
    let Some(values) = public_fields(
        terminal,
        "Device security target and evidence",
        &[
            ("Exact 16-character lowercase application serial", ""),
            (
                "Public qualification evidence file (required for applying stages)",
                "",
            ),
            ("Original manager operation ID (recovery only)", ""),
        ],
    )?
    else {
        return Ok(());
    };
    if !recovery && !values[2].is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "original operation is only for recovery",
        ));
    }
    let evidence = if values[1].is_empty() {
        None
    } else {
        Some(setup::review_public_input(Path::new(&values[1]))?)
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
        original_operation: recovery.then(|| values[2].clone()),
        serial: values[0].clone(),
        evidence,
        normal_state: normal,
        commissioning_state: commission,
        stop_normal,
        stop_commissioning,
    };
    request.validate()?;
    let lines = vec![
        format!("Stage: {:?}; exact serial: {}", request.action, request.serial),
        format!("Authenticated distribution: {}; qualification evidence: {:?}", request.manifest_digest, request.evidence),
        format!("Normal service: {}; commissioning service: {}", request.normal_state, request.commissioning_state),
        format!("Approved service stops: normal {}; commissioning {}. No automatic restart or commissioning.", stop_normal, stop_commissioning),
        "Optional and irreversible. Unsupported hardware, nonblank storage, mismatched evidence or unexpected OTP must stop; no erase or reset is offered. Unlocked use remains supported.".into(),
        "Enable and lock require the sole restricted commissioning service already running; fresh blank/uncommissioned observations are checked before its separately approved stop and BOOTSEL handoff.".into(),
        "Preparation may install the authenticated transient commissioning unit without starting it; approved stops retain that unit for attended second-terminal transitions.".into(),
        "Review the applicable physical, tool and image qualification evidence yourself. BOOTSEL preview does not prove fitted flash or blank storage; application reports are not independent attestation.".into(),
        "One stage only. The existing firmware tool owns prompts, physical transitions, observations and the original protected record. Never answer its prompts automatically. A pending write blocks advancement; only the admitted pre-OTP resume or read-only permission reconciliation is offered.".into(),
        "Use a second terminal to run sudo systemctl start/stop pico2-kes-agent-commission.service only when the tool requests it, and perform its physical transitions; do not start another USB owner. No signing key is requested.".into(),
    ];
    if !review(
        terminal,
        "Review optional device security",
        lines,
        Some(&request.serial),
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
