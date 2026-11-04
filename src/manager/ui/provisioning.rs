use super::{
    review,
    setup::{apply, bundle},
    widgets::{FieldSpec, form_validated},
};
use crate::manager::{
    config_builder::candidate_usb_serial,
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
    let serial_default = candidate_usb_serial().unwrap_or_default();
    let specs = [
        FieldSpec::text(
            "Exact 16-character lowercase application serial",
            &serial_default,
        ),
        FieldSpec::text_hint(
            "Public qualification evidence file (required for applying stages)",
            "",
            "Absolute path to qualification JSON when preparing/enabling/locking",
        ),
        FieldSpec::text_hint(
            "Original manager operation ID (recovery only)",
            "",
            if recovery {
                "32 lowercase hex operation ID"
            } else {
                "Leave empty unless recovering an interrupted stage"
            },
        ),
    ];
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
    let manifest_digest = verified.selection().manifest_digest.to_string();
    let Some(request) = form_validated(
        terminal,
        "Device security target and evidence",
        &specs,
        |values| {
            if !recovery && !values[2].trim().is_empty() {
                return Err((Some(2), "Original operation ID is only for recovery".into()));
            }
            let evidence = if values[1].trim().is_empty() {
                None
            } else {
                Some(
                    setup::review_public_input(Path::new(values[1].trim()))
                        .map_err(|e| (Some(1), e.to_string()))?,
                )
            };
            let req = Request {
                action: provision_action,
                bundle: source.clone(),
                manifest_digest: manifest_digest.clone(),
                candidate_accepted: candidate,
                original_operation: recovery.then(|| values[2].trim().to_owned()),
                serial: values[0].trim().to_owned(),
                evidence,
                normal_state: normal.clone(),
                commissioning_state: commission.clone(),
                stop_normal,
                stop_commissioning,
            };
            req.validate().map_err(|e| (Some(0), e.to_string()))?;
            Ok(req)
        },
    )?
    else {
        return Ok(());
    };

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
    if !review(
        terminal,
        "Review optional irreversible device security",
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
