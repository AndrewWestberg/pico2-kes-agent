use super::{
    setup,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::manager::{
    model::InstallationRole, observe::Worker, terminal::TerminalOwner, uninstall,
};
use std::{
    io,
    path::{Path, PathBuf},
};

pub(super) fn recover_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    selected_bundle: Option<&PathBuf>,
    operation_id: &str,
    plan_digest: &str,
) -> io::Result<()> {
    let checked = uninstall::review_uninstall_recovery(operation_id, plan_digest)?;
    let mut lines = vec![
        format!("Original operation: {operation_id}"),
        format!("Original plan SHA : {plan_digest}"),
        "Recovery never stops a newly changed service; configuration, records, identities, and Pico 2 storage remain untouched."
            .into(),
    ];
    lines.extend(checked.lines);
    if !review_mode(
        terminal,
        "Review original uninstall recovery",
        lines,
        ConfirmMode::Enter("stage uninstall recovery plan"),
    )? {
        return Ok(());
    }
    if crate::manager::host::trusted_manager().is_ok() {
        return setup::apply(terminal, worker, socket, checked.action, None);
    }
    let Some((path, bundle, accepted)) = setup::bundle(terminal, selected_bundle)? else {
        return Ok(());
    };
    let mut action = checked.action;
    if let crate::manager::host::HostAction::UninstallRecovery {
        bootstrap,
        bootstrap_manifest_digest,
        candidate_accepted,
        ..
    } = &mut action
    {
        *bootstrap = Some(path);
        *bootstrap_manifest_digest = Some(bundle.selection().manifest_digest.to_string());
        *candidate_accepted = accepted;
    }
    setup::apply(terminal, worker, socket, action, Some(&bundle))
}

pub(super) fn run(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    role: InstallationRole,
    selected_bundle: Option<&PathBuf>,
) -> io::Result<()> {
    let mode_opts = [
        ("new", "Select installed host components to remove"),
        ("recover", "Reconcile an interrupted uninstall record"),
    ];
    let stop_opts = if role == InstallationRole::Primary {
        &[
            ("no", "Do not stop running pico2-kes-agentd"),
            ("yes", "Stop pico2-kes-agentd if affected"),
        ][..]
    } else {
        &[("no", "Backup role has no agent service")][..]
    };
    let specs = [
        FieldSpec::select("Workflow", "new", &mode_opts),
        FieldSpec::text_hint(
            "Components to remove (comma-separated, for new workflow)",
            "manager,daemon,cli,firmware,tool,deployment",
            "Configuration, records, and Pico 2 storage are always preserved",
        ),
        FieldSpec::select("Stop affected agent service", "no", stop_opts),
        FieldSpec::text_hint(
            "Original operation ID (only for recover workflow)",
            "",
            "32 hex characters",
        ),
        FieldSpec::text_hint(
            "Original approved plan digest (only for recover workflow)",
            "",
            "64 hex characters",
        ),
    ];
    enum Choice {
        New(Box<uninstall::UninstallReview>),
        Recover(String, String),
    }
    let Some(choice) =
        form_validated(terminal, "Uninstall managed components", &specs, |values| {
            if values[0] == "recover" {
                let op = values[3].trim();
                let dg = values[4].trim();
                if op.len() != 32 || !op.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err((Some(3), "Operation ID must be 32 hex characters".into()));
                }
                if dg.len() != 64 || !dg.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err((Some(4), "Plan digest must be 64 hex characters".into()));
                }
                return Ok(Choice::Recover(op.to_owned(), dg.to_owned()));
            }
            let selected: Vec<String> = values[1]
                .split(',')
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .collect();
            let stop = values[2] == "yes" && role == InstallationRole::Primary;
            let checked = uninstall::review_uninstall(selected, stop)
                .map_err(|e| (Some(1), e.to_string()))?;
            Ok(Choice::New(Box::new(checked)))
        })?
    else {
        return Ok(());
    };
    match choice {
        Choice::Recover(op, dg) => {
            recover_record(terminal, worker, socket, selected_bundle, &op, &dg)
        }
        Choice::New(checked) => {
            let mut lines = vec![
                "Registered files and links to remove (modified/external files block removal):"
                    .into(),
            ];
            lines.extend(checked.details.iter().map(|l| format!("  Remove: {l}")));
            lines.push(String::new());
            lines.push("Preserved operational paths (never erased by uninstall):".into());
            lines.extend(checked.retained.iter().map(|l| format!("  Retain: {l}")));
            if !review_mode(
                terminal,
                "Review selected uninstall",
                lines,
                ConfirmMode::Enter("approve removal & stage host plan"),
            )? {
                return Ok(());
            }
            setup::apply(terminal, worker, socket, checked.action, None)
        }
    }
}
