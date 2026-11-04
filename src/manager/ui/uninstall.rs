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
        ConfirmMode::YesNo { danger: true },
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
    _selected_bundle: Option<&PathBuf>,
) -> io::Result<()> {
    let stop_opts = if role == InstallationRole::Primary {
        &[
            ("no", "Do not stop running pico2-kes-agentd"),
            ("yes", "Stop pico2-kes-agentd if affected"),
        ][..]
    } else {
        &[("no", "Backup role has no agent service")][..]
    };
    let components = [
        ("manager", ""),
        ("daemon", ""),
        ("cli", ""),
        ("firmware", ""),
        ("tool", ""),
        ("deployment", ""),
    ];
    let specs = [
        FieldSpec::multiselect(
            "Components to remove",
            "manager,daemon,cli,firmware,tool,deployment",
            &components,
        ),
        FieldSpec::select("Stop affected agent service", "no", stop_opts),
    ];
    let Some(checked) =
        form_validated(terminal, "Uninstall managed components", &specs, |values| {
            let selected = values[0]
                .split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect();
            uninstall::review_uninstall(
                selected,
                values[1] == "yes" && role == InstallationRole::Primary,
            )
            .map_err(|e| (Some(0), e.to_string()))
        })?
    else {
        return Ok(());
    };
    {
        let mut lines = vec![
            "Registered files and links to remove (modified/external files block removal):".into(),
        ];
        lines.extend(checked.details.iter().map(|l| format!("  Remove: {l}")));
        lines.push(String::new());
        lines.push("Preserved operational paths (never erased by uninstall):".into());
        lines.extend(checked.retained.iter().map(|l| format!("  Retain: {l}")));
        if !review_mode(
            terminal,
            "Review selected uninstall",
            lines,
            ConfirmMode::YesNo { danger: true },
        )? {
            return Ok(());
        }
        setup::apply(terminal, worker, socket, checked.action, None)
    }
}
