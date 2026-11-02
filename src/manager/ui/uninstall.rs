use super::{public_fields, review, setup};
use crate::manager::{
    model::InstallationRole, observe::Worker, terminal::TerminalOwner, uninstall,
};
use std::{
    io,
    path::{Path, PathBuf},
};

pub(super) fn run(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    role: InstallationRole,
    selected_bundle: Option<&PathBuf>,
) -> io::Result<()> {
    let Some(choice) = public_fields(
        terminal,
        "Uninstall",
        &[(
            "Choose new removal or original-record recovery: new/recover",
            "new",
        )],
    )?
    else {
        return Ok(());
    };
    if choice[0] == "recover" {
        let Some(values) = public_fields(
            terminal,
            "Reopen original removal",
            &[
                ("Original operation ID", ""),
                ("Original approved plan digest", ""),
            ],
        )?
        else {
            return Ok(());
        };
        let checked = uninstall::review_uninstall_recovery(&values[0], &values[1])?;
        let mut lines = vec![format!("Original operation {} and plan {}; no new removal identity.", values[0], values[1]), "Absent paths are observations, not proof of who removed them. Recovery never stops a newly changed service; stop it separately before review.".into()];
        lines.extend(checked.lines);
        lines.push("Changed or external files block recovery. Configuration, records, identities, device storage and producer drop-ins remain untouched. This is not erasure or revocation.".into());
        if !review(
            terminal,
            "Review original removal recovery",
            lines,
            Some("RECOVER ORIGINAL REMOVAL"),
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
        return setup::apply(terminal, worker, socket, action, Some(&bundle));
    }
    if choice[0] != "new" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "choose new or recover",
        ));
    }
    let Some(values) = public_fields(
        terminal,
        "Select components for removal",
        &[
            (
                "Comma-separated installed components: manager,daemon,cli,firmware,tool,deployment",
                "",
            ),
            (
                "Approve stopping the affected managed daemon if active? yes/no",
                "no",
            ),
        ],
    )?
    else {
        return Ok(());
    };
    let selected: Vec<String> = values[0]
        .split(',')
        .map(|value| value.trim().to_owned())
        .collect();
    let stop = match values[1].as_str() {
        "yes" if role == InstallationRole::Primary => true,
        "no" => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stop approval must be yes on primary or no",
            ));
        }
    };
    let checked = uninstall::review_uninstall(selected, stop)?;
    let mut lines = vec!["Exact registered files and links below will be removed; a changed or external file blocks removal. Administrative approval is required.".into()];
    lines.extend(
        checked
            .details
            .iter()
            .map(|line| format!("Remove/change: {line}")),
    );
    lines.extend(
        checked
            .retained
            .iter()
            .map(|line| format!("Retain: {line}")),
    );
    lines.push("Only an explicitly approved affected agent service is stopped. Producer services are never restarted. Removing binaries does not erase keys or revoke them; the running manager can complete its report after self-removal.".into());
    if !review(
        terminal,
        "Review selected uninstall",
        lines,
        Some("REMOVE SELECTED COMPONENTS"),
    )? {
        return Ok(());
    }
    setup::apply(terminal, worker, socket, checked.action, None)
}
