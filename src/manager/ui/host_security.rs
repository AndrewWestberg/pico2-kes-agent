use super::{
    setup,
    widgets::{ConfirmMode, review_mode},
};
use crate::manager::{host::HostAction, host_security, observe::Worker, terminal::TerminalOwner};
use std::{io, path::Path};

pub(super) fn ensure(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    commissioning: bool,
) -> io::Result<Option<bool>> {
    let mut reviewed = host_security::review(commissioning)?;
    if reviewed.ready {
        return Ok(Some(false));
    }
    let mut lines = vec![
        "The tool will disable active swap and prevent system-managed swap and sleep from starting. These host-wide changes persist after reboot.".into(),
        "This can increase out-of-memory risk and disable suspend and hibernation.".into(),
        "Confirm that snapshots and crash dumps protect secrets in memory, and that backup private keys are stored off this host. The tool cannot verify these policies.".into(),
    ];
    if !commissioning {
        lines.push("The tool will install memory protection for cardano-node.service and restart it if running. Confirm your operating policy protects node memory from core dumps and swap.".into());
    }
    if !review_mode(
        terminal,
        "Review host security prerequisites",
        lines,
        ConfirmMode::YesNo { danger: true },
    )? {
        return Ok(None);
    }
    reviewed.request.snapshot_policy_acknowledged = true;
    reviewed.request.backup_private_off_primary = true;
    reviewed.request.node_memory_acknowledged = !commissioning;
    match setup::apply(
        terminal,
        worker,
        socket,
        HostAction::HostSecurity {
            request: reviewed.request,
        },
        None,
    ) {
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(None),
        result => result?,
    }
    if !host_security::review(commissioning)?.ready {
        return Err(io::Error::other(
            "Host security prerequisites remain incomplete; inspect the original record in Activity",
        ));
    }
    Ok(Some(true))
}
