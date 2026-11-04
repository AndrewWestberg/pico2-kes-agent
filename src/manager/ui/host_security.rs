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
    reviewed.lines.extend([
        String::new(),
        "These changes apply host-wide and persist across reboot. Disabling swap and sleep can increase out-of-memory risk and remove suspend/hibernate.".into(),
        "Confirm your snapshot and crashdump policy protects secrets in memory (this cannot be verified automatically), and backup private keys are held off the primary host.".into(),
    ]);
    if !commissioning {
        reviewed.lines.push("Confirm NODE_MEMORY_POLICY=core-and-swap-disabled: node limits are checked, and your operational policy protects node memory.".into());
    }
    if !review_mode(
        terminal,
        "Review host security prerequisites",
        reviewed.lines,
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
