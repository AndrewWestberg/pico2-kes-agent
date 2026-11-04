use super::{
    review, setup,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::manager::{
    host::{self, HostAction},
    observe::Worker,
    producer::{self, Request, Target},
    terminal::TerminalOwner,
};
use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Install,
}
pub(super) const ACTIONS: &[(Action, &str)] =
    &[(Action::Install, "Install producer memory hardening drop-in")];

pub(super) fn recover_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    operation_id: &str,
    plan_digest: &str,
) -> io::Result<()> {
    let reviewed = producer::review_recovery(operation_id, plan_digest)?;
    if !review_mode(
        terminal,
        "Recover original producer batch",
        reviewed.lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(());
    }
    setup::apply(terminal, worker, socket, reviewed.action, None)
}

pub(super) fn run(
    action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    _selected: Option<&PathBuf>,
) -> io::Result<()> {
    if action >= ACTIONS.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid producer action",
        ));
    }
    let restart_opts = [
        ("no", "Do not restart running producer units now"),
        ("yes", "Restart running producer units after daemon-reload"),
    ];
    let nodes = crate::manager::discovery::node::discover_nodes();
    let options: Vec<(&str, &str)> = nodes.iter().map(|n| (n.unit.as_str(), "")).collect();
    if options.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No Cardano node service units discovered",
        ));
    }
    let specs = [
        FieldSpec::multiselect("Producer units", "", &options),
        FieldSpec::select(
            "Restart currently active units after installing drop-in",
            "no",
            &restart_opts,
        ),
    ];
    let Some((mut request, approve_restart)) =
        form_validated(terminal, "Producer memory hardening", &specs, |values| {
            let names: Vec<_> = values[0].split(',').filter(|s| !s.is_empty()).collect();
            let req = Request {
                policy_sha256: producer::policy_sha256(),
                targets: names
                    .iter()
                    .map(|unit| Target {
                        unit: (*unit).into(),
                        existing: None,
                        restart: false,
                    })
                    .collect(),
            };
            req.validate().map_err(|e| (Some(0), e.to_string()))?;
            Ok((req, values[1] == "yes"))
        })?
    else {
        return Ok(());
    };

    let mut lines = vec![
        format!("Policy SHA-256: {}", request.policy_sha256),
        "Drop-in content to install (root:root 0644):".into(),
    ];
    lines.extend(
        include_str!("../../../deploy/cardano-node-memory-hardening.conf")
            .lines()
            .map(|line| format!("  {line}")),
    );
    lines.push(String::new());
    lines.push("Target units:".into());
    for target in &mut request.targets {
        target.existing = producer::inspect(&target.unit)?;
        let path = producer::destination(&target.unit)?;
        let is_active = host::service_state(&target.unit).is_ok_and(|s| s == "active");
        target.restart = approve_restart && is_active;
        let state_desc = match &target.existing {
            None => "create new drop-in".to_owned(),
            Some(e) => format!("replace reviewed inode {} (mode {:04o})", e.inode, e.mode),
        };
        lines.push(format!(
            "  {} -> {} ({state_desc}; restart={})",
            target.unit,
            path.display(),
            target.restart
        ));
    }
    let _ = review;
    if !review_mode(
        terminal,
        "Review producer memory hardening",
        lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(());
    }
    setup::apply(
        terminal,
        worker,
        socket,
        HostAction::ProducerHardening { request },
        None,
    )
}
