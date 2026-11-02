use super::{public_fields, review, setup};
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
    Recover,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (Action::Install, "Install producer memory hardening"),
    (Action::Recover, "Recover original producer batch"),
];

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
    if ACTIONS[action].0 == Action::Recover {
        let Some(values) = public_fields(
            terminal,
            "Original producer operation",
            &[
                ("Original maintenance operation ID", ""),
                ("Original approved plan digest", ""),
            ],
        )?
        else {
            return Ok(());
        };
        let reviewed = producer::review_recovery(&values[0], &values[1])?;
        if !review(
            terminal,
            "Recover original producer batch",
            reviewed.lines,
            Some("RECOVER ORIGINAL PRODUCER BATCH"),
        )? {
            return Ok(());
        }
        return setup::apply(terminal, worker, socket, reviewed.action, None);
    }
    let Some(values) = public_fields(
        terminal,
        "Producer services",
        &[(
            "Concrete .service names, separated by spaces (maximum 64)",
            "",
        )],
    )?
    else {
        return Ok(());
    };
    let names: Vec<_> = values[0].split_whitespace().collect();
    let mut request = Request {
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
    request.validate()?;
    for target in &mut request.targets {
        target.existing = producer::inspect(&target.unit)?;
        let path = producer::destination(&target.unit)?;
        let mut lines = vec![
            format!("Selected unit: {}", target.unit),
            format!("Exact destination: {}", path.display()),
        ];
        match &target.existing {
            None => lines.push("Destination absent; create only if still absent.".into()),
            Some(e) => {
                lines.push(format!(
                    "Existing file: device {} inode {} owner {} group {} mode {:04o}",
                    e.device, e.inode, e.owner, e.group, e.mode
                ));
                lines.push(format!(
                    "Exact existing contents, hexadecimal: {}",
                    e.contents
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ));
                lines.push("Confirmation approves replacing these exact reviewed contents and ownership only; changed files are refused.".into());
            }
        }
        lines.push("Install the authenticated unchanged project policy as root:root mode 0644; unrelated files remain untouched.".into());
        lines.push(format!(
            "Reviewed policy SHA-256: {}",
            request.policy_sha256
        ));
        lines.extend(
            include_str!("../../../deploy/cardano-node-memory-hardening.conf")
                .lines()
                .map(|line| format!("New policy: {line}")),
        );
        if !review(
            terminal,
            "Review producer drop-in",
            lines,
            Some("APPROVE FILE"),
        )? {
            return Ok(());
        }
        match host::service_state(&target.unit) {
            Ok(state) if state == "active" => {
                target.restart = review(terminal, "Optional producer restart", vec![format!("{} is currently running.", target.unit), "Approve restarting only this unit after installation and daemon-reload? Cancel here defers the effect until its next start/restart.".into(), "The helper checks it is still running; stopped units are never started.".into()], Some("RESTART"))?;
            }
            state => {
                review(
                    terminal,
                    "No producer restart approved",
                    vec![
                        format!(
                            "{}: {}",
                            target.unit,
                            match state {
                                Ok(s) => s,
                                Err(e) => format!("state unavailable: {e}"),
                            }
                        ),
                        "No restart is approved; policy applies on its next start/restart.".into(),
                    ],
                    None,
                )?;
            }
        }
    }
    let mut lines: Vec<String> = request
        .targets
        .iter()
        .map(|t| {
            format!(
                "{} -> {}; restart if still running: {}",
                t.unit,
                producer::destination(&t.unit).unwrap().display(),
                t.restart
            )
        })
        .collect();
    lines.push("Install approved files, run systemctl daemon-reload, and execute only the individually approved restarts. Failed and partial operations are recorded; no node discovery or runtime policy audit is performed.".into());
    if !review(
        terminal,
        "Confirm producer hardening batch",
        lines,
        Some("APPLY"),
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
