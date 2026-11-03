use super::{foreground, public_fields, review};
use crate::{
    config::RunMode,
    files,
    manager::{
        host::{self, HostAction, HostPlan},
        lifecycle::{self, Mutation},
        model::InstallationRole,
        observe::Worker,
        release::{self, Admission, VerifiedBundle},
        setup,
        terminal::TerminalOwner,
    },
};
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Install,
    InspectPlan,
    FirstInstall,
    CommissionConfig,
    StartCommission,
    ReconcileFirstInstall,
    Commission,
    StopCommission,
    NormalConfig,
    StartNormal,
}

pub(super) const ACTIONS: &[(Action, &str)] = &[
    (Action::Install, "Install authenticated host bundle"),
    (
        Action::InspectPlan,
        "Inspect original host plan (read-only; never replay)",
    ),
    (
        Action::FirstInstall,
        "Factory-only firmware install / original record (skip compatible blank app)",
    ),
    (
        Action::CommissionConfig,
        "Review/install explicit commissioning configuration",
    ),
    (
        Action::StartCommission,
        "Start restricted commissioning service",
    ),
    (
        Action::ReconcileFirstInstall,
        "Reconcile original first install with attended blank-application evidence",
    ),
    (Action::Commission, "Commission intended blank application"),
    (
        Action::StopCommission,
        "Stop restricted commissioning service",
    ),
    (
        Action::NormalConfig,
        "Review/install explicit normal configuration and pin",
    ),
    (
        Action::StartNormal,
        "Start normal service (existing preflight still applies)",
    ),
];

pub(super) fn bundle(
    terminal: &mut TerminalOwner,
    selected: Option<&PathBuf>,
) -> io::Result<Option<(PathBuf, VerifiedBundle, bool)>> {
    let retained = if selected.is_none() {
        match host::installation_registry() {
            Ok(registry) => registry.current.map(|selection| {
                Path::new("/usr/lib/pico2-kes-agent/sources").join(selection.manifest_digest.to_string())
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let selected = selected.or(retained.as_ref());
    let default = selected.and_then(|p| p.to_str()).unwrap_or("");
    let Some(values) = public_fields(
        terminal,
        "Select authenticated bundle",
        &[("Absolute bundle directory", default)],
    )?
    else {
        return Ok(None);
    };
    let path = PathBuf::from(&values[0]);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle path must be absolute",
        ));
    }
    let candidate = selected.is_some_and(|p| p == &path) && review(terminal, "Candidate admission is not qualification", vec![
        format!("Explicit or installed retained bundle: {}", path.display()),
        "Allow signed candidate status only for attended acceptance on a disposable host?".into(),
        "Cancel here uses ordinary qualified-only admission. Signature, compatibility, state and hardware checks remain mandatory.".into(),
    ], Some("DISPOSABLE CANDIDATE"))?;
    let verified = release::verify_bundle(
        &path,
        if candidate {
            Admission::AttendedCandidate
        } else {
            Admission::Qualified
        },
    )?;
    Ok(Some((path, verified, candidate)))
}

pub(super) fn apply(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    action: HostAction,
    bootstrap: Option<&VerifiedBundle>,
) -> io::Result<()> {
    let executable = match &action {
        HostAction::UpdateRecovery {
            operation_id,
            original_plan_digest,
            ..
        } => host::trusted_recovery_manager(operation_id, original_plan_digest)?,
        _ => host::trusted_manager().or_else(|error| match bootstrap {
            Some(bundle) => host::trusted_bootstrap_manager(bundle),
            None => Err(error),
        })?,
    };
    let plan = HostPlan::new(action)?;
    let Some(values) = public_fields(
        terminal,
        "Retain approved public host plan",
        &[(
            "New absolute plan file in an owner-controlled directory",
            "",
        )],
    )?
    else {
        return Ok(());
    };
    let path = PathBuf::from(&values[0]);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plan path must be absolute",
        ));
    }
    let mut lines: Vec<String> = serde_json::to_string_pretty(&plan)
        .map_err(io::Error::other)?
        .lines()
        .map(str::to_owned)
        .collect();
    lines.push(format!(
        "Plan retained at {}; do not replace an interrupted plan with a new identity.",
        path.display()
    ));
    lines.push("The privileged helper rechecks actual ownership/state/hashes and asks for this exact digest again. No node operation is authorized.".into());
    if !review(
        terminal,
        "Review finite host action",
        lines,
        Some(&plan.approved_digest),
    )? {
        return Ok(());
    }
    files::publish_no_clobber(
        &path,
        &serde_json::to_vec(&plan).map_err(io::Error::other)?,
        0o600,
    )?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/pkexec");
        command.arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&path);
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    review(terminal, "Host action result", vec![
        format!("Helper exit: {status}; original plan: {}", path.display()),
        "Inspect the retained maintenance checkpoints and fresh Overview. A running service does not establish pool delivery or forging.".into(),
        "If interrupted, retain this original plan; do not repeat under a new plan to conceal uncertainty.".into(),
    ], None)?;
    Ok(())
}

pub(super) fn run(
    action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    role: InstallationRole,
    socket: &Path,
    selected: Option<&PathBuf>,
) -> io::Result<()> {
    let action = ACTIONS
        .get(action)
        .map(|entry| entry.0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown setup action"))?;
    if role == InstallationRole::Backup && !matches!(action, Action::Install | Action::InspectPlan)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backup role cannot configure or contact a primary daemon/device",
        ));
    }
    match action {
        Action::Install => {
            let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
                return Ok(());
            };
            apply(
                terminal,
                worker,
                socket,
                HostAction::Install {
                    bundle: source,
                    role,
                    manifest_digest: verified.selection().manifest_digest.to_string(),
                    candidate_accepted: candidate,
                },
                Some(&verified),
            )
        }
        Action::CommissionConfig | Action::NormalConfig => {
            let commissioning = action == Action::CommissionConfig;
            let Some(values) = public_fields(
                terminal,
                "Explicit public configuration input",
                &[("Absolute candidate config file", "")],
            )?
            else {
                return Ok(());
            };
            let candidate = PathBuf::from(&values[0]);
            if !candidate.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "candidate path must be absolute",
                ));
            }
            configuration(terminal, worker, socket, commissioning, candidate)
        }
        Action::FirstInstall => {
            let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
                return Ok(());
            };
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let suggested = format!("/var/lib/p2kesup/firmware/{stamp:032x}.json");
            let Some(values) = public_fields(
                terminal,
                "Attended first install",
                &[
                    (
                        "New record, or original record to reopen (32 lowercase hex filename)",
                        &suggested,
                    ),
                    (
                        "Mode: preview or apply; existing records reopen read-only",
                        "preview",
                    ),
                ],
            )?
            else {
                return Ok(());
            };
            let apply_transfer = match values[1].as_str() {
                "preview" => false,
                "apply" => true,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "mode must be preview or apply",
                    ));
                }
            };
            let record = PathBuf::from(&values[0]);
            if !record.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "record path must be absolute",
                ));
            }
            apply(
                terminal,
                worker,
                socket,
                HostAction::FirmwareFirstInstall {
                    bundle: source,
                    manifest_digest: verified.selection().manifest_digest.to_string(),
                    candidate_accepted: candidate,
                    record,
                    apply: apply_transfer,
                },
                None,
            )
        }
        Action::StartCommission | Action::StopCommission => {
            let Some(values) = public_fields(
                terminal,
                "Restricted service and original recovery",
                &[(
                    "Original uncertain transfer operation ID, or empty for ordinary setup",
                    "",
                )],
            )?
            else {
                return Ok(());
            };
            apply(
                terminal,
                worker,
                socket,
                HostAction::CommissionService {
                    start: action == Action::StartCommission,
                    expected_state: host::observed_service_state(true)?,
                    recovery_operation: (!values[0].is_empty()).then(|| values[0].clone()),
                },
                None,
            )
        }
        Action::ReconcileFirstInstall => {
            let Some(values) = public_fields(
                terminal,
                "Reconcile the original transfer, never reflash",
                &[
                    ("Original host transfer operation ID", ""),
                    (
                        "Observed application USB serial on the same physical board",
                        "",
                    ),
                ],
            )?
            else {
                return Ok(());
            };
            let expected_service_state = host::observed_service_state(true)?;
            if !review(terminal, "Attended physical association", vec![
                format!("Original operation: {}; intended application serial: {}", values[0], values[1]),
                format!("Reviewed restricted service: {expected_service_state}"),
                "Physically confirm this is the same board as the original BOOTSEL transfer. Software cannot infer that association from a CHIPID or serial.".into(),
                "The helper reauthenticates the original staged bundle and observes the sole restricted daemon. Missing, wrong, unknown or nonblank post-state remains blocked.".into(),
                "A matching blank application can resolve the original host operation; it does not prove a missing flush checkpoint or rewrite the firmware tool record.".into(),
            ], Some(&format!("ASSOCIATE {} {}", values[0], values[1])))? { return Ok(()) }
            apply(
                terminal,
                worker,
                socket,
                HostAction::ReconcileFirstInstall {
                    operation_id: values[0].clone(),
                    serial: values[1].clone(),
                    expected_service_state,
                },
                None,
            )
        }
        Action::Commission => {
            let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
                return Ok(());
            };
            let Some(values) = public_fields(
                terminal,
                "Commission exact blank application",
                &[
                    ("Observed application USB serial", ""),
                    ("New absolute public enrollment output", ""),
                    ("New absolute original receipt path", ""),
                    ("New absolute receipt reference path", ""),
                    (
                        "New absolute public admission plan in an owner-controlled directory",
                        "",
                    ),
                ],
            )?
            else {
                return Ok(());
            };
            if values[1..]
                .iter()
                .any(|value| !Path::new(value).is_absolute())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "all output and plan paths must be absolute",
                ));
            }
            let trusted = host::trusted_cli()?;
            let helper = host::trusted_manager()?;
            let admission = HostPlan::new(HostAction::CommissionAdmission {
                bundle: source,
                manifest_digest: verified.selection().manifest_digest.to_string(),
                candidate_accepted: candidate,
                serial: values[0].clone(),
                socket: socket.to_owned(),
                expected_service_state: host::observed_service_state(true)?,
            })?;
            let mut lines = vec![
                format!("Intended application serial: {}", values[0]),
                "Physically confirm this is the same intended board. BOOTSEL CHIPID is not an application serial or pin; the software cannot establish that physical association for you.".into(),
                format!("Public enrollment output: {}; receipt: {}; retained reference: {}", values[1], values[2], values[3]),
                format!("Public read-only admission plan: {}", values[4]),
                "The privileged helper only authenticates fresh evidence; the existing operator CLI owns the original commissioning receipt and mutation.".into(),
                "Admission rechecks selected compatible live build and blank commissioning state. This does not erase, run OTP, replace an existing pin or start normal operation.".into(),
            ];
            lines.extend(
                serde_json::to_string_pretty(&admission)
                    .map_err(io::Error::other)?
                    .lines()
                    .map(str::to_owned),
            );
            if !review(
                terminal,
                "Commissioning changes identity",
                lines,
                Some(&format!("COMMISSION {}", values[0])),
            )? {
                return Ok(());
            }
            files::publish_no_clobber(
                Path::new(&values[4]),
                &serde_json::to_vec(&admission).map_err(io::Error::other)?,
                0o600,
            )?;
            if let Some(active) = worker.take() {
                active.shutdown();
            }
            let outcome = (|| {
                let mut command = if rustix::process::geteuid().is_root() {
                    Command::new(helper)
                } else {
                    let mut command = Command::new("/usr/bin/pkexec");
                    command.arg(helper);
                    command
                };
                command.arg("host-admit").arg("--plan").arg(&values[4]);
                let status = foreground(terminal, worker, socket, &mut command, false)?;
                if !status.success() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "read-only admission did not pass ({status}); no commissioning request was submitted"
                        ),
                    ));
                }
                let authority = super::lifecycle::admission(terminal, socket, Some(&values[0]))?;
                let trusted = trusted.bind_peer(&authority);
                lifecycle::submit(
                    &trusted,
                    socket,
                    Path::new(&values[3]),
                    Path::new(&values[2]),
                    0,
                    Mutation::Commission {
                        usb_serial: values[0].clone(),
                        out: values[1].clone(),
                    },
                )
            })();
            if terminal.terminal().is_ok() {
                *worker = Some(Worker::start(socket.to_owned(), None));
            }
            let outcome = outcome?;
            review(terminal, "Original commissioning outcome", vec![
                format!("Outcome: {:?}; uncertain: {}; receipt reference: {}", outcome.class, outcome.uncertain, values[3]),
                "Retain the original receipt even if output was lost. Review the returned public identity/pin in explicit normal configuration; stop restricted mode before separately approved normal startup.".into(),
                if outcome.class == lifecycle::ExitClass::Success && !outcome.uncertain { "Public enrollment completed; normal readiness is not yet established." } else { "Do not submit again under a new receipt. Reconcile this original operation." }.into(),
            ], None)?;
            Ok(())
        }
        Action::StartNormal => apply(
            terminal,
            worker,
            socket,
            HostAction::Service {
                operation: host::ServiceAction::Start,
                expected_state: host::observed_service_state(false)?,
            },
            None,
        ),
        Action::InspectPlan => {
            let Some(values) = public_fields(
                terminal,
                "Inspect retained host plan; no action is applied",
                &[("Absolute original host plan file", "")],
            )?
            else {
                return Ok(());
            };
            let path = PathBuf::from(&values[0]);
            if !path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "plan path must be absolute",
                ));
            }
            let executable = host::trusted_manager()?;
            let mut command = if rustix::process::geteuid().is_root() {
                Command::new(executable)
            } else {
                let mut command = Command::new("/usr/bin/pkexec");
                command.arg(executable);
                command
            };
            command.arg("host-inspect").arg("--plan").arg(&path);
            let status = foreground(terminal, worker, socket, &mut command, true)?;
            review(terminal, "Original host-plan inspection", vec![
                format!("Helper exit: {status}; original plan: {}", path.display()),
                "Inspection never creates a replacement operation or applies the plan. Missing evidence is not permission to replay.".into(),
            ], None)?;
            Ok(())
        }
    }
}

pub(super) fn configuration(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    commissioning: bool,
    candidate: PathBuf,
) -> io::Result<()> {
    let checked = setup::review_config(
        &candidate,
        if commissioning {
            RunMode::Commissioning
        } else {
            RunMode::Normal
        },
    )?;
    let (previous, previous_bytes) = setup::current_config_review()?.unzip();
    let mut lines = vec![format!("Source: {}; SHA-256: {}", checked.source.display(), checked.sha256), format!("Current configuration SHA-256: {}", previous.as_deref().unwrap_or("absent")), "Review every pin, network/genesis path, binding and access setting below. No value was discovered from a node or guessed.".into()];
    lines.push(format!("Input validation: {}", checked.validation));
    lines.extend(checked.inputs.iter().map(|input| {
        format!(
            "Public input: {}; SHA-256: {}",
            input.path.display(),
            input.sha256
        )
    }));
    lines.push("Exact replacement diff: '-' old lines; '+' proposed lines. Quoting preserves tabs, escapes and final-newline differences.".into());
    if let Some(bytes) = previous_bytes {
        let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
        lines.extend(text.split_inclusive('\n').map(|line| format!("- {line:?}")));
    }
    let text = std::str::from_utf8(&checked.bytes).map_err(io::Error::other)?;
    lines.extend(text.split_inclusive('\n').map(|line| format!("+ {line:?}")));
    lines.push("A service-identity sibling-candidate check precedes replacement; failure preserves working bytes/mode/owner. Service restart is a separate approved action. Existing host-memory and cardano-node.service preflight obligations are unchanged.".into());
    if !review(
        terminal,
        "Review configuration",
        lines,
        Some(&checked.sha256),
    )? {
        return Ok(());
    }
    let recovery_operation = if commissioning {
        let Some(values) = public_fields(
            terminal,
            "Original first-install recovery",
            &[(
                "Original uncertain transfer operation ID, or empty for ordinary setup",
                "",
            )],
        )?
        else {
            return Ok(());
        };
        (!values[0].is_empty()).then(|| values[0].clone())
    } else {
        None
    };
    apply(
        terminal,
        worker,
        socket,
        HostAction::Config {
            candidate,
            candidate_digest: checked.sha256,
            expected_current_digest: previous,
            commissioning,
            inputs: checked.inputs,
            recovery_operation,
        },
        None,
    )
}
