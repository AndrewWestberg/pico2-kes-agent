use super::{
    foreground, review,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::{
    config::RunMode,
    files,
    manager::{
        config_builder::{
            bind_pool_bytes, candidate_usb_serial, configured_networks, default_pool_socket_path,
            publish_candidate,
        },
        host::{self, HostAction, HostPlan},
        lifecycle::{self, Mutation},
        model::InstallationRole,
        observe::Worker,
        release::{self, Admission, VerifiedBundle},
        setup,
        terminal::TerminalOwner,
        workspace::{self, WorkspaceKind},
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
}
pub(super) const ACTIONS: &[(Action, &str)] =
    &[(Action::Install, "Install authenticated host bundle")];

pub(super) fn bundle(
    terminal: &mut TerminalOwner,
    selected: Option<&PathBuf>,
) -> io::Result<Option<(PathBuf, VerifiedBundle, bool)>> {
    let retained = if selected.is_none() {
        match host::installation_registry() {
            Ok(registry) => registry.current.map(|selection| {
                Path::new("/usr/lib/pico2-kes-agent/sources")
                    .join(selection.manifest_digest.to_string())
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let path = if let Some(path) = selected.or(retained.as_ref()) {
        path.clone()
    } else {
        let specs = [FieldSpec::text(
            "Absolute authenticated bundle directory",
            "",
        )];
        let Some(path) = form_validated(terminal, "Select bundle", &specs, |values| {
            let path = PathBuf::from(values[0].trim());
            if !path.is_absolute() {
                return Err((Some(0), "Bundle path must be absolute".into()));
            }
            Ok(path)
        })?
        else {
            return Ok(None);
        };
        path
    };
    let (verified, candidate) = match release::verify_bundle(&path, Admission::Qualified) {
        Ok(bundle) => (bundle, false),
        Err(qualified_error) => {
            let bundle = release::verify_bundle(&path, Admission::AttendedCandidate)
                .map_err(|_| qualified_error)?;
            if !review_mode(
                terminal,
                "Candidate bundle is not qualified",
                vec![
                    format!("Bundle: {}", path.display()),
                    "Use this signed candidate for attended acceptance on a disposable host?"
                        .into(),
                ],
                ConfirmMode::YesNo { danger: false },
            )? {
                return Ok(None);
            }
            (bundle, true)
        }
    };
    Ok(Some((path, verified, candidate)))
}

fn start_mode(action: &HostAction) -> Option<bool> {
    match action {
        HostAction::Service {
            operation: host::ServiceAction::Start | host::ServiceAction::Restart,
            ..
        } => Some(false),
        HostAction::CommissionService { start: true, .. } => Some(true),
        _ => None,
    }
}

fn matches_record(
    record: &crate::manager::model::MaintenanceRecord,
    id: Option<&str>,
    digest: Option<&str>,
) -> bool {
    id.is_none_or(|id| record.operation_id.to_string() == id)
        && digest.is_none_or(|digest| record.plan_digest.to_string() == digest)
}

fn failure_observations(plan: &HostPlan) -> Vec<String> {
    let (id, digest) = match &plan.action {
        HostAction::UpgradeRecovery {
            operation_id,
            original_plan_digest,
            ..
        }
        | HostAction::UpdateRecovery {
            operation_id,
            original_plan_digest,
            ..
        }
        | HostAction::FirmwareRecovery {
            operation_id,
            original_plan_digest,
            ..
        }
        | HostAction::HostSecurityRecovery {
            operation_id,
            original_plan_digest,
            ..
        }
        | HostAction::WipeRecovery {
            operation_id,
            original_plan_digest,
        }
        | HostAction::ProducerRecovery {
            operation_id,
            original_plan_digest,
            ..
        }
        | HostAction::HostReconcile {
            operation_id,
            original_plan_digest,
        }
        | HostAction::UninstallRecovery {
            operation_id,
            original_plan_digest,
            ..
        } => (
            Some(operation_id.as_str()),
            Some(original_plan_digest.as_str()),
        ),
        HostAction::ReconcileFirstInstall { operation_id, .. } => {
            (Some(operation_id.as_str()), None)
        }
        HostAction::Config {
            recovery_operation: Some(operation_id),
            ..
        }
        | HostAction::CommissionService {
            recovery_operation: Some(operation_id),
            ..
        } => (Some(operation_id.as_str()), None),
        _ => (None, Some(plan.approved_digest.as_str())),
    };
    use crate::manager::records::{Record, RecordStore};
    let Ok(records) = RecordStore::list_host_readonly() else {
        return Vec::new();
    };
    records
        .into_iter()
        .find_map(|record| match record {
            Record::Supported(record) if matches_record(&record, id, digest) => Some(
                record
                    .post_observations
                    .iter()
                    .rev()
                    .take(6)
                    .map(|line| super::safe(&line.chars().take(512).collect::<String>()))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

pub(crate) fn apply(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    mut action: HostAction,
    bootstrap: Option<&VerifiedBundle>,
) -> io::Result<()> {
    if let Some(commissioning) = start_mode(&action) {
        let Some(changed) = super::host_security::ensure(terminal, worker, socket, commissioning)?
        else {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Host security review declined; service start paused",
            ));
        };
        if changed {
            match &mut action {
                HostAction::Service { expected_state, .. } => {
                    *expected_state = host::observed_service_state(false)?
                }
                HostAction::CommissionService { expected_state, .. } => {
                    *expected_state = host::observed_service_state(true)?
                }
                _ => unreachable!(),
            }
        }
    }
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
    let stem = action.stem();
    let summary = action.summary();
    let plan = HostPlan::new(action)?;
    let path = workspace::next_path(WorkspaceKind::Plans, stem, "json")?;
    let summary_lines = vec![
        summary.clone(),
        "The privileged helper will recheck this scope and ask Proceed? [y/N].".into(),
    ];
    let mut lines = vec![
        format!("Action summary : {summary}"),
        format!("Plan file      : {}", path.display()),
        format!("Plan ID        : {}", plan.plan_id),
        "The privileged helper will show the summary and plan digest, then ask for confirmation."
            .into(),
        String::new(),
        "Exact JSON scope:".into(),
    ];
    lines.extend(
        serde_json::to_string_pretty(&plan)
            .map_err(io::Error::other)?
            .lines()
            .map(str::to_owned),
    );
    if !super::widgets::review_details(terminal, "Review host change", summary_lines, lines)? {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Change cancelled; no host action was submitted",
        ));
    }
    files::publish_no_clobber(
        &path,
        &serde_json::to_vec(&plan).map_err(io::Error::other)?,
        0o600,
    )?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&path);
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    let mut result_lines = vec![
        format!("Action: {summary}"),
        format!("Helper exit: {status}"),
        format!("Retained plan: {}", path.display()),
        "Inspect Overview (1) or Activity (6) for updated state and checkpoints. A running service alone does not prove pool delivery or forging."
            .into(),
        "If interrupted, reconcile the original record in Activity (6) — never repeat under a new identity."
            .into(),
    ];
    if !status.success() {
        let observations = failure_observations(&plan);
        if !observations.is_empty() {
            result_lines.push("Original record observations:".into());
            result_lines.extend(observations);
        }
    }
    review(terminal, "Host action result", result_lines)?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "Host action failed or was cancelled ({status}); inspect the original record in Activity"
        )));
    }
    Ok(())
}

pub(crate) fn default_socket_group() -> String {
    if let Ok(Some((_, bytes))) = setup::current_config_review()
        && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(group) = val.get("socket_group").and_then(serde_json::Value::as_str)
        && !group.is_empty()
    {
        return group.to_owned();
    }
    "pico2-kes-agent".into()
}

pub(crate) fn commissioning_config_core(serial: &str) -> io::Result<PathBuf> {
    let spec = crate::manager::config_builder::CommissioningSpec {
        usb_serial: serial.into(),
        socket_group: default_socket_group(),
        ..Default::default()
    };
    publish_candidate(
        "commission-config",
        &crate::manager::config_builder::build_commissioning_bytes(&spec)?,
    )
}

pub(crate) fn normal_config_core(
    spec: &crate::manager::config_builder::NormalConfigSpec,
) -> io::Result<(PathBuf, Vec<setup::GenesisImport>)> {
    let previous = setup::current_config_review()?.map(|(_, bytes)| bytes);
    let bytes = crate::manager::config_builder::build_normal_bytes(spec, previous.as_deref())?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let dir = Path::new("/etc/pico2-kes-agent/genesis").join(&spec.network_name);
    let byron = dir.join("byron-genesis.json");
    let shelley = dir.join("shelley-genesis.json");
    let imports = vec![
        setup::GenesisImport {
            source: setup::review_public_input(&spec.byron_genesis_file)?,
            dest: byron.clone(),
        },
        setup::GenesisImport {
            source: setup::review_public_input(&spec.shelley_genesis_file)?,
            dest: shelley.clone(),
        },
    ];
    value["networks"][spec.network_name.as_str()]["byron_genesis_file"] = serde_json::json!(byron);
    value["networks"][spec.network_name.as_str()]["shelley_genesis_file"] =
        serde_json::json!(shelley);
    let bytes = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
    Ok((publish_candidate("normal-config", &bytes)?, imports))
}

pub(crate) fn bind_pool_workflow(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    pool_id: &str,
    incarnation_id: &str,
    preferred_network: Option<&str>,
) -> io::Result<()> {
    let Some((_, current_bytes)) = setup::current_config_review()? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "working normal configuration (/etc/pico2-kes-agent/config.json) is not present yet",
        ));
    };
    let networks = configured_networks(&current_bytes);
    if networks.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "working configuration has no configured networks; install normal configuration first",
        ));
    }
    let default_net = preferred_network
        .filter(|n| networks.iter().any(|candidate| candidate == *n))
        .unwrap_or_else(|| networks[0].as_str());
    let default_sock = default_pool_socket_path(&current_bytes, pool_id)
        .to_string_lossy()
        .into_owned();
    let net_pairs: Vec<(&str, &str)> = networks
        .iter()
        .map(|n| (n.as_str(), "configured network"))
        .collect();
    let restart_opts = [
        (
            "yes",
            "Restart pico2-kes-agentd after config update so socket & context start",
        ),
        ("no", "Install config only; restart service later"),
    ];
    let specs = [
        FieldSpec::readonly("Pool ID", pool_id),
        FieldSpec::readonly("Incarnation ID", incarnation_id),
        FieldSpec::select("Network binding", default_net, &net_pairs),
        FieldSpec::text("KES Service V2 Unix socket path", &default_sock),
        FieldSpec::select("Restart agent service afterward", "yes", &restart_opts),
    ];
    let Some((candidate, restart_after)) = form_validated(
        terminal,
        "Bind enrolled pool in host configuration",
        &specs,
        |values| {
            let sock = PathBuf::from(values[3].trim());
            if !sock.is_absolute() {
                return Err((Some(3), "Socket path must be absolute".into()));
            }
            let updated =
                bind_pool_bytes(&current_bytes, pool_id, incarnation_id, &values[2], &sock)
                    .map_err(|e| (Some(3), e.to_string()))?;
            let path = publish_candidate(
                &format!("bind-pool-{}", workspace::short_id(pool_id)),
                &updated,
            )
            .map_err(|e| (None, e.to_string()))?;
            setup::review_config(&path, RunMode::Normal)
                .map_err(|e| (Some(3), format!("Validation failed: {e}")))?;
            Ok((path, values[4] == "yes"))
        },
    )?
    else {
        return Ok(());
    };
    configuration(terminal, worker, socket, false, candidate)?;
    if restart_after {
        let expected_state = host::observed_service_state(false)?;
        apply(
            terminal,
            worker,
            socket,
            HostAction::Service {
                operation: host::ServiceAction::Restart,
                expected_state,
            },
            None,
        )?;
    }
    Ok(())
}

pub(super) fn run(
    _action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    role: InstallationRole,
    socket: &Path,
    selected: Option<&PathBuf>,
) -> io::Result<()> {
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

pub(crate) fn commission_core(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    selected: Option<&PathBuf>,
    serial: &str,
) -> io::Result<Option<PathBuf>> {
    let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
        return Ok(None);
    };
    let serial = serial.to_owned();
    let out_path = workspace::next_path(WorkspaceKind::Exports, &serial, "device.json")?
        .to_string_lossy()
        .into_owned();
    let receipt_path = workspace::next_path(WorkspaceKind::Receipts, "commission", "receipt.json")?
        .to_string_lossy()
        .into_owned();
    let reference_path = workspace::next_path(WorkspaceKind::References, "commission", "ref.json")?;
    let admission_plan_path =
        workspace::next_path(WorkspaceKind::Plans, "commission-admission", "json")?;

    let trusted = host::trusted_cli()?;
    let helper = host::trusted_manager()?;
    let admission = HostPlan::new(HostAction::CommissionAdmission {
        bundle: source,
        manifest_digest: verified.selection().manifest_digest.to_string(),
        candidate_accepted: candidate,
        serial: serial.clone(),
        socket: socket.to_owned(),
        expected_service_state: host::observed_service_state(true)?,
    })?;
    let mut lines = super::widgets::progress_steps(
        &[
            "Detect board",
            "Prepare firmware",
            "Commission",
            "Configure",
            "Start agent",
        ],
        2,
    );
    lines.extend([
                format!("Intended application serial : {serial}"),
                format!("Public identity output      : {out_path}"),
                format!("Original CLI receipt        : {receipt_path}"),
                format!("Managed reference record    : {}", reference_path.display()),
                format!("Read-only admission plan    : {}", admission_plan_path.display()),
                String::new(),
                "Physically confirm this is the intended blank Pico 2 board. BOOTSEL CHIPID is not an application identity pin."
                    .into(),
                "This generates the persistent device identity on the Pico 2. It does not lock OTP or start normal mode."
                    .into(),
            ]);
    if !review_mode(
        terminal,
        "Confirm blank-device commissioning",
        lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(None);
    }
    files::publish_no_clobber(
        &admission_plan_path,
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
            let mut command = Command::new("/usr/bin/sudo");
            command.arg("--").arg(helper);
            command
        };
        command
            .arg("host-admit")
            .arg("--plan")
            .arg(&admission_plan_path);
        let status = foreground(terminal, worker, socket, &mut command, false)?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "read-only admission did not pass ({status}); no commissioning request was submitted"
                ),
            ));
        }
        let authority = super::lifecycle::admission(terminal, socket, Some(&serial))?;
        let trusted = trusted.bind_peer(&authority);
        lifecycle::submit(
            &trusted,
            socket,
            &reference_path,
            Path::new(&receipt_path),
            0,
            Mutation::Commission {
                usb_serial: serial.clone(),
                out: out_path.clone(),
            },
        )
    })();
    if terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    let outcome = outcome?;
    review(
        terminal,
        "Commissioning outcome",
        vec![
            format!(
                "Outcome: {:?}; uncertain: {}",
                outcome.class, outcome.uncertain
            ),
            format!("Device identity file: {out_path}"),
            format!("Retained reference  : {}", reference_path.display()),
            if outcome.class == lifecycle::ExitClass::Success && !outcome.uncertain {
                "Continue setup to install the normal configuration and start the agent.".into()
            } else {
                "Do not submit again under a new receipt. Reconcile this original operation in Activity (6)."
                        .into()
            },
        ],
    )?;
    Ok(
        (outcome.class == lifecycle::ExitClass::Success && !outcome.uncertain)
            .then(|| PathBuf::from(out_path)),
    )
}

pub(super) fn inspect_plan_file(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    path: &Path,
) -> io::Result<()> {
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.arg("host-inspect").arg("--plan").arg(path);
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    review(
        terminal,
        "Original host-plan inspection",
        vec![
            format!("Helper exit: {status}; original plan: {}", path.display()),
            "Inspection never creates a replacement operation or applies the plan.".into(),
        ],
    )?;
    Ok(())
}

pub(crate) fn configuration(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    commissioning: bool,
    candidate: PathBuf,
) -> io::Result<()> {
    configuration_with_imports(
        terminal,
        worker,
        socket,
        commissioning,
        candidate,
        Vec::new(),
    )
}

pub(crate) fn configuration_with_imports(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    commissioning: bool,
    candidate: PathBuf,
    genesis_imports: Vec<setup::GenesisImport>,
) -> io::Result<()> {
    configuration_inner(
        terminal,
        worker,
        socket,
        commissioning,
        candidate,
        genesis_imports,
        None,
    )
}

pub(crate) fn configuration_recovery(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    candidate: PathBuf,
    operation_id: &str,
) -> io::Result<()> {
    configuration_inner(
        terminal,
        worker,
        socket,
        true,
        candidate,
        Vec::new(),
        Some(operation_id.to_owned()),
    )
}

fn configuration_inner(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    commissioning: bool,
    candidate: PathBuf,
    genesis_imports: Vec<setup::GenesisImport>,
    recovery_operation: Option<String>,
) -> io::Result<()> {
    let checked = setup::review_config_with_imports(
        &candidate,
        if commissioning {
            RunMode::Commissioning
        } else {
            RunMode::Normal
        },
        &genesis_imports,
    )?;
    let (previous, previous_bytes) = setup::current_config_review()?.unzip();
    let mut lines = vec![
        format!("Candidate source : {}", checked.source.display()),
        format!("Candidate SHA-256: {}", checked.sha256),
        format!(
            "Current SHA-256  : {}",
            previous.as_deref().unwrap_or("(absent)")
        ),
        format!("Validation       : {}", checked.validation),
    ];
    let value: serde_json::Value =
        serde_json::from_slice(&checked.bytes).map_err(io::Error::other)?;
    let networks = value["networks"]
        .as_object()
        .map(|networks| networks.keys().cloned().collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let summary = vec![
        format!(
            "Pico 2: {}",
            value["device"]["usb_serial"]
                .as_str()
                .unwrap_or("unavailable")
        ),
        format!(
            "Mode: {}",
            if commissioning {
                "commissioning"
            } else {
                "normal pinned agent"
            }
        ),
        format!(
            "Networks: {}",
            if networks.is_empty() {
                "none (commissioning)"
            } else {
                &networks
            }
        ),
        format!(
            "Public genesis files to import: {}. Existing configuration is replaced only after validation.",
            genesis_imports.len()
        ),
    ];
    lines.extend(checked.inputs.iter().map(|input| {
        format!(
            "Genesis input    : {} (SHA-256 {})",
            input.path.display(),
            input.sha256
        )
    }));
    lines.push(String::new());
    lines.push("Exact configuration diff ('-' current, '+' proposed):".into());
    if let Some(bytes) = previous_bytes {
        let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
        lines.extend(text.lines().map(|line| format!("- {line}")));
    }
    let text = std::str::from_utf8(&checked.bytes).map_err(io::Error::other)?;
    lines.extend(text.lines().map(|line| format!("+ {line}")));
    lines.push(String::new());
    lines.push(
        "Service-identity validation runs before atomic replacement; failure leaves working config untouched."
            .into(),
    );
    if !super::widgets::review_details(terminal, "Review configuration", summary, lines)? {
        return Ok(());
    }
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
            genesis_imports,
            recovery_operation,
        },
        None,
    )
}

pub(super) fn reconcile_first_install_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    initial_op_id: &str,
) -> io::Result<()> {
    let op_id = initial_op_id.to_owned();
    let serial = candidate_usb_serial().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Connect exactly one application board to associate with this record",
        )
    })?;
    let expected_service_state = host::observed_service_state(true)?;
    if !review_mode(
        terminal,
        "Attended physical association",
        vec![
            format!("Original operation: {op_id}; intended application serial: {serial}"),
            format!("Reviewed restricted service: {expected_service_state}"),
            "Physically confirm this is the same board as the original BOOTSEL transfer. Software cannot infer that association from a CHIPID or serial."
                .into(),
        ],
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(());
    }
    apply(
        terminal,
        worker,
        socket,
        HostAction::ReconcileFirstInstall {
            operation_id: op_id,
            serial,
            expected_service_state,
        },
        None,
    )
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn only_service_starts_require_security_review() {
        for operation in [host::ServiceAction::Start, host::ServiceAction::Restart] {
            assert_eq!(
                start_mode(&HostAction::Service {
                    operation,
                    expected_state: "inactive".into(),
                }),
                Some(false)
            );
        }
        assert_eq!(
            start_mode(&HostAction::Service {
                operation: host::ServiceAction::Stop,
                expected_state: "active".into(),
            }),
            None
        );
        for start in [true, false] {
            assert_eq!(
                start_mode(&HostAction::CommissionService {
                    start,
                    expected_state: "inactive".into(),
                    recovery_operation: Some("original".into()),
                }),
                start.then_some(true)
            );
        }
        assert_eq!(
            start_mode(&HostAction::HostSecurityRecovery {
                operation_id: "original".into(),
                original_plan_digest: "digest".into(),
                bootstrap: None,
                bootstrap_manifest_digest: None,
                candidate_accepted: false,
            }),
            None
        );
    }

    #[test]
    fn record_selection_uses_plan_digest_and_original_identity_for_recovery() {
        let id = "00000000000000000000000000000000";
        let other = "11111111111111111111111111111111";
        let digest = "0000000000000000000000000000000000000000000000000000000000000000";
        let other_digest = "1111111111111111111111111111111111111111111111111111111111111111";
        let record: crate::manager::model::MaintenanceRecord =
            serde_json::from_value(serde_json::json!({
                "schema_version": 1, "operation_id": id, "action": "service", "plan_digest": digest,
                "selected": null, "approved_scope": [], "previous_service_state": null,
                "pre_observations": [], "checkpoints": [], "post_observations": [],
                "outcome": "failed-known", "bundle_digest": null, "image_digest": null,
                "physical_selection": null
            }))
            .unwrap();
        assert!(matches_record(&record, None, Some(digest)));
        assert!(!matches_record(&record, None, Some(other_digest)));
        assert!(matches_record(&record, Some(id), Some(digest)));
        assert!(!matches_record(&record, Some(other), Some(digest)));
        assert!(!matches_record(&record, Some(id), Some(other_digest)));
    }
}
