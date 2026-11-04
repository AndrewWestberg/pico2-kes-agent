use super::{
    foreground, public_fields, review,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::{
    config::RunMode,
    files,
    manager::{
        config_builder::{
            self, CommissioningSpec, DEFAULT_MAX_CONTEXT_AGE_MS, NormalConfigSpec, bind_pool_bytes,
            candidate_usb_serial, configured_networks, default_pool_socket_path,
            latest_commissioned_device_path, parse_commissioned_device, publish_candidate,
            suggested_transition_epochs,
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
        "Build or install commissioning configuration",
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
        "Build or install normal configuration and identity pin",
    ),
    (
        Action::StartNormal,
        "Start normal service (existing preflight applies)",
    ),
];

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
    let selected = selected.or(retained.as_ref());
    let default = selected.and_then(|p| p.to_str()).unwrap_or("");
    let specs = [FieldSpec::text("Absolute bundle directory", default)];
    let Some(path) = form_validated(terminal, "Select authenticated bundle", &specs, |values| {
        let p = PathBuf::from(values[0].trim());
        if !p.is_absolute() {
            return Err((Some(0), "Bundle path must be absolute".into()));
        }
        Ok(p)
    })?
    else {
        return Ok(None);
    };
    let candidate = selected.is_some_and(|p| p == &path)
        && review(
            terminal,
            "Candidate admission is not qualification",
            vec![
                format!("Explicit or installed retained bundle: {}", path.display()),
                "Allow signed candidate status only for attended acceptance on a disposable host?"
                    .into(),
                "Cancel here uses ordinary qualified-only admission. Signature, compatibility, state and hardware checks remain mandatory."
                    .into(),
            ],
            Some("DISPOSABLE CANDIDATE"),
        )?;
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
    let stem = action.stem();
    let summary = action.summary();
    let plan = HostPlan::new(action)?;
    let path = workspace::next_path(WorkspaceKind::Plans, stem, "json")?;
    let mut lines = vec![
        format!("Action summary : {summary}"),
        format!("Plan file      : {}", path.display()),
        format!("Plan ID        : {}", plan.plan_id),
        "Press Enter to stage this plan and open the privileged helper (sudo).".into(),
        "The privileged helper will display the standalone 64-hex approval digest once for confirmation."
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
    if !review_mode(
        terminal,
        "Review finite host action",
        lines,
        ConfirmMode::Enter("stage plan & launch privileged host-apply"),
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
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&path);
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    review(
        terminal,
        "Host action result",
        vec![
            format!("Action: {summary}"),
            format!("Helper exit: {status}"),
            format!("Retained plan: {}", path.display()),
            "Inspect Overview (1) or Activity (6) for updated state and checkpoints. A running service alone does not prove pool delivery or forging."
                .into(),
            "If interrupted, reconcile the original record in Activity (6) — never repeat under a new identity."
                .into(),
        ],
        None,
    )?;
    Ok(())
}

fn default_socket_group() -> String {
    if let Ok(Some((_, bytes))) = setup::current_config_review()
        && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(group) = val.get("socket_group").and_then(serde_json::Value::as_str)
        && !group.is_empty()
    {
        return group.to_owned();
    }
    "pico2-kes-agent".into()
}

pub(super) fn guided_commissioning_candidate(
    terminal: &mut TerminalOwner,
) -> io::Result<Option<PathBuf>> {
    let defaults = CommissioningSpec {
        socket_group: default_socket_group(),
        ..CommissioningSpec::default()
    };
    let sock_dir = defaults.socket_directory.to_string_lossy().into_owned();
    let mgmt_sock = defaults.management_socket.to_string_lossy().into_owned();
    let state_dir = defaults.state_directory.to_string_lossy().into_owned();
    let mode_opts = [
        ("guided", "Build commissioning config from fields below"),
        ("file", "Supply an existing JSON config file path"),
    ];
    let specs = [
        FieldSpec::select("Configuration input mode", "guided", &mode_opts),
        FieldSpec::text_hint(
            "Observed 16-char USB serial (guided mode)",
            &defaults.usb_serial,
            "Auto-filled when 1 Pico 2 app is on USB; verify physical board",
        ),
        FieldSpec::text("Socket group (guided mode)", &defaults.socket_group),
        FieldSpec::text("Socket directory (guided mode)", &sock_dir),
        FieldSpec::text("Management socket (guided mode)", &mgmt_sock),
        FieldSpec::text("State directory (guided mode)", &state_dir),
        FieldSpec::text_hint(
            "Existing JSON file path (only if mode = file)",
            "",
            "Leave empty when using guided mode",
        ),
    ];
    form_validated(terminal, "Commissioning configuration", &specs, |values| {
        if values[0] == "file" {
            let p = PathBuf::from(values[6].trim());
            if !p.is_absolute() {
                return Err((Some(6), "Existing JSON file path must be absolute".into()));
            }
            return Ok(p);
        }
        let serial = values[1].trim();
        if serial.len() != 16 || !serial.is_ascii() {
            return Err((
                Some(1),
                "USB serial must be the exact 16-character ASCII firmware serial".into(),
            ));
        }
        let spec = CommissioningSpec {
            usb_serial: serial.to_owned(),
            socket_group: values[2].trim().to_owned(),
            socket_directory: PathBuf::from(values[3].trim()),
            management_socket: PathBuf::from(values[4].trim()),
            state_directory: PathBuf::from(values[5].trim()),
        };
        let bytes = config_builder::build_commissioning_bytes(&spec)
            .map_err(|e| (Some(1), e.to_string()))?;
        publish_candidate("commission-config", &bytes).map_err(|e| (None, e.to_string()))
    })
}

pub(super) fn guided_normal_candidate(terminal: &mut TerminalOwner) -> io::Result<Option<PathBuf>> {
    let latest_dev = latest_commissioned_device_path();
    let parsed_dev = latest_dev
        .as_deref()
        .and_then(|p| parse_commissioned_device(p).ok());
    let dev_path_default = latest_dev
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let id_default = parsed_dev
        .as_ref()
        .map(|d| d.device_id.clone())
        .unwrap_or_default();
    let pk_default = parsed_dev
        .as_ref()
        .map(|d| d.identity_public_key.clone())
        .unwrap_or_default();
    let serial_default = parsed_dev
        .as_ref()
        .map(|d| d.usb_serial.clone())
        .or_else(candidate_usb_serial)
        .unwrap_or_default();
    let group_default = default_socket_group();
    let age_default = DEFAULT_MAX_CONTEXT_AGE_MS.to_string();

    let mode_opts = [
        (
            "guided",
            "Build normal pinned config (computes Shelley SHA-256)",
        ),
        ("file", "Supply an existing JSON config file path"),
    ];
    let net_opts = [
        ("mainnet", "Cardano mainnet (208 Byron epochs)"),
        ("preprod", "Cardano preprod (4 Byron epochs)"),
        ("preview", "Cardano preview (0 Byron epochs)"),
        ("custom", "Custom network name in field below"),
    ];
    let specs = [
        FieldSpec::select("Configuration input mode", "guided", &mode_opts),
        FieldSpec::text_hint(
            "Commissioned device.json path (optional if IDs entered below)",
            &dev_path_default,
            "If set, device_id / public_key / usb_serial are loaded from this file",
        ),
        FieldSpec::text("Device ID (32 lowercase hex)", &id_default),
        FieldSpec::text("Identity public key (64 lowercase hex)", &pk_default),
        FieldSpec::text("USB serial (16 chars)", &serial_default),
        FieldSpec::select("Network preset", "mainnet", &net_opts),
        FieldSpec::text_hint(
            "Custom network name (only if preset = custom)",
            "",
            "Leave empty for mainnet / preprod / preview",
        ),
        FieldSpec::text("Absolute Byron genesis file path", ""),
        FieldSpec::text_hint(
            "Absolute Shelley genesis file path",
            "",
            "SHA-256 genesis_digest is computed automatically from this file",
        ),
        FieldSpec::text_hint(
            "Byron-to-Shelley transition epochs ('auto' uses preset)",
            "auto",
            "mainnet=208, preprod=4, preview=0",
        ),
        FieldSpec::text("Max context age in ms (1000..=30000)", &age_default),
        FieldSpec::text("Socket group", &group_default),
        FieldSpec::text_hint(
            "Existing JSON file path (only if mode = file)",
            "",
            "Leave empty when using guided mode",
        ),
    ];

    let existing = setup::current_config_review()?.map(|(_, bytes)| bytes);
    form_validated(terminal, "Normal pinned configuration", &specs, |values| {
        if values[0] == "file" {
            let p = PathBuf::from(values[12].trim());
            if !p.is_absolute() {
                return Err((Some(12), "Existing JSON file path must be absolute".into()));
            }
            return Ok(p);
        }
        let (device_id, identity_public_key, usb_serial) = if !values[1].trim().is_empty() {
            let dev = parse_commissioned_device(Path::new(values[1].trim()))
                .map_err(|e| (Some(1), e.to_string()))?;
            (dev.device_id, dev.identity_public_key, dev.usb_serial)
        } else {
            (
                values[2].trim().to_owned(),
                values[3].trim().to_owned(),
                values[4].trim().to_owned(),
            )
        };
        if device_id.len() != 32 || !device_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err((Some(2), "Device ID must be 32 hex characters".into()));
        }
        if identity_public_key.len() != 64
            || !identity_public_key.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err((
                Some(3),
                "Identity public key must be 64 hex characters".into(),
            ));
        }
        if usb_serial.len() != 16 || !usb_serial.is_ascii() {
            return Err((Some(4), "USB serial must be 16 ASCII characters".into()));
        }
        let network_name = if values[5] == "custom" {
            let name = values[6].trim();
            if name.is_empty() {
                return Err((Some(6), "Enter a custom network name".into()));
            }
            name.to_owned()
        } else {
            values[5].clone()
        };
        let byron = PathBuf::from(values[7].trim());
        if !byron.is_absolute() {
            return Err((Some(7), "Byron genesis path must be absolute".into()));
        }
        let shelley = PathBuf::from(values[8].trim());
        if !shelley.is_absolute() {
            return Err((Some(8), "Shelley genesis path must be absolute".into()));
        }
        let epochs = if values[9].trim().eq_ignore_ascii_case("auto") {
            suggested_transition_epochs(&network_name)
        } else {
            values[9].trim().parse::<u64>().map_err(|_| {
                (
                    Some(9),
                    "Transition epochs must be an integer or 'auto'".into(),
                )
            })?
        };
        let max_age_ms = values[10]
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|ms| (1_000..=30_000).contains(ms))
            .ok_or_else(|| {
                (
                    Some(10),
                    "Max context age must be between 1000 and 30000 ms".into(),
                )
            })?;
        let spec = NormalConfigSpec {
            device_id,
            identity_public_key,
            usb_serial,
            socket_directory: PathBuf::from("/run/pico2-kes-agent"),
            socket_group: values[11].trim().to_owned(),
            management_socket: PathBuf::from("/run/pico2-kes-agent/management.sock"),
            state_directory: PathBuf::from("/var/lib/pico2-kes-agent"),
            network_name,
            byron_genesis_file: byron,
            shelley_genesis_file: shelley,
            byron_to_shelley_epochs: epochs,
            max_context_age_ms: max_age_ms,
        };
        let bytes = config_builder::build_normal_bytes(&spec, existing.as_deref())
            .map_err(|e| (Some(8), e.to_string()))?;
        let candidate =
            publish_candidate("normal-config", &bytes).map_err(|e| (None, e.to_string()))?;
        setup::review_config(&candidate, RunMode::Normal)
            .map_err(|e| (None, format!("Configuration validation failed: {e}")))?;
        Ok(candidate)
    })
}

pub(super) fn bind_pool_workflow(
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
        Action::CommissionConfig => {
            let Some(candidate) = guided_commissioning_candidate(terminal)? else {
                return Ok(());
            };
            configuration(terminal, worker, socket, true, candidate)
        }
        Action::NormalConfig => {
            let Some(candidate) = guided_normal_candidate(terminal)? else {
                return Ok(());
            };
            configuration(terminal, worker, socket, false, candidate)
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
            let mode_opts = [
                ("preview", "Read-only BOOTSEL inspection (no flash writes)"),
                ("apply", "Flash factory firmware image to blank Pico 2"),
            ];
            let specs = [
                FieldSpec::select("Transfer mode", "preview", &mode_opts),
                FieldSpec::text(
                    "Firmware record path (new 32-hex filename, or existing to reopen read-only)",
                    &suggested,
                ),
            ];
            let Some((apply_transfer, record)) = form_validated(
                terminal,
                "Attended first firmware install",
                &specs,
                |values| {
                    let record = PathBuf::from(values[1].trim());
                    if !record.is_absolute() {
                        return Err((Some(1), "Record path must be absolute".into()));
                    }
                    Ok((values[0] == "apply", record))
                },
            )?
            else {
                return Ok(());
            };
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
        Action::StartCommission | Action::StopCommission => apply(
            terminal,
            worker,
            socket,
            HostAction::CommissionService {
                start: action == Action::StartCommission,
                expected_state: host::observed_service_state(true)?,
                recovery_operation: None,
            },
            None,
        ),
        Action::ReconcileFirstInstall => {
            reconcile_first_install_record(terminal, worker, socket, "")
        }
        Action::Commission => {
            let Some((source, verified, candidate)) = bundle(terminal, selected)? else {
                return Ok(());
            };
            let serial_default = candidate_usb_serial().unwrap_or_default();
            let out_default = workspace::next_path(
                WorkspaceKind::Exports,
                if serial_default.is_empty() {
                    "commissioned-device"
                } else {
                    &serial_default
                },
                "device.json",
            )?
            .to_string_lossy()
            .into_owned();
            let receipt_default =
                workspace::next_path(WorkspaceKind::Receipts, "commission", "receipt.json")?
                    .to_string_lossy()
                    .into_owned();
            let reference_path =
                workspace::next_path(WorkspaceKind::References, "commission", "ref.json")?;
            let admission_plan_path =
                workspace::next_path(WorkspaceKind::Plans, "commission-admission", "json")?;

            let specs = [
                FieldSpec::text_hint(
                    "Observed 16-char application USB serial",
                    &serial_default,
                    "Verify physical board identity before commissioning",
                ),
                FieldSpec::text(
                    "Public device identity output file (transferable to backup/config)",
                    &out_default,
                ),
                FieldSpec::text("Original CLI receipt path", &receipt_default),
            ];
            let Some((serial, out_path, receipt_path)) = form_validated(
                terminal,
                "Commission intended blank Pico 2",
                &specs,
                |values| {
                    let ser = values[0].trim();
                    if ser.len() != 16 || !ser.is_ascii() {
                        return Err((Some(0), "USB serial must be 16 ASCII characters".into()));
                    }
                    let out = values[1].trim();
                    if !Path::new(out).is_absolute() {
                        return Err((Some(1), "Output path must be absolute".into()));
                    }
                    let rec = values[2].trim();
                    if !Path::new(rec).is_absolute() {
                        return Err((Some(2), "Receipt path must be absolute".into()));
                    }
                    Ok((ser.to_owned(), out.to_owned(), rec.to_owned()))
                },
            )?
            else {
                return Ok(());
            };

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
            let lines = vec![
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
            ];
            if !review(
                terminal,
                "Confirm blank-device commissioning",
                lines,
                Some(&format!("COMMISSION {serial}")),
            )? {
                return Ok(());
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
                        "Next: Stop commissioning service (step 5), then build & install normal configuration (step 6) — it will auto-detect your new device.json!"
                            .into()
                    } else {
                        "Do not submit again under a new receipt. Reconcile this original operation in Activity (6)."
                            .into()
                    },
                ],
                None,
            )?;
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
            let latest_plan = workspace::list_files(WorkspaceKind::Plans)?
                .into_iter()
                .next()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let Some(values) = public_fields(
                terminal,
                "Inspect retained host plan (read-only)",
                &[("Absolute original host plan file", &latest_plan)],
            )?
            else {
                return Ok(());
            };
            let path = PathBuf::from(values[0].trim());
            if !path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "plan path must be absolute",
                ));
            }
            inspect_plan_file(terminal, worker, socket, &path)
        }
    }
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
        None,
    )?;
    Ok(())
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
    let mut lines = vec![
        format!("Candidate source : {}", checked.source.display()),
        format!("Candidate SHA-256: {}", checked.sha256),
        format!(
            "Current SHA-256  : {}",
            previous.as_deref().unwrap_or("(absent)")
        ),
        format!("Validation       : {}", checked.validation),
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
    if !review_mode(
        terminal,
        "Review configuration diff",
        lines,
        ConfirmMode::Enter("approve diff & stage host plan"),
    )? {
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
            recovery_operation: None,
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
    let serial_hint = candidate_usb_serial().unwrap_or_default();
    let specs = [
        FieldSpec::text(
            "Original host transfer operation ID (32 lowercase hex)",
            initial_op_id,
        ),
        FieldSpec::text(
            "Observed application USB serial on the same physical board",
            &serial_hint,
        ),
    ];
    let Some((op_id, serial)) = form_validated(
        terminal,
        "Reconcile original first transfer (never reflash)",
        &specs,
        |values| {
            let op = values[0].trim();
            let ser = values[1].trim();
            if op.len() != 32 || !op.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err((Some(0), "Operation ID must be 32 hex characters".into()));
            }
            if ser.len() != 16 || !ser.is_ascii() {
                return Err((Some(1), "USB serial must be 16 ASCII characters".into()));
            }
            Ok((op.to_owned(), ser.to_owned()))
        },
    )?
    else {
        return Ok(());
    };
    let expected_service_state = host::observed_service_state(true)?;
    if !review(
        terminal,
        "Attended physical association",
        vec![
            format!("Original operation: {op_id}; intended application serial: {serial}"),
            format!("Reviewed restricted service: {expected_service_state}"),
            "Physically confirm this is the same board as the original BOOTSEL transfer. Software cannot infer that association from a CHIPID or serial."
                .into(),
        ],
        Some(&format!("ASSOCIATE {serial}")),
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
