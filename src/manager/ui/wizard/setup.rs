use super::super::{
    activity, lifecycle, setup,
    widgets::{self, ConfirmMode, FieldSpec, form_validated, review_mode},
};
use super::state::{self, Observed, SetupStep};
use crate::manager::{
    config_builder::{self, DEFAULT_MAX_CONTEXT_AGE_MS, NormalConfigSpec},
    discovery::{
        files::{self, FileKind},
        node::{self, KnownNetwork, NodeCandidate},
        usb,
    },
    host::{self, HostAction},
    maintenance::WipeEvidence,
    model::{DeviceMode, InstallationRole},
    observe::Worker,
    setup as backend,
    terminal::TerminalOwner,
};
use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn state_active(state: &str) -> bool {
    state.starts_with("state=active;")
}

fn inspect(
    terminal: &mut TerminalOwner,
    serial: &str,
    normal_socket: Option<&Path>,
) -> io::Result<WipeEvidence> {
    let (digest, config) = backend::current_config_review()?
        .ok_or_else(|| io::Error::other("Configuration unavailable"))?;
    let parsed: serde_json::Value = serde_json::from_slice(&config).map_err(io::Error::other)?;
    let state_directory = PathBuf::from(
        parsed["state_directory"]
            .as_str()
            .ok_or_else(|| io::Error::other("State directory unavailable"))?,
    );
    let authority = normal_socket
        .map(|socket| lifecycle::admission(terminal, socket, None))
        .transpose()?;
    let socket = match &authority {
        Some(a) => a.socket.clone(),
        None => backend::commissioning_socket(serial)?,
    };
    let peer = match &authority {
        Some(a) => (a.pid, a.uid),
        None => host::restricted_daemon_identity()?,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let device_info = backend::observation(&socket, "device.info", deadline, peer)?;
    let security = backend::observation(&socket, "device.security", deadline, peer)?;
    let status = backend::observation(&socket, "device.status", deadline, peer)?;
    let inventory = if device_info["device_id"].is_string() {
        backend::observation(&socket, "device.inventory", deadline, peer)?
    } else {
        serde_json::Value::Null
    };
    let again = backend::observation(&socket, "device.info", deadline, peer)?;
    let same_peer = match (&authority, normal_socket) {
        (Some(before), Some(socket)) => lifecycle::admission(terminal, socket, None)? == *before,
        _ => host::restricted_daemon_identity()? == peer,
    };
    if device_info != again || device_info["usb_serial"] != serial || !same_peer
        || backend::current_config_review()?.map(|(d, _)| d) != Some(digest.clone())
        || authority.as_ref().is_some_and(|a| !matches!(&a.identity, crate::manager::lifecycle::AuthorityIdentity::Normal { device_id, .. } if device_info["device_id"] == *device_id)) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Device or daemon changed during observation"));
    }
    if device_info["schema_version"] != 1
        || device_info.get("device_id").is_none()
        || (device_info["device_id"].is_null() && status["commissioning_state"] != "blank")
        || (device_info["device_id"].is_string() && status["commissioning_state"] != "committed")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Device commissioning state is unavailable or inconsistent",
        ));
    }
    Ok(WipeEvidence {
        device_info,
        security,
        status,
        inventory,
        config_sha256: digest,
        state_directory,
    })
}

fn choose(
    terminal: &mut TerminalOwner,
    title: &str,
    labels: &[String],
) -> io::Result<Option<usize>> {
    let ids: Vec<String> = (0..labels.len()).map(|n| n.to_string()).collect();
    let options: Vec<(&str, &str)> = ids
        .iter()
        .zip(labels)
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let specs = [FieldSpec::select(title, &ids[0], &options)];
    form_validated(terminal, title, &specs, |v| {
        v[0].parse()
            .map_err(|_| (Some(0), "Invalid selection".into()))
    })
}

fn normal_candidate(
    terminal: &mut TerminalOwner,
    device: &Path,
) -> io::Result<Option<(PathBuf, Vec<backend::GenesisImport>)>> {
    let nodes = node::discover_nodes();
    let node = if nodes.is_empty() {
        let Some(byron) =
            widgets::pick_file(terminal, "Select Byron genesis JSON", &[FileKind::Any])?
        else {
            return Ok(None);
        };
        let Some(shelley) =
            widgets::pick_file(terminal, "Select Shelley genesis JSON", &[FileKind::Any])?
        else {
            return Ok(None);
        };
        let bytes = crate::manager::discovery::read_file(&shelley, 16 * 1024 * 1024)?;
        let genesis: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let (network, byron_epochs) = match genesis["networkMagic"].as_u64() {
            Some(764824073) => (KnownNetwork::Mainnet, Some(208)),
            Some(1) => (KnownNetwork::Preprod, Some(4)),
            Some(2) => (KnownNetwork::Preview, Some(0)),
            Some(_) => (KnownNetwork::Custom("custom".into()), None),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shelley genesis has no networkMagic",
                ));
            }
        };
        NodeCandidate {
            unit: "custom-node.service".into(),
            config: None,
            byron,
            shelley,
            network,
            byron_epochs,
            shelley_hash_matches: None,
        }
    } else if nodes.len() == 1 {
        nodes[0].clone()
    } else {
        let labels: Vec<String> = nodes
            .iter()
            .map(|n| format!("{} · {:?}", n.unit, n.network))
            .collect();
        let Some(index) = choose(terminal, "Select node", &labels)? else {
            return Ok(None);
        };
        nodes[index].clone()
    };
    if node.shelley_hash_matches == Some(false) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Node config Shelley genesis hash does not match",
        ));
    }
    let network = match &node.network {
        KnownNetwork::Mainnet => "mainnet".to_owned(),
        KnownNetwork::Preprod => "preprod".to_owned(),
        KnownNetwork::Preview => "preview".to_owned(),
        KnownNetwork::Custom(name) => name.clone(),
    };
    let epochs = match node.byron_epochs {
        Some(n) => n,
        None => {
            let specs = [FieldSpec::text("Byron to Shelley transition epochs", "")];
            let Some(n) = form_validated(terminal, "Custom network", &specs, |v| {
                v[0].trim()
                    .parse::<u64>()
                    .map_err(|_| (Some(0), "Enter a non-negative integer".into()))
            })?
            else {
                return Ok(None);
            };
            n
        }
    };
    let dev = config_builder::parse_commissioned_device(device)?;
    let spec = NormalConfigSpec {
        device_id: dev.device_id,
        identity_public_key: dev.identity_public_key,
        usb_serial: dev.usb_serial,
        socket_directory: "/run/pico2-kes-agent".into(),
        socket_group: setup::default_socket_group(),
        management_socket: "/run/pico2-kes-agent/management.sock".into(),
        state_directory: "/var/lib/pico2-kes-agent".into(),
        network_name: network.clone(),
        byron_genesis_file: node.byron.clone(),
        shelley_genesis_file: node.shelley.clone(),
        byron_to_shelley_epochs: epochs,
        max_context_age_ms: DEFAULT_MAX_CONTEXT_AGE_MS,
    };
    Ok(Some(setup::normal_config_core(&spec)?))
}

pub(crate) fn run(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    selected: Option<&PathBuf>,
) -> io::Result<()> {
    let mut selected_serial: Option<String> = None;
    let mut trusted: Option<PathBuf> = None;
    let mut evidence: Option<WipeEvidence> = None;
    let mut observed_serial: Option<String> = None;
    let mut configured_kept = false;
    let mut configured_wipe = false;
    loop {
        let boards = usb::list_pico2()?;
        let (apps, bootsel) = state::count_modes(boards.iter().map(|b| b.mode));
        let serial = selected_serial
            .as_ref()
            .filter(|s| {
                boards
                    .iter()
                    .any(|b| b.mode == DeviceMode::Application && b.serial.as_ref() == Some(*s))
            })
            .cloned()
            .or_else(|| {
                if apps == 1 {
                    boards
                        .iter()
                        .find(|b| b.mode == DeviceMode::Application)
                        .and_then(|b| b.serial.clone())
                } else {
                    None
                }
            });
        if serial != observed_serial {
            evidence = None;
            trusted = None;
            configured_kept = false;
            configured_wipe = false;
            observed_serial = serial.clone();
        }
        let config = backend::current_config_review()?.map(|(_, b)| b);
        let parsed = config
            .as_deref()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
        let normal_config = parsed
            .as_ref()
            .is_some_and(|v| v.pointer("/device/id").and_then(|v| v.as_str()).is_some());
        let config_matches = serial.as_ref().is_some_and(|s| {
            parsed
                .as_ref()
                .and_then(|v| v.pointer("/device/usb_serial"))
                .and_then(|v| v.as_str())
                == Some(s)
        });
        let commission_state = host::observed_service_state(true)?;
        let normal_state = host::observed_service_state(false)?;
        let activity = activity::discover(InstallationRole::Primary);
        let pending: Vec<_> = activity
            .items
            .iter()
            .filter(|item| item.needs_reconcile())
            .collect();
        if pending.len() == 1
            && let activity::ActivityItem::HostRecord { record, .. } = pending[0]
            && activity::first_install_needs_postcheck(record)
            && apps == 1
            && bootsel == 0
            && !normal_config
        {
            let serial = serial
                .as_deref()
                .ok_or_else(|| io::Error::other("Application serial unavailable"))?;
            let id = record.operation_id.to_string();
            if !config_matches {
                let candidate = setup::commissioning_config_core(serial)?;
                setup::configuration_recovery(terminal, worker, socket, candidate, &id)?;
                if backend::current_config_review()?.map(|(_, b)| b) == config {
                    return Ok(());
                }
                continue;
            }
            if !state_active(&commission_state) {
                setup::apply(
                    terminal,
                    worker,
                    socket,
                    HostAction::CommissionService {
                        start: true,
                        expected_state: commission_state.clone(),
                        recovery_operation: Some(id),
                    },
                    None,
                )?;
                if host::observed_service_state(true)? == commission_state {
                    return Ok(());
                }
                continue;
            }
            setup::reconcile_first_install_record(terminal, worker, socket, &id)?;
            if activity::discover(InstallationRole::Primary).unresolved_count > 0 {
                return Ok(());
            }
            continue;
        }
        let o = Observed {
            unresolved: !pending.is_empty(),
            apps,
            bootsel,
            selected: serial.is_some(),
            config_serial_matches: config_matches,
            commission_running: state_active(&commission_state),
            identity: evidence
                .as_ref()
                .map(|e| !e.device_info["device_id"].is_null()),
            trusted_device: trusted.is_some() || (normal_config && config_matches),
            normal_config,
            agent_running: state_active(&normal_state),
            configured_kept,
            configured_wipe,
        };
        match state::next_setup_step(&o) {
            SetupStep::Activity => {
                review_mode(
                    terminal,
                    "Interrupted operation",
                    vec!["Open Activity and reconcile the original record before setup.".into()],
                    ConfirmMode::Enter("return"),
                )?;
                return Ok(());
            }
            SetupStep::Detect | SetupStep::UnplugOthers => {
                review_mode(terminal, "Connect Pico 2", vec!["Connect one Pico 2 application board, or one BOOTSEL board; unplug other BOOTSEL boards.".into()], ConfirmMode::Enter("return"))?;
                return Ok(());
            }
            SetupStep::PickBoard => {
                let candidates: Vec<_> = boards
                    .iter()
                    .filter(|b| b.mode == DeviceMode::Application && b.serial.is_some())
                    .collect();
                if candidates.is_empty() {
                    return Err(io::Error::other(
                        "No application board has a readable serial",
                    ));
                }
                let labels: Vec<_> = candidates
                    .iter()
                    .map(|b| {
                        format!(
                            "{} · {} · application",
                            b.serial.as_deref().unwrap_or("unknown"),
                            b.port
                        )
                    })
                    .collect();
                let Some(index) = choose(terminal, "Select Pico 2", &labels)? else {
                    return Ok(());
                };
                selected_serial = candidates[index].serial.clone();
            }
            SetupStep::FlashFactory => {
                let mut lines = widgets::progress_steps(
                    &[
                        "Detect board",
                        "Prepare firmware",
                        "Commission",
                        "Configure",
                        "Start agent",
                    ],
                    1,
                );
                lines.push(
                    "Flash the single connected BOOTSEL board with the selected factory firmware?"
                        .into(),
                );
                if !review_mode(
                    terminal,
                    "Install factory firmware",
                    lines,
                    ConfirmMode::YesNo { danger: false },
                )? {
                    return Ok(());
                }
                let Some((bundle, verified, accepted)) = setup::bundle(terminal, selected)? else {
                    return Ok(());
                };
                let id = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_nanos();
                setup::apply(
                    terminal,
                    worker,
                    socket,
                    HostAction::FirmwareFirstInstall {
                        bundle,
                        manifest_digest: verified.selection().manifest_digest.to_string(),
                        candidate_accepted: accepted,
                        record: PathBuf::from(format!("/var/lib/p2kesup/firmware/{id:032x}.json")),
                        apply: true,
                    },
                    None,
                )?;
                if usb::list_pico2()?
                    .iter()
                    .all(|b| b.mode != DeviceMode::Application)
                {
                    return Ok(());
                }
            }
            SetupStep::CommissionConfig => {
                if normal_config {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Selected board does not match the existing configuration; preserve its pin and select the configured board",
                    ));
                }
                let serial = serial
                    .as_deref()
                    .ok_or_else(|| io::Error::other("Application serial unavailable"))?;
                let candidate = setup::commissioning_config_core(serial)?;
                setup::configuration(terminal, worker, socket, true, candidate)?;
                if backend::current_config_review()?.map(|(_, b)| b) == config {
                    return Ok(());
                }
            }
            SetupStep::StartCommission | SetupStep::StopCommission => {
                let start = state::next_setup_step(&o) == SetupStep::StartCommission;
                setup::apply(
                    terminal,
                    worker,
                    socket,
                    HostAction::CommissionService {
                        start,
                        expected_state: commission_state.clone(),
                        recovery_operation: None,
                    },
                    None,
                )?;
                if host::observed_service_state(true)? == commission_state {
                    return Ok(());
                }
            }
            SetupStep::ConfiguredChoice => {
                let choices = vec![
                    "Keep it: preserve the current configuration and identity pin".into(),
                    "Wipe it and start over: review board and erase all pools and KES keys".into(),
                ];
                let Some(choice) = choose(terminal, "This Pico 2 is already set up", &choices)?
                else {
                    return Ok(());
                };
                if choice == 0 {
                    configured_kept = true;
                } else {
                    if !state_active(&normal_state) {
                        if !review_mode(terminal, "Inspect configured board", vec!["Start the normal agent to verify the existing identity pin and inspect the board before wipe?".into()], ConfirmMode::YesNo { danger: false })? { return Ok(()); }
                        setup::apply(
                            terminal,
                            worker,
                            socket,
                            HostAction::Service {
                                operation: host::ServiceAction::Start,
                                expected_state: normal_state.clone(),
                            },
                            None,
                        )?;
                        if !state_active(&host::observed_service_state(false)?) {
                            return Ok(());
                        }
                    }
                    configured_wipe = true;
                }
            }
            SetupStep::InspectApp => {
                evidence = Some(inspect(
                    terminal,
                    serial
                        .as_deref()
                        .ok_or_else(|| io::Error::other("Application serial unavailable"))?,
                    if normal_config { Some(socket) } else { None },
                )?);
            }
            SetupStep::Commission => {
                trusted = setup::commission_core(
                    terminal,
                    worker,
                    socket,
                    selected,
                    serial.as_deref().unwrap(),
                )?;
                if trusted.is_none() {
                    return Ok(());
                }
            }
            SetupStep::AlreadyCommissioned => {
                let serial = serial.as_deref().unwrap();
                let observed = evidence.as_ref().unwrap();
                let unlocked = state::wipe_available(&observed.security);
                let found = files::device_for_serial(serial);
                let mut choices = vec![if normal_config {
                    "Keep it: preserve the current configuration and identity pin".into()
                } else {
                    format!(
                        "Keep it: connect using device.json ({})",
                        found
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "not found".into())
                    )
                }];
                if unlocked {
                    choices.push("Wipe it and start over: erase all pools and KES keys".into());
                } else {
                    choices[0].push_str(" · OTP locked: wipe unavailable");
                }
                let Some(choice) = choose(terminal, "This Pico 2 is already set up", &choices)?
                else {
                    return Ok(());
                };
                if choice == 0 {
                    if normal_config {
                        configured_kept = true;
                        continue;
                    }
                    let path = match found {
                        Some(p) => Some(p),
                        None => widgets::pick_file(
                            terminal,
                            "Select trusted device.json (needed to verify the board identity)",
                            &[FileKind::DeviceJson],
                        )?,
                    };
                    let Some(path) = path else {
                        return Ok(());
                    };
                    let device = config_builder::parse_commissioned_device(&path)?;
                    if device.usb_serial != serial
                        || observed.device_info["device_id"] != device.device_id
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "device.json does not match the observed board",
                        ));
                    }
                    trusted = Some(path);
                } else {
                    let mut lines = widgets::progress_steps(
                        &[
                            "Detect board",
                            "Choose keep or wipe",
                            "Commission",
                            "Configure",
                            "Start agent",
                        ],
                        1,
                    );
                    lines.extend(["DESTRUCTIVE: all pools and KES keys on this Pico 2 will be lost.".into(), "Stop your block producers first. New operational certificates will be needed.".into(), format!("Board: {serial}"), "Host configuration and state will be archived, not deleted.".into()]);
                    if let Some(pools) = observed.inventory["pools"].as_array() {
                        lines.extend(pools.iter().map(|pool| {
                            format!(
                                "Pool: {}",
                                pool["pool_id"].as_str().unwrap_or("(unavailable)")
                            )
                        }));
                    }
                    if !review_mode(
                        terminal,
                        "Wipe board and start over",
                        lines,
                        ConfirmMode::YesNo { danger: true },
                    )? {
                        return Ok(());
                    }
                    setup::apply(
                        terminal,
                        worker,
                        socket,
                        HostAction::WipeBoard {
                            serial: serial.into(),
                            expected_state: observed.clone(),
                        },
                        None,
                    )?;
                    trusted = None;
                    configured_kept = false;
                    configured_wipe = false;
                    if !state_active(&host::observed_service_state(true)?) {
                        return Ok(());
                    }
                    let blank = inspect(terminal, serial, None)?;
                    if !blank.device_info["device_id"].is_null()
                        || blank.security["storage_blank_at_boot"] != true
                        || blank.status["commissioning_state"] != "blank"
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Wipe did not produce an observed blank board",
                        ));
                    }
                    evidence = Some(blank);
                }
            }
            SetupStep::NormalConfig => {
                let path = trusted
                    .as_deref()
                    .ok_or_else(|| io::Error::other("Trusted device.json required"))?;
                let Some((candidate, imports)) = normal_candidate(terminal, path)? else {
                    return Ok(());
                };
                setup::configuration_with_imports(
                    terminal, worker, socket, false, candidate, imports,
                )?;
                if backend::current_config_review()?.map(|(_, b)| b) == config {
                    return Ok(());
                }
                configured_kept = true;
            }
            SetupStep::StartAgent => {
                setup::apply(
                    terminal,
                    worker,
                    socket,
                    HostAction::Service {
                        operation: host::ServiceAction::Start,
                        expected_state: normal_state.clone(),
                    },
                    None,
                )?;
                if host::observed_service_state(false)? == normal_state {
                    return Ok(());
                }
            }
            SetupStep::Done => {
                if review_mode(
                    terminal,
                    "Pico 2 setup complete",
                    vec!["Your Pico 2 is connected. Add a pool now?".into()],
                    ConfirmMode::YesNo { danger: false },
                )? {
                    return super::pool::run(terminal, worker, socket);
                }
                return Ok(());
            }
        }
    }
}
