//! Inventory and explicitly reviewed workflows; observations are not an atomic health check.

use std::os::unix::process::CommandExt;
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::Duration,
};
mod backup;
mod lifecycle;
mod navigation;
mod producer;
mod provisioning;
mod releases;
mod service;
mod setup;
mod status;
mod uninstall;
mod widgets;

use navigation::{Action, View};
#[cfg(test)]
use widgets::review_paragraph;
use widgets::{public_fields, review, tone};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use serde_json::Value;

use super::{
    model::{InstallationRole, Observation, ObservationState},
    observe::{Snapshot, Worker},
    terminal::TerminalOwner,
};
use crate::cli;

/// Run the finite bootstrap installation without entering the interactive menu.
pub fn install(bundle: PathBuf, role: InstallationRole) -> io::Result<()> {
    use super::{
        host::{self, HostAction, HostPlan},
        release::{self, Admission},
    };
    use std::io::{IsTerminal, Write};

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other(
            "installation requires an attended terminal",
        ));
    }
    let (verified, candidate_accepted) = match release::verify_bundle(&bundle, Admission::Qualified)
    {
        Ok(verified) => (verified, false),
        Err(qualified_error) => {
            let verified = release::verify_bundle(&bundle, Admission::AttendedCandidate)
                .map_err(|_| qualified_error)?;
            println!(
                "This signed bundle is a candidate, not a qualified release. Install only on a disposable host."
            );
            print!("Type DISPOSABLE CANDIDATE to accept: ");
            io::stdout().flush()?;
            if host::read_confirmation(io::stdin().lock())?.trim() != "DISPOSABLE CANDIDATE" {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "candidate not accepted",
                ));
            }
            (verified, true)
        }
    };
    let executable = host::trusted_bootstrap_manager(&verified)?;
    let plan = HostPlan::new(HostAction::Install {
        bundle,
        role,
        manifest_digest: verified.selection().manifest_digest.to_string(),
        candidate_accepted,
    })?;
    let cache = super::release_discovery::default_cache()?;
    let path = cache.join(format!("install-plan-{}.json", plan.plan_id));
    crate::files::publish_no_clobber(
        &path,
        &serde_json::to_vec(&plan).map_err(io::Error::other)?,
        0o600,
    )?;
    println!(
        "Installation plan retained at {}. The privileged helper will display the scope and request its digest.",
        path.display()
    );
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    let status = command
        .arg("host-apply")
        .arg("--plan")
        .arg(&path)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "installation failed or was interrupted ({status}); retain the original plan {}",
            path.display()
        )));
    }
    println!(
        "Installation completed; retained plan: {}",
        safe(&path.to_string_lossy())
    );
    println!(
        "Reopen with: {}",
        if role == InstallationRole::Backup {
            "p2kesup --role backup"
        } else {
            "p2kesup"
        }
    );
    Ok(())
}

pub fn upgrade(version: Option<&str>, bundle: Option<PathBuf>) -> io::Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upgrade requires an attended terminal",
        ));
    }
    let store = super::records::RecordStore::open_host(super::setup::service_identity()?.1)?;
    if store.list()?.iter().any(|record| match record {
        super::records::Record::Supported(record) => {
            !super::host::maintenance_outcome_allows_new_action(&record.outcome)
        }
        super::records::Record::Unknown(_) => true,
    }) {
        return Err(io::Error::other(
            "unresolved maintenance blocks upgrade, including no-op claims; recover the original operation (p2kesup upgrade --resume ORIGINAL_PLAN for an upgrade)",
        ));
    }
    let (digest, registry, service, _) = super::host::update_review()?;
    super::host::verify_installed_ownership()?;
    let explicit = version.is_some() || bundle.is_some();
    let path = match bundle {
        Some(path) => path,
        None => super::release_discovery::fetch_release(version)?,
    };
    let verified = super::release::verify_bundle(
        &path,
        if explicit {
            super::release::Admission::AttendedCandidate
        } else {
            super::release::Admission::Qualified
        },
    )?;
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    if super::host::same_selection(current, verified.selection()) {
        println!(
            "Managed {:?} host selection is already {}. No changes made; device firmware was not checked.",
            registry.role, current.tag
        );
        return Ok(());
    }
    let mut terminal = TerminalOwner::acquire()?;
    let result = releases::upgrade_direct(&mut terminal, path, verified, digest, registry, service);
    let closed = terminal.close();
    result?;
    closed?;
    println!("Upgrade completed and validated. Re-run p2kesup to use the installed manager.");
    Ok(())
}

pub fn resume_upgrade(path: PathBuf) -> io::Result<()> {
    use super::{
        host::{self, HostAction, HostPlan},
        records::{Record, RecordStore},
    };
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "original plan must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original plan exceeds 1 MiB",
        ));
    }
    let plan: HostPlan = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    plan.validate()?;
    if !matches!(&plan.action, HostAction::Upgrade { .. }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "original plan is not an upgrade",
        ));
    }
    let store = RecordStore::open_host(super::setup::service_identity()?.1)?;
    let mut matches = store.list()?.into_iter().filter_map(|record| match record {
        Record::Supported(record)
            if record.plan_digest.to_string() == plan.approved_digest
                && record.action == "upgrade" =>
        {
            Some(record)
        }
        _ => None,
    });
    let record = matches.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "original upgrade record not found")
    })?;
    if matches.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple original records match the plan",
        ));
    }
    let operation = record.operation_id.to_string();
    let mut action = host::review_upgrade_recovery(&operation, &plan.approved_digest)?;
    let HostAction::UpgradeRecovery {
        temporary_validation,
        ..
    } = &mut action
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery review",
        ));
    };
    *temporary_validation = true;
    let executable = host::trusted_upgrade_recovery_manager(&operation, &plan.approved_digest)?;
    let mut terminal = TerminalOwner::acquire()?;
    let result = releases::resume_upgrade_direct(&mut terminal, action, executable, &operation);
    let closed = terminal.close();
    result?;
    closed?;
    println!(
        "Original upgrade recovery completed; consult its retained record for the observed outcome."
    );
    Ok(())
}

enum Exit {
    Quit,
    Reexec(PathBuf),
}

fn safe(text: &str) -> String {
    use std::fmt::Write;
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(escaped, "{}", c.escape_unicode()).expect("writing to String");
        } else {
            escaped.push(c);
        }
    }
    escaped
}

fn foreground(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    command: &mut Command,
    acknowledge: bool,
) -> io::Result<ExitStatus> {
    let observing = worker.is_some();
    if let Some(active) = worker.take() {
        active.shutdown();
    }
    let result = terminal.foreground(command, acknowledge);
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    result
}

fn observation<T>(label: &str, value: &Observation<T>, elapsed: Duration) -> String {
    let age = value.age.map(|a| a.saturating_add(elapsed));
    let state = if value.state == ObservationState::Fresh
        && age.is_some_and(|a| a >= Duration::from_secs(10))
    {
        ObservationState::Stale
    } else {
        value.state
    };
    let age = age
        .map(|a| format!("{}s", a.as_secs()))
        .unwrap_or_else(|| "unknown".into());
    let error = value
        .public_error
        .as_ref()
        .map(|e| format!("; {}", safe(e)))
        .unwrap_or_default();
    format!(
        "{label}: {state:?}; age {age}; source {}{error}",
        safe(&value.source)
    )
}

fn json_lines(lines: &mut Vec<String>, label: &str, value: &Value) {
    lines.push(format!("{label}:"));
    if let Ok(text) = serde_json::to_string_pretty(value) {
        lines.extend(text.lines().map(|line| {
            let mut line = safe(line);
            if line.trim_end().ends_with(": null") || line.trim_end().ends_with(": null,") {
                line.push_str("  (unknown or not present)");
            }
            line
        }));
    }
}

fn overview(
    snapshot: Option<&Snapshot>,
    role: InstallationRole,
    bundle: Option<&PathBuf>,
) -> Vec<String> {
    let mut lines = vec![
        format!("Role: {role:?}"),
        "Read-only observations; sources are not simultaneous.".into(),
    ];
    if let Some(path) = bundle {
        lines.push(format!(
            "Explicit bundle (not verified or executed): {}",
            safe(&path.to_string_lossy())
        ));
    }
    let Some(s) = snapshot else {
        lines.push("Backup role: daemon and device are not contacted.".into());
        return lines;
    };
    let elapsed = s.captured_at.elapsed();
    lines.push(observation("Local inventory", &s.local, elapsed));
    if let Some(local) = &s.local.value {
        lines.push(format!("Support: {}", safe(&local.support)));
        lines.push(observation("USB candidate mode", &local.usb_mode, elapsed));
        if let Some(mode) = local.usb_mode.value {
            lines.push(format!(
                "USB mode: {mode:?}; bootloader association requires physical attendance"
            ));
        }
        lines.push(observation(
            "Manager executable",
            &local.own_executable,
            elapsed,
        ));
        if let Some(path) = &local.own_executable.value {
            lines.push(safe(&path.to_string_lossy()));
        }
        lines.push(observation(
            "PATH candidates",
            &local.path_candidates,
            elapsed,
        ));
        if let Some(paths) = &local.path_candidates.value {
            lines.extend(paths.iter().map(|p| safe(&p.to_string_lossy())));
        }
        lines.push(observation("Service", &local.service, elapsed));
        if let Some(service) = &local.service.value {
            lines.extend(service.lines().map(safe));
        }
        lines.push(observation("Configuration", &local.config, elapsed));
        lines.push(observation(
            "Configuration ownership",
            &local.config_ownership,
            elapsed,
        ));
        if let Some(metadata) = &local.config_ownership.value {
            lines.push(safe(metadata));
        }
        lines.push(observation(
            "Installation registry",
            &local.registry,
            elapsed,
        ));
        for component in &local.components {
            lines.push(format!(
                "Component: {}; ownership {:?}",
                safe(&component.component),
                component.ownership
            ));
            lines.push(observation("Installed", &component.installed, elapsed));
            if let Some(build) = &component.installed.value {
                lines.push(format!(
                    "Installed version {} build {} digest {} path {}",
                    safe(&build.version),
                    safe(&build.build_id),
                    build
                        .digest
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    safe(&build.path.to_string_lossy())
                ));
            }
            lines.push(observation("Running", &component.running, elapsed));
            if let Some(running) = &component.running.value {
                lines.push(format!(
                    "Running version {} build {} digest {} path {} pid {}",
                    safe(&running.build.version),
                    safe(&running.build.build_id),
                    running
                        .build
                        .digest
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    safe(&running.build.path.to_string_lossy()),
                    running
                        .pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "unknown".into())
                ));
            }
            if let Some(build) = &component.selected {
                lines.push(format!(
                    "Selected version {} build {} digest {} path {}",
                    safe(&build.version),
                    safe(&build.build_id),
                    build
                        .digest
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    safe(&build.path.to_string_lossy())
                ));
            } else {
                lines.push("Selected: unknown".into());
            }
            if let Some(provenance) = &component.provenance {
                lines.push(format!("Provenance: {}", safe(provenance)));
            }
        }
        if let Some(path) = &local.config.value {
            lines.push(safe(&path.to_string_lossy()));
        }
    }
    lines.push(observation("Host registry", &s.host, elapsed));
    if let Some(value) = &s.host.value {
        json_lines(&mut lines, "Host observation", value);
    }
    lines.push(observation("Device information", &s.device, elapsed));
    if let Some(value) = &s.device.value {
        json_lines(
            &mut lines,
            "Device observation (security report is not attestation)",
            value,
        );
    }
    lines.push(observation("Device membership", &s.membership, elapsed));
    lines.push(format!("Joined pool identities: {}", s.pools.len()));
    lines
}

fn detail(s: &Snapshot, selected: usize) -> Vec<String> {
    let Some(pool) = s.pools.get(selected) else {
        return vec!["No pool selected.".into()];
    };
    let elapsed = s.captured_at.elapsed();
    let mut lines = vec![
        format!("Pool: {}", safe(&pool.pool_id)),
        format!("Incarnation: {}", safe(&pool.incarnation_id)),
        observation("Host registry", &s.host, elapsed),
        observation("Device membership", &s.membership, elapsed),
        observation("Pool observation", &pool.observation, elapsed),
    ];
    match &pool.host {
        Some(v) => json_lines(&mut lines, "Host binding", v),
        None => lines
            .push("Host binding: not observed (absence requires a complete fresh snapshot)".into()),
    }
    match &pool.membership {
        Some(v) => json_lines(&mut lines, "Device membership", v),
        None => lines.push(
            "Device membership: not observed (absence requires a complete fresh snapshot)".into(),
        ),
    }
    if let Some(v) = &pool.observation.value {
        json_lines(&mut lines, "Pool, generation, certificate and context", v);
    }
    lines
}

/// Open read-only inventory; changes require separately reviewed actions.
pub fn run(role: InstallationRole, socket: PathBuf, bundle: Option<PathBuf>) -> i32 {
    let mut terminal = match TerminalOwner::acquire() {
        Ok(terminal) => terminal,
        Err(error) => {
            eprintln!(
                "manager requires an interactive terminal: {}",
                safe(&error.to_string())
            );
            return if error.kind() == io::ErrorKind::PermissionDenied {
                cli::EXIT_PERMISSION
            } else {
                cli::EXIT_UNAVAILABLE
            };
        }
    };
    let mut worker =
        (role == InstallationRole::Primary).then(|| Worker::start(socket.clone(), None));
    let result = event_loop(&mut terminal, &mut worker, role, bundle.as_ref(), &socket);
    if let Some(worker) = worker {
        worker.shutdown();
    }
    let close = terminal.close();
    match (result, close) {
        (Ok(Exit::Quit), Ok(())) => cli::EXIT_SUCCESS,
        (Ok(Exit::Reexec(path)), Ok(())) => {
            let result = super::host::trusted_manager().and_then(|current| {
                if current != path {
                    return Err(io::Error::other("installed manager changed after review"));
                }
                let mut command = Command::new(path);
                command
                    .args([
                        "--role",
                        match role {
                            InstallationRole::Primary => "primary",
                            InstallationRole::Backup => "backup",
                        },
                    ])
                    .arg("--socket")
                    .arg(socket);
                if let Some(bundle) = bundle {
                    command.arg("--bundle").arg(bundle);
                }
                Err::<(), _>(command.exec())
            });
            eprintln!(
                "manager re-exec failed: {}",
                safe(&result.unwrap_err().to_string())
            );
            cli::EXIT_FAILURE
        }
        (Err(error), _) | (Ok(_), Err(error)) => {
            eprintln!("manager terminal error: {}", safe(&error.to_string()));
            if error.kind() == io::ErrorKind::PermissionDenied {
                cli::EXIT_PERMISSION
            } else {
                cli::EXIT_FAILURE
            }
        }
    }
}

fn action_menu(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    title: &str,
    entries: &[navigation::Entry],
    selected: usize,
) {
    let mut state = ListState::default().with_selected((!entries.is_empty()).then_some(selected));
    frame.render_stateful_widget(
        List::new(entries.iter().map(|entry| ListItem::new(entry.label)))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD)),
            )
            .highlight_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
            .highlight_symbol(" > "),
        area,
        &mut state,
    );
}

fn release_action(
    action: releases::Action,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    bundle: Option<&PathBuf>,
    state: &mut releases::State,
    snapshot: Option<&Snapshot>,
    role: InstallationRole,
) -> io::Result<Option<PathBuf>> {
    use releases::Action;
    match action {
        Action::Browse => {
            review(terminal, "Release evidence", state.lines(), None)?;
        }
        Action::Refresh => state.refresh(),
        Action::Prerelease => state.toggle_prerelease(),
        Action::Offline => state.toggle_offline(),
        Action::Select => {
            releases::component_update(terminal, worker, socket, bundle, state, snapshot, role)?
        }
        Action::FirmwarePreview => releases::firmware_preview(terminal, worker, socket, bundle)?,
        Action::FirmwareUpdate => releases::firmware_update(terminal, worker, socket, bundle)?,
        Action::Inspect => setup::run(1, terminal, worker, role, socket, bundle)?,
        Action::RecoverFirmware => releases::recover_firmware(terminal, worker, socket)?,
        Action::Fallback => releases::fallback(terminal, worker, socket)?,
        Action::Reexec => return releases::reexec(terminal),
        Action::Remove => state.remove(terminal)?,
    }
    Ok(None)
}

fn event_loop(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    role: InstallationRole,
    bundle: Option<&PathBuf>,
    socket: &Path,
) -> io::Result<Exit> {
    let roots = navigation::roots(role);
    let mut view = View::Overview;
    let mut history = Vec::new();
    let mut evidence_origin = View::Overview;
    let mut menu_view = view;
    let mut entries = navigation::entries(view, role);
    let mut selected = 0usize;
    let mut overview_selected = 6usize;
    let mut selected_identity: Option<(String, String)> = None;
    let mut scroll = 0u16;
    let mut diagnostics = super::observe::Diagnostics::default();
    let mut release_state = releases::State::new();
    let mut last_snapshot: Option<std::sync::Arc<Snapshot>> = None;
    let mut last_draw = std::time::Instant::now();
    let mut redraw = true;
    let mut small = false;
    loop {
        redraw |= release_state.poll();
        if menu_view != view {
            entries = navigation::entries(view, role);
            selected = 0;
            scroll = 0;
            menu_view = view;
            redraw = true;
        }
        let snapshot = worker.as_ref().map(Worker::snapshot);
        let changed = match (&snapshot, &last_snapshot) {
            (Some(current), Some(previous)) => !std::sync::Arc::ptr_eq(current, previous),
            (None, None) => false,
            _ => true,
        };
        if changed && let Some(snapshot) = &snapshot {
            diagnostics.record(snapshot);
        }
        if selected_identity.is_none()
            && let Some(s) = &snapshot
            && let Some(&index) = status::pool_order(s).first()
        {
            let pool = &s.pools[index];
            selected_identity = Some((pool.pool_id.clone(), pool.incarnation_id.clone()));
        }
        let pool_index = snapshot.as_ref().and_then(|s| {
            selected_identity.as_ref().and_then(|(pool, incarnation)| {
                s.pools
                    .iter()
                    .position(|p| &p.pool_id == pool && &p.incarnation_id == incarnation)
            })
        });
        if redraw || changed || last_draw.elapsed() >= Duration::from_secs(1) {
            let size = terminal.terminal()?.size()?;
            small = size.width < 80 || size.height < 24;
            terminal.terminal()?.draw(|frame| {
                let screen = frame.area();
                if small {
                    frame.render_widget(Paragraph::new("Resize to 80×24 · q quit").style(tone(Color::Yellow)), screen);
                    return;
                }
                let width = screen.width.min(120);
                let area = Rect::new(screen.x + (screen.width - width) / 2, screen.y, width, screen.height);
                let regions = Layout::vertical([Constraint::Length(3), Constraint::Min(1), Constraint::Length(2)]).split(area);
                let header = Line::from(vec![
                    Span::styled("p2kesup  ", tone(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw(if role == InstallationRole::Primary { "primary  " } else { "backup  " }),
                    Span::styled(safe(env!("P2KES_EMBEDDED_VERSION")), tone(Color::Yellow)),
                ]);
                let root = if matches!(view, View::Evidence | View::Help) { evidence_origin.root() } else { view.root() };
                let tabs = Line::from(roots.iter().enumerate().flat_map(|(index, candidate)| [
                    Span::styled(format!("{} {}", index + 1, candidate.label()),
                        if *candidate == root { tone(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED) } else { Style::default() }),
                    Span::raw("  "),
                ]).collect::<Vec<_>>());
                frame.render_widget(Paragraph::new(vec![header, tabs]), regions[0]);
                match view {
                    View::Overview => status::render_overview(frame, regions[1], snapshot.as_deref(), role, overview_selected),
                    View::Pools => status::render_pools(frame, regions[1], snapshot.as_deref(), pool_index.unwrap_or(usize::MAX)),
                    View::Device => {
                        let parts = Layout::vertical([Constraint::Length(8), Constraint::Min(1)]).split(regions[1]);
                        status::render_device(frame, parts[0], snapshot.as_deref());
                        action_menu(frame, parts[1], "Device actions", &entries, selected);
                    }
                    View::Details => {
                        let lines = snapshot.as_ref().map(|s| status::pool_lines(s, pool_index.unwrap_or(usize::MAX)))
                            .unwrap_or_else(|| vec![Line::from("Pool: unavailable")]);
                        let summary = Paragraph::new(lines).wrap(Wrap { trim: false });
                        let height = (summary.line_count(regions[1].width) as u16).min(regions[1].height.saturating_sub(6));
                        let parts = Layout::vertical([Constraint::Length(height), Constraint::Min(6)]).split(regions[1]);
                        frame.render_widget(summary, parts[0]);
                        if pool_index.is_some() {
                            action_menu(frame, parts[1], "Pool actions", &entries, selected);
                        } else {
                            frame.render_widget(Paragraph::new("Selected pool: unavailable · Esc back").style(tone(Color::Yellow)), parts[1]);
                        }
                    }
                    View::Evidence | View::Help => {
                        let lines = if view == View::Help {
                            vec![
                                "1–6 / Tab / Shift-Tab: section".into(),
                                "↑↓ / j k: select or scroll".into(),
                                "Enter: open / review".into(),
                                "Pools → a: enrollment and recipient actions".into(),
                                "d: full evidence · r: refresh".into(),
                                "Esc: back · q: quit".into(),
                                "Colors: green verified condition; yellow attention/unknown; red fault.".into(),
                                "NO_COLOR: labels and selection remain available.".into(),
                                "Viewing makes no changes. Actions require separate review.".into(),
                                "Recovery: original plan or receipt; never a replacement retry.".into(),
                            ]
                        } else if matches!(evidence_origin, View::Pools | View::Details) {
                            snapshot.as_ref().map(|s| detail(s, pool_index.unwrap_or(usize::MAX))).unwrap_or_default()
                        } else {
                            overview(snapshot.as_deref(), role, bundle)
                        };
                        let paragraph = Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>())
                            .block(Block::default().borders(Borders::ALL).title(view.label()))
                            .wrap(Wrap { trim: false });
                        let max = paragraph.line_count(regions[1].width.saturating_sub(2))
                            .saturating_sub(usize::from(regions[1].height)).min(usize::from(u16::MAX)) as u16;
                        scroll = scroll.min(max);
                        frame.render_widget(paragraph.scroll((scroll, 0)), regions[1]);
                    }
                    _ => {
                        let hint = match view {
                            View::Setup => "Device: existing or blank? Missing configuration does not mean blank.",
                            View::SetupExisting => "Preserve identity/state. Use the original trusted pin and public inputs.",
                            View::SetupNew => "Blank device only. Each step checks current state; no automatic replay.",
                            View::Activity => "Recovery: original plans / receipts only. No replacement retries.",
                            View::DeviceSecurity => "OTP: irreversible. Separate qualification and confirmation required.",
                            View::ProducerHardening => "Policy: explicit services only. Restart requires approval.",
                            View::Recipients => "Private recipient: backup host only. Transfer public file only.",
                            View::Restore => "Restore: protected local output. Existing files are never overwritten.",
                            View::Releases => "Installed / running versions: d. Updates require authenticated releases.",
                            _ => "pico2-kes-agentd: service and configuration",
                        };
                        let mut summary = vec![Line::from(hint).style(tone(Color::DarkGray)), Line::default()];
                        if view == View::Releases {
                            summary.extend(status::software_lines(snapshot.as_deref()));
                        } else if matches!(view, View::SetupExisting | View::SetupNew) {
                            summary.extend(status::setup_lines(snapshot.as_deref()));
                        }
                        let paragraph = Paragraph::new(summary).wrap(Wrap { trim: false });
                        let height = paragraph.line_count(regions[1].width).min(7) as u16;
                        let parts = Layout::vertical([Constraint::Length(height), Constraint::Min(1)]).split(regions[1]);
                        frame.render_widget(paragraph, parts[0]);
                        action_menu(frame, parts[1], view.label(), &entries, selected);
                    }
                }
                let keys = match view {
                    View::Overview => "↑↓ Select   Enter Open   d Evidence   r Refresh   ? Help   q Quit",
                    View::Pools => "↑↓ Select  Enter Pool  a Actions  d Evidence  r Refresh  q Quit",
                    View::Evidence | View::Help => "↑↓ Scroll   Esc Back   r Refresh   q Quit",
                    _ => "↑↓ Select   Enter Open   Esc Back   d Evidence   ? Help   q Quit",
                };
                frame.render_widget(Paragraph::new(vec![Line::from(keys), Line::from("Tab / Shift-Tab: section   1–6: jump").style(tone(Color::DarkGray))]), regions[2]);
            })?;
            last_snapshot = snapshot.clone();
            last_draw = std::time::Instant::now();
            redraw = false;
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        redraw = true;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.code == KeyCode::Char('q') {
            return Ok(Exit::Quit);
        }
        if small {
            continue;
        }
        match key.code {
            KeyCode::Char(c @ '1'..='6') => {
                if let Some(next) = roots.get(c as usize - '1' as usize) {
                    view = *next;
                    history.clear();
                }
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let index = roots
                    .iter()
                    .position(|candidate| *candidate == view.root())
                    .unwrap_or(0);
                let step = if key.code == KeyCode::BackTab {
                    roots.len() - 1
                } else {
                    1
                };
                view = roots[(index + step) % roots.len()];
                history.clear();
            }
            KeyCode::Char('?') | KeyCode::Char('d') => {
                if !matches!(view, View::Help | View::Evidence) {
                    evidence_origin = view;
                    history.push(view);
                    view = if key.code == KeyCode::Char('?') {
                        View::Help
                    } else {
                        View::Evidence
                    };
                }
            }
            KeyCode::Esc => view = history.pop().unwrap_or(View::Overview),
            KeyCode::Char('a') if view == View::Pools => {
                history.push(view);
                view = View::PoolActions;
            }
            KeyCode::Char('r') => {
                if view == View::Releases {
                    release_state.refresh();
                }
                if let Some(worker) = worker {
                    worker.refresh();
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
                let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
                if view == View::Overview {
                    overview_selected = if down {
                        (overview_selected + 1).min(6)
                    } else {
                        overview_selected.saturating_sub(1)
                    };
                } else if view == View::Pools {
                    if let Some(s) = &snapshot {
                        let order = status::pool_order(s);
                        let current = pool_index
                            .and_then(|i| order.iter().position(|&candidate| candidate == i));
                        let next = match current {
                            Some(i) if down => (i + 1).min(order.len().saturating_sub(1)),
                            Some(i) => i.saturating_sub(1),
                            None => 0,
                        };
                        if let Some(&index) = order.get(next) {
                            let pool = &s.pools[index];
                            selected_identity =
                                Some((pool.pool_id.clone(), pool.incarnation_id.clone()));
                        }
                    }
                } else if matches!(view, View::Help | View::Evidence) {
                    scroll = if down {
                        scroll.saturating_add(1)
                    } else {
                        scroll.saturating_sub(1)
                    };
                } else {
                    selected = if down {
                        selected
                            .saturating_add(1)
                            .min(entries.len().saturating_sub(1))
                    } else {
                        selected.saturating_sub(1)
                    };
                }
            }
            KeyCode::Enter if view == View::Overview => {
                history.push(view);
                view = if role == InstallationRole::Backup {
                    View::Recipients
                } else if overview_selected < 6 {
                    [
                        View::Releases,
                        View::Setup,
                        View::Host,
                        View::Device,
                        View::Device,
                        View::Pools,
                    ][overview_selected]
                } else {
                    match status::next_step(snapshot.as_deref()) {
                        status::NextStep::Setup => View::Setup,
                        status::NextStep::Host => View::Host,
                        status::NextStep::Pools => View::Pools,
                        status::NextStep::Refresh => {
                            if let Some(worker) = worker {
                                worker.refresh();
                            }
                            history.pop();
                            View::Overview
                        }
                    }
                };
            }
            KeyCode::Enter if view == View::Pools && pool_index.is_some() => {
                history.push(view);
                view = View::Details;
            }
            KeyCode::Enter => {
                if view == View::Details && pool_index.is_none() {
                    continue;
                }
                let Some(entry) = entries.get(selected) else {
                    continue;
                };
                if let Action::Open(next) = entry.action {
                    evidence_origin = view;
                    history.push(view);
                    view = next;
                    continue;
                }
                release_state.pause();
                let target = if view == View::Details {
                    selected_identity
                        .as_ref()
                        .map(|(p, i)| (p.as_str(), i.as_str()))
                } else {
                    None
                };
                let result = match entry.action {
                    Action::Setup(index) => {
                        setup::run(index, terminal, worker, role, socket, bundle).map(|()| None)
                    }
                    Action::Release(action) => release_action(
                        action,
                        terminal,
                        worker,
                        socket,
                        bundle,
                        &mut release_state,
                        snapshot.as_deref(),
                        role,
                    ),
                    Action::Lifecycle(index) => {
                        lifecycle::run(index, terminal, worker, socket, target).map(|()| None)
                    }
                    Action::Service(index) => {
                        service::run(index, terminal, worker, socket, &diagnostics).map(|()| None)
                    }
                    Action::Security(index) => {
                        provisioning::run(index, terminal, worker, socket, bundle).map(|()| None)
                    }
                    Action::Producer(index) => {
                        producer::run(index, terminal, worker, socket, bundle).map(|()| None)
                    }
                    Action::Backup(index) => {
                        backup::run(index, terminal, worker, socket, bundle).map(|()| None)
                    }
                    Action::Uninstall => {
                        uninstall::run(terminal, worker, socket, role, bundle).map(|()| None)
                    }
                    Action::Open(_) => unreachable!(),
                };
                match result {
                    Ok(Some(path)) => return Ok(Exit::Reexec(path)),
                    Ok(None) => {}
                    Err(error) => {
                        review(terminal, "Blocked / incomplete", vec![error.to_string(), "Recovery: Activity → original plan / receipt. Do not create a replacement retry.".into()], None)?;
                    }
                }
                release_state.resume();
                last_snapshot = None;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Observation, ObservationState, observation, review_paragraph, safe};
    use std::time::Duration;

    #[test]
    fn review_refuses_content_beyond_the_scroll_range() {
        let maximum = usize::from(u16::MAX);
        assert!(review_paragraph("review", vec!["x".into(); maximum - 1]).is_err());
        let paragraph = review_paragraph("review", vec!["x".into(); maximum - 2]).unwrap();
        assert_eq!(paragraph.line_count(78), maximum);
    }

    #[test]
    fn controls_and_direction_overrides_cannot_reach_the_terminal() {
        assert_eq!(
            safe("a\u{1b}[31m\n\u{202e}z"),
            "a\\u{1b}[31m\\u{a}\\u{202e}z"
        );
    }

    #[test]
    fn retained_observation_ages_without_another_snapshot() {
        let value = Observation {
            source: "test".into(),
            value: Some(1),
            observed_at_unix_us: None,
            age: Some(Duration::from_secs(9)),
            state: ObservationState::Fresh,
            public_error: None,
        };
        assert!(observation("pool", &value, Duration::from_secs(1)).contains("Stale; age 10s"));
    }
}
