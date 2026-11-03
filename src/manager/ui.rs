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
mod producer;
mod provisioning;
mod releases;
mod service;
mod setup;
mod uninstall;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    text::Line,
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
    use std::io::{IsTerminal, Write};
    use super::{host::{self, HostAction, HostPlan}, release::{self, Admission}};

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("installation requires an attended terminal"));
    }
    let (verified, candidate_accepted) = match release::verify_bundle(&bundle, Admission::Qualified) {
        Ok(verified) => (verified, false),
        Err(qualified_error) => {
            let verified = release::verify_bundle(&bundle, Admission::AttendedCandidate)
                .map_err(|_| qualified_error)?;
            println!("This signed bundle is a candidate, not a qualified release. Install only on a disposable host.");
            print!("Type DISPOSABLE CANDIDATE to accept: ");
            io::stdout().flush()?;
            if host::read_confirmation(io::stdin().lock())?.trim() != "DISPOSABLE CANDIDATE" {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "candidate not accepted"));
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
    crate::files::publish_no_clobber(&path, &serde_json::to_vec(&plan).map_err(io::Error::other)?, 0o600)?;
    println!("Installation plan retained at {}. The privileged helper will display the scope and request its digest.", path.display());
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/pkexec");
        command.arg(executable);
        command
    };
    let status = command.arg("host-apply").arg("--plan").arg(&path).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("installation failed or was interrupted ({status}); retain the original plan {}", path.display())));
    }
    println!("Installation completed; retained plan: {}", safe(&path.to_string_lossy()));
    println!("Reopen with: {}", if role == InstallationRole::Backup { "p2kesup --role backup" } else { "p2kesup" });
    Ok(())
}

pub fn upgrade(version: Option<&str>, bundle: Option<PathBuf>) -> io::Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "upgrade requires an attended terminal"));
    }
    let store = super::records::RecordStore::open_host(super::setup::service_identity()?.1)?;
    if store.list()?.iter().any(|record| match record {
        super::records::Record::Supported(record) => !super::host::maintenance_outcome_allows_new_action(&record.outcome),
        super::records::Record::Unknown(_) => true,
    }) {
        return Err(io::Error::other("unresolved maintenance blocks upgrade, including no-op claims; recover the original operation (p2kesup upgrade --resume ORIGINAL_PLAN for an upgrade)"));
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
        if explicit { super::release::Admission::AttendedCandidate } else { super::release::Admission::Qualified },
    )?;
    let current = registry.current.as_ref().ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    if super::host::same_selection(current, verified.selection()) {
        println!("Managed {:?} host selection is already {}. No changes made; device firmware was not checked.", registry.role, current.tag);
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
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    use super::{host::{self, HostAction, HostPlan}, records::{Record, RecordStore}};
    let file = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "original plan must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "original plan exceeds 1 MiB"));
    }
    let plan: HostPlan = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    plan.validate()?;
    if !matches!(&plan.action, HostAction::Upgrade { .. }) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "original plan is not an upgrade"));
    }
    let store = RecordStore::open_host(super::setup::service_identity()?.1)?;
    let mut matches = store.list()?.into_iter().filter_map(|record| match record {
        Record::Supported(record) if record.plan_digest.to_string() == plan.approved_digest && record.action == "upgrade" => Some(record),
        _ => None,
    });
    let record = matches.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "original upgrade record not found"))?;
    if matches.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "multiple original records match the plan"));
    }
    let operation = record.operation_id.to_string();
    let mut action = host::review_upgrade_recovery(&operation, &plan.approved_digest)?;
    let HostAction::UpgradeRecovery { temporary_validation, .. } = &mut action else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid recovery review"));
    };
    *temporary_validation = true;
    let executable = host::trusted_upgrade_recovery_manager(&operation, &plan.approved_digest)?;
    let mut terminal = TerminalOwner::acquire()?;
    let result = releases::resume_upgrade_direct(&mut terminal, action, executable, &operation);
    let closed = terminal.close();
    result?;
    closed?;
    println!("Original upgrade recovery completed; consult its retained record for the observed outcome.");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Overview,
    Pools,
    Details,
    Setup,
    Releases,
    Operations,
    Service,
    DeviceSecurity,
    ProducerHardening,
    BackupHost,
    Uninstall,
    Help,
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

fn public_fields(
    terminal: &mut TerminalOwner,
    title: &str,
    fields: &[(&str, &str)],
) -> io::Result<Option<Vec<String>>> {
    let mut values: Vec<String> = fields
        .iter()
        .map(|(_, value)| (*value).to_owned())
        .collect();
    let mut selected = 0;
    let mut redraw = true;
    loop {
        let size = terminal.terminal()?.size()?;
        let small = size.width < 80 || size.height < 24;
        if redraw {
            terminal.terminal()?.draw(|frame| {
                let lines: Vec<Line> = if small {
                    vec![Line::from("Resize to at least 80×24; Esc or q cancels without applying.")]
                } else {
                    let value = safe(&values[selected]);
                    let start = value.char_indices().rev().nth(255).map_or(0, |(index, _)| index);
                    let shown = if start == 0 { value } else { format!("…{}", &value[start..]) };
                    vec![
                        Line::from(format!("Field {} of {}: {}", selected + 1, fields.len(), fields[selected].0)),
                        Line::from(shown),
                        Line::from("Long values show their final 256 characters here; review the full target before approval."),
                        Line::from("Public inputs only. Never enter a private key or passphrase here."),
                        Line::from("Tab/Shift-Tab: field; Enter: next/review; Esc: cancel; Backspace: edit"),
                    ]
                };
                frame.render_widget(
                    Paragraph::new(lines).wrap(Wrap { trim: false })
                        .block(Block::default().borders(Borders::ALL).title(title)),
                    frame.area(),
                );
            })?;
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
        if key.code == KeyCode::Esc || (small && key.code == KeyCode::Char('q')) {
            return Ok(None);
        }
        if small {
            continue;
        }
        match key.code {
            KeyCode::Tab => selected = (selected + 1) % fields.len(),
            KeyCode::BackTab => selected = (selected + fields.len() - 1) % fields.len(),
            KeyCode::Enter if selected + 1 == fields.len() => return Ok(Some(values)),
            KeyCode::Enter => selected += 1,
            KeyCode::Backspace => {
                values[selected].pop();
            }
            KeyCode::Char(c)
                if !c.is_control()
                    && values[selected].len() + c.len_utf8() <= 4096
                    && !key.modifiers.intersects(
                        crossterm::event::KeyModifiers::CONTROL
                            | crossterm::event::KeyModifiers::ALT,
                    ) =>
            {
                values[selected].push(c);
            }
            _ => {}
        }
    }
}

fn review_paragraph(title: &str, lines: Vec<String>) -> io::Result<Paragraph<'_>> {
    let lines: Vec<Line> = lines
        .into_iter()
        .map(|line| Line::from(safe(&line)))
        .collect();
    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(title));
    if paragraph.line_count(78) > usize::from(u16::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "review exceeds the terminal scroll range; reformat public inputs before approval",
        ));
    }
    Ok(paragraph)
}

fn review(
    terminal: &mut TerminalOwner,
    title: &str,
    lines: Vec<String>,
    confirmation: Option<&str>,
) -> io::Result<bool> {
    let mut paragraph = review_paragraph(title, lines)?;
    let mut scroll = 0u16;
    let mut redraw = true;
    loop {
        let size = terminal.terminal()?.size()?;
        let small = size.width < 80 || size.height < 24;
        if redraw {
            paragraph = paragraph.scroll((scroll, 0));
            terminal.terminal()?.draw(|frame| {
                let areas = Layout::vertical([Constraint::Min(1), Constraint::Length(2)])
                    .split(frame.area());
                if small {
                    frame.render_widget(
                        Paragraph::new("Resize to at least 80×24; Esc or q cancels."),
                        areas[0],
                    );
                } else {
                    frame.render_widget(&paragraph, areas[0]);
                }
                frame.render_widget(
                    Paragraph::new(if confirmation.is_some() {
                        "↑↓/j k: scroll; Enter: explicit confirmation; Esc/q: cancel"
                    } else {
                        "↑↓/j k: scroll; Esc/q: return"
                    }),
                    areas[1],
                );
            })?;
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
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            return Ok(false);
        }
        if small {
            continue;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => scroll = scroll.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
            KeyCode::Enter if confirmation.is_some() => {
                let expected = confirmation.expect("checked confirmation");
                let label = format!("Type exactly {expected}");
                return Ok(public_fields(terminal, title, &[(&label, "")])?
                    .is_some_and(|values| values[0] == expected));
            }
            _ => {}
        }
    }
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
            lines.push(safe(service));
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
    area: ratatui::layout::Rect,
    title: &str,
    labels: impl Iterator<Item = &'static str>,
    selected: usize,
) {
    let mut state = ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(
        List::new(labels.map(ListItem::new))
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
}
fn event_loop(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    role: InstallationRole,
    bundle: Option<&PathBuf>,
    socket: &Path,
) -> io::Result<Exit> {
    let mut view = View::Overview;
    let mut previous = View::Overview;
    let mut selected = 0usize;
    let mut selected_identity: Option<(String, String)> = None;
    let mut scroll = 0u16;
    let mut setup_selected = 0usize;
    let mut release_selected = 0usize;
    let mut lifecycle_selected = 0usize;
    let mut service_selected = 0usize;
    let mut security_selected = 0usize;
    let mut producer_selected = 0usize;
    let mut backup_selected = 0usize;
    let mut diagnostics = super::observe::Diagnostics::default();
    let mut release_state = releases::State::new();
    let release_actions = if role == InstallationRole::Primary {
        releases::PRIMARY_ACTIONS
    } else {
        releases::BACKUP_ACTIONS
    };
    let setup_count = if role == InstallationRole::Primary {
        setup::ACTIONS.len()
    } else {
        2
    };
    let views: &[View] = if role == InstallationRole::Primary {
        &[
            View::Overview,
            View::Pools,
            View::Setup,
            View::Releases,
            View::Operations,
            View::Service,
            View::DeviceSecurity,
            View::ProducerHardening,
            View::Uninstall,
        ]
    } else {
        &[
            View::Overview,
            View::Setup,
            View::Releases,
            View::BackupHost,
            View::Uninstall,
        ]
    };
    let mut last_snapshot: Option<std::sync::Arc<Snapshot>> = None;
    let mut last_draw = std::time::Instant::now();
    let mut redraw = true;
    let mut small = false;
    loop {
        redraw |= release_state.poll();
        let snapshot = worker.as_ref().map(Worker::snapshot);
        let changed = match (&snapshot, &last_snapshot) {
            (Some(current), Some(previous)) => !std::sync::Arc::ptr_eq(current, previous),
            (None, None) => false,
            _ => true,
        };
        if changed && let Some(snapshot) = &snapshot {
            diagnostics.record(snapshot);
        }
        if redraw || changed || last_draw.elapsed() >= Duration::from_secs(1) {
            if let Some(s) = &snapshot {
                if let Some((pool, incarnation)) = &selected_identity
                    && let Some(index) = s
                        .pools
                        .iter()
                        .position(|p| &p.pool_id == pool && &p.incarnation_id == incarnation)
                {
                    selected = index;
                }
                selected = selected.min(s.pools.len().saturating_sub(1));
                selected_identity = s
                    .pools
                    .get(selected)
                    .map(|p| (p.pool_id.clone(), p.incarnation_id.clone()));
            }
            let size = terminal.terminal()?.size()?;
            small = size.width < 80 || size.height < 24;
            terminal.terminal()?.draw(|frame| {
            let area = frame.area();
            if small {
                frame.render_widget(Paragraph::new("Terminal too small. Resize to at least 80×24; q quits.").block(Block::default().borders(Borders::ALL).title("p2kesup")), area);
                return;
            }
            let regions = Layout::vertical([Constraint::Length(3), Constraint::Min(1), Constraint::Length(2)]).split(area);
            let header = format!("{view:?} | {} | Tab / Shift-Tab changes section", if role == InstallationRole::Primary { "primary" } else { "backup: no daemon/device" });
            frame.render_widget(Paragraph::new(header).block(Block::default().borders(Borders::ALL).title("p2kesup")), regions[0]);
            match view {
                View::Pools => {
                    let items: Vec<ListItem> = snapshot.as_ref().map(|s| s.pools.iter().map(|p| ListItem::new(format!("{} / {}  [{:?}]", safe(&p.pool_id), safe(&p.incarnation_id), p.observation.state))).collect()).unwrap_or_default();
                    let mut state = ListState::default().with_selected((!items.is_empty()).then_some(selected));
                    frame.render_stateful_widget(List::new(items).block(Block::default().borders(Borders::ALL).title("Pools — Enter for details; empty is not necessarily complete" )).highlight_symbol("> "), regions[1], &mut state);
                }
                View::Setup => {
                    let items: Vec<ListItem> = setup::ACTIONS[..setup_count].iter().map(|(_, name)| ListItem::new(*name)).collect();
                    let mut state = ListState::default().with_selected(Some(setup_selected));
                    frame.render_stateful_widget(List::new(items).block(Block::default().borders(Borders::ALL).title("Setup — separate reviewed steps; never replay a setup script")).highlight_symbol("> "), regions[1], &mut state);
                }
                View::Releases => {
                    let areas = Layout::vertical([Constraint::Length(release_actions.len() as u16 + 2), Constraint::Min(1)]).split(regions[1]);
                    let items: Vec<ListItem> = release_actions.iter().map(|action| ListItem::new(action.label())).collect();
                    let mut state = ListState::default().with_selected(Some(release_selected));
                    frame.render_stateful_widget(List::new(items).block(Block::default().borders(Borders::ALL).title("Releases — exact authenticated tuples; original maintenance evidence")).highlight_symbol("> "), areas[0], &mut state);
                    let lines: Vec<Line> = release_state.lines().iter().map(|line| Line::from(safe(line))).collect();
                    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), areas[1]);
                }
                View::Operations => action_menu(frame, regions[1], "Operations — Enter reviews; Esc cancels", lifecycle::ACTIONS.iter().map(|(_, label)| *label), lifecycle_selected),
                View::Service => action_menu(frame, regions[1], "Service — Enter reviews; Esc cancels", service::ACTIONS.iter().map(|(_, label)| *label), service_selected),
                View::DeviceSecurity => action_menu(frame, regions[1], "DeviceSecurity — Enter reviews; Esc cancels", provisioning::ACTIONS.iter().map(|(_, label)| *label), security_selected),
                View::ProducerHardening => action_menu(frame, regions[1], "ProducerHardening — Enter reviews; Esc cancels", producer::ACTIONS.iter().map(|(_, label)| *label), producer_selected),
                View::BackupHost => action_menu(frame, regions[1], "BackupHost — Enter reviews; Esc cancels", backup::ACTIONS.iter().map(|(_, label)| *label), backup_selected),
                _ => {
                    let (title, lines) = match view {
                        View::Overview => ("Overview", overview(snapshot.as_deref(), role, bundle)),
                        View::Details => ("Pool details", snapshot.as_ref().map(|s| detail(s, selected)).unwrap_or_default()),
                        View::Uninstall => ("Uninstall", vec!["Enter reviews selected managed components or recovery of an original removal; opening this screen removes nothing.".into(), "External/modified files block removal. Stop approval applies only to the managed daemon when selected components affect it.".into(), "Configuration, journals, receipts, identity/pin, maintenance records, service account/group, producer drop-ins and all device state remain.".into(), "No producer restart, secure-wipe claim or revocation claim.".into()]),
                        View::Help => ("Help", vec!["Up/down or j/k: select or scroll".into(), "Tab/Shift-Tab: next/previous view".into(), "Enter: details or review; Esc: back".into(), "r: refresh observations; ?: help; q: quit".into(), "Viewing never changes installation/device. Applying asks exact target confirmation.".into(), "Backup role never contacts a daemon or device.".into()]),
                        View::Pools | View::Setup | View::Releases | View::Operations | View::Service | View::DeviceSecurity | View::ProducerHardening | View::BackupHost => unreachable!(),
                    };
                    let text: Vec<Line> = lines.into_iter().map(Line::from).collect();
                    frame.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(title)).wrap(Wrap { trim: false }).scroll((scroll, 0)), regions[1]);
                }
            }
            let footer = "↑↓/j k: move  Enter: review  Esc: back  r: refresh  ?: help  q: quit";
            frame.render_widget(Paragraph::new(footer), regions[2]);
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
            KeyCode::Tab | KeyCode::BackTab => {
                let index = views
                    .iter()
                    .position(|candidate| *candidate == view)
                    .unwrap_or(0);
                let step = if key.code == KeyCode::BackTab {
                    views.len() - 1
                } else {
                    1
                };
                view = views[(index + step) % views.len()];
                scroll = 0;
            }
            KeyCode::Char('?') => {
                if view != View::Help {
                    previous = view;
                    view = View::Help;
                    scroll = 0;
                }
            }
            KeyCode::Esc => {
                view = if view == View::Help {
                    previous
                } else if view == View::Details {
                    View::Pools
                } else {
                    View::Overview
                };
                scroll = 0;
            }
            KeyCode::Enter if view == View::Uninstall => {
                release_state.pause();
                if let Err(error) = uninstall::run(terminal, worker, socket, role, bundle) {
                    review(terminal, "Uninstall blocked or failed", vec![error.to_string(), "No unproven ownership authorizes removal; retain the original maintenance record after any partial failure.".into()], None)?;
                }
                release_state.refresh();
                last_snapshot = None;
            }
            KeyCode::Enter if view == View::Setup => {
                release_state.pause();
                if let Err(error) =
                    setup::run(setup_selected, terminal, worker, role, socket, bundle)
                {
                    review(terminal, "Setup blocked or failed", vec![error.to_string(), "Preserve original records. Failure or unknown state is not permission to retry under a new identity.".into()], None)?;
                }
                release_state.refresh();
                last_snapshot = None;
            }
            KeyCode::Enter if view == View::Releases => {
                release_state.pause();
                use releases::Action;
                let result = match release_actions[release_selected] {
                    Action::Browse => review(
                        terminal,
                        "Authenticated release inventory",
                        release_state.lines(),
                        None,
                    )
                    .map(|_| None),
                    Action::Refresh => {
                        release_state.refresh();
                        Ok(None)
                    }
                    Action::Prerelease => {
                        release_state.toggle_prerelease();
                        Ok(None)
                    }
                    Action::Offline => {
                        release_state.toggle_offline();
                        Ok(None)
                    }
                    Action::Select => releases::component_update(
                        terminal,
                        worker,
                        socket,
                        bundle,
                        &release_state,
                        snapshot.as_deref(),
                        role,
                    )
                    .map(|()| None),
                    Action::FirmwarePreview => {
                        releases::firmware_preview(terminal, worker, socket, bundle).map(|()| None)
                    }
                    Action::FirmwareUpdate => {
                        releases::firmware_update(terminal, worker, socket, bundle).map(|()| None)
                    }
                    Action::Inspect => {
                        setup::run(1, terminal, worker, role, socket, bundle).map(|()| None)
                    }
                    Action::RecoverFirmware => {
                        releases::recover_firmware(terminal, worker, socket).map(|()| None)
                    }
                    Action::Fallback => releases::fallback(terminal, worker, socket).map(|()| None),
                    Action::Reexec => releases::reexec(terminal),
                    Action::Remove => release_state.remove(terminal).map(|()| None),
                };
                match result {
                    Ok(Some(path)) => return Ok(Exit::Reexec(path)),
                    Ok(None) => {}
                    Err(error) => {
                        review(terminal, "Release operation blocked or incomplete", vec![error.to_string(), "Retain original plans/receipts after interruption. Unknown state never authorizes replay, erasure, pin replacement or automatic fallback.".into()], None)?;
                    }
                }
                release_state.resume();
                last_snapshot = None;
            }
            KeyCode::Enter
                if matches!(
                    view,
                    View::Operations
                        | View::Service
                        | View::DeviceSecurity
                        | View::ProducerHardening
                        | View::BackupHost
                ) =>
            {
                release_state.pause();
                let result = match view {
                    View::Operations => {
                        lifecycle::run(lifecycle_selected, terminal, worker, socket, bundle)
                    }
                    View::Service => {
                        service::run(service_selected, terminal, worker, socket, &diagnostics)
                    }
                    View::DeviceSecurity => {
                        provisioning::run(security_selected, terminal, worker, socket, bundle)
                    }
                    View::ProducerHardening => {
                        producer::run(producer_selected, terminal, worker, socket, bundle)
                    }
                    View::BackupHost => {
                        backup::run(backup_selected, terminal, worker, socket, bundle)
                    }
                    _ => unreachable!(),
                };
                if let Err(error) = result {
                    review(terminal, "Operation blocked or incomplete", vec![error.to_string(),
                        "Retain original receipts and records. Reopening does not authorize new-ID retries or automatic recovery.".into()], None)?;
                }
                release_state.resume();
                last_snapshot = None;
            }
            KeyCode::Enter
                if view == View::Pools
                    && snapshot.as_ref().is_some_and(|s| !s.pools.is_empty()) =>
            {
                view = View::Details;
                scroll = 0;
            }
            KeyCode::Char('r') => {
                if view == View::Releases {
                    release_state.refresh();
                }
                if let Some(worker) = worker {
                    worker.refresh();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if view == View::Pools {
                    if let Some(s) = &snapshot {
                        selected = selected
                            .saturating_add(1)
                            .min(s.pools.len().saturating_sub(1));
                        selected_identity = s
                            .pools
                            .get(selected)
                            .map(|p| (p.pool_id.clone(), p.incarnation_id.clone()));
                    }
                } else if view == View::Setup {
                    setup_selected = (setup_selected + 1).min(setup_count - 1);
                } else if view == View::Releases {
                    release_selected = (release_selected + 1).min(release_actions.len() - 1);
                } else if view == View::Operations {
                    lifecycle_selected = (lifecycle_selected + 1).min(lifecycle::ACTIONS.len() - 1);
                } else if view == View::Service {
                    service_selected = (service_selected + 1).min(service::ACTIONS.len() - 1);
                } else if view == View::DeviceSecurity {
                    security_selected =
                        (security_selected + 1).min(provisioning::ACTIONS.len() - 1);
                } else if view == View::ProducerHardening {
                    producer_selected = (producer_selected + 1).min(producer::ACTIONS.len() - 1);
                } else if view == View::BackupHost {
                    backup_selected = (backup_selected + 1).min(backup::ACTIONS.len() - 1);
                } else {
                    scroll = scroll.saturating_add(1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if view == View::Pools {
                    selected = selected.saturating_sub(1);
                    selected_identity = snapshot
                        .as_ref()
                        .and_then(|s| s.pools.get(selected))
                        .map(|p| (p.pool_id.clone(), p.incarnation_id.clone()));
                } else if view == View::Setup {
                    setup_selected = setup_selected.saturating_sub(1);
                } else if view == View::Releases {
                    release_selected = release_selected.saturating_sub(1);
                } else if view == View::Operations {
                    lifecycle_selected = lifecycle_selected.saturating_sub(1);
                } else if view == View::Service {
                    service_selected = service_selected.saturating_sub(1);
                } else if view == View::DeviceSecurity {
                    security_selected = security_selected.saturating_sub(1);
                } else if view == View::ProducerHardening {
                    producer_selected = producer_selected.saturating_sub(1);
                } else if view == View::BackupHost {
                    backup_selected = backup_selected.saturating_sub(1);
                } else {
                    scroll = scroll.saturating_sub(1);
                }
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
