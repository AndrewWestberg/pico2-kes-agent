//! Inventory and explicitly reviewed workflows; observations are not an atomic health check.

use std::os::unix::process::CommandExt;
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::{Duration, Instant},
};
mod activity;
mod backup;
mod host_security;
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
mod wizard;

use navigation::{Action, View};
#[cfg(test)]
use widgets::review_paragraph;
use widgets::{FieldSpec, form_validated, review, tone};

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
    observe::{self, LocalOverview, Snapshot, Worker},
    terminal::TerminalOwner,
    workspace::{self, WorkspaceKind},
};
use crate::cli;

/// Run the finite bootstrap installation without entering the interactive menu.
pub fn install(bundle: PathBuf, role: InstallationRole) -> io::Result<()> {
    use super::{
        host::{self, HostAction, HostPlan},
        release::{self, Admission},
    };
    use std::io::IsTerminal;

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
                "This signed bundle is a candidate, not an approved release. Install only on a disposable host."
            );
            if !host::ask_yes_no("Proceed with this candidate installation?")? {
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
    let path = match workspace::next_path(WorkspaceKind::Plans, "install-plan", "json") {
        Ok(p) => p,
        Err(_) => {
            let cache = super::release_discovery::default_cache()?;
            cache.join(format!("install-plan-{}.json", plan.plan_id))
        }
    };
    crate::files::publish_no_clobber(
        &path,
        &serde_json::to_vec_pretty(&plan).map_err(io::Error::other)?,
        0o600,
    )?;
    println!(
        "Installation plan retained at {}. The privileged helper will display the scope and plan digest for your records.",
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
            "unresolved maintenance blocks upgrade, including no-op claims; recover the original operation (open p2kesup -> 6 Activity, or run p2kesup upgrade --resume ORIGINAL_PLAN)",
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

pub(super) fn safe(text: &str) -> String {
    use std::fmt::Write;
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control()
            || matches!(
                c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum EvidenceTab {
    #[default]
    Summary,
    Host,
    Device,
    Pools,
}

impl EvidenceTab {
    const ALL: &[Self] = &[Self::Summary, Self::Host, Self::Device, Self::Pools];

    fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Host => "Host & Binaries",
            Self::Device => "Device (non-attested)",
            Self::Pools => "Pools & Raw JSON",
        }
    }

    fn step(self, forward: bool) -> Self {
        let idx = Self::ALL.iter().position(|&t| t == self).unwrap_or(0);
        let delta = if forward { 1 } else { Self::ALL.len() - 1 };
        Self::ALL[(idx + delta) % Self::ALL.len()]
    }
}

fn build_evidence_lines(
    tab: EvidenceTab,
    snapshot: Option<&Snapshot>,
    backup_local: Option<&LocalOverview>,
    role: InstallationRole,
    bundle: Option<&PathBuf>,
    pool_index: Option<usize>,
) -> Vec<String> {
    let mut lines = vec![format!(
        "Role: {role:?} · Read-only observations (sources are not simultaneous)."
    )];
    if let Some(path) = bundle {
        lines.push(format!(
            "Launched --bundle (unverified until workflow): {}",
            safe(&path.to_string_lossy())
        ));
    }
    lines.push(String::new());

    if role == InstallationRole::Backup {
        lines.push(
            "Backup role: primary daemon, socket, and USB device are never contacted.".into(),
        );
        if let Some(local) = backup_local {
            lines.push(format!("Support: {}", safe(&local.support)));
            lines.push(observation("Swap free", &local.swap_free, Duration::ZERO));
            lines.push(observation(
                "Service state",
                &local.service_state,
                Duration::ZERO,
            ));
            lines.push(observation(
                "Installation registry",
                &local.registry,
                Duration::ZERO,
            ));
            for c in &local.components {
                lines.push(format!(
                    "Component {} ({:?}):",
                    safe(&c.component),
                    c.ownership
                ));
                lines.push(format!(
                    "  {}",
                    observation("Installed", &c.installed, Duration::ZERO)
                ));
            }
        }
        return lines;
    }

    let Some(s) = snapshot else {
        lines.push("Awaiting initial primary snapshot...".into());
        return lines;
    };
    let elapsed = s.captured_at.elapsed();

    match tab {
        EvidenceTab::Summary => {
            lines.push(observation("Local inventory", &s.local, elapsed));
            if let Some(local) = &s.local.value {
                lines.push(format!("Platform support : {}", safe(&local.support)));
                lines.push(observation("USB candidate", &local.usb_mode, elapsed));
                lines.push(observation("Swap preflight", &local.swap_free, elapsed));
                lines.push(observation("Service state", &local.service_state, elapsed));
                lines.push(observation("Configuration", &local.config, elapsed));
                lines.push(observation(
                    "Config ownership",
                    &local.config_ownership,
                    elapsed,
                ));
            }
            lines.push(observation("Host registry", &s.host, elapsed));
            lines.push(observation("Device info", &s.device, elapsed));
            lines.push(observation("Device membership", &s.membership, elapsed));
            lines.push(format!("Joined pools observed: {}", s.pools.len()));
        }
        EvidenceTab::Host => {
            if let Some(local) = &s.local.value {
                lines.push(observation(
                    "Manager executable",
                    &local.own_executable,
                    elapsed,
                ));
                if let Some(p) = &local.own_executable.value {
                    lines.push(format!("  {}", safe(&p.to_string_lossy())));
                }
                lines.push(observation(
                    "PATH candidates",
                    &local.path_candidates,
                    elapsed,
                ));
                if let Some(paths) = &local.path_candidates.value {
                    lines.extend(
                        paths
                            .iter()
                            .map(|p| format!("  {}", safe(&p.to_string_lossy()))),
                    );
                }
                lines.push(observation("Systemd unit", &local.service, elapsed));
                if let Some(svc) = &local.service.value {
                    lines.extend(svc.lines().map(|l| format!("  {}", safe(l))));
                }
                lines.push(String::new());
                for component in &local.components {
                    lines.push(format!(
                        "Component: {} (ownership {:?})",
                        safe(&component.component),
                        component.ownership
                    ));
                    if let Some(b) = &component.installed.value {
                        lines.push(format!(
                            "  Installed: {} build={} digest={} path={}",
                            safe(&b.version),
                            safe(&b.build_id),
                            b.digest.map_or_else(|| "unknown".into(), |d| d.to_string()),
                            safe(&b.path.to_string_lossy())
                        ));
                    }
                    if let Some(r) = &component.running.value {
                        lines.push(format!(
                            "  Running  : {} build={} pid={:?} digest={}",
                            safe(&r.build.version),
                            safe(&r.build.build_id),
                            r.pid,
                            r.build
                                .digest
                                .map_or_else(|| "unknown".into(), |d| d.to_string()),
                        ));
                    }
                }
            }
            if let Some(value) = &s.host.value {
                lines.push(String::new());
                json_lines(&mut lines, "Daemon host.observe JSON", value);
            }
        }
        EvidenceTab::Device => {
            lines.push(
                "NOTE: Firmware-reported security posture is NOT cryptographic hardware attestation."
                    .into(),
            );
            lines.push(observation("Device observation", &s.device, elapsed));
            if let Some(value) = &s.device.value {
                json_lines(&mut lines, "Device firmware & security report", value);
            }
        }
        EvidenceTab::Pools => {
            if let Some(idx) = pool_index.filter(|&i| i < s.pools.len()) {
                let pool = &s.pools[idx];
                lines.push(format!("Selected pool       : {}", safe(&pool.pool_id)));
                lines.push(format!(
                    "Selected incarnation: {}",
                    safe(&pool.incarnation_id)
                ));
                lines.push(observation("Pool observation", &pool.observation, elapsed));
                if let Some(h) = &pool.host {
                    json_lines(&mut lines, "Host binding", h);
                }
                if let Some(m) = &pool.membership {
                    json_lines(&mut lines, "Device membership", m);
                }
                if let Some(v) = &pool.observation.value {
                    json_lines(&mut lines, "Pool & generation JSON", v);
                }
            } else {
                lines.push(format!("Total joined pools: {}", s.pools.len()));
                if let Some(m) = &s.membership.value {
                    json_lines(
                        &mut lines,
                        "Device membership JSON",
                        &Value::Array(m.clone()),
                    );
                }
            }
        }
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
                    .title(format!(" {title} "))
                    .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD)),
            )
            .highlight_style(tone(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::REVERSED))
            .highlight_symbol(" > "),
        area,
        &mut state,
    );
}

#[allow(clippy::too_many_arguments)]
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
        Action::TupleUpgrade => {
            return releases::tuple_upgrade(terminal, worker, socket, bundle, state, role);
        }
        Action::Browse => {
            review(terminal, "Release evidence", state.lines())?;
        }
        Action::Refresh => state.refresh(),
        Action::Prerelease => state.toggle_prerelease(),
        Action::Offline => state.toggle_offline(),
        Action::Select => {
            releases::component_update(terminal, worker, socket, bundle, state, snapshot, role)?
        }
        Action::FirmwarePreview => {
            releases::firmware_preview(terminal, worker, socket, bundle, snapshot)?
        }
        Action::FirmwareUpdate => releases::firmware_update(terminal, worker, socket, bundle)?,
        Action::Reexec => return releases::reexec(terminal),
        Action::Remove => state.remove(terminal)?,
    }
    Ok(None)
}

fn bind_selected_pool(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    snapshot: Option<&Snapshot>,
    selected_identity: Option<&(String, String)>,
) -> io::Result<()> {
    let Some((pool_id, inc_id)) = selected_identity else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "select an enrolled pool first",
        ));
    };
    let net_hint = snapshot
        .and_then(|s| {
            s.pools
                .iter()
                .find(|p| &p.pool_id == pool_id && &p.incarnation_id == inc_id)
        })
        .and_then(|p| p.host.as_ref())
        .and_then(|h| h.get("network"))
        .and_then(Value::as_str);
    setup::bind_pool_workflow(terminal, worker, socket, pool_id, inc_id, net_hint)
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
    let mut evidence_tab = EvidenceTab::Summary;
    let mut menu_view = view;
    let mut entries = navigation::entries(view, role);
    let mut selected = 0usize;
    let mut overview_selected = 0usize;
    let mut activity_selected = 0usize;
    let mut selected_identity: Option<(String, String)> = None;
    let mut pool_filter = status::PoolFilter::default();
    let mut scroll = 0u16;
    let mut diagnostics = super::observe::Diagnostics::default();
    let mut release_state = releases::State::new();
    let mut activity_inv = activity::discover(role);
    let mut last_activity_scan = Instant::now();
    let mut backup_local = (role == InstallationRole::Backup).then(observe::local_snapshot);
    let mut last_snapshot: Option<std::sync::Arc<Snapshot>> = None;
    let mut last_draw = Instant::now();
    let mut redraw = true;
    let mut small = false;

    loop {
        redraw |= release_state.poll();
        if last_activity_scan.elapsed() >= Duration::from_secs(5) {
            let next_inv = activity::discover(role);
            if next_inv.items.len() != activity_inv.items.len()
                || next_inv.unresolved_count != activity_inv.unresolved_count
            {
                redraw = true;
            }
            activity_inv = next_inv;
            activity_selected = activity_selected.min(activity_inv.items.len().saturating_sub(1));
            last_activity_scan = Instant::now();
        }
        if menu_view != view {
            entries = navigation::entries(view, role);
            selected = 0;
            scroll = 0;
            if view == View::Activity {
                activity_inv = activity::discover(role);
                activity_selected =
                    activity_selected.min(activity_inv.items.len().saturating_sub(1));
                last_activity_scan = Instant::now();
            }
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
            && let Some(&index) = status::pool_order_filtered(s, &pool_filter).first()
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
                    frame.render_widget(
                        Paragraph::new("Resize terminal to at least 80×24 · q quit")
                            .style(tone(Color::Yellow)),
                        screen,
                    );
                    return;
                }
                let width = screen.width.min(120);
                let area = Rect::new(
                    screen.x + (screen.width - width) / 2,
                    screen.y,
                    width,
                    screen.height,
                );
                let regions = Layout::vertical([
                    Constraint::Length(2),
                    Constraint::Min(1),
                    Constraint::Length(2),
                ])
                .split(area);

                let (fresh_badge, fresh_col) = if role == InstallationRole::Backup {
                    ("[BACKUP ISOLATED]".into(), Color::Cyan)
                } else {
                    status::snapshot_freshness_badge(snapshot.as_deref())
                };
                let header = Line::from(vec![
                    Span::styled("p2kesup ", tone(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("{} ", safe(env!("P2KES_EMBEDDED_VERSION"))),
                        tone(Color::Yellow),
                    ),
                    Span::raw(if role == InstallationRole::Primary {
                        "[Primary]  "
                    } else {
                        "[Backup]  "
                    }),
                    Span::styled(fresh_badge, tone(fresh_col).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        "   ?:help d:evidence r:refresh q:quit",
                        tone(Color::DarkGray),
                    ),
                ]);

                let root = if matches!(view, View::Evidence | View::Help) {
                    evidence_origin.root()
                } else {
                    view.root()
                };
                let tabs = Line::from(
                    roots
                        .iter()
                        .enumerate()
                        .flat_map(|(index, candidate)| {
                            let mut label = format!("{} {}", index + 1, candidate.label());
                            if *candidate == View::Pools
                                && let Some(s) = snapshot.as_deref()
                                && status::fresh(&s.membership, s.captured_at.elapsed())
                                && status::fresh(&s.host, s.captured_at.elapsed())
                            {
                                label = format!("{} Pools({})", index + 1, s.pools.len());
                            } else if *candidate == View::Activity
                                && activity_inv.unresolved_count > 0
                            {
                                label = format!(
                                    "{} Activity(!{})",
                                    index + 1,
                                    activity_inv.unresolved_count
                                );
                            }
                            let active_tab = *candidate == root;
                            let tab_style = if active_tab {
                                tone(Color::Cyan)
                                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
                            } else if *candidate == View::Activity
                                && activity_inv.unresolved_count > 0
                            {
                                tone(Color::Yellow).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default()
                            };
                            [Span::styled(label, tab_style), Span::raw("  ")]
                        })
                        .collect::<Vec<_>>(),
                );
                frame.render_widget(Paragraph::new(vec![header, tabs]), regions[0]);

                match view {
                    View::Overview => status::render_overview(
                        frame,
                        regions[1],
                        snapshot.as_deref(),
                        backup_local.as_ref(),
                        role,
                        overview_selected,
                        activity_inv.unresolved_count,
                    ),
                    View::Pools => status::render_pools(
                        frame,
                        regions[1],
                        snapshot.as_deref(),
                        pool_index.unwrap_or(usize::MAX),
                        &pool_filter,
                    ),
                    View::Details => status::render_pool_detail(
                        frame,
                        regions[1],
                        snapshot.as_deref(),
                        pool_index,
                        &entries,
                        selected,
                    ),
                    View::Activity => activity::render_activity(
                        frame,
                        regions[1],
                        &activity_inv,
                        activity_selected,
                        role,
                    ),
                    View::Device => {
                        let parts =
                            Layout::vertical([Constraint::Length(8), Constraint::Min(1)])
                                .split(regions[1]);
                        status::render_device(frame, parts[0], snapshot.as_deref());
                        action_menu(frame, parts[1], "Device Actions", &entries, selected);
                    }
                    View::Evidence | View::Help => {
                        let lines = if view == View::Help {
                            vec![
                                "Navigation & Shortcuts".into(),
                                "  1–6 / Tab / Shift-Tab : Switch top-level workspace section".into(),
                                "  ↑↓ / j k / PgUp PgDn  : Move selection or scroll".into(),
                                "  Enter                 : Open item or review action".into(),
                                "  Esc                   : Return to previous screen (never mutates)".into(),
                                "  s                     : Set up my Pico 2 (from Primary Overview)".into(),
                                "  d                     : Open structured read-only Evidence drawer".into(),
                                "  r                     : Refresh host, daemon, device & activity state".into(),
                                "  q                     : Quit p2kesup".into(),
                                String::new(),
                                "Pool Shortcuts (View 2)".into(),
                                "  n : Add a pool          R : Rotate KES key       b : Repair pool binding".into(),
                                "  a : Global pool actions  f : Toggle attention-only  o : Cycle sort  / : Filter".into(),
                                String::new(),
                                "Safety & Recovery Principles".into(),
                                "  • Browsing is strictly read-only; mutations stage reviewed plans or CLI receipts.".into(),
                                "  • Interrupted operations surface in 6 Activity (!); press Enter to reconcile original ID.".into(),
                                "  • Status badges (RDY, EXP!, UNB, ATT!, [OK], [!]) remain unambiguous with NO_COLOR=1.".into(),
                            ]
                        } else {
                            build_evidence_lines(
                                evidence_tab,
                                snapshot.as_deref(),
                                backup_local.as_ref(),
                                role,
                                bundle,
                                pool_index,
                            )
                        };
                        let inner_w = regions[1].width.saturating_sub(2).max(1);
                        let inner_h = regions[1].height.saturating_sub(2).max(1);
                        let probe = Paragraph::new(
                            lines.iter().cloned().map(Line::from).collect::<Vec<_>>(),
                        )
                        .wrap(Wrap { trim: false });
                        let total = probe.line_count(inner_w).max(1);
                        let max = total
                            .saturating_sub(usize::from(inner_h))
                            .min(usize::from(u16::MAX)) as u16;
                        scroll = scroll.min(max);
                        let start = usize::from(scroll) + 1;
                        let end = (usize::from(scroll) + usize::from(inner_h)).min(total);
                        let title = if view == View::Help {
                            format!(" Help [lines {start}-{end} of {total}] ")
                        } else {
                            let tab_bar = EvidenceTab::ALL
                                .iter()
                                .map(|t| {
                                    if *t == evidence_tab {
                                        format!("[{}]", t.label())
                                    } else {
                                        t.label().to_owned()
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(" · ");
                            format!(" Evidence: {tab_bar} [{start}-{end}/{total}] ")
                        };
                        let paragraph = Paragraph::new(
                            lines.into_iter().map(Line::from).collect::<Vec<_>>(),
                        )
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(title)
                                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD)),
                        )
                        .wrap(Wrap { trim: false });
                        frame.render_widget(paragraph.scroll((scroll, 0)), regions[1]);
                    }
                    _ => {
                        let hint = match view {
                            View::DeviceSecurity => {
                                "OTP security stages are irreversible; separate verification evidence and confirmation apply."
                            }
                            View::ProducerHardening => {
                                "Installs systemd memory-hardening drop-ins only; Cardano node configs/sockets are never touched."
                            }
                            View::Recipients => {
                                "Generate HPKE backup keypairs locally; transfer ONLY the public .json file to the primary host."
                            }
                            View::Restore => {
                                "Decrypts .kes-backup to a new 0600 file; fence all producers before using restored signing keys."
                            }
                            View::Releases => {
                                "Coordinated tuple upgrades update host + firmware together; component selection is for advanced cases."
                            }
                            _ => "Manage pico2-kes-agentd service lifecycle, configuration candidates, and producer memory policy.",
                        };
                        let mut summary = vec![Line::from(hint).style(tone(Color::DarkGray))];
                        if view == View::Releases {
                            summary.extend(status::software_lines(
                                snapshot.as_deref(),
                                &release_state,
                                bundle,
                            ));
                        }
                        let paragraph = Paragraph::new(summary).wrap(Wrap { trim: false });
                        let height = (paragraph.line_count(regions[1].width) + 1).min(6) as u16;
                        let parts = Layout::vertical([Constraint::Length(height), Constraint::Min(1)])
                            .split(regions[1]);
                        frame.render_widget(paragraph, parts[0]);
                        action_menu(frame, parts[1], view.label(), &entries, selected);
                    }
                }

                let keys = match view {
                    View::Overview if role == InstallationRole::Primary => {
                        "↑↓ Action  Enter Go  s Set up Pico 2  R Rotate KES  u Software  d Details  r Refresh  q Quit"
                    }
                    View::Overview => {
                        "↑↓ Select Workflow   Enter Open   d Evidence   r Refresh   ? Help   q Quit"
                    }
                    View::Pools => {
                        "↑↓/PgDn Select  Enter Detail  n Add pool  R Rotate KES  b Bind  a Actions  f Attn  o Sort  / Filter"
                    }
                    View::Details => {
                        "↑↓ Select Action   Enter Review   R Rotate KES   b Bind Config   Esc Pools   d Details"
                    }
                    View::Activity => {
                        "↑↓ Select Record/Receipt/Plan   Enter Inspect & Reconcile   r Refresh"
                    }
                    View::Evidence => {
                        "←→ Switch Section   ↑↓/PgUp/PgDn Scroll   Esc Back   r Refresh   q Quit"
                    }
                    View::Help => "↑↓/PgUp/PgDn Scroll   Esc Back   q Quit",
                    _ => "↑↓ Select   Enter Open   Esc Back   d Evidence   ? Help   q Quit",
                };
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::from(keys),
                        Line::from("1–6 / Tab / Shift-Tab: switch section")
                            .style(tone(Color::DarkGray)),
                    ]),
                    regions[2],
                );
            })?;
            last_snapshot = snapshot.clone();
            last_draw = Instant::now();
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

        let wizard_action = if role == InstallationRole::Primary {
            match (view, key.code) {
                (View::Overview, KeyCode::Char('s')) => Some(Action::SetupWizard),
                (View::Pools, KeyCode::Char('n')) => Some(Action::AddPool),
                (View::Overview | View::Pools | View::Details, KeyCode::Char('R')) => {
                    Some(Action::RotateKes)
                }
                (View::Overview, KeyCode::Enter)
                    if overview_selected == 2
                        || (overview_selected == 0
                            && status::next_step(
                                snapshot.as_deref(),
                                activity_inv.unresolved_count,
                            ) == status::NextStep::Setup) =>
                {
                    Some(Action::SetupWizard)
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(action) = wizard_action {
            release_state.pause();
            let target = if view == View::Overview {
                snapshot
                    .as_deref()
                    .and_then(status::expiring_pool)
                    .map(|pool| (pool.pool_id.as_str(), pool.incarnation_id.as_str()))
            } else {
                selected_identity
                    .as_ref()
                    .map(|(pool, incarnation)| (pool.as_str(), incarnation.as_str()))
            };
            let result = match action {
                Action::SetupWizard => wizard::setup::run(terminal, worker, socket, bundle),
                Action::AddPool => wizard::pool::run(terminal, worker, socket),
                Action::RotateKes => match target {
                    Some((pool, incarnation)) => {
                        wizard::rotate::run(terminal, worker, socket, pool, incarnation)
                    }
                    None => Err(io::Error::other(
                        "Select a pool in Pools to rotate its KES key.",
                    )),
                },
                _ => unreachable!(),
            };
            if let Err(error) = result
                && error.kind() != io::ErrorKind::Interrupted
            {
                review(terminal, "Blocked / incomplete", vec![
                    error.to_string(),
                    "Open Activity to resume any interrupted operation; do not create a replacement retry.".into(),
                ])?;
            }
            activity_inv = activity::discover(role);
            if activity_inv.unresolved_count > 0 {
                history.push(view);
                view = View::Activity;
            }
            release_state.resume();
            last_snapshot = None;
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
                    if matches!(view, View::Pools | View::Details) {
                        evidence_tab = EvidenceTab::Pools;
                    } else if matches!(view, View::Device | View::DeviceSecurity) {
                        evidence_tab = EvidenceTab::Device;
                    } else if view == View::Host {
                        evidence_tab = EvidenceTab::Host;
                    } else {
                        evidence_tab = EvidenceTab::Summary;
                    }
                    history.push(view);
                    view = if key.code == KeyCode::Char('?') {
                        View::Help
                    } else {
                        View::Evidence
                    };
                }
            }
            KeyCode::Left | KeyCode::Char('[') if view == View::Evidence => {
                evidence_tab = evidence_tab.step(false);
                scroll = 0;
            }
            KeyCode::Right | KeyCode::Char(']') if view == View::Evidence => {
                evidence_tab = evidence_tab.step(true);
                scroll = 0;
            }
            KeyCode::Esc => {
                view = history.pop().unwrap_or(View::Overview);
            }
            KeyCode::Char('u') if view == View::Overview => {
                history.push(view);
                view = View::Releases;
            }
            KeyCode::Char('a') if view == View::Pools => {
                history.push(view);
                view = View::PoolActions;
            }
            KeyCode::Char('f') if view == View::Pools => {
                pool_filter.attention_only = !pool_filter.attention_only;
            }
            KeyCode::Char('o') if view == View::Pools => {
                pool_filter.sort = pool_filter.sort.next();
            }
            KeyCode::Char('/') if view == View::Pools => {
                let specs = [FieldSpec::text_hint(
                    "Filter pools by Pool ID or Incarnation substring",
                    &pool_filter.query,
                    "Leave blank and press Enter to clear filter",
                )];
                if let Some(q) = form_validated(terminal, "Filter Pools", &specs, |v| {
                    Ok(v[0].trim().to_owned())
                })? {
                    pool_filter.query = q;
                    if let Some(s) = &snapshot
                        && let Some(&idx) = status::pool_order_filtered(s, &pool_filter).first()
                    {
                        let p = &s.pools[idx];
                        selected_identity = Some((p.pool_id.clone(), p.incarnation_id.clone()));
                    }
                }
            }
            KeyCode::Char('b')
                if matches!(view, View::Pools | View::Details)
                    && role == InstallationRole::Primary =>
            {
                release_state.pause();
                if let Err(error) = bind_selected_pool(
                    terminal,
                    worker,
                    socket,
                    snapshot.as_deref(),
                    selected_identity.as_ref(),
                ) && error.kind() != io::ErrorKind::Interrupted
                {
                    review(
                        terminal,
                        "Bind pool blocked / incomplete",
                        vec![error.to_string()],
                    )?;
                }
                activity_inv = activity::discover(role);
                release_state.resume();
                last_snapshot = None;
            }
            KeyCode::Char('r') => {
                if view == View::Releases {
                    release_state.refresh();
                }
                if let Some(worker) = worker {
                    worker.refresh();
                }
                if role == InstallationRole::Backup {
                    backup_local = Some(observe::local_snapshot());
                }
                activity_inv = activity::discover(role);
                last_activity_scan = Instant::now();
            }
            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End
                if matches!(
                    view,
                    View::Help | View::Evidence | View::Pools | View::Activity
                ) =>
            {
                let page_step = 10usize;
                match view {
                    View::Help | View::Evidence => match key.code {
                        KeyCode::PageUp => scroll = scroll.saturating_sub(12),
                        KeyCode::PageDown => scroll = scroll.saturating_add(12),
                        KeyCode::Home => scroll = 0,
                        KeyCode::End => scroll = u16::MAX,
                        _ => {}
                    },
                    View::Pools => {
                        if let Some(s) = &snapshot {
                            let order = status::pool_order_filtered(s, &pool_filter);
                            let cur = pool_index
                                .and_then(|i| order.iter().position(|&c| c == i))
                                .unwrap_or(0);
                            let next = match key.code {
                                KeyCode::PageUp => cur.saturating_sub(page_step),
                                KeyCode::PageDown => {
                                    (cur + page_step).min(order.len().saturating_sub(1))
                                }
                                KeyCode::Home => 0,
                                KeyCode::End => order.len().saturating_sub(1),
                                _ => cur,
                            };
                            if let Some(&idx) = order.get(next) {
                                let p = &s.pools[idx];
                                selected_identity =
                                    Some((p.pool_id.clone(), p.incarnation_id.clone()));
                            }
                        }
                    }
                    View::Activity => {
                        let len = activity_inv.items.len();
                        activity_selected = match key.code {
                            KeyCode::PageUp => activity_selected.saturating_sub(page_step),
                            KeyCode::PageDown => {
                                (activity_selected + page_step).min(len.saturating_sub(1))
                            }
                            KeyCode::Home => 0,
                            KeyCode::End => len.saturating_sub(1),
                            _ => activity_selected,
                        };
                    }
                    _ => {}
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
                let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
                if view == View::Overview {
                    let max_idx = if role == InstallationRole::Primary {
                        6
                    } else {
                        status::BACKUP_OVERVIEW_ACTIONS.len() - 1
                    };
                    overview_selected = if down {
                        (overview_selected + 1).min(max_idx)
                    } else {
                        overview_selected.saturating_sub(1)
                    };
                } else if view == View::Pools {
                    if let Some(s) = &snapshot {
                        let order = status::pool_order_filtered(s, &pool_filter);
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
                } else if view == View::Activity {
                    let max_idx = activity_inv.items.len().saturating_sub(1);
                    activity_selected = if down {
                        activity_selected.saturating_add(1).min(max_idx)
                    } else {
                        activity_selected.saturating_sub(1)
                    };
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
                if role == InstallationRole::Backup {
                    match overview_selected {
                        0..=2 => {
                            release_state.pause();
                            if let Err(error) =
                                backup::run(overview_selected, terminal, worker, socket, bundle)
                            {
                                review(
                                    terminal,
                                    "Backup action blocked / incomplete",
                                    vec![error.to_string()],
                                )?;
                            }
                            backup_local = Some(observe::local_snapshot());
                            activity_inv = activity::discover(role);
                            release_state.resume();
                        }
                        3 => {
                            history.push(view);
                            view = View::Releases;
                        }
                        _ => {
                            history.push(view);
                            view = View::Activity;
                        }
                    }
                    continue;
                }
                history.push(view);
                view = match overview_selected {
                    0 => {
                        match status::next_step(snapshot.as_deref(), activity_inv.unresolved_count)
                        {
                            status::NextStep::Activity => View::Activity,
                            status::NextStep::Setup => {
                                unreachable!("setup wizard dispatched above")
                            }
                            status::NextStep::Host => View::Host,
                            status::NextStep::Pools => View::Pools,
                            status::NextStep::Refresh => {
                                if let Some(worker) = worker {
                                    worker.refresh();
                                }
                                activity_inv = activity::discover(role);
                                history.pop();
                                View::Overview
                            }
                        }
                    }
                    1 => View::Pools,
                    2 => unreachable!("setup wizard dispatched above"),
                    3 => View::Host,
                    4 => View::Device,
                    5 => View::Releases,
                    _ => View::Activity,
                };
            }
            KeyCode::Enter if view == View::Pools => {
                if pool_index.is_some() {
                    history.push(view);
                    view = View::Details;
                } else if snapshot.as_deref().is_some_and(|s| {
                    s.pools.is_empty() && status::fresh(&s.membership, s.captured_at.elapsed())
                }) {
                    history.push(view);
                    view = View::PoolActions;
                }
            }
            KeyCode::Enter if view == View::Activity => {
                let Some(item) = activity_inv.items.get(activity_selected).cloned() else {
                    continue;
                };
                release_state.pause();
                if let Err(error) = activity::open_item(&item, terminal, worker, socket, bundle)
                    && error.kind() != io::ErrorKind::Interrupted
                {
                    review(
                        terminal,
                        "Reconciliation blocked / incomplete",
                        vec![
                        error.to_string(),
                        "Retain the original record/receipt; never submit a duplicate replacement."
                            .into(),
                    ],
                    )?;
                }
                activity_inv = activity::discover(role);
                activity_selected =
                    activity_selected.min(activity_inv.items.len().saturating_sub(1));
                release_state.resume();
                last_snapshot = None;
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
                    Action::SetupWizard => {
                        wizard::setup::run(terminal, worker, socket, bundle).map(|()| None)
                    }
                    Action::AddPool => wizard::pool::run(terminal, worker, socket).map(|()| None),
                    Action::RotateKes => match target {
                        Some((pool, incarnation)) => {
                            wizard::rotate::run(terminal, worker, socket, pool, incarnation)
                                .map(|()| None)
                        }
                        None => Err(io::Error::other("Select a pool first.")),
                    },
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
                        lifecycle::run(index, terminal, worker, socket, target, snapshot.as_deref())
                            .map(|()| None)
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
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        review(terminal, "Blocked / incomplete", vec![
                            error.to_string(),
                            "Recovery: open 6 Activity to inspect or reconcile the original record/receipt (never create a replacement retry)."
                                .into(),
                        ])?;
                    }
                }
                if role == InstallationRole::Backup {
                    backup_local = Some(observe::local_snapshot());
                }
                activity_inv = activity::discover(role);
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
