use std::time::Duration;

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use serde_json::Value;

use super::super::{
    model::{DeviceMode, InstallationRole, Observation, ObservationState},
    observe::{ConfigAccess, JoinedPool, Snapshot},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NextStep {
    Setup,
    Host,
    Pools,
    Refresh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Assessment {
    Attention,
    Unknown,
    Ready,
}

fn fresh<T>(observation: &Observation<T>, elapsed: Duration) -> bool {
    observation.state == ObservationState::Fresh
        && observation.value.is_some()
        && observation
            .age
            .is_some_and(|age| age.saturating_add(elapsed) < Duration::from_secs(10))
}

fn state<T>(observation: &Observation<T>, elapsed: Duration) -> &'static str {
    if fresh(observation, elapsed) {
        "fresh"
    } else if observation.state == ObservationState::Stale
        || (observation.state == ObservationState::Fresh && observation.value.is_some())
    {
        "stale"
    } else {
        match observation.state {
            ObservationState::Unavailable => "unavailable",
            ObservationState::Unsupported => "unsupported",
            _ => "unknown",
        }
    }
}

fn generation(value: Option<&Value>) -> Assessment {
    let Some(value) = value else {
        return Assessment::Unknown;
    };
    if value.is_null() {
        return Assessment::Attention;
    }
    if !value.is_object() {
        return Assessment::Unknown;
    }
    match value.get("certificate_present").and_then(Value::as_bool) {
        Some(false) => Assessment::Attention,
        Some(true) => match (
            value.get("relative_period").and_then(Value::as_u64),
            value.get("remaining_valid_periods").and_then(Value::as_u64),
            value.get("health").and_then(Value::as_u64),
        ) {
            (Some(_), Some(remaining), Some(health)) if remaining > 0 && health == 0 => {
                Assessment::Ready
            }
            (_, Some(0), _) | (_, _, Some(1..=255)) => Assessment::Attention,
            _ => Assessment::Unknown,
        },
        None => Assessment::Unknown,
    }
}

fn pool_assessment(snapshot: &Snapshot, pool: &JoinedPool) -> Assessment {
    let elapsed = snapshot.captured_at.elapsed();
    if !fresh(&snapshot.host, elapsed)
        || !fresh(&snapshot.membership, elapsed)
        || !fresh(&pool.observation, elapsed)
    {
        return Assessment::Unknown;
    }
    let Some(host) = &pool.host else {
        return Assessment::Attention;
    };
    if pool.membership.is_none() {
        return Assessment::Attention;
    }
    match (
        host.get("configured").and_then(Value::as_bool),
        host.get("effective").and_then(Value::as_bool),
    ) {
        (Some(true), Some(true)) => {}
        (Some(_), Some(_)) => return Assessment::Attention,
        _ => return Assessment::Unknown,
    }
    let Some(value) = &pool.observation.value else {
        return Assessment::Unknown;
    };
    match value.pointer("/context/valid").and_then(Value::as_bool) {
        Some(false) => return Assessment::Attention,
        None => return Assessment::Unknown,
        Some(true) => {}
    }
    match value.get("health").and_then(Value::as_u64) {
        Some(0) => {}
        Some(1..=255) => return Assessment::Attention,
        _ => return Assessment::Unknown,
    }
    let active = generation(value.get("active"));
    if active != Assessment::Ready {
        return active;
    }
    match value.get("staged") {
        Some(Value::Null) => Assessment::Ready,
        Some(staged) => generation(Some(staged)),
        None => Assessment::Unknown,
    }
}

pub(super) fn pool_order(snapshot: &Snapshot) -> Vec<usize> {
    let mut indices: Vec<_> = (0..snapshot.pools.len()).collect();
    indices.sort_by(|&a, &b| {
        let a = &snapshot.pools[a];
        let b = &snapshot.pools[b];
        (pool_assessment(snapshot, a), &a.pool_id, &a.incarnation_id).cmp(&(
            pool_assessment(snapshot, b),
            &b.pool_id,
            &b.incarnation_id,
        ))
    });
    indices
}
fn overview_assessment(s: &Snapshot) -> Assessment {
    let elapsed = s.captured_at.elapsed();
    let Some(local) = s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed)) else {
        return Assessment::Unknown;
    };
    if !fresh(&local.config_access, elapsed) || !fresh(&local.service_state, elapsed) {
        return Assessment::Unknown;
    }
    match local.config_access.value {
        Some(ConfigAccess::Absent) => return Assessment::Attention,
        Some(ConfigAccess::Readable) => {}
        _ => return Assessment::Unknown,
    }
    match &local.service_state.value {
        Some(service) if service.load == "loaded" && service.active == "active" => {}
        Some(_) => return Assessment::Attention,
        None => return Assessment::Unknown,
    }
    if !fresh(&s.host, elapsed)
        || !fresh(&s.device, elapsed)
        || !fresh(&s.membership, elapsed)
        || s.device
            .value
            .as_ref()
            .and_then(|v| v.get("device_id"))
            .and_then(Value::as_str)
            .is_none()
    {
        return Assessment::Unknown;
    }
    if s.pools.is_empty() {
        return Assessment::Attention;
    }
    s.pools
        .iter()
        .map(|pool| pool_assessment(s, pool))
        .min()
        .unwrap_or(Assessment::Unknown)
}

pub(super) fn next_step(snapshot: Option<&Snapshot>) -> NextStep {
    let Some(s) = snapshot else {
        return NextStep::Refresh;
    };
    let elapsed = s.captured_at.elapsed();
    if !fresh(&s.local, elapsed) {
        return NextStep::Refresh;
    }
    let Some(local) = &s.local.value else {
        return NextStep::Refresh;
    };
    if !fresh(&local.config_access, elapsed) {
        return NextStep::Refresh;
    }
    match local.config_access.value {
        Some(ConfigAccess::Absent) => return NextStep::Setup,
        Some(ConfigAccess::Denied) | None => return NextStep::Refresh,
        Some(ConfigAccess::Readable) => {}
    }
    if !fresh(&local.service_state, elapsed) {
        return NextStep::Refresh;
    }
    match &local.service_state.value {
        Some(service) if service.load != "loaded" || service.active != "active" => {
            return NextStep::Host;
        }
        None => return NextStep::Refresh,
        _ => {}
    }
    if !fresh(&s.host, elapsed) || !fresh(&s.device, elapsed) || !fresh(&s.membership, elapsed) {
        return NextStep::Refresh;
    }
    if s.pools.is_empty()
        || s.pools
            .iter()
            .any(|pool| pool_assessment(s, pool) != Assessment::Ready)
    {
        NextStep::Pools
    } else {
        NextStep::Refresh
    }
}

fn tone(color: Color) -> Style {
    super::widgets::tone(color)
}
fn row(label: &'static str, value: impl Into<String>, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<20}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.into(), tone(color)),
    ])
}
fn label(assessment: Assessment) -> (&'static str, Color) {
    match assessment {
        Assessment::Attention => ("attention", Color::Yellow),
        Assessment::Unknown => ("unknown", Color::Yellow),
        Assessment::Ready => ("ready", Color::Green),
    }
}
fn pool_reason(s: &Snapshot, pool: &JoinedPool) -> &'static str {
    let elapsed = s.captured_at.elapsed();
    if !fresh(&s.host, elapsed)
        || !fresh(&s.membership, elapsed)
        || !fresh(&pool.observation, elapsed)
    {
        return "observation unavailable or stale";
    }
    let Some(host) = &pool.host else {
        return "host binding absent";
    };
    if pool.membership.is_none() {
        return "device membership absent";
    }
    match host.get("configured").and_then(Value::as_bool) {
        Some(false) => return "binding not configured",
        None => return "binding configuration unknown",
        _ => {}
    }
    match host.get("effective").and_then(Value::as_bool) {
        Some(false) => return "binding not effective",
        None => return "binding effectiveness unknown",
        _ => {}
    }
    let Some(v) = &pool.observation.value else {
        return "pool unknown";
    };
    match v.pointer("/context/valid").and_then(Value::as_bool) {
        Some(false) => return "context unavailable",
        None => return "context unknown",
        _ => {}
    }
    match v.get("health").and_then(Value::as_u64) {
        Some(0) => {}
        Some(_) => return "pool health not ready",
        None => return "pool health unknown",
    }
    if generation(v.get("active")) != Assessment::Ready {
        return "active generation needs review";
    }
    if v.get("staged").is_none() {
        return "staged generation unknown";
    }
    if !v["staged"].is_null() && generation(v.get("staged")) != Assessment::Ready {
        return "staged generation needs review";
    }
    "checks passed"
}

fn generation_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "unknown".into();
    };
    if value.is_null() {
        return "none".into();
    }
    if !value.is_object() {
        return "unknown".into();
    }
    let cert = match value.get("certificate_present").and_then(Value::as_bool) {
        Some(true) => "present",
        Some(false) => "absent",
        None => "unknown",
    };
    let remaining = value
        .get("remaining_valid_periods")
        .and_then(Value::as_u64)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".into());
    let id = value
        .get("generation_id")
        .and_then(Value::as_str)
        .map(|id| {
            if id.chars().count() > 8 {
                format!("{}…", super::safe(&id.chars().take(8).collect::<String>()))
            } else {
                super::safe(id)
            }
        })
        .unwrap_or_else(|| "unknown".into());
    format!("{id} · cert {cert} · {remaining} periods left")
}

pub(super) fn render_overview(
    frame: &mut Frame,
    area: Rect,
    snapshot: Option<&Snapshot>,
    role: InstallationRole,
    selected: usize,
) {
    use ratatui::layout::{Constraint, Layout};
    let areas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .split(area);
    if role == InstallationRole::Backup {
        frame.render_widget(
            Paragraph::new("Backup workspace")
                .style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::BOTTOM)),
            areas[0],
        );
        frame.render_widget(
            Paragraph::new(vec![
                row("Recipients", "create / transfer public record", Color::Cyan),
                Line::default(),
                row("Restore", "decrypt to protected local output", Color::Cyan),
                Line::default(),
                Line::from("Private keys stay on this backup host.").style(tone(Color::Yellow)),
            ]),
            areas[1],
        );
        frame.render_widget(
            Paragraph::new(" > Next: recipients   [Enter]")
                .style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL)),
            areas[2],
        );
        return;
    }
    let elapsed = snapshot
        .map(|s| s.captured_at.elapsed())
        .unwrap_or_default();
    let local = snapshot.and_then(|s| s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed)));
    let access = local.and_then(|l| {
        l.config_access
            .value
            .filter(|_| fresh(&l.config_access, elapsed))
    });
    let config = match access {
        Some(ConfigAccess::Readable) => "readable",
        Some(ConfigAccess::Absent) => "missing",
        Some(ConfigAccess::Denied) => "access denied",
        None => "unknown",
    };
    let service = local
        .map(|l| {
            if fresh(&l.service_state, elapsed) {
                l.service_state
                    .value
                    .as_ref()
                    .map(|s| match (s.load.as_str(), s.active.as_str()) {
                        ("not-found", _) => "not installed",
                        ("loaded", "active") => "running",
                        ("loaded", "inactive") => "stopped",
                        (_, "failed") => "failed",
                        ("loaded", "activating") => "starting",
                        ("loaded", "deactivating") => "stopping",
                        _ => "unknown",
                    })
                    .unwrap_or("unknown")
            } else {
                state(&l.service_state, elapsed)
            }
        })
        .unwrap_or("unknown");
    let usb = local
        .map(|l| {
            if fresh(&l.usb_mode, elapsed) {
                match l.usb_mode.value {
                    Some(DeviceMode::Application) => "application mode",
                    Some(DeviceMode::Bootloader) => "BOOTSEL mode",
                    Some(DeviceMode::Absent) => "not detected",
                    Some(DeviceMode::Ambiguous) => "multiple devices",
                    None => "unknown",
                }
            } else {
                state(&l.usb_mode, elapsed)
            }
        })
        .unwrap_or("unknown");
    let device = snapshot
        .map(|s| {
            if fresh(&s.device, elapsed) {
                "observed / unverified"
            } else if s.device.state == ObservationState::Stale {
                "stale / unverified"
            } else {
                "unverified"
            }
        })
        .unwrap_or("unverified");
    let pools = snapshot
        .map(|s| {
            if fresh(&s.membership, elapsed) && fresh(&s.host, elapsed) {
                format!("{} observed", s.pools.len())
            } else {
                "unknown".into()
            }
        })
        .unwrap_or_else(|| "unknown".into());
    let installed_build = local
        .and_then(|l| l.components.iter().find(|c| c.component == "manager"))
        .and_then(|c| {
            c.installed
                .value
                .as_ref()
                .filter(|_| fresh(&c.installed, elapsed))
        });
    let installed = installed_build
        .map(|build| super::safe(&build.version))
        .unwrap_or_else(|| "unknown".into());
    let (banner, color) = if service == "failed" {
        ("[!] pico2-kes-agentd: failed", Color::Red)
    } else if access == Some(ConfigAccess::Absent) {
        ("[!] Setup: incomplete", Color::Yellow)
    } else {
        match snapshot
            .map(overview_assessment)
            .unwrap_or(Assessment::Unknown)
        {
            Assessment::Ready => ("[OK] Pool checks: passed", Color::Green),
            Assessment::Attention => ("[!] Status: attention needed", Color::Yellow),
            Assessment::Unknown => ("[?] Status: unknown", Color::Yellow),
        }
    };
    frame.render_widget(
        Paragraph::new(banner)
            .style(tone(color).add_modifier(Modifier::BOLD))
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(tone(color)),
            ),
        areas[0],
    );
    let rows = [
        (
            "Installed software",
            installed,
            if installed_build.is_some() {
                Color::Green
            } else {
                Color::Yellow
            },
        ),
        (
            "Configuration",
            config.into(),
            if access == Some(ConfigAccess::Readable) {
                Color::Green
            } else {
                Color::Yellow
            },
        ),
        (
            "pico2-kes-agentd",
            service.into(),
            match service {
                "running" => Color::Green,
                "failed" => Color::Red,
                "stopped" => Color::DarkGray,
                _ => Color::Yellow,
            },
        ),
        ("USB", usb.into(), Color::DarkGray),
        ("Device identity", device.into(), Color::Yellow),
        ("Pools", pools, Color::DarkGray),
    ];
    let items = rows.into_iter().map(|(label, value, color)| {
        ListItem::new(vec![row(label, value, color), Line::default()])
    });
    let mut state = ListState::default().with_selected((selected < 6).then_some(selected));
    frame.render_stateful_widget(
        List::new(items)
            .highlight_symbol(" > ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        areas[1],
        &mut state,
    );
    let next = match next_step(snapshot) {
        NextStep::Setup => "continue setup",
        NextStep::Host => "review host",
        NextStep::Pools => "review pools",
        NextStep::Refresh => "refresh observations",
    };
    frame.render_widget(
        Paragraph::new(format!(
            " {} Next: {next}   [Enter]",
            if selected == 6 { ">" } else { " " }
        ))
        .style(tone(Color::Cyan).add_modifier(if selected == 6 {
            Modifier::BOLD
        } else {
            Modifier::empty()
        }))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(tone(Color::Cyan)),
        ),
        areas[2],
    );
}

pub(super) fn render_pools(
    frame: &mut Frame,
    area: Rect,
    snapshot: Option<&Snapshot>,
    selected: usize,
) {
    let Some(s) = snapshot else {
        frame.render_widget(
            Paragraph::new("Pools: unknown")
                .block(Block::default().title(" Pools ").borders(Borders::ALL)),
            area,
        );
        return;
    };
    let order = pool_order(s);
    let items: Vec<_> = order
        .iter()
        .map(|&index| {
            let pool = &s.pools[index];
            let (status, color) = label(pool_assessment(s, pool));
            let v = pool
                .observation
                .value
                .as_ref()
                .filter(|_| fresh(&pool.observation, s.captured_at.elapsed()));
            let context = v
                .and_then(|v| v.pointer("/context/valid"))
                .and_then(Value::as_bool)
                .map(|b| if b { "valid" } else { "unavailable" })
                .unwrap_or("unknown");
            let prefix: String = pool.pool_id.chars().take(12).collect();
            let incarnation: String = pool.incarnation_id.chars().take(8).collect();
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{} / {}  ", super::safe(&prefix), super::safe(&incarnation)),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(status, tone(color)),
                ]),
                Line::from(format!("  {}", pool_reason(s, pool))),
                Line::from(format!(
                    "  active: {}",
                    generation_text(v.and_then(|v| v.get("active")))
                )),
                Line::from(format!(
                    "  staged: {}",
                    generation_text(v.and_then(|v| v.get("staged")))
                )),
                Line::from(format!("  context: {context}")),
            ])
        })
        .collect();
    let mut state = ListState::default();
    state.select(order.iter().position(|&i| i == selected));
    if items.is_empty() {
        let text = if fresh(&s.membership, s.captured_at.elapsed())
            && fresh(&s.host, s.captured_at.elapsed())
        {
            "No pools observed"
        } else {
            "Pools: unknown"
        };
        frame.render_widget(
            Paragraph::new(text).block(Block::default().title(" Pools ").borders(Borders::ALL)),
            area,
        );
    } else {
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::default().title(" Pools ").borders(Borders::ALL))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                .highlight_symbol("> "),
            area,
            &mut state,
        );
    }
}

pub(super) fn pool_lines(s: &Snapshot, index: usize) -> Vec<Line<'static>> {
    let Some(pool) = s.pools.get(index) else {
        return vec![row("Pool", "not selected", Color::Yellow)];
    };
    let elapsed = s.captured_at.elapsed();
    let v = pool
        .observation
        .value
        .as_ref()
        .filter(|_| fresh(&pool.observation, elapsed));
    let (assessment, color) = label(pool_assessment(s, pool));
    let context = v
        .and_then(|v| v.pointer("/context/valid"))
        .and_then(Value::as_bool)
        .map(|valid| if valid { "valid" } else { "unavailable" })
        .unwrap_or("unknown");
    vec![
        Line::from(format!("Pool: {}", super::safe(&pool.pool_id))),
        Line::from(format!(
            "Incarnation: {}",
            super::safe(&pool.incarnation_id)
        )),
        row("Status", assessment, color),
        row("Reason", pool_reason(s, pool), color),
        row(
            "Observation",
            state(&pool.observation, elapsed),
            Color::Cyan,
        ),
        Line::from(format!(
            "Active: {}",
            generation_text(v.and_then(|v| v.get("active")))
        )),
        Line::from(format!(
            "Staged: {}",
            generation_text(v.and_then(|v| v.get("staged")))
        )),
        row("Context", context, Color::Cyan),
        row("Recipient evidence", "exported artifact", Color::DarkGray),
    ]
}

pub(super) fn render_device(frame: &mut Frame, area: Rect, snapshot: Option<&Snapshot>) {
    let mut lines = Vec::new();
    if let Some(s) = snapshot {
        let elapsed = s.captured_at.elapsed();
        let info = s
            .device
            .value
            .as_ref()
            .filter(|_| fresh(&s.device, elapsed));
        lines.push(row("Observation", state(&s.device, elapsed), Color::Cyan));
        for (name, key) in [
            ("Device identity", "device_id"),
            ("USB serial", "usb_serial"),
            ("Firmware", "version"),
            ("Build", "build_id"),
        ] {
            let value = info
                .and_then(|v| v.get(key))
                .and_then(Value::as_str)
                .map(super::safe)
                .unwrap_or_else(|| "unknown".into());
            lines.push(row(name, value, Color::Cyan));
        }
    } else {
        lines.push(row("Observation", "unknown", Color::Yellow));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(ratatui::widgets::Wrap { trim: false })
            .block(Block::default().title(" Device ").borders(Borders::ALL)),
        area,
    );
}

pub(super) fn software_lines(snapshot: Option<&Snapshot>) -> Vec<Line<'static>> {
    let Some(s) = snapshot else {
        return vec![row(
            "Installed versions",
            "use installation evidence",
            Color::DarkGray,
        )];
    };
    let elapsed = s.captured_at.elapsed();
    let Some(local) = s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed)) else {
        return vec![row("Installed versions", "unknown", Color::Yellow)];
    };
    ["manager", "cli", "daemon"]
        .into_iter()
        .map(|component| {
            let build = local
                .components
                .iter()
                .find(|c| c.component == component)
                .and_then(|c| {
                    c.installed
                        .value
                        .as_ref()
                        .filter(|_| fresh(&c.installed, elapsed))
                });
            row(
                component,
                build
                    .map(|b| super::safe(&b.version))
                    .unwrap_or_else(|| "unknown".into()),
                if build.is_some() {
                    Color::Green
                } else {
                    Color::Yellow
                },
            )
        })
        .collect()
}

pub(super) fn setup_lines(snapshot: Option<&Snapshot>) -> Vec<Line<'static>> {
    let Some(s) = snapshot else {
        return vec![row("Checks", "unknown", Color::Yellow)];
    };
    let elapsed = s.captured_at.elapsed();
    let local = s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed));
    let access = local.and_then(|l| {
        l.config_access
            .value
            .filter(|_| fresh(&l.config_access, elapsed))
    });
    let config = match access {
        Some(ConfigAccess::Readable) => "[Present] validate before applying",
        Some(ConfigAccess::Absent) => "[Needs input] configuration file",
        Some(ConfigAccess::Denied) => "[Blocked] read permission",
        None => "[Unknown] refresh / inspect evidence",
    };
    let service = local.and_then(|l| {
        l.service_state
            .value
            .as_ref()
            .filter(|_| fresh(&l.service_state, elapsed))
    });
    let service = match service {
        Some(s) if s.active == "active" => "[Running] mode / identity checked on apply",
        Some(s) if s.active == "inactive" => "[Stopped] configuration and policy required",
        Some(s) if s.active == "failed" => "[Failed] inspect host diagnostics",
        _ => "[Unknown] inspect host",
    };
    vec![
        row("Configuration", config, Color::Yellow),
        row("Normal service", service, Color::DarkGray),
        row(
            "Device eligibility",
            "[Check] verified separately for each action",
            Color::Yellow,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn observed<T>(value: T) -> Observation<T> {
        Observation {
            source: String::new(),
            value: Some(value),
            observed_at_unix_us: None,
            age: Some(Duration::ZERO),
            state: ObservationState::Fresh,
            public_error: None,
        }
    }
    #[test]
    fn pool_readiness_requires_fresh_complete_evidence() {
        let pool = JoinedPool {
            pool_id: "pool".into(),
            incarnation_id: "incarnation".into(),
            membership: Some(json!({})),
            host: Some(json!({"configured": true, "effective": true})),
            observation: observed(json!({"health":0, "context":{"valid":true},
                "active":{"certificate_present":true,"health":0,"relative_period":1,"remaining_valid_periods":2},
                "staged":null})),
        };
        let mut snapshot = Snapshot {
            captured_at: std::time::Instant::now(),
            local: Observation {
                source: String::new(),
                value: None,
                observed_at_unix_us: None,
                age: None,
                state: ObservationState::Unknown,
                public_error: None,
            },
            host: observed(json!({})),
            device: observed(json!({})),
            membership: observed(vec![]),
            pools: vec![pool],
        };
        assert_eq!(
            pool_assessment(&snapshot, &snapshot.pools[0]),
            Assessment::Ready
        );
        snapshot.pools[0].observation.state = ObservationState::Stale;
        assert_eq!(
            pool_assessment(&snapshot, &snapshot.pools[0]),
            Assessment::Unknown
        );
        snapshot.pools[0].observation.state = ObservationState::Fresh;
        snapshot.pools[0].observation.value.as_mut().unwrap()["context"]["valid"] = Value::Null;
        assert_eq!(
            pool_assessment(&snapshot, &snapshot.pools[0]),
            Assessment::Unknown
        );
    }
    #[test]
    fn certificate_and_context_are_not_invented() {
        assert_eq!(generation(None), Assessment::Unknown);
        assert_eq!(generation(Some(&Value::Null)), Assessment::Attention);
        assert_eq!(
            generation(Some(&json!({"certificate_present": true, "health": 0}))),
            Assessment::Unknown
        );
        assert_eq!(
            generation(Some(&json!({"certificate_present": false}))),
            Assessment::Attention
        );
        assert_eq!(
            generation(Some(
                &json!({"certificate_present": true, "health": 0, "relative_period": 0, "remaining_valid_periods": 2})
            )),
            Assessment::Ready
        );
        assert_eq!(
            generation(Some(
                &json!({"certificate_present": true, "health": 0, "relative_period": null, "remaining_valid_periods": 2})
            )),
            Assessment::Unknown
        );
        assert_eq!(
            generation(Some(
                &json!({"certificate_present": true, "health": 0, "relative_period": 2, "remaining_valid_periods": 0})
            )),
            Assessment::Attention
        );
    }
    #[test]
    fn freshness_requires_value_and_age() {
        let mut o = Observation {
            source: String::new(),
            value: Some(1),
            observed_at_unix_us: None,
            age: Some(Duration::ZERO),
            state: ObservationState::Fresh,
            public_error: None,
        };
        assert!(fresh(&o, Duration::ZERO));
        assert!(!fresh(&o, Duration::from_secs(10)));
        o.state = ObservationState::Stale;
        assert!(!fresh(&o, Duration::ZERO));
        o.state = ObservationState::Fresh;
        o.value = None;
        assert!(!fresh(&o, Duration::ZERO));
    }
}
