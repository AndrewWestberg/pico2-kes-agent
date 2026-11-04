use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use serde_json::Value;

use super::super::{
    model::{DeviceMode, InstallationRole, Observation, ObservationState},
    observe::{ConfigAccess, JoinedPool, LocalOverview, Snapshot},
    workspace,
};
use super::releases;

/// Warning threshold (in KES periods) below which an active certificate is flagged `EXP!`.
const EXPIRING_PERIOD_THRESHOLD: u64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NextStep {
    Activity,
    Setup,
    Host,
    Pools,
    Refresh,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum PoolSort {
    #[default]
    AttentionFirst,
    ExpirySoonest,
    PoolId,
}

impl PoolSort {
    pub fn next(self) -> Self {
        match self {
            Self::AttentionFirst => Self::ExpirySoonest,
            Self::ExpirySoonest => Self::PoolId,
            Self::PoolId => Self::AttentionFirst,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AttentionFirst => "attention-first",
            Self::ExpirySoonest => "soonest-expiry",
            Self::PoolId => "pool-id",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct PoolFilter {
    pub query: String,
    pub attention_only: bool,
    pub sort: PoolSort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Assessment {
    Attention,
    Unknown,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PinPosture {
    Matched,
    Mismatch,
    Commissioning,
    ObservedUnpinned,
    Unverified,
}

pub(super) fn fresh<T>(observation: &Observation<T>, elapsed: Duration) -> bool {
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

pub(super) fn snapshot_freshness_badge(snapshot: Option<&Snapshot>) -> (String, Color) {
    let Some(s) = snapshot else {
        return ("[INIT]".into(), Color::Yellow);
    };
    let elapsed = s.captured_at.elapsed();
    let age_s = s
        .local
        .age
        .map(|a| a.saturating_add(elapsed).as_secs())
        .unwrap_or_else(|| elapsed.as_secs());
    if fresh(&s.local, elapsed)
        && (fresh(&s.device, elapsed) || s.device.state == ObservationState::Unavailable)
    {
        (format!("[FRESH {age_s}s]"), Color::Green)
    } else {
        (format!("[STALE {age_s}s]"), Color::Yellow)
    }
}

pub(super) fn pin_posture(snapshot: Option<&Snapshot>) -> (PinPosture, String, Color) {
    let Some(s) = snapshot else {
        return (
            PinPosture::Unverified,
            "Unverified (no snapshot)".into(),
            Color::Yellow,
        );
    };
    let elapsed = s.captured_at.elapsed();
    let local = s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed));
    let cfg_pin = local
        .and_then(|l| {
            l.config_summary
                .value
                .as_ref()
                .filter(|_| fresh(&l.config_summary, elapsed))
        })
        .and_then(|c| c.pinned_device_id.as_deref());
    let cfg_readable = local.and_then(|l| {
        l.config_access
            .value
            .filter(|_| fresh(&l.config_access, elapsed))
    }) == Some(ConfigAccess::Readable);

    let dev_obs = s
        .device
        .value
        .as_ref()
        .filter(|_| fresh(&s.device, elapsed));

    match (cfg_readable, cfg_pin, dev_obs) {
        (_, Some(pin), Some(dev)) => match dev.get("device_id").and_then(Value::as_str) {
            Some(live_id) if live_id == pin => (
                PinPosture::Matched,
                format!("Pinned & matched ({})", workspace::short_id(live_id)),
                Color::Green,
            ),
            Some(live_id) => (
                PinPosture::Mismatch,
                format!("MISMATCH ({} != pin)", workspace::short_id(live_id)),
                Color::Red,
            ),
            None => (
                PinPosture::Mismatch,
                "Blank device (pin expected!)".into(),
                Color::Red,
            ),
        },
        (true, None, Some(dev)) => {
            if let Some(live_id) = dev.get("device_id").and_then(Value::as_str) {
                (
                    PinPosture::ObservedUnpinned,
                    format!("Unpinned ({})", workspace::short_id(live_id)),
                    Color::Yellow,
                )
            } else {
                (
                    PinPosture::Commissioning,
                    "Blank / commissioning".into(),
                    Color::Yellow,
                )
            }
        }
        (_, Some(pin), None) => (
            PinPosture::Unverified,
            format!("Pin {} (live unverified)", workspace::short_id(pin)),
            Color::Yellow,
        ),
        (_, None, Some(dev)) => {
            let id = dev
                .get("device_id")
                .and_then(Value::as_str)
                .map(workspace::short_id)
                .unwrap_or_else(|| "blank".into());
            (
                PinPosture::ObservedUnpinned,
                format!("Observed ({id}, unverified)"),
                Color::Yellow,
            )
        }
        _ => (
            PinPosture::Unverified,
            "Unavailable / unverified".into(),
            Color::Yellow,
        ),
    }
}

/// Computes remaining KES periods and trusted wall-clock duration until expiry (`FR-005`).
/// Wall-clock duration is returned ONLY when observations are fresh (`<10s`) and
/// Computes `(remaining_periods, Option<wall_clock_duration>)` for `slot` (`"active"` or
/// `"staged"`). Wall-clock time is emitted ONLY when the pool observation, host snapshot,
/// membership, and validated local config are all `<10s` fresh, `config_identity` matches
/// the running daemon's loaded config, `context.valid == true`, and host UTC aligns with
/// the observed `current_absolute_period`.
pub(super) fn trusted_expiry_estimate(
    snapshot: &Snapshot,
    pool: &JoinedPool,
    slot: &str,
) -> Option<(u64, Option<Duration>)> {
    let now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_micros()).ok());
    trusted_expiry_estimate_at(snapshot, pool, slot, now_us)
}

pub(super) fn trusted_expiry_estimate_at(
    snapshot: &Snapshot,
    pool: &JoinedPool,
    slot: &str,
    now_unix_us: Option<u64>,
) -> Option<(u64, Option<Duration>)> {
    let elapsed = snapshot.captured_at.elapsed();
    if !fresh(&pool.observation, elapsed) {
        return None;
    }
    let obs = pool.observation.value.as_ref()?;
    let slot_val = obs.get(slot)?;
    if !slot_val.is_object() {
        return None;
    }
    if slot_val.get("certificate_present").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let remaining = slot_val
        .get("remaining_valid_periods")
        .and_then(Value::as_u64)?;
    let context_valid = obs.pointer("/context/valid").and_then(Value::as_bool) == Some(true)
        && fresh(&snapshot.host, elapsed)
        && fresh(&snapshot.membership, elapsed);
    if !context_valid {
        return Some((remaining, None));
    }
    let wall_clock = if remaining == 0 {
        Some(Duration::ZERO)
    } else {
        (|| {
            let now_us = now_unix_us?;
            let host_cfg_id = snapshot
                .host
                .value
                .as_ref()?
                .get("config_identity")
                .and_then(Value::as_str)?;
            let local = snapshot
                .local
                .value
                .as_ref()
                .filter(|_| fresh(&snapshot.local, elapsed))?;
            let summary = local
                .config_summary
                .value
                .as_ref()
                .filter(|_| fresh(&local.config_summary, elapsed))?;
            if summary.config_identity.as_deref() != Some(host_cfg_id) {
                return None;
            }
            let host_binding = pool.host.as_ref()?;
            if host_binding.get("effective").and_then(Value::as_bool) != Some(true) {
                return None;
            }
            let network = host_binding.get("network").and_then(Value::as_str)?;
            let net_cfg = summary.validated_networks.get(network)?;
            let observed_period = slot_val
                .get("current_absolute_period")
                .and_then(Value::as_u64)?;
            let now_period =
                net_cfg.timing.slot_at_time(now_us).ok()? / net_cfg.binding.slots_per_period();
            if now_period != observed_period {
                return None;
            }
            let period_us = net_cfg
                .binding
                .slots_per_period()
                .checked_mul(net_cfg.timing.slot_length_us)
                .filter(|&d| d > 0)?;
            let next_us = net_cfg
                .next_boundary_us(now_us)
                .ok()?
                .saturating_sub(now_us);
            remaining
                .checked_sub(1)?
                .checked_mul(period_us)?
                .checked_add(next_us)
                .map(Duration::from_micros)
        })()
    };
    Some((remaining, wall_clock))
}

pub(super) fn format_wall_duration(dur: Duration) -> String {
    let secs = dur.as_secs();
    if secs == 0 {
        return "0m".into();
    }
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("~{days}d {hours:02}h")
    } else if hours > 0 {
        format!("~{hours}h {mins:02}m")
    } else if mins > 0 {
        format!("~{mins}m")
    } else {
        "<1m".into()
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

pub(super) fn pool_assessment(snapshot: &Snapshot, pool: &JoinedPool) -> Assessment {
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
    if value
        .pointer("/active/remaining_valid_periods")
        .and_then(Value::as_u64)
        .is_some_and(|r| r <= EXPIRING_PERIOD_THRESHOLD)
        && generation(value.get("staged")) != Assessment::Ready
    {
        return Assessment::Attention;
    }
    match value.get("staged") {
        Some(Value::Null) => Assessment::Ready,
        Some(staged) => generation(Some(staged)),
        None => Assessment::Unknown,
    }
}

pub(super) fn pool_is_unbound(snapshot: &Snapshot, pool: &JoinedPool) -> bool {
    let elapsed = snapshot.captured_at.elapsed();
    if !fresh(&snapshot.host, elapsed) {
        return false;
    }
    match &pool.host {
        None => true,
        Some(h) => h.get("configured").and_then(Value::as_bool) == Some(false),
    }
}

fn pool_status_code(snapshot: &Snapshot, pool: &JoinedPool) -> (&'static str, Color) {
    let elapsed = snapshot.captured_at.elapsed();
    if !fresh(&snapshot.host, elapsed)
        || !fresh(&snapshot.membership, elapsed)
        || !fresh(&pool.observation, elapsed)
    {
        if pool.observation.state == ObservationState::Stale
            || (pool.observation.state == ObservationState::Fresh
                && pool.observation.value.is_some())
        {
            return ("STL?", Color::Yellow);
        }
        return ("UNK?", Color::Yellow);
    }
    if pool_is_unbound(snapshot, pool) {
        return ("UNB ", Color::Yellow);
    }
    if let Some((rem, _)) = trusted_expiry_estimate(snapshot, pool, "active")
        && rem <= EXPIRING_PERIOD_THRESHOLD
        && generation(
            pool.observation
                .value
                .as_ref()
                .and_then(|v| v.get("staged")),
        ) != Assessment::Ready
    {
        return ("EXP!", if rem == 0 { Color::Red } else { Color::Yellow });
    }
    match pool_assessment(snapshot, pool) {
        Assessment::Ready => ("RDY ", Color::Green),
        Assessment::Attention => ("ATT!", Color::Yellow),
        Assessment::Unknown => ("UNK?", Color::Yellow),
    }
}

pub(super) fn pool_order_filtered(snapshot: &Snapshot, filter: &PoolFilter) -> Vec<usize> {
    let q = filter.query.trim().to_ascii_lowercase();
    let mut indices: Vec<_> = (0..snapshot.pools.len())
        .filter(|&i| {
            let p = &snapshot.pools[i];
            if !q.is_empty()
                && !p.pool_id.to_ascii_lowercase().contains(&q)
                && !p.incarnation_id.to_ascii_lowercase().contains(&q)
            {
                return false;
            }
            if filter.attention_only && pool_assessment(snapshot, p) == Assessment::Ready {
                return false;
            }
            true
        })
        .collect();

    indices.sort_by(|&a, &b| {
        let pa = &snapshot.pools[a];
        let pb = &snapshot.pools[b];
        match filter.sort {
            PoolSort::AttentionFirst => (
                pool_assessment(snapshot, pa),
                trusted_expiry_estimate(snapshot, pa, "active").map_or(u64::MAX, |(r, _)| r),
                &pa.pool_id,
                &pa.incarnation_id,
            )
                .cmp(&(
                    pool_assessment(snapshot, pb),
                    trusted_expiry_estimate(snapshot, pb, "active").map_or(u64::MAX, |(r, _)| r),
                    &pb.pool_id,
                    &pb.incarnation_id,
                )),
            PoolSort::ExpirySoonest => (
                trusted_expiry_estimate(snapshot, pa, "active").map_or(u64::MAX, |(r, _)| r),
                pool_assessment(snapshot, pa),
                &pa.pool_id,
                &pa.incarnation_id,
            )
                .cmp(&(
                    trusted_expiry_estimate(snapshot, pb, "active").map_or(u64::MAX, |(r, _)| r),
                    pool_assessment(snapshot, pb),
                    &pb.pool_id,
                    &pb.incarnation_id,
                )),
            PoolSort::PoolId => {
                (&pa.pool_id, &pa.incarnation_id).cmp(&(&pb.pool_id, &pb.incarnation_id))
            }
        }
    });
    indices
}

fn overview_assessment(s: &Snapshot, unresolved_records: usize) -> Assessment {
    if unresolved_records > 0 {
        return Assessment::Attention;
    }
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
    let (pin, _, _) = pin_posture(Some(s));
    if pin != PinPosture::Matched {
        return if matches!(pin, PinPosture::Mismatch | PinPosture::Commissioning) {
            Assessment::Attention
        } else {
            Assessment::Unknown
        };
    }
    if !fresh(&s.host, elapsed) || !fresh(&s.device, elapsed) || !fresh(&s.membership, elapsed) {
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

pub(super) fn next_step(snapshot: Option<&Snapshot>, unresolved_records: usize) -> NextStep {
    if unresolved_records > 0 {
        return NextStep::Activity;
    }
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
    if let Some(cfg) = local
        .config_summary
        .value
        .as_ref()
        .filter(|_| fresh(&local.config_summary, elapsed))
        && cfg.pinned_device_id.is_none()
    {
        return NextStep::Setup;
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
    NextStep::Pools
}

fn tone(color: Color) -> Style {
    super::widgets::tone(color)
}

fn kv_line(key: &'static str, value: impl Into<String>, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{key:<9}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.into(), tone(color)),
    ])
}

fn pool_next_action(s: &Snapshot, pool: &JoinedPool) -> &'static str {
    let elapsed = s.captured_at.elapsed();
    if !fresh(&s.host, elapsed)
        || !fresh(&s.membership, elapsed)
        || !fresh(&pool.observation, elapsed)
    {
        return "Refresh (r)";
    }
    if pool_is_unbound(s, pool) {
        return "Bind cfg (b)";
    }
    if let Some(h) = &pool.host
        && h.get("effective").and_then(Value::as_bool) == Some(false)
    {
        return "Restart agt";
    }
    let Some(v) = &pool.observation.value else {
        return "Inspect";
    };
    let active_ok = generation(v.get("active")) == Assessment::Ready;
    let staged_val = v.get("staged");
    let staged_present = staged_val.is_some_and(|st| st.is_object());
    let staged_cert = staged_val
        .and_then(|st| st.get("certificate_present"))
        .and_then(Value::as_bool)
        == Some(true);
    if !active_ok {
        if staged_present && !staged_cert {
            return "Rotate KES (R)";
        }
        if !staged_present {
            return "Rotate KES (R)";
        }
        return "Inspect cert";
    }
    if staged_present && !staged_cert {
        return "Rotate KES (R)";
    }
    if let Some((rem, _)) = trusted_expiry_estimate(s, pool, "active")
        && rem <= EXPIRING_PERIOD_THRESHOLD
        && !staged_present
    {
        return "Rotate KES (R)";
    }
    "--"
}

pub(super) fn expiring_pool(snapshot: &Snapshot) -> Option<&JoinedPool> {
    let elapsed = snapshot.captured_at.elapsed();
    if !fresh(&snapshot.host, elapsed) || !fresh(&snapshot.membership, elapsed) {
        return None;
    }
    snapshot
        .pools
        .iter()
        .filter_map(|pool| {
            let (remaining, _) = trusted_expiry_estimate(snapshot, pool, "active")?;
            (remaining <= EXPIRING_PERIOD_THRESHOLD).then_some((pool, remaining))
        })
        .min_by_key(|(_, remaining)| *remaining)
        .map(|(pool, _)| pool)
}

fn soonest_expiry_summary(snapshot: Option<&Snapshot>) -> (String, Color) {
    let Some(s) = snapshot else {
        return (
            "Soonest KES expiry: awaiting fresh daemon & device observation".into(),
            Color::DarkGray,
        );
    };
    let elapsed = s.captured_at.elapsed();
    if !fresh(&s.host, elapsed) || !fresh(&s.membership, elapsed) {
        return (
            "Soonest KES expiry: withheld (inventory stale or unavailable)".into(),
            Color::Yellow,
        );
    }
    if s.pools.is_empty() {
        return (
            "No pools yet — open Pools and choose Add a pool (n).".into(),
            Color::Yellow,
        );
    }
    let mut best: Option<(&JoinedPool, u64, Option<Duration>)> = None;
    let mut any_stale = false;
    for pool in &s.pools {
        if !fresh(&pool.observation, elapsed) {
            any_stale = true;
            continue;
        }
        if let Some((rem, wall)) = trusted_expiry_estimate(s, pool, "active")
            && best.is_none_or(|(_, b_rem, _)| rem < b_rem)
        {
            best = Some((pool, rem, wall));
        }
    }
    match best {
        Some((pool, rem, Some(wall))) => {
            let net = pool
                .host
                .as_ref()
                .and_then(|h| h.get("network"))
                .and_then(Value::as_str)
                .unwrap_or("bound-net");
            let mut text = format!(
                "Soonest KES expiry: pool {} in {rem}p ({}, host_utc+{})",
                workspace::short_id(&pool.pool_id),
                format_wall_duration(wall),
                super::safe(net)
            );
            if rem <= EXPIRING_PERIOD_THRESHOLD {
                text.push_str(&format!(
                    " — Press R to rotate KES for pool {}",
                    workspace::short_id(&pool.pool_id)
                ));
            }
            let color = if rem == 0 {
                Color::Red
            } else if rem <= EXPIRING_PERIOD_THRESHOLD {
                Color::Yellow
            } else {
                Color::Green
            };
            (text, color)
        }
        Some((pool, rem, None)) => {
            let mut text = format!(
                "Soonest KES expiry: pool {} in {rem}p (wall-clock withheld: context unavailable)",
                workspace::short_id(&pool.pool_id)
            );
            if rem <= EXPIRING_PERIOD_THRESHOLD {
                text.push_str(&format!(
                    " — Press R to rotate KES for pool {}",
                    workspace::short_id(&pool.pool_id)
                ));
            }
            (text, Color::Yellow)
        }
        None if any_stale => (
            "Soonest KES expiry: withheld (one or more pool observations stale)".into(),
            Color::Yellow,
        ),
        None => (
            "Soonest KES expiry: no active operational certificate installed yet".into(),
            Color::Yellow,
        ),
    }
}

pub(super) fn manager_needs_reexec(local: Option<&LocalOverview>, elapsed: Duration) -> bool {
    let Some(l) = local else {
        return false;
    };
    let Some(comp) = l.components.iter().find(|c| c.component == "manager") else {
        return false;
    };
    let Some(inst) = comp
        .installed
        .value
        .as_ref()
        .filter(|_| fresh(&comp.installed, elapsed))
    else {
        return false;
    };
    let running = crate::build_info::identity("p2kesup");
    inst.version != running.version || inst.build_id != running.build_id
}

pub(super) const BACKUP_OVERVIEW_ACTIONS: &[&str] = &[
    "Create protected HPKE backup recipient keypair",
    "Emergency plaintext KES restore (local)",
    "Public recipient transfer & custody guidance",
    "Software releases & tuple updates",
    "Activity & retained backup records",
];

pub(super) fn render_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: Option<&Snapshot>,
    backup_local: Option<&LocalOverview>,
    role: InstallationRole,
    selected: usize,
    unresolved_records: usize,
) {
    if role == InstallationRole::Backup {
        render_backup_overview(frame, area, backup_local, selected, unresolved_records);
        return;
    }

    let chunks = Layout::vertical([Constraint::Length(4), Constraint::Min(10)]).split(area);
    let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let elapsed = snapshot
        .map(|s| s.captured_at.elapsed())
        .unwrap_or_default();
    let local = snapshot.and_then(|s| s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed)));
    let access = local.and_then(|l| {
        l.config_access
            .value
            .filter(|_| fresh(&l.config_access, elapsed))
    });
    let cfg_summary = local.and_then(|l| {
        l.config_summary
            .value
            .as_ref()
            .filter(|_| fresh(&l.config_summary, elapsed))
    });

    let (svc_text, svc_color) = match local.and_then(|l| {
        l.service_state
            .value
            .as_ref()
            .filter(|_| fresh(&l.service_state, elapsed))
    }) {
        Some(s) if s.load == "loaded" && s.active == "active" => (
            match s.main_pid {
                Some(pid) => format!("active (pid {pid}) [OK]"),
                None => "active [OK]".into(),
            },
            Color::Green,
        ),
        Some(s) if s.active == "failed" => ("FAILED [!!]".into(), Color::Red),
        Some(s) if s.load == "not-found" => ("not installed [!]".into(), Color::Yellow),
        Some(s) => (format!("{} [--]", super::safe(&s.active)), Color::Yellow),
        None => ("unknown [?]".into(), Color::Yellow),
    };

    let (agent_text, agent_color) = {
        let comp = local.and_then(|l| l.components.iter().find(|c| c.component == "daemon"));
        let inst = comp.and_then(|c| {
            c.installed
                .value
                .as_ref()
                .filter(|_| fresh(&c.installed, elapsed))
        });
        let run = comp.and_then(|c| {
            c.running
                .value
                .as_ref()
                .filter(|_| fresh(&c.running, elapsed))
        });
        match (inst, run) {
            (Some(i), Some(r)) if i.digest.is_some() && i.digest == r.build.digest => (
                format!("{} (match) [OK]", super::safe(&i.version)),
                Color::Green,
            ),
            (Some(i), Some(r)) => (
                format!(
                    "{} != run {} [!]",
                    super::safe(&i.version),
                    super::safe(&r.build.version)
                ),
                Color::Yellow,
            ),
            (Some(i), None) => (
                format!("{} (not running)", super::safe(&i.version)),
                Color::DarkGray,
            ),
            _ => ("unknown".into(), Color::Yellow),
        }
    };

    let running_mgr = crate::build_info::identity("p2kesup");
    let (mgr_text, mgr_color) = if manager_needs_reexec(local, elapsed) {
        (
            format!("{} [RE-EXEC NEEDED]", super::safe(running_mgr.version)),
            Color::Yellow,
        )
    } else {
        (
            format!("{} [OK]", super::safe(running_mgr.version)),
            Color::Green,
        )
    };

    let (cfg_text, cfg_color) = match (access, cfg_summary) {
        (Some(ConfigAccess::Readable), Some(c)) if c.pinned_device_id.is_some() => (
            format!("Pinned ({} pool cfg) [OK]", c.configured_pools),
            Color::Green,
        ),
        (Some(ConfigAccess::Readable), Some(_)) => {
            ("Commissioning mode [SETUP]".into(), Color::Yellow)
        }
        (Some(ConfigAccess::Readable), None) => ("Readable (parse check)".into(), Color::Yellow),
        (Some(ConfigAccess::Absent), _) => ("Missing [SETUP]".into(), Color::Yellow),
        (Some(ConfigAccess::Denied), _) => ("Access denied [!]".into(), Color::Red),
        (None, _) => ("Unknown [?]".into(), Color::Yellow),
    };

    let (swap_text, swap_color): (&str, Color) =
        match local.and_then(|l| l.swap_free.value.filter(|_| fresh(&l.swap_free, elapsed))) {
            Some(true) => ("inactive [OK]", Color::Green),
            Some(false) => ("ACTIVE [!] (disable swap)", Color::Red),
            None => ("unknown", Color::Yellow),
        };

    let (rec_text, rec_color) = if unresolved_records > 0 {
        (
            format!("{unresolved_records} need reconcile [!]"),
            Color::Yellow,
        )
    } else {
        ("none pending [OK]".into(), Color::Green)
    };

    let plat_text = local
        .map(|l| {
            let s = super::safe(&l.support);
            if s.chars().count() > 26 {
                format!("{}…", s.chars().take(25).collect::<String>())
            } else {
                s
            }
        })
        .unwrap_or_else(|| "unknown".into());

    // Right column: Device (non-attested) & Fleet
    let (usb_text, usb_color): (&str, Color) =
        match local.and_then(|l| l.usb_mode.value.filter(|_| fresh(&l.usb_mode, elapsed))) {
            Some(DeviceMode::Application) => ("Application (1209:4b45)", Color::Green),
            Some(DeviceMode::Bootloader) => ("BOOTSEL mode", Color::Yellow),
            Some(DeviceMode::Absent) => ("Not detected [!]", Color::Yellow),
            Some(DeviceMode::Ambiguous) => ("Multiple USB boards [!]", Color::Red),
            None => ("Unknown", Color::Yellow),
        };

    let (_, pin_text, pin_color) = pin_posture(snapshot);
    let dev_info = snapshot.and_then(|s| {
        s.device
            .value
            .as_ref()
            .filter(|_| fresh(&s.device, elapsed))
    });
    let serial_text = dev_info
        .and_then(|d| d.get("usb_serial"))
        .and_then(Value::as_str)
        .map(super::safe)
        .or_else(|| {
            cfg_summary
                .and_then(|c| c.usb_serial.as_deref())
                .map(|s| format!("{} (cfg)", super::safe(s)))
        })
        .unwrap_or_else(|| "unknown".into());
    let fw_text = match dev_info {
        Some(d) => {
            let ver = d
                .get("version")
                .and_then(Value::as_str)
                .map(super::safe)
                .unwrap_or_else(|| "?".into());
            let proto = d
                .get("protocol_major")
                .and_then(Value::as_u64)
                .map_or_else(|| "?".into(), |n| n.to_string());
            let stor = d
                .get("storage_version")
                .and_then(Value::as_u64)
                .map_or_else(|| "?".into(), |n| n.to_string());
            format!("{ver} (proto v{proto}, store v{stor})")
        }
        None => "unknown".into(),
    };

    let (cap_text, fleet_line1, fleet_line2, fleet_color) = match snapshot {
        Some(s) if fresh(&s.membership, elapsed) && fresh(&s.host, elapsed) => {
            let max_cap = dev_info
                .and_then(|d| d.get("capacity"))
                .and_then(Value::as_u64)
                .unwrap_or(64);
            let mut rdy = 0usize;
            let mut exp = 0usize;
            let mut unb = 0usize;
            let mut att = 0usize;
            let mut unk = 0usize;
            for p in &s.pools {
                match pool_status_code(s, p).0 {
                    "RDY " => rdy += 1,
                    "EXP!" => exp += 1,
                    "UNB " => unb += 1,
                    "ATT!" => att += 1,
                    _ => unk += 1,
                }
            }
            let cap = format!("{} / {max_cap} pools", s.pools.len());
            let l1 = format!("{rdy} ready · {exp} expiring");
            let l2 = format!("{unb} unbound · {att} attn · {unk} unk");
            let col = if exp > 0 || unb > 0 || att > 0 || unk > 0 || s.pools.is_empty() {
                Color::Yellow
            } else {
                Color::Green
            };
            (cap, l1, l2, col)
        }
        _ => (
            "unknown (inventory unavailable)".into(),
            "unknown".into(),
            "do not infer 0 pools".into(),
            Color::Yellow,
        ),
    };

    // Banner + CTA + Soonest expiry
    let step = next_step(snapshot, unresolved_records);
    let cta_text = match step {
        NextStep::Activity => "Reconcile interrupted operation in Activity (6)",
        NextStep::Setup => "Set up my Pico 2 (s)",
        NextStep::Host => "Inspect or start pico2-kes-agentd in Host (4)",
        NextStep::Pools => "Open Pools to add a pool or rotate its KES key (2)",
        NextStep::Refresh => "Refresh host & device observations (r)",
    };
    let (banner_title, banner_color) = if svc_color == Color::Red {
        (" [!!] pico2-kes-agentd failed ", Color::Red)
    } else if unresolved_records > 0 {
        (
            " [!] Unresolved operation needs reconciliation ",
            Color::Yellow,
        )
    } else if access == Some(ConfigAccess::Absent)
        || cfg_summary.is_some_and(|c| c.pinned_device_id.is_none())
    {
        (" [SETUP] Set up my Pico 2 ", Color::Yellow)
    } else {
        match snapshot
            .map(|s| overview_assessment(s, unresolved_records))
            .unwrap_or(Assessment::Unknown)
        {
            Assessment::Ready => (" [OK] Primary KES Agent Ready ", Color::Green),
            Assessment::Attention => (" [!] Fleet or Host Attention Needed ", Color::Yellow),
            Assessment::Unknown => (" [?] Observation Incomplete or Stale ", Color::Yellow),
        }
    };
    let (expiry_line, expiry_color) = soonest_expiry_summary(snapshot);
    let jump_labels = [
        cta_text,
        "Jump -> 2 Pools (KES fleet & rotations)",
        "Set up my Pico 2 (new or existing board)",
        "Jump -> 4 Host (service, config, producer hardening)",
        "Jump -> 3 Device (firmware & OTP security)",
        "Jump -> 5 Software (tuple upgrades & releases)",
        "Jump -> 6 Activity (records, plans & receipts)",
    ];
    let chosen_label = jump_labels.get(selected).copied().unwrap_or(cta_text);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!(
                        " > Action [{}/{}]: {chosen_label} ",
                        selected + 1,
                        jump_labels.len()
                    ),
                    tone(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled("[Enter]", Style::default().add_modifier(Modifier::BOLD)),
            ]),
            Line::styled(format!("   {expiry_line}"), tone(expiry_color)),
        ])
        .block(
            Block::default()
                .title(banner_title)
                .title_style(tone(banner_color).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(tone(banner_color)),
        ),
        chunks[0],
    );

    let left_lines = vec![
        kv_line("Service", svc_text, svc_color),
        kv_line("Agentd", agent_text, agent_color),
        kv_line("Manager", mgr_text, mgr_color),
        kv_line("Config", cfg_text, cfg_color),
        kv_line("Swap", swap_text, swap_color),
        kv_line("Records", rec_text, rec_color),
        kv_line("Platform", plat_text, Color::DarkGray),
    ];
    frame.render_widget(
        Paragraph::new(left_lines).block(
            Block::default()
                .title(" Host & Software ")
                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL),
        ),
        cols[0],
    );

    let right_lines = vec![
        kv_line("USB", usb_text, usb_color),
        kv_line("Pin/ID", pin_text, pin_color),
        kv_line("Serial", serial_text, Color::Cyan),
        kv_line("Firmware", fw_text, Color::Cyan),
        kv_line("Capacity", cap_text, fleet_color),
        kv_line("Fleet", fleet_line1, fleet_color),
        kv_line("States", fleet_line2, fleet_color),
    ];
    frame.render_widget(
        Paragraph::new(right_lines).block(
            Block::default()
                .title(" Device (non-attested) & Fleet ")
                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL),
        ),
        cols[1],
    );
}

fn render_backup_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    local: Option<&LocalOverview>,
    selected: usize,
    unresolved_records: usize,
) {
    let parts = Layout::vertical([Constraint::Length(8), Constraint::Min(6)]).split(area);
    let (swap_str, swap_col) = match local.and_then(|l| l.swap_free.value) {
        Some(true) => ("inactive [OK]", Color::Green),
        Some(false) => (
            "ACTIVE [!] (disable swap before plaintext restore)",
            Color::Red,
        ),
        None => ("unknown", Color::Yellow),
    };
    let (svc_str, svc_col) = match local.and_then(|l| l.service_state.value.as_ref()) {
        Some(s) if s.active == "active" => (
            "ACTIVE [!!] (primary daemon running on backup host!)",
            Color::Red,
        ),
        Some(_) => ("inactive / absent [OK]", Color::Green),
        None => ("unknown", Color::Yellow),
    };
    let cli_ver = local
        .and_then(|l| l.components.iter().find(|c| c.component == "cli"))
        .and_then(|c| c.installed.value.as_ref())
        .map(|b| super::safe(&b.version))
        .unwrap_or_else(|| "unknown".into());
    let (rec_str, rec_col) = if unresolved_records > 0 {
        (
            format!("{unresolved_records} uncertain backup record(s) — check Activity"),
            Color::Yellow,
        )
    } else {
        ("clean [OK]".into(), Color::Green)
    };

    let posture = vec![
        kv_line(
            "Role",
            "Isolated Backup Host (no daemon/device/node contact)",
            Color::Cyan,
        ),
        kv_line("Swap", swap_str, swap_col),
        kv_line("Primary", svc_str, svc_col),
        kv_line("CLI bin", cli_ver, Color::Green),
        kv_line("Records", rec_str, rec_col),
        Line::styled(
            "Private recipient keys & passphrases never leave this backup host.",
            tone(Color::Yellow),
        ),
    ];
    frame.render_widget(
        Paragraph::new(posture).block(
            Block::default()
                .title(" Backup Host Isolation & Preflight ")
                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL),
        ),
        parts[0],
    );

    let items: Vec<ListItem<'_>> = BACKUP_OVERVIEW_ACTIONS
        .iter()
        .map(|label| ListItem::new(*label))
        .collect();
    let mut state = ListState::default()
        .with_selected((selected < BACKUP_OVERVIEW_ACTIONS.len()).then_some(selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Backup Workflows ")
                    .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL),
            )
            .highlight_symbol(" > ")
            .highlight_style(tone(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        parts[1],
        &mut state,
    );
}

fn format_pool_table_row(s: &Snapshot, pool: &JoinedPool) -> Line<'static> {
    let elapsed = s.captured_at.elapsed();
    let (st_code, st_col) = pool_status_code(s, pool);
    let pool_short = workspace::short_id(&pool.pool_id);
    let inc2: String = pool.incarnation_id.chars().take(2).collect();
    let id_col = format!("{}:{}", super::safe(&pool_short), super::safe(&inc2));

    let bind_col = if !fresh(&s.host, elapsed) {
        "unknown "
    } else {
        match &pool.host {
            None => "no-cfg  ",
            Some(h) => match (
                h.get("configured").and_then(Value::as_bool),
                h.get("effective").and_then(Value::as_bool),
            ) {
                (Some(true), Some(true)) => "eff/ok  ",
                (Some(false), _) => "no-cfg  ",
                (Some(true), Some(false)) => "pend-rst",
                _ => "unknown ",
            },
        }
    };

    let obs = pool
        .observation
        .value
        .as_ref()
        .filter(|_| fresh(&pool.observation, elapsed));

    let active_col = match obs.and_then(|v| v.get("active")) {
        None => "unknown  ".to_owned(),
        Some(Value::Null) => "none     ".to_owned(),
        Some(a) => match a.get("certificate_present").and_then(Value::as_bool) {
            Some(false) => "no-cert  ".to_owned(),
            Some(true) => {
                if let Some(p) = a.get("current_absolute_period").and_then(Value::as_u64) {
                    format!("p{p:<8}")
                } else {
                    "cert/no-t".to_owned()
                }
            }
            None => "unknown  ".to_owned(),
        },
    };

    let rem_col = match trusted_expiry_estimate(s, pool, "active") {
        Some((rem, Some(wall))) => format!("{rem:>2}p ({:<9})", format_wall_duration(wall)),
        Some((rem, None)) => format!("{rem:>2}p (withheld) "),
        None => "--             ".to_owned(),
    };

    let staged_col = match obs.and_then(|v| v.get("staged")) {
        None => "unknown   ",
        Some(Value::Null) => "none      ",
        Some(st) => match (
            st.get("certificate_present").and_then(Value::as_bool),
            generation(Some(st)),
        ) {
            (Some(false), _) => "wait-cert ",
            (Some(true), Assessment::Ready) => "ready     ",
            (Some(true), _) => "attn      ",
            _ => "unknown   ",
        },
    };

    let next_col = pool_next_action(s, pool);

    Line::from(vec![
        Span::styled(
            format!("{st_code} "),
            tone(st_col).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "{id_col:<13} {bind_col:<8} {active_col:<9} {rem_col:<15} {staged_col:<10} {next_col}"
        )),
    ])
}

pub(super) fn render_pools(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: Option<&Snapshot>,
    selected: usize,
    filter: &PoolFilter,
) {
    let parts = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(area);
    let Some(s) = snapshot else {
        frame.render_widget(
            Paragraph::new("Pools: awaiting daemon & device snapshot")
                .block(Block::default().title(" Pools ").borders(Borders::ALL)),
            area,
        );
        return;
    };
    let elapsed = s.captured_at.elapsed();
    let order = pool_order_filtered(s, filter);

    let summary_text = if fresh(&s.membership, elapsed) && fresh(&s.host, elapsed) {
        let mut rdy = 0usize;
        let mut exp = 0usize;
        let mut unb = 0usize;
        let mut oth = 0usize;
        for p in &s.pools {
            match pool_status_code(s, p).0 {
                "RDY " => rdy += 1,
                "EXP!" => exp += 1,
                "UNB " => unb += 1,
                _ => oth += 1,
            }
        }
        let mut meta = format!(
            "Fleet: {}/64 · {rdy} RDY · {exp} EXP · {unb} UNB · {oth} ATT/UNK · Sort: {}",
            s.pools.len(),
            filter.sort.label()
        );
        if filter.attention_only {
            meta.push_str(" · [ATTN ONLY]");
        }
        if !filter.query.is_empty() {
            meta.push_str(&format!(" · [/{}]", super::safe(&filter.query)));
        }
        meta
    } else {
        "Fleet: membership or host binding observation stale/unavailable (never implies 0 pools)"
            .into()
    };

    let col_header = "  ST   POOL:INC      BIND     ACTIVE    REM (EST)       STAGED     NEXT";
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(summary_text, tone(Color::Cyan).add_modifier(Modifier::BOLD)),
            Line::styled(col_header, Style::default().add_modifier(Modifier::BOLD)),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        parts[0],
    );

    if order.is_empty() {
        let msg = if !s.pools.is_empty() {
            "No pools match the active filter. Press 'f' or '/' to clear filters."
        } else if fresh(&s.membership, elapsed) && fresh(&s.host, elapsed) {
            "0 pools enrolled on this Pico 2. Press 'n' to enroll a pool (or 'a' for global pool/recipient actions)."
        } else {
            "Pool inventory unavailable or stale. Ensure pico2-kes-agentd is active and press 'r' to refresh."
        };
        frame.render_widget(
            Paragraph::new(msg)
                .wrap(Wrap { trim: false })
                .block(Block::default().title(" Pools ").borders(Borders::ALL)),
            parts[1],
        );
        return;
    }

    let items: Vec<ListItem<'_>> = order
        .iter()
        .map(|&idx| ListItem::new(format_pool_table_row(s, &s.pools[idx])))
        .collect();
    let pos = order.iter().position(|&i| i == selected);
    let mut state = ListState::default().with_selected(pos);
    let title = match pos {
        Some(p) => format!(" Pools ({}/{}) ", p + 1, order.len()),
        None => format!(" Pools ({}) ", order.len()),
    };
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(title)
                    .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL),
            )
            .highlight_symbol("> ")
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)),
        parts[1],
        &mut state,
    );
}

fn slot_card_lines(
    s: &Snapshot,
    pool: &JoinedPool,
    slot: &str,
    empty_hint: &'static str,
) -> Vec<Line<'static>> {
    let elapsed = s.captured_at.elapsed();
    let Some(obs) = pool
        .observation
        .value
        .as_ref()
        .filter(|_| fresh(&pool.observation, elapsed))
    else {
        return vec![
            kv_line("Gen ID", "unknown (stale)", Color::Yellow),
            kv_line("Cert", "unknown", Color::Yellow),
            kv_line("Period", "unknown", Color::Yellow),
            kv_line("Remain", "withheld (stale)", Color::Yellow),
        ];
    };
    let Some(slot_val) = obs.get(slot) else {
        return vec![kv_line("State", "unknown", Color::Yellow)];
    };
    if slot_val.is_null() {
        return vec![
            kv_line("Gen ID", "(empty)", Color::DarkGray),
            Line::styled(empty_hint, tone(Color::DarkGray)),
        ];
    }
    let gen_id = slot_val
        .get("generation_id")
        .and_then(Value::as_str)
        .map(workspace::short_id)
        .map(|s| super::safe(&s))
        .unwrap_or_else(|| "?".into());
    let rev = slot_val
        .get("revision")
        .and_then(Value::as_u64)
        .map_or_else(|| "?".into(), |n| n.to_string());
    let health = slot_val.get("health").and_then(Value::as_u64).unwrap_or(99);
    let h_str = if health == 0 { "ok" } else { "fault" };
    let cert_present = slot_val.get("certificate_present").and_then(Value::as_bool) == Some(true);
    let cert_str = if cert_present {
        let st = slot_val
            .get("certificate_start")
            .and_then(Value::as_u64)
            .map_or_else(|| "?".into(), |n| n.to_string());
        let ex = slot_val
            .get("certificate_expiry")
            .and_then(Value::as_u64)
            .map_or_else(|| "?".into(), |n| n.to_string());
        let lt = slot_val
            .get("certificate_lifetime")
            .and_then(Value::as_u64)
            .map_or_else(|| "?".into(), |n| n.to_string());
        format!("{st}..{ex} (len {lt})")
    } else {
        "absent (install OpCert)".into()
    };
    let per_str = if cert_present {
        let abs_p = slot_val
            .get("current_absolute_period")
            .and_then(Value::as_u64)
            .map_or_else(|| "?".into(), |n| n.to_string());
        let rel_p = slot_val
            .get("relative_period")
            .and_then(Value::as_u64)
            .map_or_else(|| "?".into(), |n| n.to_string());
        format!("abs {abs_p} / rel {rel_p}")
    } else {
        "--".into()
    };
    let (rem_str, rem_col) = match trusted_expiry_estimate(s, pool, slot) {
        Some((rem, Some(wall))) => (
            format!("{rem}p ({})", format_wall_duration(wall)),
            if rem == 0 {
                Color::Red
            } else if rem <= EXPIRING_PERIOD_THRESHOLD {
                Color::Yellow
            } else {
                Color::Green
            },
        ),
        Some((rem, None)) => (format!("{rem}p (time withheld)"), Color::Yellow),
        None => ("--".into(), Color::DarkGray),
    };

    vec![
        kv_line(
            "Gen ID",
            format!("{gen_id} (r{rev}, {h_str})"),
            if health == 0 { Color::Cyan } else { Color::Red },
        ),
        kv_line(
            "Cert",
            cert_str,
            if cert_present {
                Color::Green
            } else {
                Color::Yellow
            },
        ),
        kv_line("Period", per_str, Color::Cyan),
        kv_line("Remain", rem_str, rem_col),
    ]
}

pub(super) fn render_pool_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: Option<&Snapshot>,
    pool_index: Option<usize>,
    entries: &[super::navigation::Entry],
    selected: usize,
) {
    let Some(s) = snapshot else {
        frame.render_widget(Paragraph::new("Pool: snapshot unavailable"), area);
        return;
    };
    let Some(idx) = pool_index.filter(|&i| i < s.pools.len()) else {
        frame.render_widget(
            Paragraph::new("Selected pool unavailable · press Esc to return to Pools")
                .style(tone(Color::Yellow)),
            area,
        );
        return;
    };
    let pool = &s.pools[idx];
    let elapsed = s.captured_at.elapsed();
    let (st_code, st_col) = pool_status_code(s, pool);
    let obs = pool
        .observation
        .value
        .as_ref()
        .filter(|_| fresh(&pool.observation, elapsed));
    let rev = obs
        .and_then(|v| v.get("revision"))
        .and_then(Value::as_u64)
        .map_or_else(|| "?".into(), |n| n.to_string());
    let floor = obs
        .and_then(|v| v.get("period_floor"))
        .and_then(Value::as_u64)
        .map_or_else(|| "none".into(), |n| n.to_string());
    let bind_desc = match &pool.host {
        Some(h) if fresh(&s.host, elapsed) => {
            let cfg = h.get("configured").and_then(Value::as_bool) == Some(true);
            let eff = h.get("effective").and_then(Value::as_bool) == Some(true);
            let net = h
                .get("network")
                .and_then(Value::as_str)
                .map(super::safe)
                .unwrap_or_else(|| "?".into());
            match (cfg, eff) {
                (true, true) => format!("configured+effective ({net}) [OK]"),
                (false, _) => format!("UNBOUND in config.json ({net}) — press 'b' to bind"),
                (true, false) => format!("configured ({net}), pending agentd restart"),
            }
        }
        _ if fresh(&s.host, elapsed) => "UNBOUND in config.json — press 'b' to bind".into(),
        _ => "host binding unknown".into(),
    };

    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Min(5),
    ])
    .split(area);
    let slots =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("[{}] ", st_code.trim()),
                    tone(st_col).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("Pool {} ", super::safe(&pool.pool_id))),
            ]),
            Line::from(format!(
                "Inc {} · Rev {rev} · Floor {floor} · {bind_desc}",
                super::safe(&pool.incarnation_id)
            )),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new(slot_card_lines(
            s,
            pool,
            "active",
            "Create gen -> export .vkey -> install OpCert",
        ))
        .block(
            Block::default()
                .title(" Active Slot ")
                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL),
        ),
        slots[0],
    );
    frame.render_widget(
        Paragraph::new(slot_card_lines(
            s,
            pool,
            "staged",
            "Ready to stage next KES rotation key",
        ))
        .block(
            Block::default()
                .title(" Staged Slot ")
                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL),
        ),
        slots[1],
    );

    super::action_menu(frame, rows[2], "Pool Lifecycle Actions", entries, selected);
}

pub(super) fn render_device(frame: &mut Frame<'_>, area: Rect, snapshot: Option<&Snapshot>) {
    let mut lines = Vec::new();
    let (_, pin_text, pin_col) = pin_posture(snapshot);
    lines.push(kv_line("Pin/ID", pin_text, pin_col));
    if let Some(s) = snapshot {
        let elapsed = s.captured_at.elapsed();
        let info = s
            .device
            .value
            .as_ref()
            .filter(|_| fresh(&s.device, elapsed));
        lines.push(kv_line("Observe", state(&s.device, elapsed), Color::Cyan));
        for (name, key) in [
            ("Device", "device_id"),
            ("Serial", "usb_serial"),
            ("Firmware", "version"),
            ("Build", "build_id"),
        ] {
            let value = info
                .and_then(|v| v.get(key))
                .and_then(Value::as_str)
                .map(super::safe)
                .unwrap_or_else(|| "unknown".into());
            lines.push(kv_line(name, value, Color::Cyan));
        }
    } else {
        lines.push(kv_line("Observe", "unknown", Color::Yellow));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(" Device (firmware report — non-attested) ")
                .title_style(tone(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL),
        ),
        area,
    );
}

pub(super) fn software_lines(
    snapshot: Option<&Snapshot>,
    release_state: &releases::State,
    launched_bundle: Option<&std::path::PathBuf>,
) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    if let Some(s) = snapshot {
        let elapsed = s.captured_at.elapsed();
        if let Some(local) = s.local.value.as_ref().filter(|_| fresh(&s.local, elapsed)) {
            let mut parts = Vec::new();
            for comp in ["manager", "daemon", "cli", "firmware"] {
                let ver = local
                    .components
                    .iter()
                    .find(|c| c.component == comp)
                    .and_then(|c| {
                        c.installed
                            .value
                            .as_ref()
                            .filter(|_| fresh(&c.installed, elapsed))
                            .or(c.selected.as_ref())
                    })
                    .map(|b| super::safe(&b.version))
                    .unwrap_or_else(|| "?".into());
                parts.push(format!("{comp}={ver}"));
            }
            let reexec_tag = if manager_needs_reexec(Some(local), elapsed) {
                " [RE-EXEC NEEDED]"
            } else {
                ""
            };
            out.push(Line::styled(
                format!("Installed : {}{reexec_tag}", parts.join(" · ")),
                tone(if reexec_tag.is_empty() {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ));
        }
    }
    let mode = if release_state.online {
        "online"
    } else {
        "offline"
    };
    let offers_summary = if release_state.offers.is_empty() {
        super::safe(&release_state.status)
    } else {
        let tags: Vec<String> = release_state
            .offers
            .iter()
            .take(3)
            .map(|o| {
                format!(
                    "{} [{}]",
                    super::safe(&o.selection.tag),
                    o.selection.channel
                )
            })
            .collect();
        format!(
            "{} qualified offer(s): {}",
            release_state.offers.len(),
            tags.join(", ")
        )
    };
    out.push(Line::styled(
        format!(
            "Discovery : {mode} (prerelease={}) · {offers_summary}",
            release_state.prerelease
        ),
        tone(Color::Cyan),
    ));
    if let Some(b) = launched_bundle {
        out.push(Line::styled(
            format!("--bundle  : {}", super::safe(&b.to_string_lossy())),
            tone(Color::Yellow),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};
    use serde_json::json;

    fn observed<T>(value: T) -> Observation<T> {
        Observation {
            source: "test".into(),
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
            pool_id: "a".repeat(56),
            incarnation_id: "b".repeat(32),
            membership: Some(json!({})),
            host: Some(json!({"configured": true, "effective": true})),
            observation: observed(json!({"health":0, "context":{"valid":true},
                "active":{"certificate_present":true,"health":0,"relative_period":1,"remaining_valid_periods":10},
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
    fn trusted_wall_clock_expiry_withheld_when_stale_or_untrusted() {
        let net_cfg = crate::daemon::context::NetworkConfig {
            binding: kes_core::identity::NetworkBinding::new(
                kes_core::identity::Digest32::from_bytes([0x11; 32]),
                764_824_073,
                129_600,
                62,
            )
            .unwrap(),
            timing: crate::daemon::context::SlotTiming {
                start_slot: 0,
                start_time_us: 1_000_000_000_000_000,
                slot_length_us: 1_000_000,
            },
            max_age: Duration::from_secs(30),
        };
        let mut validated_networks = std::collections::HashMap::new();
        validated_networks.insert("mainnet".to_owned(), net_cfg);
        let mut local = crate::manager::observe::local_snapshot();
        local.config_summary = observed(crate::manager::observe::ConfigSummary {
            pinned_device_id: Some("a".repeat(32)),
            usb_serial: Some("P2KES00000000001".into()),
            networks: vec!["mainnet".into()],
            configured_pools: 1,
            config_identity: Some("c".repeat(64)),
            validated_networks,
        });

        let pool = JoinedPool {
            pool_id: "1".repeat(56),
            incarnation_id: "2".repeat(32),
            membership: Some(json!({})),
            host: Some(json!({"configured": true, "effective": true, "network": "mainnet"})),
            observation: observed(json!({
                "health": 0,
                "context": {
                    "valid": true,
                    "source": "host_utc",
                    "age_us": 1_000,
                    "reason": null
                },
                "active": {
                    "certificate_present": true,
                    "health": 0,
                    "current_absolute_period": 10,
                    "relative_period": 10,
                    "remaining_valid_periods": 3
                },
                "staged": null
            })),
        };
        let mut snapshot = Snapshot {
            captured_at: std::time::Instant::now(),
            local: observed(local),
            host: observed(json!({"config_identity": "c".repeat(64)})),
            device: observed(json!({})),
            membership: observed(vec![]),
            pools: vec![pool],
        };
        // Period 10 starts at start_time_us + 10 * 129_600s; halfway through period 10 leaves
        // 64_800s (18h) in period 10 plus 2 full 129_600s (36h) periods = 324_000s (3d 18h).
        let now_us = 1_000_000_000_000_000u64 + (10 * 129_600 + 64_800) * 1_000_000;
        let (rem, wall) =
            trusted_expiry_estimate_at(&snapshot, &snapshot.pools[0], "active", Some(now_us))
                .unwrap();
        assert_eq!(rem, 3);
        assert_eq!(wall, Some(Duration::from_secs(324_000)));
        assert_eq!(format_wall_duration(wall.unwrap()), "~3d 18h");

        // Config identity drift -> periods retained, wall-clock withheld
        snapshot.host = observed(json!({"config_identity": "d".repeat(64)}));
        let (rem_drift, wall_drift) =
            trusted_expiry_estimate_at(&snapshot, &snapshot.pools[0], "active", Some(now_us))
                .unwrap();
        assert_eq!(rem_drift, 3);
        assert_eq!(wall_drift, None);
        snapshot.host = observed(json!({"config_identity": "c".repeat(64)}));

        // Context invalid -> periods retained if present, wall-clock withheld
        snapshot.pools[0].observation.value.as_mut().unwrap()["context"]["valid"] = json!(false);
        let (rem2, wall2) =
            trusted_expiry_estimate_at(&snapshot, &snapshot.pools[0], "active", Some(now_us))
                .unwrap();
        assert_eq!(rem2, 3);
        assert_eq!(wall2, None);

        // Stale observation -> completely withheld
        snapshot.pools[0].observation.state = ObservationState::Stale;
        assert!(
            trusted_expiry_estimate_at(&snapshot, &snapshot.pools[0], "active", Some(now_us))
                .is_none()
        );
    }

    #[test]
    fn pin_posture_distinguishes_matched_unpinned_and_mismatch() {
        let mut local = crate::manager::observe::local_snapshot();
        local.config_access = observed(ConfigAccess::Readable);
        local.config_summary = observed(crate::manager::observe::ConfigSummary {
            pinned_device_id: Some("a".repeat(32)),
            usb_serial: Some("P2KES00000000001".into()),
            networks: vec!["mainnet".into()],
            configured_pools: 1,
            config_identity: None,
            validated_networks: std::collections::HashMap::new(),
        });
        let mut snap = Snapshot {
            captured_at: std::time::Instant::now(),
            local: observed(local),
            host: observed(json!({})),
            device: observed(json!({"device_id": "a".repeat(32)})),
            membership: observed(vec![]),
            pools: vec![],
        };
        assert_eq!(pin_posture(Some(&snap)).0, PinPosture::Matched);

        snap.device = observed(json!({"device_id": "b".repeat(32)}));
        assert_eq!(pin_posture(Some(&snap)).0, PinPosture::Mismatch);

        snap.local
            .value
            .as_mut()
            .unwrap()
            .config_summary
            .value
            .as_mut()
            .unwrap()
            .pinned_device_id = None;
        assert_eq!(pin_posture(Some(&snap)).0, PinPosture::ObservedUnpinned);
    }

    #[test]
    fn rotation_shortcut_chooses_nearest_fresh_expiry_within_threshold() {
        let mut snapshot = Snapshot {
            captured_at: std::time::Instant::now(),
            local: Observation {
                source: "test".into(), value: None, observed_at_unix_us: None,
                age: None, state: ObservationState::Stale, public_error: None,
            },
            host: observed(json!({})),
            device: observed(json!({})),
            membership: observed(vec![]),
            pools: [4, 2, 1].into_iter().enumerate().map(|(i, remaining)| JoinedPool {
                pool_id: format!("{i:056x}"),
                incarnation_id: format!("{i:032x}"),
                membership: None,
                host: None,
                observation: observed(json!({
                    "active": {"certificate_present": true, "remaining_valid_periods": remaining}
                })),
            }).collect(),
        };
        assert_eq!(
            expiring_pool(&snapshot).unwrap().pool_id,
            format!("{:056x}", 2)
        );
        snapshot.pools[2].observation.state = ObservationState::Stale;
        assert_eq!(
            expiring_pool(&snapshot).unwrap().pool_id,
            format!("{:056x}", 1)
        );
        snapshot.pools[1].observation.value.as_mut().unwrap()["active"]["certificate_present"] =
            json!(false);
        assert!(expiring_pool(&snapshot).is_none());
        snapshot.pools[0].observation.value.as_mut().unwrap()["active"]["remaining_valid_periods"] =
            json!(0);
        assert_eq!(
            expiring_pool(&snapshot).unwrap().pool_id,
            format!("{:056x}", 0)
        );
        snapshot.membership.state = ObservationState::Stale;
        assert!(expiring_pool(&snapshot).is_none());
    }

    #[test]
    fn renders_80x24_overview_and_64_pool_table_cleanly() {
        let pools: Vec<JoinedPool> = (0..64)
            .map(|i| JoinedPool {
                pool_id: format!("{i:056x}"),
                incarnation_id: format!("{i:032x}"),
                membership: Some(json!({})),
                host: Some(
                    json!({"configured": i % 7 != 0, "effective": i % 7 != 0, "network": "mainnet"}),
                ),
                observation: observed(json!({
                    "revision": 1,
                    "health": 0,
                    "period_floor": 100,
                    "context": {
                        "valid": true,
                        "source": "host_utc",
                        "age_us": 500,
                        "reason": null
                    },
                    "active": {
                        "generation_id": format!("{i:032x}"),
                        "revision": 1,
                        "certificate_present": true,
                        "certificate_start": 100,
                        "certificate_lifetime": 62,
                        "certificate_expiry": 162,
                        "current_absolute_period": 120,
                        "relative_period": 20,
                        "remaining_valid_periods": (i as u64) % 15 + 1,
                        "health": 0
                    },
                    "staged": null
                })),
            })
            .collect();
        let snap = Snapshot {
            captured_at: std::time::Instant::now(),
            local: observed(crate::manager::observe::local_snapshot()),
            host: observed(json!({})),
            device: observed(
                json!({"device_id": "a".repeat(32), "usb_serial": "P2KES00000000001", "version": "0.2.0", "protocol_major": 1, "storage_version": 1, "capacity": 64}),
            ),
            membership: observed(vec![]),
            pools,
        };
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                let area = Rect::new(0, 2, 80, 20);
                render_overview(f, area, Some(&snap), None, InstallationRole::Primary, 0, 1);
            })
            .unwrap();
        terminal
            .draw(|f| {
                let area = Rect::new(0, 2, 80, 20);
                render_pools(f, area, Some(&snap), 0, &PoolFilter::default());
            })
            .unwrap();
        let entries = super::super::navigation::entries(
            super::super::navigation::View::Details,
            InstallationRole::Primary,
        );
        terminal
            .draw(|f| {
                let area = Rect::new(0, 2, 80, 20);
                render_pool_detail(f, area, Some(&snap), Some(0), &entries, 0);
            })
            .unwrap();
        terminal
            .draw(|f| {
                let area = Rect::new(0, 2, 80, 20);
                render_backup_overview(f, area, snap.local.value.as_ref(), 0, 0);
            })
            .unwrap();
        let activity_inv = super::super::activity::ActivityInventory::default();
        terminal
            .draw(|f| {
                let area = Rect::new(0, 2, 80, 20);
                super::super::activity::render_activity(
                    f,
                    area,
                    &activity_inv,
                    0,
                    InstallationRole::Primary,
                );
            })
            .unwrap();
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
