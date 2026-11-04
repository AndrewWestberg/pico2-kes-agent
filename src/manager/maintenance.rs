//! Public evidence for version maintenance; no device access bypasses the daemon.

use super::{model::ReleaseSelection, release::Manifest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashSet, path::Path, time::Instant};

/// Complete public observations from one authenticated daemon scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub device_info: Value,
    pub security: Value,
    pub inventory: Value,
    pub host: Value,
    pub status: Value,
    pub pools: Vec<Value>,
}

/// Exact host configuration and public observations from the sole authenticated daemon.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WipeEvidence {
    pub config_sha256: String,
    pub state_directory: std::path::PathBuf,
    pub device_info: Value,
    pub security: Value,
    pub inventory: Value,
    pub status: Value,
}

fn request(
    socket: &Path,
    pid: u32,
    uid: u32,
    deadline: Instant,
    action: &str,
    arguments: Value,
) -> Result<Value, String> {
    let id = "00000000000000000000000000000001";
    let bytes = serde_json::to_vec(
        &json!({"version":1,"request_id":id,"action":action,"arguments":arguments}),
    )
    .map_err(|e| e.to_string())?;
    let bytes = crate::cli::client::request_until_peer(socket, &bytes, deadline, pid, uid)
        .map_err(|e| e.into_io().to_string())?;
    kes_protocol::management::Message::decode(&bytes).map_err(|_| "invalid management response")?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid management response")?;
    if value["request_id"] != id || value["outcome"] != "success" {
        return Err(value["error"]["code"]
            .as_str()
            .unwrap_or("management request failed")
            .into());
    }
    Ok(value["result"].clone())
}

fn key(v: &Value) -> Result<(&str, &str), String> {
    let p = v["pool_id"].as_str().ok_or("missing pool identity")?;
    let i = v["incarnation_id"]
        .as_str()
        .ok_or("missing incarnation identity")?;
    Ok((p, i))
}

fn host(socket: &Path, pid: u32, uid: u32, deadline: Instant) -> Result<Value, String> {
    let mut cursor = None::<String>;
    let mut first = None::<Value>;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut configured = 0usize;
    let mut effective = 0usize;
    loop {
        let mut args = json!({"page_size":16});
        if let Some(c) = &cursor {
            args["cursor"] = json!(c);
        }
        if let Some(f) = &first {
            args["snapshot_id"] = f["snapshot_id"].clone();
        }
        let page = request(socket, pid, uid, deadline, "host.observe", args)?;
        let sid = page["snapshot_id"]
            .as_str()
            .ok_or("missing host snapshot identity")?;
        if first
            .as_ref()
            .is_some_and(|f| f["snapshot_id"] != sid || f["total"] != page["total"])
        {
            return Err("host snapshot changed".into());
        }
        if first.is_none() {
            first = Some(page.clone());
        }
        let items = page["bindings"].as_array().ok_or("missing host bindings")?;
        if items.len() > 16 {
            return Err("host page too large".into());
        }
        for item in items {
            let (p, i) = key(item)?;
            if !seen.insert((p.to_owned(), i.to_owned())) {
                return Err("duplicate host binding".into());
            }
            configured += usize::from(item["configured"].as_bool().ok_or("invalid binding")?);
            effective += usize::from(item["effective"].as_bool().ok_or("invalid binding")?);
            if configured > 64 || effective > 64 || entries.len() >= 128 {
                return Err("host binding limit exceeded".into());
            }
            entries.push(item.clone());
        }
        let total = page["total"].as_u64().ok_or("missing host total")?;
        if total > 128 || entries.len() as u64 > total {
            return Err("invalid host total".into());
        }
        match &page["next_cursor"] {
            Value::Null if entries.len() as u64 == total => break,
            Value::String(next)
                if !next.is_empty() && cursor.as_ref() != Some(next) && !items.is_empty() =>
            {
                cursor = Some(next.clone())
            }
            _ => return Err("incomplete host pagination".into()),
        }
    }
    let mut result = first.ok_or("missing host page")?;
    result["bindings"] = json!(entries);
    result["next_cursor"] = Value::Null;
    Ok(result)
}

/// Read all membership and both slots, then repeat the inventory and journal boundary.
pub fn snapshot(
    socket: &Path,
    expected_pid: u32,
    expected_uid: u32,
    deadline: Instant,
) -> Result<Evidence, String> {
    let call = |action, args| request(socket, expected_pid, expected_uid, deadline, action, args);
    let host = host(socket, expected_pid, expected_uid, deadline)?;
    let device_info = call("device.info", json!({}))?;
    let security = call("device.security", json!({}))?;
    let status = call("device.status", json!({}))?;
    let inventory = call("device.inventory", json!({}))?;
    let device = device_info["device_id"]
        .as_str()
        .ok_or("commissioned device identity unavailable")?;
    if device.is_empty()
        || inventory["device_id"] != device
        || status["device_id"] != device
        || status["commissioning_state"] != "committed"
        || status["receipt_pending"] != false
        || status["revision"].as_u64().is_none()
    {
        return Err("device identity or durable status unavailable".into());
    }
    let members = inventory["pools"]
        .as_array()
        .ok_or("inventory unavailable")?;
    if members.len() > 64 || inventory["revision"].as_u64().is_none() {
        return Err("invalid inventory".into());
    }
    let mut seen = HashSet::new();
    let mut pools = Vec::with_capacity(members.len());
    for member in members {
        let (p, i) = key(member)?;
        if !seen.insert((p.to_owned(), i.to_owned())) {
            return Err("duplicate inventory identity".into());
        }
        let revision = member["revision"]
            .as_u64()
            .ok_or("missing membership revision")?;
        let pool = call("pool.observe", json!({"pool_id":p,"incarnation_id":i}))?;
        if key(&pool)? != (p, i)
            || pool["device_id"] != device
            || pool["revision"].as_u64() != Some(revision)
            || !pool["failure"].is_null()
        {
            return Err("pool changed or failed during scan".into());
        }
        pools.push(pool);
    }
    if call("device.inventory", json!({}))? != inventory {
        return Err("inventory changed during scan".into());
    }
    let final_host = call(
        "host.observe",
        json!({"page_size":1,"snapshot_id":host["snapshot_id"]}),
    )?;
    if final_host["snapshot_id"] != host["snapshot_id"] {
        return Err("host journal changed during scan".into());
    }
    let end_status = call("device.status", json!({}))?;
    if end_status["device_id"] != device
        || end_status["revision"] != status["revision"]
        || end_status["receipt_pending"] != false
    {
        return Err("device state changed during scan".into());
    }
    let result = Evidence {
        device_info,
        security,
        inventory,
        host,
        status,
        pools,
    };
    validate(&result)?;
    Ok(result)
}

fn number(v: &Value, name: &str) -> Result<u64, String> {
    v[name].as_u64().ok_or_else(|| format!("missing {name}"))
}

fn generation(v: &Value) -> Result<Option<(u64, u64)>, String> {
    v["generation_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("missing generation identity")?;
    v["artifact_digest"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("missing artifact digest")?;
    number(v, "revision")?;
    number(v, "period")?;
    if !matches!(v["health"].as_u64(), Some(0..=4)) {
        return Err("unknown generation health".into());
    }
    let present = v["certificate_present"]
        .as_bool()
        .ok_or("missing certificate state")?;
    if !present {
        for field in [
            "certificate_start",
            "certificate_lifetime",
            "certificate_expiry",
            "relative_period",
            "remaining_valid_periods",
        ] {
            if v.get(field) != Some(&Value::Null) {
                return Err("invalid absent certificate".into());
            }
        }
        number(v, "current_absolute_period")?;
        return Ok(None);
    }
    let start = number(v, "certificate_start")?;
    let expiry = start
        .checked_add(number(v, "certificate_lifetime")?)
        .ok_or("certificate expiry overflow")?;
    if v["certificate_expiry"].as_u64() != Some(expiry) {
        return Err("invalid certificate expiry".into());
    }
    let current = number(v, "current_absolute_period")?;
    if v["relative_period"].as_u64() != current.checked_sub(start)
        || v["remaining_valid_periods"].as_u64() != Some(expiry.saturating_sub(current))
    {
        return Err("invalid certificate period context".into());
    }
    Ok(Some((start, expiry)))
}

fn validate(e: &Evidence) -> Result<(), String> {
    let members = e.inventory["pools"]
        .as_array()
        .ok_or("inventory unavailable")?;
    if members.len() > 64 || e.pools.len() != members.len() {
        return Err("incomplete inventory".into());
    }
    number(&e.inventory, "revision")?;
    number(&e.status, "revision")?;
    number(&e.host, "journal_position")?;
    for field in ["device_id", "usb_serial", "build_id"] {
        e.device_info[field]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("missing {field}"))?;
    }
    number(&e.device_info, "storage_version")?;
    for field in [
        "usb_serial",
        "profile",
        "stepping",
        "jedec_id",
        "sfdp_header",
        "bootkey0",
    ] {
        e.security[field]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("missing security {field}"))?;
    }
    if e.security["usb_serial"] != e.device_info["usb_serial"] {
        return Err("security report serial mismatch".into());
    }
    for field in [
        "chip_revision",
        "rom_version",
        "critical",
        "boot_flags0",
        "boot_flags1",
        "page2_lock0",
        "page2_lock1",
        "page63_lock0",
        "page63_lock1",
        "debugen",
        "debugen_lock",
        "density_bits_minus_one",
    ] {
        number(&e.security, field)?;
    }
    if e.security["redundancy_ok"].as_bool().is_none()
        || e.security["storage_blank_at_boot"].as_bool().is_none()
    {
        return Err("security report unavailable".into());
    }
    if e.inventory["device_id"] != e.device_info["device_id"]
        || e.status["device_id"] != e.device_info["device_id"]
        || e.status["commissioning_state"] != "committed"
        || e.status["receipt_pending"] != false
    {
        return Err("device status unavailable".into());
    }
    e.host["snapshot_id"]
        .as_str()
        .ok_or("missing journal identity")?;
    e.host["config_identity"]
        .as_str()
        .ok_or("missing config identity")?;
    e.host["bindings"]
        .as_array()
        .ok_or("missing host bindings")?;
    let mut seen = HashSet::new();
    for member in members {
        let k = key(member)?;
        if !seen.insert(k) {
            return Err("duplicate membership".into());
        }
        let pool = e
            .pools
            .iter()
            .find(|p| key(p).ok() == Some(k))
            .ok_or("missing pool evidence")?;
        if pool["device_id"] != e.device_info["device_id"]
            || pool["revision"] != member["revision"]
            || pool.get("failure") != Some(&Value::Null)
            || pool["context"]["valid"] != true
        {
            return Err("pool context unavailable".into());
        }
        if !matches!(pool["health"].as_u64(), Some(0..=4)) {
            return Err("unknown pool health".into());
        }
        if !pool
            .get("period_floor")
            .is_some_and(|v| v.is_null() || v.as_u64().is_some())
        {
            return Err("invalid period floor".into());
        }
        for (role, code) in [("active", 0), ("staged", 1)] {
            let slot = pool.get(role).ok_or("missing generation slot")?;
            if !slot.is_null() {
                if slot["role"].as_u64() != Some(code) {
                    return Err("invalid generation role".into());
                }
                generation(slot)?;
                if pool["period_floor"].as_u64().is_some_and(|floor| {
                    slot["current_absolute_period"]
                        .as_u64()
                        .is_none_or(|current| current < floor)
                }) {
                    return Err("context period below accepted floor".into());
                }
            }
        }
        if !pool["active"].is_null()
            && !pool["staged"].is_null()
            && pool["active"]["generation_id"] == pool["staged"]["generation_id"]
        {
            return Err("duplicate generation identity".into());
        }
        for name in ["revision", "timestamp_us", "high_water_us"] {
            number(&pool["publication"], name)?;
        }
        if !matches!(
            pool["publication"]["kind"].as_str(),
            Some("none" | "drop" | "key")
        ) {
            return Err("unknown publication state".into());
        }
        let publication = &pool["publication"];
        if number(publication, "timestamp_us")? > number(publication, "high_water_us")? {
            return Err("invalid publication high-water".into());
        }
        if publication["kind"] == "key" {
            if pool["active"].is_null()
                || publication["generation_id"] != pool["active"]["generation_id"]
                || publication["relative_period"] != pool["active"]["period"]
                || publication["certificate_digest"].as_str().is_none()
            {
                return Err("publication does not match active generation".into());
            }
        } else if ["generation_id", "relative_period", "certificate_digest"]
            .iter()
            .any(|field| publication.get(*field) != Some(&Value::Null))
        {
            return Err("invalid empty publication descriptor".into());
        }
    }
    Ok(())
}

fn same_generation(old: &Value, new: &Value) -> Result<(), String> {
    for k in [
        "generation_id",
        "artifact_digest",
        "certificate_start",
        "certificate_lifetime",
        "certificate_expiry",
    ] {
        if old[k] != new[k] {
            return Err(format!("generation {k} changed"));
        }
    }
    if number(new, "revision")? < number(old, "revision")?
        || number(new, "period")? < number(old, "period")?
        || number(new, "current_absolute_period")? < number(old, "current_absolute_period")?
    {
        return Err("generation period or revision regressed".into());
    }
    Ok(())
}

/// Compare retained state without treating missing evidence as an expiry or a successful update.
pub fn compare(before: &Evidence, after: &Evidence) -> Result<(), String> {
    compare_inner(before, after, &[])
}

fn compare_inner(
    before: &Evidence,
    after: &Evidence,
    authorized: &[ReconciledMutation],
) -> Result<(), String> {
    validate(before)?;
    validate(after)?;
    for field in [
        "usb_serial",
        "profile",
        "stepping",
        "jedec_id",
        "sfdp_header",
        "bootkey0",
        "chip_revision",
        "rom_version",
        "critical",
        "boot_flags0",
        "boot_flags1",
        "page2_lock0",
        "page2_lock1",
        "page63_lock0",
        "page63_lock1",
        "debugen",
        "debugen_lock",
        "density_bits_minus_one",
        "redundancy_ok",
    ] {
        if before.security[field] != after.security[field] {
            return Err("security or fitted storage report changed".into());
        }
    }
    if before.device_info["device_id"] != after.device_info["device_id"]
        || before.device_info["usb_serial"] != after.device_info["usb_serial"]
        || before.host["config_identity"] != after.host["config_identity"]
    {
        return Err("device or configuration continuity is uncertain".into());
    }
    if authorized.is_empty()
        && (before.inventory["revision"] != after.inventory["revision"]
            || before.status["revision"] != after.status["revision"]
            || before.host["snapshot_id"] != after.host["snapshot_id"]
            || before.host["journal_position"] != after.host["journal_position"]
            || before.host["bindings"] != after.host["bindings"])
    {
        return Err("device, recipient, membership or journal continuity is uncertain".into());
    }
    if !authorized.is_empty() {
        if number(&after.inventory, "revision")? < number(&before.inventory, "revision")?
            || number(&after.status, "revision")? < number(&before.status, "revision")?
        {
            return Err("device revision regressed".into());
        }
        let kept = |v: &Value| -> Result<Vec<Value>, String> {
            let mut result = Vec::new();
            for binding in v.as_array().ok_or("host bindings unavailable")? {
                let k = key(binding)?;
                if !authorized.iter().any(|a| {
                    a.generation.is_none() && (a.pool.as_str(), a.incarnation.as_str()) == k
                }) {
                    result.push(binding.clone());
                }
            }
            Ok(result)
        };
        if kept(&before.host["bindings"])? != kept(&after.host["bindings"])? {
            return Err("unexplained binding change".into());
        }
    }
    let mut used = vec![false; authorized.len()];
    for old in &before.pools {
        let k = key(old)?;
        let new = match after.pools.iter().find(|p| key(p).ok() == Some(k)) {
            Some(value) => value,
            None => {
                let (index, authority) = authorized
                    .iter()
                    .enumerate()
                    .find(|(_, a)| {
                        a.generation.is_none() && (a.pool.as_str(), a.incarnation.as_str()) == k
                    })
                    .ok_or("pool disappeared without reconciled deletion")?;
                if authority.expected_revision < number(old, "revision")? {
                    return Err("deletion predates pre-state".into());
                }
                let high_water = authority
                    .deletion_high_water
                    .ok_or("deletion publication evidence unavailable")?;
                let prior_high_water = number(&old["publication"], "high_water_us")?;
                if high_water < prior_high_water
                    || (old["publication"]["kind"] == "key" && high_water <= prior_high_water)
                {
                    return Err("deletion publication high-water regressed".into());
                }
                used[index] = true;
                continue;
            }
        };
        let old_floor = old["period_floor"].as_u64();
        let new_floor = new["period_floor"].as_u64();
        if number(new, "revision")? < number(old, "revision")?
            || old_floor.is_some_and(|floor| new_floor.is_none_or(|next| next < floor))
        {
            return Err("pool revision or period floor regressed".into());
        }
        let activated = !old["staged"].is_null()
            && !new["active"].is_null()
            && old["staged"]["generation_id"] == new["active"]["generation_id"];
        if activated {
            same_generation(&old["staged"], &new["active"])?;
            let (start, expiry) =
                generation(&new["active"])?.ok_or("activation requires a certificate")?;
            let current = number(&new["active"], "current_absolute_period")?;
            if current < start || current >= expiry {
                return Err("activation lacks valid certificate context".into());
            }
        }
        for role in ["active", "staged"] {
            let previous = &old[role];
            if previous.is_null() {
                if !new[role].is_null() && !(role == "active" && activated) {
                    return Err("unexplained generation appeared".into());
                }
                continue;
            }
            if role == "staged" && activated {
                if !new["staged"].is_null() {
                    return Err("unexplained staged generation".into());
                }
                continue;
            }
            if role == "active" && activated {
                continue;
            }
            if new[role].is_null() {
                if role == "staged"
                    && let Some((index, authority)) =
                        authorized.iter().enumerate().find(|(_, a)| {
                            (a.pool.as_str(), a.incarnation.as_str()) == k
                                && a.generation.as_deref() == previous["generation_id"].as_str()
                        })
                {
                    if authority.expected_revision < number(old, "revision")?
                        || authority.expected_revision >= number(new, "revision")?
                    {
                        return Err("discard revision outside observed interval".into());
                    }
                    used[index] = true;
                    continue;
                }
                let (_, expiry) = generation(previous)?.ok_or("expiry requires a certificate")?;
                if new_floor.is_none_or(|floor| floor < expiry) {
                    return Err("generation disappeared without proven expiry".into());
                }
            } else {
                same_generation(previous, &new[role])?;
            }
        }
        let a = &old["publication"];
        let b = &new["publication"];
        for field in ["revision", "timestamp_us", "high_water_us"] {
            if number(b, field)? < number(a, field)? {
                return Err("publication regressed".into());
            }
        }
        if a != b {
            if number(b, "revision")? <= number(a, "revision")?
                || number(b, "timestamp_us")? <= number(a, "high_water_us")?
            {
                return Err("publication changed without forward revision and timestamp".into());
            }
            let kind = b["kind"].as_str().ok_or("publication unavailable")?;
            if kind == "key" {
                if b["generation_id"] != new["active"]["generation_id"]
                    || b["relative_period"].as_u64().is_none()
                    || b["certificate_digest"].as_str().is_none()
                {
                    return Err("publication not bound to active generation".into());
                }
                if a["kind"] == "key"
                    && a["generation_id"] == b["generation_id"]
                    && (a["certificate_digest"] != b["certificate_digest"]
                        || number(b, "relative_period")? < number(a, "relative_period")?)
                {
                    return Err("publication continuity lost".into());
                }
            } else if kind != "drop" || (!activated && new["active"] != Value::Null) {
                return Err("unexplained publication change".into());
            }
        }
    }
    for pool in &after.pools {
        if !before
            .pools
            .iter()
            .any(|old| key(old).ok() == key(pool).ok())
        {
            return Err("unexplained pool appeared".into());
        }
    }
    if used.iter().any(|v| !v) {
        return Err("reconciled operation not reflected in observed state".into());
    }
    Ok(())
}

/// Approval expires when any revision, target, journal or accepted public state changes.
pub fn revalidate(before: &Evidence, now: &Evidence) -> Result<(), String> {
    compare(before, now)?;
    if before.inventory != now.inventory
        || before.device_info != now.device_info
        || before.security != now.security
        || before.status != now.status
    {
        return Err("reviewed device state changed".into());
    }
    for old in &before.pools {
        let target = key(old)?;
        let current = now
            .pools
            .iter()
            .find(|p| key(p).ok() == Some(target))
            .ok_or("reviewed pool disappeared")?;
        for field in [
            "revision",
            "period_floor",
            "publication",
            "health",
            "failure",
        ] {
            if old[field] != current[field] {
                return Err("reviewed pool state changed".into());
            }
        }
        for role in ["active", "staged"] {
            for field in [
                "generation_id",
                "revision",
                "role",
                "period",
                "health",
                "artifact_digest",
                "certificate_present",
                "certificate_start",
                "certificate_lifetime",
                "certificate_expiry",
            ] {
                if old[role][field] != current[role][field] {
                    return Err("reviewed generation changed".into());
                }
            }
            if old[role].is_null() != current[role].is_null() {
                return Err("reviewed slot changed".into());
            }
        }
    }
    Ok(())
}

/// The daemon authenticates the configured pin and serial before producing device.info.
pub fn admit_firmware(
    e: &Evidence,
    serial: &str,
    selected: &ReleaseSelection,
    manifest: &Manifest,
) -> Result<(), String> {
    validate(e)?;
    if e.device_info["usb_serial"] != serial || serial.is_empty() {
        return Err("pinned serial mismatch".into());
    }
    let storage = number(&e.device_info, "storage_version")?;
    if !manifest.compatibility.storage_versions.contains(&storage)
        || !manifest
            .compatibility
            .security_profiles
            .iter()
            .any(|p| e.device_info["security_profile"] == *p)
        || e.security["profile"] != e.device_info["security_profile"]
        || e.security["stepping"] != "A2"
        || !manifest
            .compatibility
            .hardware
            .iter()
            .any(|v| v == "rp2350-a2")
        || e.security["jedec_id"] != "ef4016"
        || e.security["sfdp_header"] != "534644500a0100ff00080117800000ff"
        || e.security["density_bits_minus_one"].as_u64() != Some(0x1ffffff)
        || e.security["redundancy_ok"] != true
        || e.device_info["protocol_major"].as_u64() != Some(1)
        || !manifest
            .compatibility
            .usb_profiles
            .iter()
            .any(|v| v == "usb-protocol-1")
        || !selected
            .components
            .iter()
            .any(|c| c.component == "firmware")
    {
        return Err("firmware or current storage/security compatibility unavailable".into());
    }
    Ok(())
}

pub fn postcheck(
    before: &Evidence,
    after: &Evidence,
    expected_build: &str,
    expected_storage: u64,
) -> Result<(), String> {
    if after.device_info["build_id"] != expected_build
        || after.device_info["storage_version"].as_u64() != Some(expected_storage)
        || after.security["storage_blank_at_boot"] != false
    {
        return Err("selected live firmware build or storage mismatch".into());
    }
    compare(before, after)
}

/// Created only by querying the original operation through the authenticated daemon.
pub struct ReconciledMutation {
    pool: String,
    incarnation: String,
    generation: Option<String>,
    operation_id: String,
    sequence: u64,
    expected_revision: u64,
    deletion_high_water: Option<u64>,
}

fn reconcile_original(
    receipt_path: &Path,
    device_id: &str,
    socket: &Path,
    pid: u32,
    uid: u32,
    deadline: Instant,
    completed: &[crate::daemon::journal::CompletedMutation],
) -> Result<ReconciledMutation, String> {
    use kes_core::{
        identity::{DeviceId, Digest32, GenerationId, IncarnationId, OperationId, PoolId},
        operation::{Action, GenerationTarget, Mutation, PoolTarget},
    };
    let receipt = super::lifecycle::load_public_receipt(receipt_path).map_err(|e| e.to_string())?;
    let saved = receipt
        .response
        .as_ref()
        .ok_or("original receipt has no device request digest")?;
    let digest = saved
        .pointer("/result/request_digest")
        .and_then(Value::as_str)
        .ok_or("original receipt has no device request digest")?;
    let digest_id = Digest32::parse_hex(digest).map_err(|_| "invalid original request digest")?;
    let operation = receipt.request["operation_id"]
        .as_str()
        .ok_or("missing operation identity")?;
    let operation_id =
        OperationId::parse_hex(operation).map_err(|_| "invalid operation identity")?;
    let entry = completed
        .iter()
        .find(|entry| {
            entry.key.operation_id == *operation_id.as_bytes()
                && entry.key.request_digest == *digest_id.as_bytes()
        })
        .ok_or("original operation is not completed in journal")?;
    let intent: Value =
        serde_json::from_slice(&entry.intent).map_err(|_| "invalid journal intent")?;
    if intent != receipt.request {
        return Err("receipt does not match original journal intent".into());
    }
    let args = &receipt.request["arguments"];
    let (pool, incarnation) = key(args)?;
    let target = PoolTarget {
        pool: PoolId::parse_hex(pool).map_err(|_| "invalid pool")?,
        incarnation: IncarnationId::parse_hex(incarnation).map_err(|_| "invalid incarnation")?,
    };
    let (action, generation, kind) = match receipt.request["action"].as_str() {
        Some("pool.delete") => (
            Action::Delete {
                target,
                publication_time_us: None,
            },
            None,
            "deleted",
        ),
        Some("generation.discard") => {
            let id = args["generation_id"].as_str().ok_or("missing generation")?;
            let generation = GenerationId::parse_hex(id).map_err(|_| "invalid generation")?;
            (
                Action::Discard {
                    target: GenerationTarget {
                        pool: target,
                        generation,
                    },
                },
                Some(id.to_owned()),
                "applied",
            )
        }
        _ => return Err("original receipt is not deletion or discard".into()),
    };
    let result = request(
        socket,
        pid,
        uid,
        deadline,
        "operation.reconcile",
        json!({"operation_id":operation,"request_digest":digest}),
    )?;
    if result["operation_id"] != operation
        || result["request_digest"] != digest
        || result["kind"] != kind
    {
        return Err("original operation did not reconcile as committed".into());
    }
    if kind == "deleted" && (result["pool_id"] != pool || result["incarnation_id"] != incarnation) {
        return Err("reconciled deletion target mismatch".into());
    }
    let sequence = number(&result, "sequence")?;
    if sequence != entry.key.sequence {
        return Err("reconciled sequence mismatch".into());
    }
    let device = DeviceId::parse_hex(device_id).map_err(|_| "invalid device identity")?;
    let revision = number(&receipt.request, "expected_revision")?;
    let mutation = Mutation::managed(device, sequence, operation_id, revision, action)
        .map_err(|_| "invalid original operation")?;
    if mutation.usb_digest() != digest_id {
        return Err("original receipt target does not match authenticated request digest".into());
    }
    let deletion_high_water = if kind == "deleted" {
        let high_water = number(&result, "high_water_us")?;
        if result.get("drop_timestamp_us").is_none() {
            return Err("missing deletion publication evidence".into());
        }
        if !result["drop_timestamp_us"].is_null()
            && result["drop_timestamp_us"].as_u64() != Some(high_water)
        {
            return Err("invalid deletion publication evidence".into());
        }
        Some(high_water)
    } else {
        None
    };
    Ok(ReconciledMutation {
        pool: pool.to_owned(),
        incarnation: incarnation.to_owned(),
        generation,
        operation_id: operation.to_owned(),
        sequence,
        expected_revision: revision,
        deletion_high_water,
    })
}

fn journal_snapshot(config: &str, entries: &[crate::daemon::journal::CompletedMutation]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(config.as_bytes());
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hash.update(entry.key.sequence.to_be_bytes());
        hash.update(entry.key.operation_id);
        hash.update(entry.key.request_digest);
        hash.update(entry.terminal.result_digest);
        hash.update(Sha256::digest(&entry.intent));
        hash.update(Sha256::digest(&entry.terminal.public_result));
    }
    kes_core::identity::Digest32::from_bytes(hash.finalize().into()).to_string()
}

/// Account only original completed deletion/discard operations, authenticated against
/// the daemon and the complete retained journal at both snapshot boundaries.
pub fn compare_authorized(
    before: &Evidence,
    after: &Evidence,
    receipts: &[std::path::PathBuf],
    socket: &Path,
    peer: (u32, u32),
    deadline: Instant,
    journal_path: &Path,
) -> Result<(), String> {
    let (pid, uid) = peer;
    validate(before)?;
    validate(after)?;
    if receipts.is_empty() {
        return compare(before, after);
    }
    if receipts.len() > 128 {
        return Err("too many reconciliation receipts".into());
    }
    let entries = crate::daemon::journal::inspect_completed(journal_path, uid, deadline)
        .map_err(|e| format!("journal inspection failed: {e:?}"))?;
    let start = usize::try_from(number(&before.host, "journal_position")?)
        .map_err(|_| "journal position overflow")?;
    let end = usize::try_from(number(&after.host, "journal_position")?)
        .map_err(|_| "journal position overflow")?;
    if end != entries.len() || start > end || end - start != receipts.len() {
        return Err("journal contains unaccounted operations".into());
    }
    let config = before.host["config_identity"]
        .as_str()
        .ok_or("config identity unavailable")?;
    if after.host["config_identity"] != config
        || before.host["snapshot_id"] != journal_snapshot(config, &entries[..start])
        || after.host["snapshot_id"] != journal_snapshot(config, &entries)
    {
        return Err("journal prefix or snapshot identity mismatch".into());
    }
    let device = before.device_info["device_id"]
        .as_str()
        .ok_or("device identity unavailable")?;
    let mut authorized = Vec::with_capacity(receipts.len());
    for path in receipts {
        let mutation =
            reconcile_original(path, device, socket, pid, uid, deadline, &entries[start..])?;
        if authorized
            .iter()
            .any(|a: &ReconciledMutation| a.operation_id == mutation.operation_id)
        {
            return Err("duplicate reconciled operation".into());
        }
        authorized.push(mutation);
    }
    for entry in &entries[start..] {
        if !authorized.iter().any(|a| {
            a.sequence == entry.key.sequence
                && a.operation_id
                    == kes_core::identity::OperationId::from_bytes(entry.key.operation_id)
                        .to_string()
        }) {
            return Err("journal operation not independently reconciled".into());
        }
    }
    let final_host = request(
        socket,
        pid,
        uid,
        deadline,
        "host.observe",
        json!({"page_size":1,"snapshot_id":after.host["snapshot_id"]}),
    )?;
    if final_host["snapshot_id"] != after.host["snapshot_id"] {
        return Err("journal changed during reconciliation".into());
    }
    compare_inner(before, after, &authorized)
}

/// Reopen the original protected record without advancing or rewriting it.
pub struct RecoveryObservation {
    pub record: super::model::MaintenanceRecord,
    pub live: Option<Evidence>,
    pub assessment: Result<(), String>,
}

pub fn observe_recovery(
    store: &super::records::RecordStore,
    operation: &kes_core::identity::OperationId,
    socket: &Path,
    expected_pid: u32,
    expected_uid: u32,
    deadline: Instant,
) -> Result<RecoveryObservation, String> {
    let record = store
        .load(operation)
        .map_err(|e| e.to_string())?
        .supported()
        .map_err(|e| e.to_string())?;
    let before: Evidence = serde_json::from_str(
        record
            .pre_observations
            .first()
            .ok_or("original pre-state unavailable")?,
    )
    .map_err(|_| "original pre-state invalid")?;
    let live = match snapshot(socket, expected_pid, expected_uid, deadline) {
        Ok(value) => value,
        Err(error) => {
            return Ok(RecoveryObservation {
                record,
                live: None,
                assessment: Err(error),
            });
        }
    };
    let assessment = if record.action != "firmware-update" {
        Err("not a firmware maintenance record".into())
    } else if !record.checkpoints.iter().any(|c| c.name == "activated") {
        Err("transfer and flush are not confirmed by the original record".into())
    } else if let Some(firmware) = record
        .selected
        .as_ref()
        .and_then(|s| s.components.iter().find(|c| c.component == "firmware"))
    {
        match before.device_info["storage_version"].as_u64() {
            Some(storage) => postcheck(&before, &live, &firmware.build_id, storage),
            None => Err("original storage version unavailable".into()),
        }
    } else {
        Err("original selected firmware unavailable".into())
    };
    Ok(RecoveryObservation {
        record,
        live: Some(live),
        assessment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn generation(id: &str, role: u64, period: u64) -> Value {
        json!({"generation_id":id,"revision":1,"role":role,"period":period,"health":0,
          "artifact_digest":"aa","certificate_present":true,"certificate_start":10,
          "certificate_lifetime":10,"certificate_expiry":20,"current_absolute_period":12,
          "relative_period":2,"remaining_valid_periods":8,"reason":null})
    }
    fn evidence() -> Evidence {
        Evidence {
            device_info: json!({"device_id":"device","usb_serial":"serial","build_id":"build","storage_version":1}),
            security: json!({"usb_serial":"serial","profile":"unlocked","stepping":"A2","jedec_id":"aa","sfdp_header":"aa","bootkey0":"aa","chip_revision":2,"rom_version":2,"critical":0,"boot_flags0":0,"boot_flags1":0,"page2_lock0":0,"page2_lock1":0,"page63_lock0":0,"page63_lock1":0,"debugen":0,"debugen_lock":0,"density_bits_minus_one":0,"redundancy_ok":true,"storage_blank_at_boot":false}),
            inventory: json!({"device_id":"device","revision":1,"pools":[{"pool_id":"p","incarnation_id":"i","revision":1}]}),
            host: json!({"snapshot_id":"journal","config_identity":"config","journal_position":0,"bindings":[]}),
            status: json!({"device_id":"device","revision":1,"commissioning_state":"committed","receipt_pending":false}),
            pools: vec![
                json!({"device_id":"device","pool_id":"p","incarnation_id":"i","revision":1,"health":0,
              "active":generation("a",0,2),"staged":generation("b",1,0),"period_floor":12,"failure":null,
              "context":{"valid":true},"publication":{"revision":1,"timestamp_us":1,"high_water_us":1,"kind":"key","generation_id":"a","relative_period":2,"certificate_digest":"cc"}}),
            ],
        }
    }
    #[test]
    fn forward_evolution_and_activation_are_not_rollback() {
        let before = evidence();
        let mut after = before.clone();
        after.pools[0]["active"]["period"] = json!(3);
        after.pools[0]["active"]["revision"] = json!(2);
        after.pools[0]["period_floor"] = json!(13);
        for role in ["active", "staged"] {
            after.pools[0][role]["current_absolute_period"] = json!(13);
            after.pools[0][role]["relative_period"] = json!(3);
            after.pools[0][role]["remaining_valid_periods"] = json!(7);
        }
        after.pools[0]["publication"]["revision"] = json!(2);
        after.pools[0]["publication"]["timestamp_us"] = json!(2);
        after.pools[0]["publication"]["high_water_us"] = json!(2);
        after.pools[0]["publication"]["relative_period"] = json!(3);
        assert!(compare(&before, &after).is_ok());
        let mut activated = before.clone();
        activated.pools[0]["active"] = generation("b", 0, 2);
        activated.pools[0]["staged"] = Value::Null;
        activated.pools[0]["publication"]["revision"] = json!(2);
        activated.pools[0]["publication"]["timestamp_us"] = json!(2);
        activated.pools[0]["publication"]["high_water_us"] = json!(2);
        activated.pools[0]["publication"]["generation_id"] = json!("b");
        assert!(compare(&before, &activated).is_ok());
    }
    #[test]
    fn expiry_requires_proven_floor_and_context() {
        let mut before = evidence();
        before.pools[0]["staged"] = Value::Null;
        let mut after = before.clone();
        after.pools[0]["active"] = Value::Null;
        after.pools[0]["period_floor"] = json!(20);
        after.pools[0]["publication"] = json!({"revision":2,"timestamp_us":2,"high_water_us":2,"kind":"drop","generation_id":null,"relative_period":null,"certificate_digest":null});
        assert!(compare(&before, &after).is_ok());
        after.pools[0]["period_floor"] = json!(19);
        assert!(compare(&before, &after).is_err());
        after.pools[0]["period_floor"] = json!(20);
        after.pools[0]["context"]["valid"] = json!(false);
        assert!(compare(&before, &after).is_err());
    }
    #[test]
    fn only_the_exact_reconciled_discard_explains_disappearance() {
        let before = evidence();
        let mut after = before.clone();
        after.pools[0]["staged"] = Value::Null;
        after.pools[0]["revision"] = json!(2);
        after.inventory["pools"][0]["revision"] = json!(2);
        let mut authority = ReconciledMutation {
            pool: "p".into(),
            incarnation: "i".into(),
            generation: Some("b".into()),
            operation_id: "op".into(),
            sequence: 1,
            expected_revision: 1,
            deletion_high_water: None,
        };
        assert!(compare(&before, &after).is_err());
        assert!(compare_inner(&before, &after, std::slice::from_ref(&authority)).is_ok());
        authority.generation = Some("other".into());
        assert!(compare_inner(&before, &after, &[authority]).is_err());
    }
    #[test]
    fn deletion_needs_exact_original_target() {
        let before = evidence();
        let mut after = before.clone();
        after.pools.clear();
        after.inventory["pools"] = json!([]);
        let authority = ReconciledMutation {
            pool: "p".into(),
            incarnation: "i".into(),
            generation: None,
            operation_id: "op".into(),
            sequence: 1,
            expected_revision: 1,
            deletion_high_water: Some(2),
        };
        assert!(compare(&before, &after).is_err());
        assert!(compare_inner(&before, &after, &[authority]).is_ok());
    }
    #[test]
    fn reviewed_device_build_and_storage_cannot_be_substituted() {
        let before = evidence();
        let mut changed = before.clone();
        changed.device_info["build_id"] = json!("other");
        assert!(revalidate(&before, &changed).is_err());
        changed = before.clone();
        changed.device_info["storage_version"] = json!(2);
        assert!(revalidate(&before, &changed).is_err());
        assert!(postcheck(&before, &changed, "other", 1).is_err());
    }
    #[test]
    fn missing_unknown_regression_and_overflow_are_uncertain() {
        let before = evidence();
        let mut after = before.clone();
        after.pools[0]["staged"] = Value::Null;
        assert!(compare(&before, &after).is_err());
        after = before.clone();
        after.pools[0]["period_floor"] = json!(11);
        assert!(compare(&before, &after).is_err());
        after = before.clone();
        after.inventory["pools"] = json!([]);
        assert!(compare(&before, &after).is_err());
        after = before.clone();
        after.pools[0]["context"]["valid"] = json!(false);
        assert!(compare(&before, &after).is_err());
        after = before.clone();
        after.pools[0]["active"]["certificate_start"] = json!(u64::MAX);
        assert!(compare(&before, &after).is_err());
    }
}
