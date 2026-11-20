//! Human and JSON rendering for unified daemon `status`.

use serde_json::Value;

pub fn render_status(result: &Value, json_mode: bool) -> Result<String, String> {
    if json_mode {
        return serde_json::to_string_pretty(result).map_err(|e| e.to_string());
    }
    let mut out = String::new();
    let health = result
        .get("health")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let revision = result
        .get("revision")
        .and_then(Value::as_u64)
        .map(|r| r.to_string())
        .unwrap_or_else(|| "-".into());
    out.push_str(&format!("health: {health}  revision: {revision}\n"));

    if let Some(pending) = result.get("pending_operation").filter(|v| !v.is_null()) {
        let action = pending
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        out.push_str(&format!(
            "WARNING: pending operation ({action}) — run `p2kes reconcile`\n"
        ));
    }

    if let Some(dev) = result.get("device").filter(|v| !v.is_null()) {
        let id = dev.get("device_id").and_then(Value::as_str).unwrap_or("-");
        let serial = dev.get("usb_serial").and_then(Value::as_str).unwrap_or("-");
        let proto = dev
            .get("usb_protocol_major")
            .and_then(Value::as_u64)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "device: {id}  serial: {serial}  usb_protocol_major: {proto}\n"
        ));
    }

    if let Some(pools) = result.get("pools").and_then(Value::as_array) {
        if pools.is_empty() {
            out.push_str("pools: none\n");
        } else {
            out.push_str(&format!("pools ({}):\n", pools.len()));
            for pool in pools {
                let pid = pool.get("pool_id").and_then(Value::as_str).unwrap_or("-");
                let inc = pool
                    .get("incarnation_id")
                    .and_then(Value::as_str)
                    .unwrap_or("-");
                let active = pool
                    .get("active")
                    .and_then(|a| a.get("generation_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("none");
                let staged = pool
                    .get("staged")
                    .and_then(|s| s.get("generation_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("none");
                out.push_str(&format!(
                    "  {pid}  inc={inc}  active={active}  staged={staged}\n"
                ));
            }
        }
    }
    Ok(out)
}
