use serde_json::Value;

pub fn human(response: &Value) -> Option<String> {
    let result = response.get("result")?;
    let health = result.get("health")?.as_str()?;
    let mut fields = vec![format!("health={health}")];
    if let Some(device) = result.get("device_id").and_then(Value::as_str) {
        fields.push(format!("device={device}"));
    }
    if let Some(pool) = result
        .get("pool")
        .and_then(Value::as_object)
        .or_else(|| result.as_object())
    {
        if let Some(pool_id) = pool.get("pool_id").and_then(Value::as_str) {
            fields.push(format!("pool={pool_id}"));
        }
        if let Some(incarnation) = pool.get("incarnation_id").and_then(Value::as_str) {
            fields.push(format!("incarnation={incarnation}"));
        }
    }
    if let Some(action) = result.get("action").and_then(Value::as_str) {
        fields.push(format!("action={action}"));
    }
    Some(fields.join(" "))
}
