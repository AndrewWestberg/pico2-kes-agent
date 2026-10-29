use kes_protocol::usb::{GenerationStatus, PublicationKind, StatusResponse};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Disconnected,
    Recovering,
    Ready,
    NotYetValid,
    Expired,
    DelayedEvolution,
    StorageFailure,
    EntropyFailure,
    PeriodUnavailable,
}

impl Health {
    pub const fn from_device(code: u8) -> Self {
        match code {
            0 => Self::Ready,
            1 => Self::NotYetValid,
            2 => Self::Expired,
            3 => Self::DelayedEvolution,
            4 => Self::PeriodUnavailable,
            13 => Self::EntropyFailure,
            _ => Self::StorageFailure,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Recovering => "recovering",
            Self::Ready => "ready",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::DelayedEvolution => "delayed_evolution",
            Self::StorageFailure => "storage_failure",
            Self::EntropyFailure => "entropy_failure",
            Self::PeriodUnavailable => "period_unavailable",
        }
    }
}

pub fn unavailable(recovering: bool, pool: Option<kes_core::identity::PoolId>) -> Value {
    let health = if recovering {
        Health::Recovering
    } else {
        Health::Disconnected
    };
    let mut result = json!({
        "health": health.as_str(),
        "action": if recovering {
            "wait for durable operation reconciliation"
        } else {
            "check USB power, permissions, cable, and the configured device identity"
        },
    });
    if let Some(pool) = pool {
        result["pool_id"] = Value::String(pool.to_string());
    }
    result
}

pub fn response(status: StatusResponse, recovering: bool) -> Value {
    let mut result = serde_json::Map::new();
    result.insert("device_id".into(), Value::String(status.device.to_string()));
    result.insert("revision".into(), json!(status.revision));
    result.insert(
        "health".into(),
        Value::String(
            if recovering {
                Health::Recovering
            } else {
                Health::from_device(status.health)
            }
            .as_str()
            .to_owned(),
        ),
    );
    result.insert(
        "commissioning_state".into(),
        Value::String(
            match status.commissioning_state {
                0 => "blank",
                1 => "committed",
                _ => "unavailable",
            }
            .to_owned(),
        ),
    );
    result.insert("receipt_pending".into(), json!(status.receipt_pending));
    if let Some(pool) = status.pool {
        result.insert(
            "pool_id".into(),
            Value::String(pool.target.pool.to_string()),
        );
        result.insert(
            "incarnation_id".into(),
            Value::String(pool.target.incarnation.to_string()),
        );
        result.insert("revision".into(), json!(pool.revision));
        result.insert(
            "health".into(),
            Value::String(Health::from_device(pool.health).as_str().to_owned()),
        );
        result.insert(
            "active".into(),
            pool.active.map(generation).unwrap_or(Value::Null),
        );
        result.insert(
            "staged".into(),
            pool.staged.map(generation).unwrap_or(Value::Null),
        );
        result.insert(
            "publication_revision".into(),
            json!(pool.publication.revision),
        );
        result.insert(
            "publication_timestamp_us".into(),
            json!(pool.publication.timestamp_us),
        );
        result.insert(
            "high_water_us".into(),
            json!(pool.publication.high_water_us),
        );
        result.insert(
            "publication_state".into(),
            Value::String(publication_kind(pool.publication.kind).to_owned()),
        );
    }
    if let Some(next) = status.next_pool {
        result.insert(
            "continuation_cursor".into(),
            Value::String(next.to_string()),
        );
    }
    Value::Object(result)
}

fn generation(value: GenerationStatus) -> Value {
    json!({
        "generation_id": value.generation.to_string(),
        "revision": value.revision,
        "role": if value.role == 0 { "active" } else { "staged" },
        "period": value.period,
        "health": Health::from_device(value.health).as_str(),
        "artifact_digest": value.artifact_digest.to_string(),
    })
}

fn publication_kind(value: PublicationKind) -> &'static str {
    match value {
        PublicationKind::None => "none",
        PublicationKind::Drop => "drop",
        PublicationKind::Key { .. } => "key",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_health_state_has_a_stable_name() {
        assert_eq!(Health::Disconnected.as_str(), "disconnected");
        assert_eq!(Health::Recovering.as_str(), "recovering");
        assert_eq!(Health::from_device(0), Health::Ready);
        assert_eq!(Health::from_device(1), Health::NotYetValid);
        assert_eq!(Health::from_device(2), Health::Expired);
        assert_eq!(Health::from_device(3), Health::DelayedEvolution);
        assert_eq!(Health::from_device(4), Health::PeriodUnavailable);
        assert_eq!(Health::from_device(12), Health::StorageFailure);
        assert_eq!(Health::from_device(13), Health::EntropyFailure);
    }
}
