//! Current KES period using the daemon's genesis-anchored timing.
use crate::daemon::context::{Error, NetworkConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KesNow {
    pub slot: u64,
    pub period: u64,
    pub next_period_at_us: u64,
}

pub fn current_kes_period(network: &NetworkConfig, now_us: u64) -> Result<KesNow, Error> {
    let slot = network.timing.slot_at_time(now_us)?;
    let period = slot
        .checked_div(network.binding.slots_per_period())
        .ok_or(Error::Clock)?;
    Ok(KesNow {
        slot,
        period,
        next_period_at_us: network.next_boundary_us(now_us)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn genesis_vectors_and_boundary() {
        for (magic, epochs) in [(764824073, 208), (1, 4), (2, 0)] {
            let byron = format!(
                r#"{{"startTime":1506203091,"protocolConsts":{{"k":2160,"protocolMagic":{magic}}},"blockVersionData":{{"slotDuration":"20000"}}}}"#
            );
            let shelley = format!(
                r#"{{"networkMagic":{magic},"slotLength":1,"slotsPerKESPeriod":129600,"maxKESEvolutions":62}}"#
            );
            let network = crate::config::network_from_genesis(
                byron.as_bytes(),
                shelley.as_bytes(),
                epochs,
                Duration::from_secs(30),
            )
            .unwrap();
            let now = current_kes_period(&network, network.timing.start_time_us).unwrap();
            assert_eq!(now.slot, epochs * 21600);
            let before = current_kes_period(&network, now.next_period_at_us - 1).unwrap();
            let at = current_kes_period(&network, now.next_period_at_us).unwrap();
            assert_eq!(before.period + 1, at.period);
            if epochs == 208 {
                let n = current_kes_period(&network, 1_793_404_800_000_000).unwrap();
                assert_eq!((n.slot, n.period), (201_838_509, 1557));
            }
        }
    }
}
