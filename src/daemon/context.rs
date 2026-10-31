//! Genesis-anchored KES context from operator-maintained host UTC.

use kes_core::{
    identity::{IncarnationId, NetworkBinding, PoolId},
    operation::PoolTarget,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotTiming {
    pub start_slot: u64,
    pub start_time_us: u64,
    pub slot_length_us: u64,
}

impl SlotTiming {
    pub fn time_at_slot(&self, slot: u64) -> Result<u64, Error> {
        let elapsed = slot.checked_sub(self.start_slot).ok_or(Error::Clock)?;
        self.start_time_us
            .checked_add(
                elapsed
                    .checked_mul(self.slot_length_us)
                    .ok_or(Error::Clock)?,
            )
            .ok_or(Error::Clock)
    }

    pub fn slot_at_time(&self, time_us: u64) -> Result<u64, Error> {
        let elapsed = time_us
            .checked_sub(self.start_time_us)
            .ok_or(Error::BeforeShelley)?;
        let slots = elapsed
            .checked_div(self.slot_length_us)
            .ok_or(Error::Clock)?;
        self.start_slot.checked_add(slots).ok_or(Error::Clock)
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub binding: NetworkBinding,
    pub timing: SlotTiming,
    pub max_age: Duration,
}

impl NetworkConfig {
    pub fn next_boundary_us(&self, now_us: u64) -> Result<u64, Error> {
        if now_us < self.timing.start_time_us {
            return Ok(self.timing.start_time_us);
        }
        let slot = self.timing.slot_at_time(now_us)?;
        let period = slot / self.binding.slots_per_period();
        let next_slot = period
            .checked_add(1)
            .and_then(|next| next.checked_mul(self.binding.slots_per_period()))
            .ok_or(Error::Clock)?;
        self.timing.time_at_slot(next_slot)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetContext {
    pub target: PoolTarget,
    pub network: NetworkBinding,
    pub period: u64,
    pub session: u64,
    pub sequence: u64,
    pub lease_seconds: u8,
    pub publication_time_us: u64,
}

pub trait Clock {
    fn now_us(&self) -> Result<u64, Error>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_us(&self) -> Result<u64, Error> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?;
        u64::try_from(duration.as_micros()).map_err(|_| Error::Clock)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidConfiguration(&'static str),
    Clock,
    BeforeShelley,
    UnknownNetwork,
    SequenceExhausted,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "context I/O: {error}"),
            Self::InvalidConfiguration(reason) => {
                write!(formatter, "invalid context configuration: {reason}")
            }
            Self::Clock => {
                formatter.write_str("host clock or timing arithmetic is outside supported range")
            }
            Self::BeforeShelley => {
                formatter.write_str("host clock precedes the Shelley transition")
            }
            Self::UnknownNetwork => formatter.write_str("pool references an unknown network"),
            Self::SequenceExhausted => formatter.write_str("context sequence exhausted"),
        }
    }
}
impl std::error::Error for Error {}

pub struct ContextProvider<C: Clock> {
    clock: C,
    session: u64,
    networks: HashMap<String, NetworkConfig>,
    target_sequences: HashMap<(PoolId, IncarnationId), u64>,
}

impl<C: Clock> ContextProvider<C> {
    pub fn new(
        clock: C,
        configs: impl IntoIterator<Item = (String, NetworkConfig)>,
    ) -> Result<Self, Error> {
        let mut networks = HashMap::new();
        for (name, config) in configs {
            validate_network_config(&config)?;
            if networks.insert(name, config).is_some() {
                return Err(Error::InvalidConfiguration("duplicate network name"));
            }
        }
        let mut random = [0; 8];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let session = u64::from_be_bytes(random);
        random.zeroize();
        Ok(Self {
            clock,
            session,
            networks,
            target_sequences: HashMap::new(),
        })
    }

    pub const fn session(&self) -> u64 {
        self.session
    }

    /// Changes the session on reconnect so prior-transport context cannot be reused.
    pub fn restart_session(&mut self) -> Result<u64, Error> {
        self.session = self
            .session
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        self.target_sequences.clear();
        Ok(self.session)
    }

    pub fn context_for(&mut self, name: &str, target: PoolTarget) -> Result<TargetContext, Error> {
        let config = self.networks.get(name).ok_or(Error::UnknownNetwork)?;
        let now_us = self.clock.now_us()?;
        let slot = config.timing.slot_at_time(now_us)?;
        let period = slot / config.binding.slots_per_period();
        let sequence = self
            .target_sequences
            .entry((target.pool, target.incarnation))
            .or_insert(0);
        let current = *sequence;
        *sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let lease_seconds = u8::try_from(config.max_age.as_secs())
            .map_err(|_| Error::InvalidConfiguration("lease exceeds 255 seconds"))?;
        Ok(TargetContext {
            target,
            network: config.binding,
            period,
            session: self.session,
            sequence: current,
            lease_seconds,
            publication_time_us: now_us,
        })
    }

    /// A scheduling failure only delays retry; it never supplies context authority.
    pub fn next_wake_delay(&self) -> Duration {
        let Ok(now_us) = self.clock.now_us() else {
            return HEARTBEAT_INTERVAL;
        };
        let mut delay = HEARTBEAT_INTERVAL;
        for config in self.networks.values() {
            // Match the whole-second lease encoded on USB, not its input milliseconds.
            delay = delay.min(Duration::from_secs(config.max_age.as_secs()) / 2);
            if let Ok(boundary) = config.next_boundary_us(now_us) {
                delay = delay.min(Duration::from_micros(boundary - now_us));
            }
        }
        delay
    }
}

pub fn validate_network_config(config: &NetworkConfig) -> Result<(), Error> {
    if config.timing.slot_length_us == 0
        || config.binding.slots_per_period() == 0
        || !(1..=30).contains(&config.max_age.as_secs())
    {
        return Err(Error::InvalidConfiguration(
            "invalid timing or lease bounds",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kes_core::identity::Digest32;
    use std::cell::Cell;

    struct TestClock(Cell<Option<u64>>);
    impl Clock for TestClock {
        fn now_us(&self) -> Result<u64, Error> {
            self.0.get().ok_or(Error::Clock)
        }
    }

    fn network() -> NetworkConfig {
        NetworkConfig {
            binding: NetworkBinding::new(Digest32::from_bytes([7; 32]), 42, 10, 64).unwrap(),
            timing: SlotTiming {
                start_slot: 0,
                start_time_us: 1_000_000,
                slot_length_us: 500_000,
            },
            max_age: DEFAULT_MAX_AGE,
        }
    }

    fn target() -> PoolTarget {
        PoolTarget {
            pool: PoolId::from_bytes([1; 28]),
            incarnation: IncarnationId::from_bytes([2; 16]),
        }
    }

    fn provider(now_us: u64, network: NetworkConfig) -> ContextProvider<TestClock> {
        ContextProvider::new(
            TestClock(Cell::new(Some(now_us))),
            [("test".into(), network)],
        )
        .unwrap()
    }

    #[test]
    fn context_age_rejects_unencodable_lease_boundaries() {
        let mut config = network();
        for (milliseconds, accepted) in
            [(1_000, true), (30_999, true), (999, false), (31_000, false)]
        {
            config.max_age = Duration::from_millis(milliseconds);
            assert_eq!(
                validate_network_config(&config).is_ok(),
                accepted,
                "{milliseconds} ms"
            );
        }
    }

    #[test]
    fn fresh_sample_crosses_boundary_without_cached_period_or_timestamp() {
        let mut provider = provider(5_999_999, network());
        for (now, period, sequence) in [(5_999_999, 0, 0), (6_000_000, 1, 1), (6_000_001, 1, 2)] {
            provider.clock.0.set(Some(now));
            let context = provider.context_for("test", target()).unwrap();
            assert_eq!(
                (
                    context.period,
                    context.publication_time_us,
                    context.sequence
                ),
                (period, now, sequence)
            );
            assert_eq!(context.network, network().binding);
            assert_eq!(context.target, target());
        }
    }

    #[test]
    fn mainnet_absolute_slot_and_upstream_regression_vector() {
        let timing = SlotTiming {
            start_slot: 4_492_800,
            start_time_us: 1_596_059_091_000_000,
            slot_length_us: 1_000_000,
        };
        let config = NetworkConfig {
            timing,
            binding: NetworkBinding::new(Digest32::from_bytes([7; 32]), 764_824_073, 129_600, 62)
                .unwrap(),
            max_age: DEFAULT_MAX_AGE,
        };
        let mut provider = provider(timing.start_time_us, config);
        assert_eq!(provider.context_for("test", target()).unwrap().period, 34);
        assert_eq!(
            timing.time_at_slot(35 * 129_600).unwrap() - timing.start_time_us,
            43_200_000_000
        );
        provider.clock.0.set(Some(1_793_404_800_000_000));
        assert_eq!(
            timing.slot_at_time(1_793_404_800_000_000).unwrap(),
            201_838_509
        );
        assert_eq!(provider.context_for("test", target()).unwrap().period, 1557);
    }

    #[test]
    fn invalid_clock_pre_shelley_and_overflow_withhold_context() {
        let mut provider = provider(999_999, network());
        assert!(matches!(
            provider.context_for("test", target()),
            Err(Error::BeforeShelley)
        ));
        provider.clock.0.set(None);
        assert!(matches!(
            provider.context_for("test", target()),
            Err(Error::Clock)
        ));
        provider.clock.0.set(Some(u64::MAX));
        provider.networks.get_mut("test").unwrap().timing = SlotTiming {
            start_slot: u64::MAX,
            start_time_us: 0,
            slot_length_us: 1,
        };
        assert!(matches!(
            provider.context_for("test", target()),
            Err(Error::Clock)
        ));
        assert!(provider.target_sequences.is_empty());
        assert!(network().timing.time_at_slot(u64::MAX).is_err());
    }

    #[test]
    fn wake_uses_earliest_network_boundary_and_encoded_lease() {
        let mut provider = provider(5_750_000, network());
        let mut other = network();
        other.timing.start_time_us = 800_000;
        provider.networks.insert("other".into(), other);
        assert_eq!(provider.next_wake_delay(), Duration::from_millis(50));
        provider.clock.0.set(Some(5_800_000));
        assert_eq!(provider.next_wake_delay(), Duration::from_millis(200));
        provider.clock.0.set(Some(6_000_000));
        assert_eq!(provider.next_wake_delay(), Duration::from_millis(4_800));
        provider.networks.get_mut("other").unwrap().max_age = Duration::from_millis(1_999);
        assert_eq!(
            provider
                .context_for("other", target())
                .unwrap()
                .lease_seconds,
            1
        );
        assert_eq!(provider.next_wake_delay(), Duration::from_millis(500));
    }

    #[test]
    fn transition_and_failed_clock_schedule_bounded_retries() {
        let mut provider = provider(750_000, network());
        assert_eq!(provider.next_wake_delay(), Duration::from_millis(250));
        assert!(matches!(
            provider.context_for("test", target()),
            Err(Error::BeforeShelley)
        ));
        provider.clock.0.set(Some(1_000_000));
        assert_eq!(provider.next_wake_delay(), HEARTBEAT_INTERVAL);
        provider.clock.0.set(None);
        assert_eq!(provider.next_wake_delay(), HEARTBEAT_INTERVAL);
        assert!(matches!(
            provider.context_for("test", target()),
            Err(Error::Clock)
        ));
        provider.clock.0.set(Some(u64::MAX));
        assert!(
            provider.networks["test"]
                .next_boundary_us(u64::MAX)
                .is_err()
        );
        assert_eq!(provider.next_wake_delay(), HEARTBEAT_INTERVAL);
    }

    #[test]
    fn reconnect_changes_session_and_resets_target_sequences() {
        let mut provider = provider(6_000_000, network());
        provider.session = 41;
        let before = provider.context_for("test", target()).unwrap();
        assert_eq!(provider.context_for("test", target()).unwrap().sequence, 1);
        assert_eq!(provider.restart_session().unwrap(), 42);
        let after = provider.context_for("test", target()).unwrap();
        assert_ne!(before.session, after.session);
        assert_eq!(after.sequence, 0);
        provider
            .target_sequences
            .insert((target().pool, target().incarnation), u64::MAX);
        assert!(matches!(
            provider.context_for("test", target()),
            Err(Error::SequenceExhausted)
        ));
        provider.session = u64::MAX;
        assert!(matches!(
            provider.restart_session(),
            Err(Error::SequenceExhausted)
        ));
    }
}
