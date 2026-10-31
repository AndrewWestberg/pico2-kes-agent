//! Bounded `cardano-cli query tip` context acquisition.

use kes_core::{
    identity::{Digest32, IncarnationId, NetworkBinding, PoolId},
    operation::PoolTarget,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const MAX_QUERY_OUTPUT: usize = 64 * 1024;
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EraSegment {
    pub start_slot: u64,
    pub start_time_us: u64,
    pub slot_length_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSelector {
    Mainnet,
    Testnet(u32),
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub cardano_cli: PathBuf,
    pub node_socket: PathBuf,
    pub genesis_file: PathBuf,
    pub expected_genesis_digest: Digest32,
    pub selector: NetworkSelector,
    pub binding: NetworkBinding,
    pub era_history: Vec<EraSegment>,
    pub max_age: Duration,
    pub query_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub absolute_period: u64,
    pub publication_time_us: u64,
    pub observed_tip_slot: u64,
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
    fn synchronized(&self) -> bool;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_us(&self) -> Result<u64, Error> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?;
        u64::try_from(duration.as_micros()).map_err(|_| Error::Clock)
    }

    fn synchronized(&self) -> bool {
        // modes = 0 queries kernel time discipline without changing the clock.
        let mut query: libc::timex = unsafe { std::mem::zeroed() };
        let state = unsafe { libc::adjtimex(&mut query) };
        clock_synchronized(state, query.status)
    }
}

fn clock_synchronized(state: libc::c_int, status: libc::c_int) -> bool {
    matches!(
        state,
        libc::TIME_OK | libc::TIME_INS | libc::TIME_DEL | libc::TIME_OOP | libc::TIME_WAIT
    ) && status & (libc::STA_UNSYNC | libc::STA_CLOCKERR) == 0
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidConfiguration(&'static str),
    GenesisMismatch,
    UnsynchronizedClock,
    Clock,
    QueryTimeout,
    QueryFailed,
    OutputTooLarge,
    InvalidOutput,
    FutureTip,
    StaleTip,
    RegressiveTip,
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
            Self::GenesisMismatch => {
                formatter.write_str("genesis file digest does not match configured network")
            }
            Self::UnsynchronizedClock => formatter.write_str("host clock is not synchronized"),
            Self::Clock => formatter.write_str("host clock is outside supported range"),
            Self::QueryTimeout => formatter.write_str("cardano-cli query timed out"),
            Self::QueryFailed => formatter.write_str("cardano-cli query failed"),
            Self::OutputTooLarge => formatter.write_str("cardano-cli output exceeded bound"),
            Self::InvalidOutput => formatter.write_str("cardano-cli returned invalid tip JSON"),
            Self::FutureTip => formatter.write_str("node tip is in the future"),
            Self::StaleTip => formatter.write_str("node tip is stale"),
            Self::RegressiveTip => formatter.write_str("node tip regressed"),
            Self::UnknownNetwork => formatter.write_str("pool references an unknown network"),
            Self::SequenceExhausted => formatter.write_str("context sequence exhausted"),
        }
    }
}
impl std::error::Error for Error {}

struct NetworkState {
    config: NetworkConfig,
    observation: Option<Observation>,
    last_refresh: Option<Instant>,
}

pub struct ContextProvider<C: Clock> {
    clock: C,
    session: u64,
    networks: HashMap<String, NetworkState>,
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
            if networks
                .insert(
                    name,
                    NetworkState {
                        config,
                        observation: None,
                        last_refresh: None,
                    },
                )
                .is_some()
            {
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

    /// Invalidates all freshness after a USB reconnect. Session identifiers
    /// are process-random at startup and monotonically changed thereafter so a
    /// reconnected device can never accept context from the prior transport.
    pub fn restart_session(&mut self) -> Result<u64, Error> {
        self.session = self
            .session
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        self.target_sequences.clear();
        for state in self.networks.values_mut() {
            state.observation = None;
            state.last_refresh = None;
        }
        Ok(self.session)
    }

    pub fn refresh(&mut self, name: &str) -> Result<Observation, Error> {
        if !self.clock.synchronized() {
            return Err(Error::UnsynchronizedClock);
        }
        let state = self.networks.get_mut(name).ok_or(Error::UnknownNetwork)?;
        verify_genesis(&state.config)?;
        let now_us = self.clock.now_us()?;
        let tip = query_tip(&state.config)?;
        let tip_time_us = time_at_slot(&state.config.era_history, tip.slot)?;
        if tip_time_us > now_us {
            return Err(Error::FutureTip);
        }
        let max_age_us = u64::try_from(state.config.max_age.as_micros())
            .map_err(|_| Error::InvalidConfiguration("max age"))?;
        if now_us - tip_time_us > max_age_us {
            return Err(Error::StaleTip);
        }
        if state
            .observation
            .is_some_and(|previous| tip.slot < previous.observed_tip_slot)
        {
            return Err(Error::RegressiveTip);
        }
        let current_slot = slot_at_time(&state.config.era_history, now_us)?;
        let period = current_slot / state.config.binding.slots_per_period();
        let observation = Observation {
            absolute_period: period,
            publication_time_us: now_us,
            observed_tip_slot: tip.slot,
        };
        state.observation = Some(observation);
        state.last_refresh = Some(Instant::now());
        Ok(observation)
    }

    pub fn context_for(&mut self, name: &str, target: PoolTarget) -> Result<TargetContext, Error> {
        let refresh = self
            .networks
            .get(name)
            .ok_or(Error::UnknownNetwork)?
            .last_refresh
            .is_none_or(|instant| instant.elapsed() >= REFRESH_INTERVAL);
        if refresh {
            self.refresh(name)?;
        }
        let state = self.networks.get(name).ok_or(Error::UnknownNetwork)?;
        let observation = state.observation.ok_or(Error::StaleTip)?;
        let sequence = self
            .target_sequences
            .entry((target.pool, target.incarnation))
            .or_insert(0);
        let current = *sequence;
        *sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let lease_seconds = u8::try_from(state.config.max_age.as_secs())
            .map_err(|_| Error::InvalidConfiguration("lease exceeds 255 seconds"))?;
        Ok(TargetContext {
            target,
            network: state.config.binding,
            period: observation.absolute_period,
            session: self.session,
            sequence: current,
            lease_seconds,
            publication_time_us: observation.publication_time_us,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tip {
    slot: u64,
    #[serde(default, rename = "syncProgress")]
    _sync_progress: Option<serde_json::Value>,
    #[serde(default, rename = "block")]
    _block: Option<u64>,
    #[serde(default, rename = "epoch")]
    _epoch: Option<u64>,
    #[serde(default, rename = "era")]
    _era: Option<String>,
    #[serde(default, rename = "hash")]
    _hash: Option<String>,
    #[serde(default, rename = "slotInEpoch")]
    _slot_in_epoch: Option<u64>,
    #[serde(default, rename = "slotsToEpochEnd")]
    _slots_to_epoch_end: Option<u64>,
}

fn query_tip(config: &NetworkConfig) -> Result<Tip, Error> {
    let mut command = Command::new(&config.cardano_cli);
    command
        .arg("query")
        .arg("tip")
        .arg("--socket-path")
        .arg(&config.node_socket);
    match config.selector {
        NetworkSelector::Mainnet => {
            command.arg("--mainnet");
        }
        NetworkSelector::Testnet(magic) => {
            command.arg("--testnet-magic").arg(magic.to_string());
        }
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or(Error::QueryFailed)?;
    let stderr = child.stderr.take().ok_or(Error::QueryFailed)?;
    let output_thread = thread::spawn(move || bounded_read(stdout));
    let error_thread = thread::spawn(move || bounded_read(stderr));
    let deadline = Instant::now() + config.query_timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = output_thread.join();
            let _ = error_thread.join();
            return Err(Error::QueryTimeout);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = output_thread.join().map_err(|_| Error::QueryFailed)??;
    let error = error_thread.join().map_err(|_| Error::QueryFailed)??;
    if output.len() > MAX_QUERY_OUTPUT || error.len() > MAX_QUERY_OUTPUT {
        return Err(Error::OutputTooLarge);
    }
    if !status.success() {
        return Err(Error::QueryFailed);
    }
    serde_json::from_slice(&output).map_err(|_| Error::InvalidOutput)
}

fn bounded_read(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take((MAX_QUERY_OUTPUT + 1) as u64)
        .read_to_end(&mut output)?;
    Ok(output)
}

pub fn validate_network_config(config: &NetworkConfig) -> Result<(), Error> {
    if config.era_history.is_empty()
        || config.binding.slots_per_period() == 0
        || !(1..=30).contains(&config.max_age.as_secs())
        || config.query_timeout.is_zero()
    {
        return Err(Error::InvalidConfiguration("invalid bounds"));
    }
    let first = config.era_history[0];
    if first.start_slot != 0 || first.slot_length_us == 0 {
        return Err(Error::InvalidConfiguration(
            "era history must start at slot zero",
        ));
    }
    for pair in config.era_history.windows(2) {
        let [previous, next] = pair else {
            unreachable!()
        };
        if next.start_slot <= previous.start_slot
            || next.slot_length_us == 0
            || time_at_slot(&config.era_history, next.start_slot)? != next.start_time_us
        {
            return Err(Error::InvalidConfiguration("non-contiguous era history"));
        }
    }
    Ok(())
}

fn verify_genesis(config: &NetworkConfig) -> Result<(), Error> {
    let mut file = File::open(&config.genesis_file)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err(Error::InvalidConfiguration("genesis file exceeds 1 MiB"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let digest = Digest32::from_bytes(Sha256::digest(&bytes).into());
    if digest != config.expected_genesis_digest || digest != config.binding.genesis() {
        return Err(Error::GenesisMismatch);
    }
    Ok(())
}

fn time_at_slot(history: &[EraSegment], slot: u64) -> Result<u64, Error> {
    let era = history
        .iter()
        .rev()
        .find(|era| era.start_slot <= slot)
        .ok_or(Error::InvalidConfiguration("era history gap"))?;
    let elapsed_slots = slot - era.start_slot;
    era.start_time_us
        .checked_add(
            elapsed_slots
                .checked_mul(era.slot_length_us)
                .ok_or(Error::Clock)?,
        )
        .ok_or(Error::Clock)
}

fn slot_at_time(history: &[EraSegment], time_us: u64) -> Result<u64, Error> {
    let era = history
        .iter()
        .rev()
        .find(|era| era.start_time_us <= time_us)
        .ok_or(Error::Clock)?;
    let elapsed = time_us - era.start_time_us;
    era.start_slot
        .checked_add(elapsed / era.slot_length_us)
        .ok_or(Error::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_age_rejects_unencodable_lease_boundaries() {
        let mut config = NetworkConfig {
            cardano_cli: PathBuf::from("/bin/false"),
            node_socket: PathBuf::from("/unused/node.sock"),
            genesis_file: PathBuf::from("/unused/genesis.json"),
            expected_genesis_digest: Digest32::from_bytes([7; 32]),
            selector: NetworkSelector::Testnet(42),
            binding: NetworkBinding::new(Digest32::from_bytes([7; 32]), 42, 100, 64).unwrap(),
            era_history: vec![EraSegment {
                start_slot: 0,
                start_time_us: 0,
                slot_length_us: 1_000_000,
            }],
            max_age: DEFAULT_MAX_AGE,
            query_timeout: Duration::from_secs(1),
        };
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
    fn cardano_tip_epoch_progress_preserves_slot_authority_and_strict_types() {
        let tip = serde_json::json!({
            "block": 4811671, "epoch": 1467, "era": "Conway",
            "hash": "f4b83f12ac778c7bf9943b3b1a14df8aa4a8c0214c84357b88af102b27d7aea0",
            "slot": 126801332, "slotInEpoch": 52532, "slotsToEpochEnd": 33868,
            "syncProgress": "100.00"
        });
        let parsed: Tip = serde_json::from_value(tip.clone()).unwrap();
        assert_eq!(parsed.slot / 129600, 978);
        for field in ["slotInEpoch", "slotsToEpochEnd"] {
            for invalid in [serde_json::json!(-1), serde_json::json!("52532")] {
                let mut malformed = tip.clone();
                malformed[field] = invalid;
                assert!(serde_json::from_value::<Tip>(malformed).is_err());
            }
        }
        let mut unknown = tip;
        unknown["unexpected"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Tip>(unknown).is_err());
    }

    #[test]
    fn kernel_clock_states_and_failure_flags_fail_closed() {
        for state in [
            libc::TIME_OK,
            libc::TIME_INS,
            libc::TIME_DEL,
            libc::TIME_OOP,
            libc::TIME_WAIT,
        ] {
            assert!(clock_synchronized(state, 0));
            assert!(clock_synchronized(state, libc::STA_PLL));
            for flag in [
                libc::STA_UNSYNC,
                libc::STA_CLOCKERR,
                libc::STA_UNSYNC | libc::STA_CLOCKERR,
            ] {
                assert!(!clock_synchronized(state, flag));
            }
        }
        for state in [-1, libc::TIME_ERROR, libc::TIME_ERROR + 1, libc::c_int::MAX] {
            assert!(!clock_synchronized(state, 0));
        }
    }

    #[test]
    fn era_conversion_is_contiguous_and_checked() {
        let history = [
            EraSegment {
                start_slot: 0,
                start_time_us: 1_000,
                slot_length_us: 20,
            },
            EraSegment {
                start_slot: 10,
                start_time_us: 1_200,
                slot_length_us: 5,
            },
        ];
        assert_eq!(time_at_slot(&history, 9).unwrap(), 1_180);
        assert_eq!(time_at_slot(&history, 10).unwrap(), 1_200);
        assert_eq!(slot_at_time(&history, 1_225).unwrap(), 15);
    }

    #[test]
    fn reconnect_changes_session_and_resets_target_sequences() {
        let target = (
            PoolId::from_bytes([1; 28]),
            IncarnationId::from_bytes([2; 16]),
        );
        let mut provider = ContextProvider {
            clock: SystemClock,
            session: 41,
            networks: HashMap::new(),
            target_sequences: HashMap::from([(target, 9)]),
        };

        assert_eq!(provider.restart_session().unwrap(), 42);
        assert_eq!(provider.session(), 42);
        assert!(provider.target_sequences.is_empty());
    }
}
