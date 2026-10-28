pub const MAX_POOLS: u8 = 64;
pub const MAX_SEQUENCE_LEN: usize = 256;
pub const MODEL_POOLS: u8 = 2;
pub const MODEL_PERIODS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RaceOrder {
    ActivateThenDiscard,
    DiscardThenActivate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Action {
    Enroll { pool: u8 },
    Generate { pool: u8 },
    Certify { pool: u8 },
    AdvancePeriod { period: u8 },
    Retry { action_index: u8 },
    TornWrite { byte: u16 },
    TornErase { byte: u16 },
    ResolveRace { pool: u8, order: RaceOrder },
    Reboot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceConfig {
    pub pools: u8,
    pub min_len: usize,
    pub max_len: usize,
}

impl SequenceConfig {
    pub const fn g3() -> Self {
        Self {
            pools: MAX_POOLS,
            min_len: 1,
            max_len: MAX_SEQUENCE_LEN,
        }
    }

    pub fn validate(self) -> Result<Self, &'static str> {
        if self.pools == 0 || self.pools > MAX_POOLS {
            return Err("pool bound must be in 1..=64");
        }
        if self.min_len == 0 || self.min_len > self.max_len || self.max_len > MAX_SEQUENCE_LEN {
            return Err("sequence bound must be in 1..=256");
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedSequence {
    pub seed: u64,
    pub actions: Vec<Action>,
}

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // Xorshift's all-zero state is absorbing; map it to a fixed public state.
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: usize) -> usize {
        debug_assert!(bound != 0);
        (self.next() as usize) % bound
    }
}

pub fn generate(config: SequenceConfig, seed: u64) -> Result<GeneratedSequence, &'static str> {
    let config = config.validate()?;
    let mut random = XorShift64::new(seed);
    let len = config.min_len + random.below(config.max_len - config.min_len + 1);
    let mut actions = Vec::with_capacity(len);
    for index in 0..len {
        let pool = random.below(config.pools as usize) as u8;
        let action = match random.below(9) {
            0 => Action::Enroll { pool },
            1 => Action::Generate { pool },
            2 => Action::Certify { pool },
            3 => Action::AdvancePeriod {
                period: random.below(64) as u8,
            },
            4 if index != 0 => Action::Retry {
                action_index: random.below(index) as u8,
            },
            4 => Action::Reboot,
            5 => Action::TornWrite {
                byte: random.below(257) as u16,
            },
            6 => Action::TornErase {
                byte: random.below(4097) as u16,
            },
            7 => Action::ResolveRace {
                pool,
                order: RaceOrder::ActivateThenDiscard,
            },
            _ => Action::ResolveRace {
                pool,
                order: RaceOrder::DiscardThenActivate,
            },
        };
        actions.push(action);
    }
    Ok(GeneratedSequence { seed, actions })
}

pub fn finite_model_actions() -> Vec<Action> {
    let mut actions = Vec::new();
    for pool in 0..MODEL_POOLS {
        actions.extend([
            Action::Enroll { pool },
            Action::Generate { pool },
            Action::Certify { pool },
            Action::ResolveRace {
                pool,
                order: RaceOrder::ActivateThenDiscard,
            },
            Action::ResolveRace {
                pool,
                order: RaceOrder::DiscardThenActivate,
            },
        ]);
    }
    for period in 0..MODEL_PERIODS {
        actions.push(Action::AdvancePeriod { period });
    }
    // Boundary faults and a retry are explicit members of the finite alphabet.
    actions.extend([
        Action::Retry { action_index: 0 },
        Action::TornWrite { byte: 0 },
        Action::TornWrite { byte: 256 },
        Action::TornErase { byte: 0 },
        Action::TornErase { byte: 4096 },
        Action::Reboot,
    ]);
    actions
}
