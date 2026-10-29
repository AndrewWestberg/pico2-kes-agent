use kes_core::{directory::PoolSchedule, identity::StorageSlot};

pub struct Scheduler {
    pools: PoolSchedule,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            pools: PoolSchedule::new(),
        }
    }

    pub fn enroll(&mut self, slot: StorageSlot) {
        self.pools.enroll(slot);
    }

    pub fn request(&mut self, slot: StorageSlot) -> bool {
        self.pools.request(slot)
    }

    /// Executes at most one pool transition so USB handling cannot be starved.
    pub fn run_one(&mut self, mut transition: impl FnMut(StorageSlot)) -> bool {
        let Some(slot) = self.pools.next_slot() else {
            return false;
        };
        transition(slot);
        true
    }
}
