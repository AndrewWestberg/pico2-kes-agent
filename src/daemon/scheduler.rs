use kes_core::{operation::PoolTarget, pool::MAX_POOLS};

/// Allocation-free round-robin work set for the daemon's configured pools.
pub struct Scheduler {
    targets: [Option<PoolTarget>; MAX_POOLS],
    pending: u64,
    cursor: u8,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            targets: [None; MAX_POOLS],
            pending: 0,
            cursor: 0,
        }
    }

    pub fn upsert(&mut self, target: PoolTarget) -> Result<usize, PoolTarget> {
        if let Some(index) = self
            .targets
            .iter()
            .position(|entry| entry.is_some_and(|current| current.pool == target.pool))
        {
            self.targets[index] = Some(target);
            return Ok(index);
        }
        let Some(index) = self.targets.iter().position(Option::is_none) else {
            return Err(target);
        };
        self.targets[index] = Some(target);
        Ok(index)
    }

    pub fn remove(&mut self, target: PoolTarget) -> bool {
        let Some(index) = self.targets.iter().position(|entry| *entry == Some(target)) else {
            return false;
        };
        self.targets[index] = None;
        self.pending &= !(1u64 << index);
        true
    }

    pub fn request(&mut self, target: PoolTarget) -> bool {
        let Some(index) = self.targets.iter().position(|entry| *entry == Some(target)) else {
            return false;
        };
        let bit = 1u64 << index;
        let fresh = self.pending & bit == 0;
        self.pending |= bit;
        fresh
    }

    pub fn request_all(&mut self) {
        for (index, target) in self.targets.iter().enumerate() {
            if target.is_some() {
                self.pending |= 1u64 << index;
            }
        }
    }

    pub fn next_target(&mut self) -> Option<PoolTarget> {
        for offset in 0..MAX_POOLS as u8 {
            let index = self.cursor.wrapping_add(offset) % MAX_POOLS as u8;
            let bit = 1u64 << index;
            if self.pending & bit != 0 {
                self.pending &= !bit;
                self.cursor = (index + 1) % MAX_POOLS as u8;
                return self.targets[index as usize];
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kes_core::identity::{IncarnationId, PoolId};

    fn target(index: u8) -> PoolTarget {
        PoolTarget {
            pool: PoolId::from_bytes([index; 28]),
            incarnation: IncarnationId::from_bytes([index; 16]),
        }
    }

    #[test]
    fn full_capacity_is_fair_and_a_65th_target_is_rejected() {
        let mut scheduler = Scheduler::new();
        for index in 0..64 {
            assert_eq!(scheduler.upsert(target(index)), Ok(index as usize));
        }
        assert_eq!(scheduler.upsert(target(64)), Err(target(64)));
        scheduler.request_all();
        for index in 0..64 {
            assert_eq!(scheduler.next_target(), Some(target(index)));
        }
        assert_eq!(scheduler.next_target(), None);
    }
    #[test]
    fn interrupted_round_resumes_with_the_next_pool_instead_of_starving_it() {
        let mut scheduler = Scheduler::new();
        for index in 0..64 {
            scheduler.upsert(target(index)).unwrap();
        }
        scheduler.request_all();
        assert_eq!(scheduler.next_target(), Some(target(0)));

        // A transport interruption requests another full pass. The retained
        // cursor must give pool 1 the next opportunity rather than retrying
        // pool 0 indefinitely.
        scheduler.request_all();
        assert_eq!(scheduler.next_target(), Some(target(1)));
    }
}
