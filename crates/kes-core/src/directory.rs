use crate::identity::StorageSlot;

/// Fixed-capacity fair work set shared by firmware lifecycle scheduling.
/// A slot occurs at most once; repeated requests coalesce without starvation.
pub struct PoolSchedule {
    enrolled: u64,
    pending: u64,
    cursor: u8,
}

impl Default for PoolSchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolSchedule {
    pub const fn new() -> Self {
        Self {
            enrolled: 0,
            pending: 0,
            cursor: 0,
        }
    }

    pub fn enroll(&mut self, slot: StorageSlot) {
        self.enrolled |= bit(slot);
    }

    pub fn remove(&mut self, slot: StorageSlot) {
        self.enrolled &= !bit(slot);
        self.pending &= !bit(slot);
    }

    pub fn request(&mut self, slot: StorageSlot) -> bool {
        let slot_bit = bit(slot);
        if self.enrolled & slot_bit == 0 {
            return false;
        }
        let fresh = self.pending & slot_bit == 0;
        self.pending |= slot_bit;
        fresh
    }

    pub fn request_all(&mut self) {
        self.pending |= self.enrolled;
    }

    pub fn next_slot(&mut self) -> Option<StorageSlot> {
        for offset in 0..StorageSlot::CAPACITY {
            let index = self.cursor.wrapping_add(offset) % StorageSlot::CAPACITY;
            let slot = StorageSlot::new(index).expect("bounded scheduler index");
            if self.pending & bit(slot) != 0 {
                self.pending &= !bit(slot);
                self.cursor = (index + 1) % StorageSlot::CAPACITY;
                return Some(slot);
            }
        }
        None
    }

    pub const fn pending_count(&self) -> u32 {
        self.pending.count_ones()
    }
}

const fn bit(slot: StorageSlot) -> u64 {
    1u64 << slot.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_64_slots_progress_once_per_round_and_reenrollment_stays_bounded() {
        let mut schedule = PoolSchedule::new();
        for index in 0..64 {
            schedule.enroll(StorageSlot::new(index).unwrap());
        }
        schedule.request_all();
        assert_eq!(schedule.pending_count(), 64);
        for expected in 0..64 {
            assert_eq!(schedule.next_slot().unwrap().get(), expected);
        }
        assert!(schedule.next_slot().is_none());

        let removed = StorageSlot::new(17).unwrap();
        schedule.remove(removed);
        assert!(!schedule.request(removed));
        schedule.enroll(removed);
        assert!(schedule.request(removed));
        assert!(!schedule.request(removed));
        assert_eq!(schedule.next_slot(), Some(removed));
    }
}
