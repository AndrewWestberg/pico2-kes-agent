use crate::identity::{Digest32, GenerationId, IncarnationId, NetworkBinding, PoolId, StorageSlot};
use crate::operation::PoolTarget;

pub const MAX_POOLS: usize = StorageSlot::CAPACITY as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Ready,
    NotYetValid,
    Expired,
    DelayedEvolution,
    StorageFailure,
    EntropyFailure,
    PeriodUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationKind {
    None,
    Key {
        generation: GenerationId,
        relative_period: u8,
        certificate_digest: Digest32,
    },
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Publication {
    target: PoolTarget,
    revision: u64,
    kind: PublicationKind,
    timestamp_us: u64,
    high_water_us: u64,
}

impl Publication {
    pub const fn initial(target: PoolTarget, timestamp_floor_us: u64) -> Self {
        Self {
            target,
            revision: 0,
            kind: PublicationKind::None,
            timestamp_us: timestamp_floor_us,
            high_water_us: timestamp_floor_us,
        }
    }

    pub fn next(
        self,
        revision: u64,
        kind: PublicationKind,
        timestamp_us: u64,
    ) -> Result<Self, PoolError> {
        if revision <= self.revision || timestamp_us <= self.high_water_us {
            return Err(PoolError::RegressivePublication);
        }
        Ok(Self {
            target: self.target,
            revision,
            kind,
            timestamp_us,
            high_water_us: timestamp_us,
        })
    }

    pub const fn target(self) -> PoolTarget {
        self.target
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    pub const fn kind(self) -> PublicationKind {
        self.kind
    }

    pub const fn timestamp_us(self) -> u64 {
        self.timestamp_us
    }

    pub const fn high_water_us(self) -> u64 {
        self.high_water_us
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Enrollment {
    pub cold_verification_key: [u8; 32],
    pub incarnation: IncarnationId,
    pub network: NetworkBinding,
    pub publication_floor_us: u64,
}

impl Enrollment {
    pub fn pool_id(self) -> PoolId {
        PoolId::from_cold_verification_key(&self.cold_verification_key)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolError {
    DuplicatePool,
    DuplicateColdIdentity,
    CapacityExceeded,
    UnknownPool,
    RevisionOverflow,
    CounterRegressive,
    PeriodRegressive,
    TargetMismatch,
    RegressivePublication,
    ActiveStagedCollision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pool {
    id: PoolId,
    cold_verification_key: [u8; 32],
    incarnation: IncarnationId,
    slot: StorageSlot,
    network: NetworkBinding,
    revision: u64,
    period_floor: Option<u64>,
    highest_certificate_counter: Option<u64>,
    publication: Publication,
    active: Option<GenerationId>,
    staged: Option<GenerationId>,
    health: Health,
}

impl Pool {
    fn new(enrollment: Enrollment, slot: StorageSlot) -> Self {
        let id = enrollment.pool_id();
        let target = PoolTarget {
            pool: id,
            incarnation: enrollment.incarnation,
        };
        Self {
            id,
            cold_verification_key: enrollment.cold_verification_key,
            incarnation: enrollment.incarnation,
            slot,
            network: enrollment.network,
            revision: 0,
            period_floor: None,
            highest_certificate_counter: None,
            publication: Publication::initial(target, enrollment.publication_floor_us),
            active: None,
            staged: None,
            health: Health::PeriodUnavailable,
        }
    }

    pub const fn id(&self) -> PoolId {
        self.id
    }

    pub const fn cold_verification_key(&self) -> &[u8; 32] {
        &self.cold_verification_key
    }

    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    pub const fn target(&self) -> PoolTarget {
        PoolTarget {
            pool: self.id,
            incarnation: self.incarnation,
        }
    }

    pub const fn slot(&self) -> StorageSlot {
        self.slot
    }

    pub const fn network(&self) -> NetworkBinding {
        self.network
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn period_floor(&self) -> Option<u64> {
        self.period_floor
    }

    pub const fn highest_certificate_counter(&self) -> Option<u64> {
        self.highest_certificate_counter
    }

    pub const fn publication(&self) -> Publication {
        self.publication
    }

    pub const fn active(&self) -> Option<GenerationId> {
        self.active
    }

    pub const fn staged(&self) -> Option<GenerationId> {
        self.staged
    }

    pub const fn health(&self) -> Health {
        self.health
    }

    pub fn raise_period_floor(&mut self, period: u64) -> Result<bool, PoolError> {
        match self.period_floor {
            Some(current) if period < current => Err(PoolError::PeriodRegressive),
            Some(current) if period == current => Ok(false),
            _ => {
                self.period_floor = Some(period);
                self.bump_revision()?;
                Ok(true)
            }
        }
    }

    pub fn accept_certificate_counter(&mut self, counter: u64) -> Result<bool, PoolError> {
        match self.highest_certificate_counter {
            Some(current) if counter < current => Err(PoolError::CounterRegressive),
            Some(current) if counter == current => Ok(false),
            _ => {
                self.highest_certificate_counter = Some(counter);
                self.bump_revision()?;
                Ok(true)
            }
        }
    }

    pub fn set_generations(
        &mut self,
        active: Option<GenerationId>,
        staged: Option<GenerationId>,
    ) -> Result<(), PoolError> {
        if active.is_some() && active == staged {
            return Err(PoolError::ActiveStagedCollision);
        }
        self.active = active;
        self.staged = staged;
        self.bump_revision()
    }

    pub fn publish(&mut self, kind: PublicationKind, timestamp_us: u64) -> Result<(), PoolError> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(PoolError::RevisionOverflow)?;
        self.publication = self.publication.next(revision, kind, timestamp_us)?;
        self.revision = revision;
        Ok(())
    }

    pub fn set_health(&mut self, health: Health) {
        self.health = health;
    }

    fn bump_revision(&mut self) -> Result<(), PoolError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(PoolError::RevisionOverflow)?;
        Ok(())
    }
}

pub struct PoolDirectory {
    slots: [Option<Pool>; MAX_POOLS],
    len: u8,
}

impl Default for PoolDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolDirectory {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_POOLS],
            len: 0,
        }
    }

    pub const fn len(&self) -> u8 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn enroll(&mut self, enrollment: Enrollment) -> Result<PoolTarget, PoolError> {
        let pool_id = enrollment.pool_id();
        if self.slots.iter().flatten().any(|pool| pool.id == pool_id) {
            return Err(PoolError::DuplicatePool);
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|pool| pool.cold_verification_key == enrollment.cold_verification_key)
        {
            return Err(PoolError::DuplicateColdIdentity);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(PoolError::CapacityExceeded)?;
        let slot = StorageSlot::new(index as u8).map_err(|_| PoolError::CapacityExceeded)?;
        let pool = Pool::new(enrollment, slot);
        let target = pool.target();
        self.slots[index] = Some(pool);
        self.len += 1;
        Ok(target)
    }

    pub fn get(&self, pool: PoolId) -> Result<&Pool, PoolError> {
        self.slots
            .iter()
            .flatten()
            .find(|entry| entry.id == pool)
            .ok_or(PoolError::UnknownPool)
    }

    pub fn get_target(&self, target: PoolTarget) -> Result<&Pool, PoolError> {
        let pool = self.get(target.pool)?;
        if pool.incarnation != target.incarnation {
            return Err(PoolError::TargetMismatch);
        }
        Ok(pool)
    }

    pub fn get_target_mut(&mut self, target: PoolTarget) -> Result<&mut Pool, PoolError> {
        let pool = self
            .slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.id == target.pool)
            .ok_or(PoolError::UnknownPool)?;
        if pool.incarnation != target.incarnation {
            return Err(PoolError::TargetMismatch);
        }
        Ok(pool)
    }

    pub fn delete(&mut self, target: PoolTarget) -> Result<Pool, PoolError> {
        let index = self
            .slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|pool| pool.id == target.pool))
            .ok_or(PoolError::UnknownPool)?;
        if self.slots[index]
            .as_ref()
            .is_some_and(|pool| pool.incarnation != target.incarnation)
        {
            return Err(PoolError::TargetMismatch);
        }
        let pool = self.slots[index].take().ok_or(PoolError::UnknownPool)?;
        self.len -= 1;
        Ok(pool)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Pool> {
        self.slots.iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network() -> NetworkBinding {
        NetworkBinding::new(Digest32::from_bytes([7; 32]), 42, 100, 64).unwrap()
    }

    fn enrollment(value: u8) -> Enrollment {
        Enrollment {
            cold_verification_key: [value; 32],
            incarnation: IncarnationId::from_bytes([value; 16]),
            network: network(),
            publication_floor_us: u64::from(value),
        }
    }

    #[test]
    fn capacity_duplicate_and_slot_identity_are_distinct() {
        let mut directory = PoolDirectory::new();
        for value in 0..64 {
            let target = directory.enroll(enrollment(value)).unwrap();
            let pool = directory.get_target(target).unwrap();
            assert_eq!(pool.slot().get(), value);
            assert_eq!(pool.id(), enrollment(value).pool_id());
        }
        assert_eq!(directory.len(), 64);
        assert_eq!(
            directory.enroll(enrollment(64)),
            Err(PoolError::CapacityExceeded)
        );
        assert_eq!(
            directory.enroll(enrollment(1)),
            Err(PoolError::DuplicatePool)
        );
    }

    #[test]
    fn deletion_and_reenrollment_reset_incarnation_local_state() {
        let mut directory = PoolDirectory::new();
        let target = directory.enroll(enrollment(1)).unwrap();
        let pool = directory.get_target_mut(target).unwrap();
        pool.raise_period_floor(12).unwrap();
        pool.accept_certificate_counter(4).unwrap();
        directory.delete(target).unwrap();
        let mut next = enrollment(1);
        next.incarnation = IncarnationId::from_bytes([99; 16]);
        let next_target = directory.enroll(next).unwrap();
        let next_pool = directory.get_target(next_target).unwrap();
        assert_ne!(target.incarnation, next_pool.incarnation());
        assert_eq!(next_pool.period_floor(), None);
        assert_eq!(next_pool.highest_certificate_counter(), None);
        assert_eq!(directory.get_target(target), Err(PoolError::TargetMismatch));
    }

    #[test]
    fn publication_is_monotonic_and_metadata_does_not_replace_it() {
        let mut directory = PoolDirectory::new();
        let target = directory.enroll(enrollment(2)).unwrap();
        let pool = directory.get_target_mut(target).unwrap();
        let initial = pool.publication();
        pool.raise_period_floor(1).unwrap();
        assert_eq!(pool.publication(), initial);
        let generation = GenerationId::from_bytes([3; 16]);
        pool.publish(
            PublicationKind::Key {
                generation,
                relative_period: 0,
                certificate_digest: Digest32::from_bytes([4; 32]),
            },
            initial.high_water_us() + 1,
        )
        .unwrap();
        let published = pool.publication();
        assert_eq!(
            pool.publish(PublicationKind::Drop, published.high_water_us()),
            Err(PoolError::RegressivePublication)
        );
        assert_eq!(pool.publication(), published);
    }
}
