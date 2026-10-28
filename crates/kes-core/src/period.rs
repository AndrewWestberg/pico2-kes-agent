use crate::generation::{Generation, GenerationError};
use crate::identity::{NetworkBinding, SessionId};
use crate::operation::PoolTarget;
use crate::pool::{Pool, PoolError};

pub const MAX_KES_LIFETIME: u8 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationTimeSample {
    timestamp_us: u64,
    synchronized: bool,
}

impl PublicationTimeSample {
    pub const fn synchronized(timestamp_us: u64) -> Self {
        Self {
            timestamp_us,
            synchronized: true,
        }
    }

    pub const fn unsynchronized(timestamp_us: u64) -> Self {
        Self {
            timestamp_us,
            synchronized: false,
        }
    }

    pub const fn timestamp_us(self) -> u64 {
        self.timestamp_us
    }

    pub const fn is_synchronized(self) -> bool {
        self.synchronized
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Freshness {
    session: SessionId,
    sequence: u64,
}

impl Freshness {
    pub const fn new(session: SessionId, sequence: u64) -> Self {
        Self { session, sequence }
    }

    pub const fn session(self) -> SessionId {
        self.session
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeriodContext {
    target: PoolTarget,
    network: NetworkBinding,
    slots_per_period: u64,
    lifetime: u8,
    absolute_period: u64,
    publication_time: PublicationTimeSample,
    freshness: Freshness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeriodContextInput {
    pub target: PoolTarget,
    pub network: NetworkBinding,
    pub slots_per_period: u64,
    pub lifetime: u8,
    pub absolute_period: u64,
    pub publication_time: PublicationTimeSample,
    pub freshness: Freshness,
}

impl PeriodContext {
    pub fn new(input: PeriodContextInput) -> Result<Self, PeriodError> {
        if input.slots_per_period == 0 {
            return Err(PeriodError::SlotsPerPeriodZero);
        }
        if !(1..=MAX_KES_LIFETIME).contains(&input.lifetime) {
            return Err(PeriodError::LifetimeOutOfRange);
        }
        if input.slots_per_period != input.network.slots_per_period()
            || input.lifetime != input.network.lifetime()
        {
            return Err(PeriodError::NetworkMismatch);
        }
        if !input.publication_time.is_synchronized() {
            return Err(PeriodError::UnsynchronizedTime);
        }
        Ok(Self {
            target: input.target,
            network: input.network,
            slots_per_period: input.slots_per_period,
            lifetime: input.lifetime,
            absolute_period: input.absolute_period,
            publication_time: input.publication_time,
            freshness: input.freshness,
        })
    }

    pub const fn target(self) -> PoolTarget {
        self.target
    }

    pub const fn network(self) -> NetworkBinding {
        self.network
    }

    pub const fn slots_per_period(self) -> u64 {
        self.slots_per_period
    }

    pub const fn lifetime(self) -> u8 {
        self.lifetime
    }

    pub const fn absolute_period(self) -> u64 {
        self.absolute_period
    }

    pub const fn publication_time(self) -> PublicationTimeSample {
        self.publication_time
    }

    pub const fn freshness(self) -> Freshness {
        self.freshness
    }

    pub fn relative_period(self, certificate_start: u64) -> Result<u8, PeriodError> {
        let relative = self
            .absolute_period
            .checked_sub(certificate_start)
            .ok_or(PeriodError::BeforeCertificateStart)?;
        if relative >= u64::from(self.lifetime) {
            return Err(PeriodError::AfterCertificateExpiry);
        }
        Ok(relative as u8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingFloor {
    context: PeriodContext,
    expected_revision: u64,
    previous_floor: Option<u64>,
}

impl PendingFloor {
    pub const fn context(self) -> PeriodContext {
        self.context
    }

    pub fn apply_to_pool(self, pool: &mut Pool) -> Result<(), PeriodError> {
        validate_target(pool, self.context)?;
        if pool.revision() != self.expected_revision || pool.period_floor() != self.previous_floor {
            return Err(PeriodError::StateChanged);
        }
        pool.raise_period_floor(self.context.absolute_period)
            .map_err(PeriodError::Pool)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeriodDecision {
    Ready,
    CommitFloor(PendingFloor),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeriodError {
    SlotsPerPeriodZero,
    LifetimeOutOfRange,
    UnsynchronizedTime,
    TargetMismatch,
    NetworkMismatch,
    PeriodRegressive,
    SequenceRegressive,
    StaleSession,
    StateChanged,
    FloorNotCommitted,
    BeforeCertificateStart,
    AfterCertificateExpiry,
    Pool(PoolError),
    Generation(GenerationError),
}

pub struct PeriodGate {
    session: SessionId,
    lease: Option<PeriodContext>,
}

impl PeriodGate {
    pub const fn new(session: SessionId) -> Self {
        Self {
            session,
            lease: None,
        }
    }

    pub fn reset(&mut self, session: SessionId) {
        self.session = session;
        self.lease = None;
    }

    pub const fn lease(&self) -> Option<PeriodContext> {
        self.lease
    }

    pub fn evaluate(
        &mut self,
        pool: &Pool,
        context: PeriodContext,
    ) -> Result<PeriodDecision, PeriodError> {
        validate_target(pool, context)?;
        self.validate_freshness(context)?;
        match pool.period_floor() {
            Some(floor) if context.absolute_period < floor => Err(PeriodError::PeriodRegressive),
            Some(floor) if context.absolute_period == floor => {
                self.lease = Some(context);
                Ok(PeriodDecision::Ready)
            }
            floor => Ok(PeriodDecision::CommitFloor(PendingFloor {
                context,
                expected_revision: pool.revision(),
                previous_floor: floor,
            })),
        }
    }

    pub fn activate_committed(
        &mut self,
        pool: &Pool,
        pending: PendingFloor,
    ) -> Result<(), PeriodError> {
        validate_target(pool, pending.context)?;
        self.validate_freshness(pending.context)?;
        if pool.period_floor() != Some(pending.context.absolute_period) {
            return Err(PeriodError::FloorNotCommitted);
        }
        self.lease = Some(pending.context);
        Ok(())
    }

    pub fn recheck_for_delivery(
        &self,
        target: PoolTarget,
        freshness: Freshness,
    ) -> Result<PeriodContext, PeriodError> {
        if freshness.session != self.session {
            return Err(PeriodError::StaleSession);
        }
        let lease = self.lease.ok_or(PeriodError::StaleSession)?;
        if lease.target != target
            || lease.freshness.session != freshness.session
            || lease.freshness.sequence != freshness.sequence
        {
            return Err(PeriodError::StateChanged);
        }
        Ok(lease)
    }

    pub fn apply_to_generation(
        &self,
        target: PoolTarget,
        freshness: Freshness,
        certificate_start: u64,
        generation: &mut Generation,
    ) -> Result<u8, PeriodError> {
        let context = self.recheck_for_delivery(target, freshness)?;
        let relative = context.relative_period(certificate_start)?;
        generation
            .set_period(relative)
            .map_err(PeriodError::Generation)?;
        Ok(relative)
    }

    fn validate_freshness(&self, context: PeriodContext) -> Result<(), PeriodError> {
        if context.freshness.session != self.session {
            return Err(PeriodError::StaleSession);
        }
        if self.lease.is_some_and(|lease| {
            lease.freshness.session == context.freshness.session
                && context.freshness.sequence <= lease.freshness.sequence
        }) {
            return Err(PeriodError::SequenceRegressive);
        }
        Ok(())
    }
}

fn validate_target(pool: &Pool, context: PeriodContext) -> Result<(), PeriodError> {
    if context.target != pool.target() {
        return Err(PeriodError::TargetMismatch);
    }
    if context.network != pool.network() {
        return Err(PeriodError::NetworkMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Digest32, IncarnationId};
    use crate::pool::{Enrollment, PoolDirectory};

    fn pool() -> Pool {
        let enrollment = Enrollment {
            cold_verification_key: [1; 32],
            incarnation: IncarnationId::from_bytes([2; 16]),
            network: NetworkBinding::new(Digest32::from_bytes([3; 32]), 42, 129_600, 64).unwrap(),
            publication_floor_us: 0,
        };
        let mut directory = PoolDirectory::new();
        let target = directory.enroll(enrollment).unwrap();
        *directory.get_target(target).unwrap()
    }

    fn context(pool: &Pool, session: SessionId, sequence: u64, period: u64) -> PeriodContext {
        PeriodContext::new(PeriodContextInput {
            target: pool.target(),
            network: pool.network(),
            slots_per_period: 129_600,
            lifetime: 64,
            absolute_period: period,
            publication_time: PublicationTimeSample::synchronized(10),
            freshness: Freshness::new(session, sequence),
        })
        .unwrap()
    }

    #[test]
    fn raised_floor_needs_commit_before_success() {
        let mut pool = pool();
        let session = SessionId::from_bytes([4; 16]);
        let mut gate = PeriodGate::new(session);
        let pending = match gate.evaluate(&pool, context(&pool, session, 1, 7)).unwrap() {
            PeriodDecision::CommitFloor(pending) => pending,
            PeriodDecision::Ready => panic!("new floor unexpectedly ready"),
        };
        assert_eq!(
            gate.activate_committed(&pool, pending),
            Err(PeriodError::FloorNotCommitted)
        );
        pending.apply_to_pool(&mut pool).unwrap();
        gate.activate_committed(&pool, pending).unwrap();
        assert_eq!(pool.period_floor(), Some(7));
    }

    #[test]
    fn equal_floor_refreshes_without_write_and_reconnect_clears_lease() {
        let mut pool = pool();
        pool.raise_period_floor(7).unwrap();
        let session = SessionId::from_bytes([4; 16]);
        let mut gate = PeriodGate::new(session);
        let revision = pool.revision();
        assert_eq!(
            gate.evaluate(&pool, context(&pool, session, 1, 7)),
            Ok(PeriodDecision::Ready)
        );
        assert_eq!(pool.revision(), revision);
        gate.reset(SessionId::from_bytes([5; 16]));
        assert_eq!(
            gate.recheck_for_delivery(pool.target(), Freshness::new(session, 1)),
            Err(PeriodError::StaleSession)
        );
    }

    #[test]
    fn checked_relative_period_rejects_underflow_and_expiry() {
        let pool = pool();
        let session = SessionId::from_bytes([4; 16]);
        assert_eq!(
            context(&pool, session, 1, 9).relative_period(10),
            Err(PeriodError::BeforeCertificateStart)
        );
        assert_eq!(
            context(&pool, session, 1, 74).relative_period(10),
            Err(PeriodError::AfterCertificateExpiry)
        );
    }
}
