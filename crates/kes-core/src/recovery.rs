use crate::identity::{Digest32, IncarnationId, PoolId, StorageSlot};
use crate::operation::PoolTarget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryAction {
    Enroll,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryIntent {
    pub action: DirectoryAction,
    pub target: PoolTarget,
    pub slot: StorageSlot,
    pub configuration_revision: u64,
    pub operation_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionTombstone {
    pub target: PoolTarget,
    pub slot: StorageSlot,
    pub publication_revision: u64,
    pub publication_high_water_us: u64,
    pub operation_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntry {
    NeverUsed,
    Enrolled {
        target: PoolTarget,
        slot: StorageSlot,
    },
    Deleted(DeletionTombstone),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolEvidence {
    Empty,
    Enrolled(PoolTarget),
    Tombstone(PoolTarget),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    Complete(DirectoryEntry),
    ContinuePoolTransaction,
    ContinueConfigurationFinalization(DirectoryEntry),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    TargetConflict,
    SlotConflict,
    Unavailable,
    MissingTombstone,
}

pub fn resolve_directory_intent(
    current: DirectoryEntry,
    intent: DirectoryIntent,
    pool: PoolEvidence,
    deletion_publication_revision: u64,
    deletion_publication_high_water_us: u64,
) -> Result<Resolution, RecoveryError> {
    if matches!(pool, PoolEvidence::Unavailable) {
        return Err(RecoveryError::Unavailable);
    }
    match intent.action {
        DirectoryAction::Enroll => resolve_enrollment(current, intent, pool),
        DirectoryAction::Delete => resolve_deletion(
            current,
            intent,
            pool,
            deletion_publication_revision,
            deletion_publication_high_water_us,
        ),
    }
}

fn resolve_enrollment(
    current: DirectoryEntry,
    intent: DirectoryIntent,
    pool: PoolEvidence,
) -> Result<Resolution, RecoveryError> {
    match (current, pool) {
        (DirectoryEntry::NeverUsed, PoolEvidence::Empty)
        | (DirectoryEntry::Deleted(_), PoolEvidence::Empty) => {
            Ok(Resolution::ContinuePoolTransaction)
        }
        (DirectoryEntry::NeverUsed, PoolEvidence::Enrolled(target))
        | (DirectoryEntry::Deleted(_), PoolEvidence::Enrolled(target))
            if target == intent.target =>
        {
            Ok(Resolution::ContinueConfigurationFinalization(
                DirectoryEntry::Enrolled {
                    target,
                    slot: intent.slot,
                },
            ))
        }
        (DirectoryEntry::Enrolled { target, slot }, PoolEvidence::Enrolled(observed))
            if target == intent.target && observed == intent.target && slot == intent.slot =>
        {
            Ok(Resolution::Complete(current))
        }
        (DirectoryEntry::Enrolled { slot, .. }, _) if slot != intent.slot => {
            Err(RecoveryError::SlotConflict)
        }
        _ => Err(RecoveryError::TargetConflict),
    }
}

fn resolve_deletion(
    current: DirectoryEntry,
    intent: DirectoryIntent,
    pool: PoolEvidence,
    publication_revision: u64,
    publication_high_water_us: u64,
) -> Result<Resolution, RecoveryError> {
    let tombstone = DeletionTombstone {
        target: intent.target,
        slot: intent.slot,
        publication_revision,
        publication_high_water_us,
        operation_digest: intent.operation_digest,
    };
    match (current, pool) {
        (DirectoryEntry::Enrolled { target, slot }, PoolEvidence::Enrolled(observed))
            if target == intent.target && observed == intent.target && slot == intent.slot =>
        {
            Ok(Resolution::ContinuePoolTransaction)
        }
        (DirectoryEntry::Enrolled { target, slot }, PoolEvidence::Tombstone(observed))
            if target == intent.target && observed == intent.target && slot == intent.slot =>
        {
            Ok(Resolution::ContinueConfigurationFinalization(
                DirectoryEntry::Deleted(tombstone),
            ))
        }
        (DirectoryEntry::Deleted(existing), PoolEvidence::Tombstone(observed))
            if existing.target == intent.target
                && existing.slot == intent.slot
                && observed == intent.target
                && existing.operation_digest == intent.operation_digest =>
        {
            Ok(Resolution::Complete(current))
        }
        (DirectoryEntry::Deleted(existing), PoolEvidence::Empty)
            if existing.target == intent.target
                && existing.slot == intent.slot
                && existing.operation_digest == intent.operation_digest =>
        {
            Ok(Resolution::Complete(current))
        }
        (_, PoolEvidence::Empty) => Err(RecoveryError::MissingTombstone),
        (DirectoryEntry::Enrolled { slot, .. }, _) if slot != intent.slot => {
            Err(RecoveryError::SlotConflict)
        }
        _ => Err(RecoveryError::TargetConflict),
    }
}

pub const fn pool_target(pool: [u8; 28], incarnation: [u8; 16]) -> PoolTarget {
    PoolTarget {
        pool: PoolId::from_bytes(pool),
        incarnation: IncarnationId::from_bytes(incarnation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(action: DirectoryAction) -> DirectoryIntent {
        DirectoryIntent {
            action,
            target: pool_target([1; 28], [2; 16]),
            slot: StorageSlot::new(3).unwrap(),
            configuration_revision: 4,
            operation_digest: Digest32::from_bytes([5; 32]),
        }
    }

    #[test]
    fn enrollment_intent_finishes_only_matching_pool_identity() {
        let intent = intent(DirectoryAction::Enroll);
        assert_eq!(
            resolve_directory_intent(DirectoryEntry::NeverUsed, intent, PoolEvidence::Empty, 0, 0),
            Ok(Resolution::ContinuePoolTransaction)
        );
        assert!(matches!(
            resolve_directory_intent(
                DirectoryEntry::NeverUsed,
                intent,
                PoolEvidence::Enrolled(intent.target),
                0,
                0
            ),
            Ok(Resolution::ContinueConfigurationFinalization(_))
        ));
        assert_eq!(
            resolve_directory_intent(
                DirectoryEntry::NeverUsed,
                intent,
                PoolEvidence::Enrolled(pool_target([9; 28], [2; 16])),
                0,
                0
            ),
            Err(RecoveryError::TargetConflict)
        );
    }

    #[test]
    fn deletion_requires_tombstone_before_slot_finalization() {
        let intent = intent(DirectoryAction::Delete);
        let enrolled = DirectoryEntry::Enrolled {
            target: intent.target,
            slot: intent.slot,
        };
        assert_eq!(
            resolve_directory_intent(enrolled, intent, PoolEvidence::Empty, 8, 9),
            Err(RecoveryError::MissingTombstone)
        );
        assert!(matches!(
            resolve_directory_intent(
                enrolled,
                intent,
                PoolEvidence::Tombstone(intent.target),
                8,
                9
            ),
            Ok(Resolution::ContinueConfigurationFinalization(
                DirectoryEntry::Deleted(_)
            ))
        ));
    }
}
