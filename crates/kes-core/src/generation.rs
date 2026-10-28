use crate::certificate::Certificate;
use crate::identity::{Digest32, GenerationId, OperationId};
use crate::public_object::PublicObject;
use zeroize::Zeroize;

pub const KES_STATE_LEN: usize = 608;
pub const KES_PERIODS: u8 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationRole {
    Active,
    Staged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientSnapshot {
    public_key: [u8; 32],
    fingerprint: Digest32,
}

impl RecipientSnapshot {
    pub const fn new(public_key: [u8; 32], fingerprint: Digest32) -> Self {
        Self {
            public_key,
            fingerprint,
        }
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn fingerprint(&self) -> Digest32 {
        self.fingerprint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupCommitment {
    backup_digest: Digest32,
    artifact_digest: Digest32,
    recipient: Option<RecipientSnapshot>,
}

impl BackupCommitment {
    pub const fn new(
        backup_digest: Digest32,
        artifact_digest: Digest32,
        recipient: Option<RecipientSnapshot>,
    ) -> Self {
        Self {
            backup_digest,
            artifact_digest,
            recipient,
        }
    }

    pub const fn backup_digest(&self) -> Digest32 {
        self.backup_digest
    }

    pub const fn artifact_digest(&self) -> Digest32 {
        self.artifact_digest
    }

    pub const fn recipient(&self) -> Option<RecipientSnapshot> {
        self.recipient
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationError {
    NumberZero,
    BackupArtifactMismatch,
    DuplicateGeneration,
    ActiveOccupied,
    StagedOccupied,
    WrongRole,
    PeriodOutOfRange,
    CertificateHotKeyMismatch,
}

pub struct Generation {
    id: GenerationId,
    number: u64,
    creation_operation: OperationId,
    verification_key: [u8; 32],
    current_state: [u8; KES_STATE_LEN],
    relative_period: u8,
    role: GenerationRole,
    certificate: Option<Certificate>,
    public_object_digest: Digest32,
    artifact_digest: Digest32,
    backup: BackupCommitment,
    auto_activation: bool,
}

impl Generation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: GenerationId,
        number: u64,
        creation_operation: OperationId,
        verification_key: [u8; 32],
        current_state: [u8; KES_STATE_LEN],
        role: GenerationRole,
        public_object: &PublicObject,
        backup: BackupCommitment,
        auto_activation: bool,
    ) -> Result<Self, GenerationError> {
        if number == 0 {
            return Err(GenerationError::NumberZero);
        }
        if public_object.generation_id() != id
            || public_object.artifact_digest() != backup.artifact_digest
        {
            return Err(GenerationError::BackupArtifactMismatch);
        }
        Ok(Self {
            id,
            number,
            creation_operation,
            verification_key,
            current_state,
            relative_period: 0,
            role,
            certificate: None,
            public_object_digest: public_object.integrity_digest(),
            artifact_digest: public_object.artifact_digest(),
            backup,
            auto_activation,
        })
    }

    pub const fn id(&self) -> GenerationId {
        self.id
    }

    pub const fn number(&self) -> u64 {
        self.number
    }

    pub const fn creation_operation(&self) -> OperationId {
        self.creation_operation
    }

    pub const fn verification_key(&self) -> &[u8; 32] {
        &self.verification_key
    }

    pub const fn current_state(&self) -> &[u8; KES_STATE_LEN] {
        &self.current_state
    }

    pub const fn relative_period(&self) -> u8 {
        self.relative_period
    }

    pub const fn role(&self) -> GenerationRole {
        self.role
    }

    pub const fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_ref()
    }

    pub const fn public_object_digest(&self) -> Digest32 {
        self.public_object_digest
    }

    pub const fn artifact_digest(&self) -> Digest32 {
        self.artifact_digest
    }

    pub const fn backup(&self) -> BackupCommitment {
        self.backup
    }

    pub const fn auto_activation(&self) -> bool {
        self.auto_activation
    }

    pub(crate) fn set_role(&mut self, role: GenerationRole) {
        self.role = role;
    }

    pub(crate) fn set_period(&mut self, period: u8) -> Result<(), GenerationError> {
        if period >= KES_PERIODS {
            return Err(GenerationError::PeriodOutOfRange);
        }
        self.relative_period = period;
        Ok(())
    }

    pub(crate) fn install_certificate(
        &mut self,
        certificate: Certificate,
    ) -> Result<(), GenerationError> {
        if certificate.hot_verification_key() != &self.verification_key {
            return Err(GenerationError::CertificateHotKeyMismatch);
        }
        self.certificate = Some(certificate);
        Ok(())
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.current_state.zeroize();
    }
}

#[derive(Default)]
pub struct GenerationSet {
    active: Option<Generation>,
    staged: Option<Generation>,
}

impl GenerationSet {
    pub const fn new() -> Self {
        Self {
            active: None,
            staged: None,
        }
    }

    pub const fn active(&self) -> Option<&Generation> {
        self.active.as_ref()
    }

    pub const fn staged(&self) -> Option<&Generation> {
        self.staged.as_ref()
    }

    pub fn insert(&mut self, mut generation: Generation) -> Result<(), GenerationError> {
        if self
            .active
            .as_ref()
            .is_some_and(|item| item.id == generation.id)
            || self
                .staged
                .as_ref()
                .is_some_and(|item| item.id == generation.id)
        {
            return Err(GenerationError::DuplicateGeneration);
        }
        if generation.auto_activation && self.active.is_none() {
            generation.set_role(GenerationRole::Active);
        }
        match generation.role {
            GenerationRole::Active if self.active.is_some() => Err(GenerationError::ActiveOccupied),
            GenerationRole::Staged if self.staged.is_some() => Err(GenerationError::StagedOccupied),
            GenerationRole::Active => {
                self.active = Some(generation);
                Ok(())
            }
            GenerationRole::Staged => {
                self.staged = Some(generation);
                Ok(())
            }
        }
    }

    pub fn activate_staged(&mut self) -> Result<Option<Generation>, GenerationError> {
        let mut staged = self.staged.take().ok_or(GenerationError::WrongRole)?;
        staged.set_role(GenerationRole::Active);
        Ok(self.active.replace(staged))
    }

    pub fn retire_active(&mut self) -> Option<Generation> {
        self.active.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_object::{MAX_ARTIFACT_LEN, PUBLIC_TREE_LEN};

    fn generation(id: u8, role: GenerationRole, auto: bool) -> Generation {
        let id = GenerationId::from_bytes([id; 16]);
        let object = PublicObject::new(id, [0; PUBLIC_TREE_LEN], &[1; MAX_ARTIFACT_LEN]).unwrap();
        Generation::new(
            id,
            1,
            OperationId::from_bytes([2; 16]),
            [3; 32],
            [4; KES_STATE_LEN],
            role,
            &object,
            BackupCommitment::new(
                Digest32::from_bytes([5; 32]),
                object.artifact_digest(),
                None,
            ),
            auto,
        )
        .unwrap()
    }

    #[test]
    fn auto_activates_only_when_active_slot_is_empty() {
        let mut set = GenerationSet::new();
        set.insert(generation(1, GenerationRole::Staged, true))
            .unwrap();
        assert_eq!(
            set.active().unwrap().id(),
            GenerationId::from_bytes([1; 16])
        );
        set.insert(generation(2, GenerationRole::Staged, true))
            .unwrap();
        assert_eq!(
            set.staged().unwrap().id(),
            GenerationId::from_bytes([2; 16])
        );
    }

    #[test]
    fn never_overwrites_staged_implicitly() {
        let mut set = GenerationSet::new();
        set.insert(generation(1, GenerationRole::Staged, false))
            .unwrap();
        assert_eq!(
            set.insert(generation(2, GenerationRole::Staged, false)),
            Err(GenerationError::StagedOccupied)
        );
    }

    #[test]
    fn generation_requires_matching_committed_artifact() {
        let id = GenerationId::from_bytes([1; 16]);
        let object = PublicObject::new(id, [0; PUBLIC_TREE_LEN], &[1]).unwrap();
        let result = Generation::new(
            id,
            1,
            OperationId::from_bytes([2; 16]),
            [3; 32],
            [4; KES_STATE_LEN],
            GenerationRole::Staged,
            &object,
            BackupCommitment::new(
                Digest32::from_bytes([5; 32]),
                Digest32::from_bytes([6; 32]),
                None,
            ),
            false,
        );
        assert!(matches!(
            result,
            Err(GenerationError::BackupArtifactMismatch)
        ));
    }
}
