use crate::generation::RecipientSnapshot;
use crate::identity::Digest32;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientError {
    RevisionZero,
    RevisionRegressive,
    RevisionConflict,
    InvalidPublicKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientPolicy {
    public_key: [u8; 32],
    fingerprint: Digest32,
    revision: u64,
}

impl RecipientPolicy {
    pub fn new(public_key: [u8; 32], revision: u64) -> Result<Self, RecipientError> {
        if revision == 0 {
            return Err(RecipientError::RevisionZero);
        }
        validate_public_key(&public_key)?;
        Ok(Self {
            public_key,
            fingerprint: Digest32::from_bytes(Sha256::digest(public_key).into()),
            revision,
        })
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn fingerprint(&self) -> Digest32 {
        self.fingerprint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn snapshot(&self) -> RecipientSnapshot {
        RecipientSnapshot::new(self.public_key, self.fingerprint)
    }

    pub fn replace(&mut self, public_key: [u8; 32], revision: u64) -> Result<(), RecipientError> {
        if revision < self.revision {
            return Err(RecipientError::RevisionRegressive);
        }
        if revision == self.revision {
            return if public_key == self.public_key {
                Ok(())
            } else {
                Err(RecipientError::RevisionConflict)
            };
        }
        *self = Self::new(public_key, revision)?;
        Ok(())
    }
}

fn validate_public_key(public_key: &[u8; 32]) -> Result<(), RecipientError> {
    // X25519 low-order inputs produce an all-zero shared secret. A fixed probe
    // scalar validates contributory behavior without introducing secret state.
    let probe = StaticSecret::from([0x5a; 32]);
    if probe
        .diffie_hellman(&PublicKey::from(*public_key))
        .was_contributory()
    {
        Ok(())
    } else {
        Err(RecipientError::InvalidPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_low_order_keys_and_regressive_policy_changes() {
        assert_eq!(
            RecipientPolicy::new([0; 32], 1),
            Err(RecipientError::InvalidPublicKey)
        );
        let key = PublicKey::from(&StaticSecret::from([1; 32])).to_bytes();
        let next = PublicKey::from(&StaticSecret::from([2; 32])).to_bytes();
        let mut policy = RecipientPolicy::new(key, 2).unwrap();
        assert_eq!(
            policy.replace(next, 1),
            Err(RecipientError::RevisionRegressive)
        );
        policy.replace(next, 3).unwrap();
        assert_eq!(policy.public_key(), &next);
        assert_eq!(policy.revision(), 3);
    }

    #[test]
    fn exact_replacement_is_idempotent_but_changed_revision_is_not() {
        let key = PublicKey::from(&StaticSecret::from([1; 32])).to_bytes();
        let other = PublicKey::from(&StaticSecret::from([2; 32])).to_bytes();
        let mut policy = RecipientPolicy::new(key, 1).unwrap();
        policy.replace(key, 1).unwrap();
        assert_eq!(
            policy.replace(other, 1),
            Err(RecipientError::RevisionConflict)
        );
    }
}
