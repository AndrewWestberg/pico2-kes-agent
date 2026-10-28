use crate::platform::{Entropy, fill_secret};
use kes_summed_ed25519_adapted as adapted;
use zeroize::Zeroizing;

pub use adapted::{PUBLIC_TREE_BYTES, PublicTreeBuffer, SIGNATURE_BYTES, STATE_BYTES};
pub const PERIODS: u8 = adapted::PERIODS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KesError {
    Entropy,
    InvalidLifetime,
    InvalidPeriod,
    StalePeriod,
    InvalidState,
    InvalidSignature,
    InvalidPublicTree,
    TreeMismatch,
    Erased,
    Exhausted,
    GenerationIncomplete,
    GenerationComplete,
}

impl From<adapted::Error> for KesError {
    fn from(error: adapted::Error) -> Self {
        match error {
            adapted::Error::InvalidPeriod => Self::InvalidPeriod,
            adapted::Error::ErasedKey => Self::Erased,
            adapted::Error::Exhausted => Self::Exhausted,
            adapted::Error::InvalidState => Self::InvalidState,
            adapted::Error::InvalidSignature => Self::InvalidSignature,
            adapted::Error::InvalidPublicTree => Self::InvalidPublicTree,
            adapted::Error::TreeMismatch => Self::TreeMismatch,
            adapted::Error::GenerationIncomplete => Self::GenerationIncomplete,
            adapted::Error::GenerationComplete => Self::GenerationComplete,
        }
    }
}

/// Device-owned Sum6KES state. No secret import or block-signing method is
/// exposed by the production API.
pub struct Sum6Kes {
    state: adapted::SigningState,
    public_tree: PublicTreeBuffer,
    lifetime: u8,
}

impl Sum6Kes {
    pub fn generate<E: Entropy>(entropy: &mut E, lifetime: u8) -> Result<Self, KesError> {
        if !(1..=PERIODS).contains(&lifetime) {
            return Err(KesError::InvalidLifetime);
        }
        let mut seed = Zeroizing::new([0; 32]);
        fill_secret(entropy, &mut *seed).map_err(|_| KesError::Entropy)?;
        let mut generation = adapted::Generation::begin(&mut seed);
        for _ in 0..PERIODS {
            generation.step()?;
        }
        let (state, public_tree) = generation.finish()?;
        Ok(Self {
            state,
            public_tree,
            lifetime,
        })
    }

    pub fn restore(
        state: &[u8; STATE_BYTES],
        period: u8,
        lifetime: u8,
        public_tree: &[u8; PUBLIC_TREE_BYTES],
    ) -> Result<Self, KesError> {
        if !(1..=PERIODS).contains(&lifetime) || period >= lifetime {
            return Err(KesError::InvalidLifetime);
        }
        let state = adapted::SigningState::from_canonical(state, period)?;
        let mut tree = PublicTreeBuffer::new();
        tree.as_bytes_mut().copy_from_slice(public_tree);
        tree.verify(&state.verification_key()?)?;
        Ok(Self {
            state,
            public_tree: tree,
            lifetime,
        })
    }

    pub fn verification_key(&self) -> [u8; 32] {
        self.state
            .verification_key()
            .expect("live Sum6KES invariant")
    }

    pub fn period(&self) -> u64 {
        u64::from(self.state.period().expect("live Sum6KES invariant"))
    }

    pub const fn lifetime(&self) -> u8 {
        self.lifetime
    }

    pub fn canonical_state(&self) -> [u8; STATE_BYTES] {
        *self
            .state
            .canonical_bytes()
            .expect("live Sum6KES invariant")
    }

    pub const fn public_tree(&self) -> &PublicTreeBuffer {
        &self.public_tree
    }

    pub fn evolve_to(&mut self, target: u64) -> Result<(), KesError> {
        let target = u8::try_from(target).map_err(|_| KesError::InvalidPeriod)?;
        if target >= self.lifetime {
            return Err(KesError::Exhausted);
        }
        let current = self.state.period().ok_or(KesError::Erased)?;
        if target < current {
            return Err(KesError::StalePeriod);
        }
        let verified = self.public_tree.verify(&self.verification_key())?;
        for _ in current..target {
            self.state.evolve(&verified)?;
        }
        Ok(())
    }

    pub fn erase(&mut self) {
        self.state.erase();
    }

    #[cfg(feature = "qualification")]
    #[doc(hidden)]
    pub fn sign_for_qualification(
        &self,
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_BYTES], KesError> {
        let mut output = [0; SIGNATURE_BYTES];
        self.state.sign_into(message, &mut output)?;
        Ok(output)
    }
}

impl Drop for Sum6Kes {
    fn drop(&mut self) {
        self.state.erase();
    }
}

pub fn verify(
    verification_key: &[u8; 32],
    period: u8,
    lifetime: u8,
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), KesError> {
    if !(1..=PERIODS).contains(&lifetime) || period >= lifetime {
        return Err(KesError::InvalidLifetime);
    }
    adapted::verify(verification_key, period, message, signature).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::EntropyError;
    use zeroize::Zeroize;

    struct FixedEntropy([u8; 32]);

    impl Entropy for FixedEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            output.copy_from_slice(&self.0);
            self.0.zeroize();
            Ok(())
        }
    }

    #[test]
    fn generation_produces_canonical_state_and_one_validated_tree() {
        let mut key = Sum6Kes::generate(&mut FixedEntropy([7; 32]), 64).unwrap();
        assert_eq!(key.period(), 0);
        assert_eq!(key.canonical_state().len(), STATE_BYTES);
        assert_eq!(key.public_tree().as_bytes().len(), PUBLIC_TREE_BYTES);
        key.public_tree().verify(&key.verification_key()).unwrap();
        key.evolve_to(63).unwrap();
        assert_eq!(key.period(), 63);
        let final_state = key.canonical_state();
        assert_eq!(key.evolve_to(64), Err(KesError::Exhausted));
        assert_eq!(key.canonical_state(), final_state);
    }

    #[test]
    fn failed_entropy_leaves_no_live_key() {
        struct Broken;
        impl Entropy for Broken {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
                output[0] = 1;
                Err(EntropyError)
            }
        }
        assert!(matches!(
            Sum6Kes::generate(&mut Broken, 64),
            Err(KesError::Entropy)
        ));
    }
}
