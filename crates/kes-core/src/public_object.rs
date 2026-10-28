use crate::identity::{Digest32, GenerationId};
use sha2::{Digest, Sha256};

pub const PUBLIC_TREE_LEN: usize = 4_064;
pub const MAX_ARTIFACT_LEN: usize = 2_048;
pub const PUBLIC_OBJECT_REGION_LEN: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicObjectError {
    EmptyArtifact,
    ArtifactTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicObject {
    generation_id: GenerationId,
    public_tree: [u8; PUBLIC_TREE_LEN],
    artifact: [u8; MAX_ARTIFACT_LEN],
    artifact_len: u16,
    artifact_digest: Digest32,
    integrity_digest: Digest32,
}

impl PublicObject {
    pub fn new(
        generation_id: GenerationId,
        public_tree: [u8; PUBLIC_TREE_LEN],
        artifact: &[u8],
    ) -> Result<Self, PublicObjectError> {
        if artifact.is_empty() {
            return Err(PublicObjectError::EmptyArtifact);
        }
        if artifact.len() > MAX_ARTIFACT_LEN {
            return Err(PublicObjectError::ArtifactTooLarge);
        }
        let mut stored_artifact = [0; MAX_ARTIFACT_LEN];
        stored_artifact[..artifact.len()].copy_from_slice(artifact);
        let artifact_digest = Digest32::from_bytes(Sha256::digest(artifact).into());
        let integrity_digest =
            integrity_digest(generation_id, &public_tree, artifact.len() as u16, artifact);
        Ok(Self {
            generation_id,
            public_tree,
            artifact: stored_artifact,
            artifact_len: artifact.len() as u16,
            artifact_digest,
            integrity_digest,
        })
    }

    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    pub const fn public_tree(&self) -> &[u8; PUBLIC_TREE_LEN] {
        &self.public_tree
    }

    pub fn artifact(&self) -> &[u8] {
        &self.artifact[..usize::from(self.artifact_len)]
    }

    pub const fn artifact_digest(&self) -> Digest32 {
        self.artifact_digest
    }

    pub const fn integrity_digest(&self) -> Digest32 {
        self.integrity_digest
    }

    pub fn verify(&self) -> bool {
        Digest32::from_bytes(Sha256::digest(self.artifact()).into()) == self.artifact_digest
            && integrity_digest(
                self.generation_id,
                &self.public_tree,
                self.artifact_len,
                self.artifact(),
            ) == self.integrity_digest
    }
}

fn integrity_digest(
    generation_id: GenerationId,
    public_tree: &[u8; PUBLIC_TREE_LEN],
    artifact_len: u16,
    artifact: &[u8],
) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(b"pico2-kes-public-object-v1");
    digest.update(generation_id.as_bytes());
    digest.update(public_tree);
    digest.update(artifact_len.to_be_bytes());
    digest.update(artifact);
    Digest32::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_fits_one_region_and_detects_corruption() {
        assert!(core::mem::size_of::<PublicObject>() <= PUBLIC_OBJECT_REGION_LEN);
        let mut object = PublicObject::new(
            GenerationId::from_bytes([3; 16]),
            [4; PUBLIC_TREE_LEN],
            &[5; MAX_ARTIFACT_LEN],
        )
        .unwrap();
        assert!(object.verify());
        object.artifact[0] ^= 1;
        assert!(!object.verify());
    }

    #[test]
    fn rejects_invalid_artifact_lengths() {
        assert_eq!(
            PublicObject::new(GenerationId::from_bytes([0; 16]), [0; PUBLIC_TREE_LEN], &[]),
            Err(PublicObjectError::EmptyArtifact)
        );
        assert_eq!(
            PublicObject::new(
                GenerationId::from_bytes([0; 16]),
                [0; PUBLIC_TREE_LEN],
                &[0; MAX_ARTIFACT_LEN + 1]
            ),
            Err(PublicObjectError::ArtifactTooLarge)
        );
    }
}
