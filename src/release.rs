//! Canonical release manifest, signature, and artifact verifier.

mod distribution;

pub(crate) use distribution::copy_verified_artifact;
pub use distribution::load_and_verify_manifest;

use serde::{Deserialize, Serialize};

use std::io;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePlatform {
    pub arch: String,
    pub os: String,
    pub min_glibc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: String,
    #[serde(default)]
    pub firmware_version: Option<String>,
    pub usb_protocol_major: u32,
    pub platform: ReleasePlatform,
    pub artifacts: Vec<ReleaseArtifact>,
}

#[derive(Debug)]
pub enum ReleaseError {
    Io(io::Error),
    InvalidManifest(String),
    SignatureFailed(String),
    PathConfinement(String),
    HashMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },
    SizeMismatch {
        artifact: String,
        expected: u64,
        actual: u64,
    },
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidManifest(msg) => write!(f, "invalid release manifest: {msg}"),
            Self::SignatureFailed(msg) => write!(f, "signature verification failed: {msg}"),
            Self::PathConfinement(msg) => write!(f, "unsafe artifact path: {msg}"),
            Self::HashMismatch {
                artifact,
                expected,
                actual,
            } => write!(
                f,
                "sha256 mismatch for {artifact}: expected {expected}, got {actual}"
            ),
            Self::SizeMismatch {
                artifact,
                expected,
                actual,
            } => write!(
                f,
                "size mismatch for {artifact}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for ReleaseError {}

impl From<io::Error> for ReleaseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
