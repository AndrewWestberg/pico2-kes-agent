//! Canonical release manifest, signature, and artifact verifier.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const PRIMARY_FINGERPRINT: &str = "4F5F6D3F6D3F6D3F6D3F6D3F6D3F6D3F6D3F6D3F";
pub const SIGNER_FINGERPRINT: &str = "8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B";
pub const REQUIRED_SCHEMA_VERSION: u32 = 2;
pub const REQUIRED_USB_PROTOCOL_MAJOR: u32 = 1;

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

pub fn validate_version(version: &str) -> Result<(), ReleaseError> {
    if version.is_empty() || version.len() > 64 {
        return Err(ReleaseError::InvalidManifest(
            "version must be 1..=64 ASCII characters".into(),
        ));
    }
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(ReleaseError::InvalidManifest(
            "version contains invalid characters".into(),
        ));
    }
    Ok(())
}

pub fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    if manifest.schema_version != REQUIRED_SCHEMA_VERSION {
        return Err(ReleaseError::InvalidManifest(format!(
            "unsupported schema_version {} (expected {})",
            manifest.schema_version, REQUIRED_SCHEMA_VERSION
        )));
    }
    validate_version(&manifest.version)?;
    if manifest.usb_protocol_major != REQUIRED_USB_PROTOCOL_MAJOR {
        return Err(ReleaseError::InvalidManifest(format!(
            "unsupported usb_protocol_major {} (expected {})",
            manifest.usb_protocol_major, REQUIRED_USB_PROTOCOL_MAJOR
        )));
    }
    if manifest.platform.arch != "x86_64"
        || manifest.platform.os != "linux"
        || manifest.platform.min_glibc != "2.36"
    {
        return Err(ReleaseError::InvalidManifest(format!(
            "unsupported platform {}/{}/{}",
            manifest.platform.arch, manifest.platform.os, manifest.platform.min_glibc
        )));
    }
    for artifact in &manifest.artifacts {
        if artifact.sha256.len() != 64 || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ReleaseError::InvalidManifest(format!(
                "invalid sha256 for artifact {}",
                artifact.name
            )));
        }
        confine_relative_path(&artifact.path)?;
    }
    Ok(())
}

pub fn confine_relative_path(rel: &str) -> Result<PathBuf, ReleaseError> {
    if rel.is_empty() || rel.starts_with('/') {
        return Err(ReleaseError::PathConfinement(format!(
            "path must be relative: {rel}"
        )));
    }
    let p = Path::new(rel);
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => clean.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReleaseError::PathConfinement(format!(
                    "disallowed path component in {rel}"
                )));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(ReleaseError::PathConfinement("empty path".into()));
    }
    Ok(clean)
}

pub fn verify_artifact_file(
    bundle_root: &Path,
    artifact: &ReleaseArtifact,
) -> Result<PathBuf, ReleaseError> {
    let rel = confine_relative_path(&artifact.path)?;
    let mut cur = bundle_root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        let meta = fs::symlink_metadata(&cur)?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathConfinement(format!(
                "symlink not allowed: {}",
                cur.display()
            )));
        }
    }
    let meta = fs::metadata(&cur)?;
    if !meta.is_file() {
        return Err(ReleaseError::PathConfinement(format!(
            "not a regular file: {}",
            cur.display()
        )));
    }
    if meta.len() != artifact.size {
        return Err(ReleaseError::SizeMismatch {
            artifact: artifact.name.clone(),
            expected: artifact.size,
            actual: meta.len(),
        });
    }
    let mut file = File::open(&cur)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != artifact.sha256.to_ascii_lowercase() {
        return Err(ReleaseError::HashMismatch {
            artifact: artifact.name.clone(),
            expected: artifact.sha256.clone(),
            actual,
        });
    }
    Ok(cur)
}

pub fn verify_gpgv_signature(
    keyring: &Path,
    sig_path: &Path,
    data_path: &Path,
) -> Result<(), ReleaseError> {
    let out = Command::new("gpgv")
        .arg("--keyring")
        .arg(keyring)
        .arg(sig_path)
        .arg(data_path)
        .output()
        .map_err(|e| ReleaseError::SignatureFailed(format!("failed to invoke gpgv: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(ReleaseError::SignatureFailed(format!(
            "gpgv rejected signature: {stderr}"
        )));
    }
    Ok(())
}

pub fn verify_openssl_secp256k1_signature(
    pubkey_pem: &Path,
    sig_path: &Path,
    data_path: &Path,
) -> Result<(), ReleaseError> {
    let out = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(pubkey_pem)
        .arg("-signature")
        .arg(sig_path)
        .arg(data_path)
        .output()
        .map_err(|e| ReleaseError::SignatureFailed(format!("failed to invoke openssl: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(ReleaseError::SignatureFailed(format!(
            "openssl rejected signature: {stderr}"
        )));
    }
    Ok(())
}

pub fn load_and_verify_manifest(bundle_root: &Path) -> Result<ReleaseManifest, ReleaseError> {
    let manifest_path = bundle_root.join("release-manifest.json");
    let raw = fs::read(&manifest_path)?;
    let manifest: ReleaseManifest = serde_json::from_slice(&raw)
        .map_err(|e| ReleaseError::InvalidManifest(format!("json parse error: {e}")))?;
    validate_manifest(&manifest)?;
    for artifact in &manifest.artifacts {
        verify_artifact_file(bundle_root, artifact)?;
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 2,
            version: "0.2.0".into(),
            firmware_version: Some("0.2.0".into()),
            usb_protocol_major: 1,
            platform: ReleasePlatform {
                arch: "x86_64".into(),
                os: "linux".into(),
                min_glibc: "2.36".into(),
            },
            artifacts: vec![],
        }
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut m = sample_manifest();
        m.schema_version = 1;
        assert!(matches!(
            validate_manifest(&m),
            Err(ReleaseError::InvalidManifest(_))
        ));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(matches!(
            confine_relative_path("../etc/passwd"),
            Err(ReleaseError::PathConfinement(_))
        ));
        assert!(matches!(
            confine_relative_path("/usr/bin/p2kes"),
            Err(ReleaseError::PathConfinement(_))
        ));
        assert!(confine_relative_path("bin/p2kes").is_ok());
    }

    #[test]
    fn detects_sha256_mismatch() {
        let dir = std::env::temp_dir().join(format!("p2kes-rel-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("p2kes");
        fs::write(&file_path, b"hello").unwrap();
        let art = ReleaseArtifact {
            name: "p2kes".into(),
            path: "p2kes".into(),
            size: 5,
            sha256: "0".repeat(64),
            mode: None,
        };
        assert!(matches!(
            verify_artifact_file(&dir, &art),
            Err(ReleaseError::HashMismatch { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_signature_fails_closed() {
        let dir = std::env::temp_dir().join(format!("p2kes-sig-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let data = dir.join("data.bin");
        let sig = dir.join("data.sig");
        let key = dir.join("nonexistent.pem");
        fs::write(&data, b"tampered").unwrap();
        fs::write(&sig, b"badsig").unwrap();
        assert!(matches!(
            verify_openssl_secp256k1_signature(&key, &sig, &data),
            Err(ReleaseError::SignatureFailed(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
