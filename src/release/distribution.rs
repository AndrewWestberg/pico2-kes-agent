use super::{ReleaseArtifact, ReleaseError, ReleaseManifest, ReleasePlatform, VerifiedFirmware};
use rustix::fs::{self as fs_at, AtFlags, CWD, Dir, FileType, Mode, OFlags, ResolveFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

mod signature;
use signature::PRODUCTION_TRUST;
#[cfg(not(test))]
use signature::TrustRoots;
#[cfg(test)]
pub(crate) use signature::TrustRoots;
use signature::{
    PrivateDir, verify_authority, verify_distribution_signature, verify_firmware_authority,
    verify_firmware_signature,
};

const DISTRIBUTION_PURPOSE: &str = "pico2-kes-agent-distribution-v1";
const FIRMWARE_RELEASE_PURPOSE: &str = "pico2-kes-firmware-release-v1";
const FIRMWARE_PROFILE: &str = "rp2350-signed-msd-v1";
const FIRMWARE_IMAGE: &str = "firmware/pico2-kes-firmware.signed.uf2";
const FIRMWARE_ELF_IN_DIST: &str = "firmware/pico2-kes-firmware.signed.elf";
const MANIFEST: &str = "distribution.json";
const MANIFEST_SIGNATURE: &str = "distribution.json.sig";
const AUTHORITY: &str = "distribution-authority.json";
const AUTHORITY_SIGNATURE: &str = "distribution-authority.json.asc";
const CERTIFICATE: &str = "firmware/release-authority.asc";
const FIRMWARE_KEY: &str = "firmware/firmware-signing-public.pem";
const FIRMWARE_RELEASE_MANIFEST: &str = "release.json";
const FIRMWARE_RELEASE_SIGNATURE: &str = "release.json.sig";
const FIRMWARE_BOOT_AUTHORITY: &str = "firmware-key.json";
const FIRMWARE_BOOT_AUTHORITY_SIG: &str = "firmware-key.json.asc";
const FIRMWARE_RELEASE_CERT: &str = "release-authority.asc";
const FIRMWARE_SIGNING_PEM: &str = "firmware-signing-public.pem";
const FIRMWARE_OTP_POLICY: &str = "otp-policy.json";
const FIRMWARE_SIGNED_ELF: &str = "pico2-kes-firmware.signed.elf";
const FIRMWARE_SIGNED_UF2: &str = "pico2-kes-firmware.signed.uf2";
const FIRMWARE_START: u32 = 0x1000_0000;
const FIRMWARE_END: u32 = 0x1010_0000;
const STATE_END: u32 = 0x1030_8000;
const FIRMWARE_ARTIFACTS: &[&str] = &[
    FIRMWARE_SIGNED_ELF,
    FIRMWARE_SIGNED_UF2,
    "pico2-otp-permissions.elf",
    "firmware.py",
    FIRMWARE_OTP_POLICY,
    FIRMWARE_SIGNING_PEM,
    FIRMWARE_BOOT_AUTHORITY,
    FIRMWARE_BOOT_AUTHORITY_SIG,
    FIRMWARE_RELEASE_CERT,
];
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

const COMPONENTS: [(&str, &str); 7] = [
    ("manager", "bin/p2kesup"),
    ("daemon", "bin/pico2-kes-agentd"),
    ("cli", "bin/p2kes"),
    ("flash", "bin/p2kes-flash"),
    ("firmware", FIRMWARE_IMAGE),
    ("tool", "tools/picotool"),
    ("deployment", "deploy/pico2-kes-agentd.service"),
];

// Remaining required payload from tools/publish_release.py (the seven components are above).
const REQUIRED_PAYLOAD: &[&str] = &[
    AUTHORITY,
    AUTHORITY_SIGNATURE,
    CERTIFICATE,
    FIRMWARE_KEY,
    "install.sh",
    "install.sh.sig",
    "tools/firmware.py",
    "deploy/70-pico2-kes-agent.rules",
    "deploy/pico2-kes-agent-host-check",
    "deploy/cardano-node-memory-hardening.conf",
    "licenses/picotool.txt",
    "licenses/mbedtls.txt",
    "licenses/libusb-1.0-0.txt",
    "licenses/libudev1.txt",
    "licenses/libstdc++6.txt",
    "licenses/libgcc-s1.txt",
    "runtime/libusb-1.0.so.0",
    "runtime/libudev.so.1",
    "runtime/libstdc++.so.6",
    "runtime/libgcc_s.so.1",
    "runtime/provenance.json",
    "firmware/pico2-kes-firmware.signed.elf",
    "firmware/pico2-otp-permissions.elf",
    "firmware/firmware.py",
    "firmware/otp-policy.json",
    "firmware/firmware-key.json",
    "firmware/firmware-key.json.asc",
    "firmware/release.json",
    "firmware/release.json.sig",
];

#[derive(Deserialize)]
struct Distribution {
    schema_version: u32,
    purpose: String,
    qualification: String,
    release: DistributionRelease,
    platform: DistributionPlatform,
    compatibility: DistributionCompatibility,
    components: Vec<DistributionComponent>,
    artifacts: Vec<DistributionArtifact>,
}

#[derive(Deserialize)]
struct DistributionRelease {
    tag: String,
    version: String,
}

#[derive(Deserialize)]
struct DistributionPlatform {
    target: String,
    glibc_min: String,
    systemd: bool,
    udev: bool,
}

#[derive(Deserialize)]
struct DistributionCompatibility {
    usb_profiles: Vec<String>,
}

#[derive(Deserialize)]
struct DistributionComponent {
    name: String,
    version: String,
    artifact: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DistributionArtifact {
    path: String,
    size_bytes: u64,
    sha256: String,
    class: String,
    mode: u32,
}

fn invalid(message: impl Into<String>) -> ReleaseError {
    ReleaseError::InvalidManifest(message.into())
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version != "."
        && version != ".."
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn safe_path(path: &str) -> Result<&Path, ReleaseError> {
    if path.len() > 240
        || !path.bytes().all(|b| (32..127).contains(&b) && b != b'\\')
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(ReleaseError::PathConfinement(path.to_owned()));
    }
    Ok(Path::new(path))
}

fn artifact_class(path: &str) -> &str {
    match path.split('/').next().unwrap() {
        "bin" => "bin",
        "firmware" => "firmware",
        "tools" => "tool",
        "deploy" => "deployment",
        "licenses" => "license",
        "runtime" => "runtime",
        _ => "bootstrap",
    }
}

fn normalize_distribution(raw: &[u8]) -> Result<ReleaseManifest, ReleaseError> {
    let manifest: Distribution =
        serde_json::from_slice(raw).map_err(|e| invalid(format!("distribution JSON: {e}")))?;
    if manifest.schema_version != 1
        || manifest.purpose != DISTRIBUTION_PURPOSE
        || !matches!(manifest.qualification.as_str(), "candidate" | "qualified")
    {
        return Err(invalid(
            "unsupported distribution schema, purpose or qualification",
        ));
    }
    if !valid_version(&manifest.release.tag)
        || !manifest.release.tag.starts_with('v')
        || manifest.release.version != manifest.release.tag
    {
        return Err(invalid("invalid distribution release tag"));
    }
    if manifest.platform.target != "x86_64-unknown-linux-gnu"
        || manifest.platform.glibc_min != "2.36"
        || !manifest.platform.systemd
        || !manifest.platform.udev
        || !manifest
            .compatibility
            .usb_profiles
            .iter()
            .any(|p| p == "usb-protocol-1")
    {
        return Err(invalid("unsupported platform or USB protocol"));
    }
    if manifest.components.len() != COMPONENTS.len() {
        return Err(invalid("unexpected distribution components"));
    }
    let mut firmware_version = None;
    for (name, path) in COMPONENTS {
        let component = manifest
            .components
            .iter()
            .find(|component| component.name == name)
            .filter(|component| component.artifact == path && valid_version(&component.version))
            .ok_or_else(|| invalid(format!("invalid component {name}")))?;
        if name == "firmware" {
            firmware_version = Some(component.version.clone());
        }
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > 256 {
        return Err(invalid("invalid distribution artifact count"));
    }
    let mut names = HashSet::from([MANIFEST, MANIFEST_SIGNATURE]);
    let mut total_bytes = 0;
    for entry in &manifest.artifacts {
        safe_path(&entry.path)?;
        if !names.insert(entry.path.as_str())
            || entry.size_bytes > MAX_FILE_BYTES
            || entry.class != artifact_class(&entry.path)
            || !matches!(entry.mode, 0o644 | 0o755)
            || (matches!(
                entry.path.as_str(),
                AUTHORITY | AUTHORITY_SIGNATURE | "install.sh.sig"
            ) && entry.mode != 0o644)
            || ((entry.class == "bin" || entry.path == "tools/picotool") && entry.mode != 0o755)
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid(format!(
                "invalid or duplicate artifact {}",
                entry.path
            )));
        }
        total_bytes += entry.size_bytes;
    }
    if total_bytes > MAX_BUNDLE_BYTES {
        return Err(invalid("distribution exceeds size limit"));
    }
    for path in COMPONENTS
        .iter()
        .map(|(_, path)| path)
        .chain(REQUIRED_PAYLOAD)
    {
        if !names.contains(path) {
            return Err(invalid(format!("missing artifact {path}")));
        }
    }
    Ok(ReleaseManifest {
        schema_version: manifest.schema_version,
        version: manifest.release.tag,
        firmware_version,
        usb_protocol_major: 1,
        platform: ReleasePlatform {
            arch: "x86_64".into(),
            os: "linux".into(),
            min_glibc: manifest.platform.glibc_min,
        },
        artifacts: manifest
            .artifacts
            .into_iter()
            .map(|entry| ReleaseArtifact {
                name: entry.path.rsplit('/').next().unwrap().into(),
                path: entry.path,
                size: entry.size_bytes,
                sha256: entry.sha256,
                mode: Some(
                    if entry.mode == 0o644 {
                        "0o644"
                    } else {
                        "0o755"
                    }
                    .into(),
                ),
            })
            .collect(),
    })
}

impl From<rustix::io::Errno> for ReleaseError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

fn open_bundle(bundle_root: &Path) -> Result<File, ReleaseError> {
    Ok(fs_at::openat2(
        CWD,
        bundle_root,
        DIRECTORY_FLAGS,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )?
    .into())
}

fn open_bundle_file(root: &File, path: &str) -> Result<(File, Metadata), ReleaseError> {
    let file = File::from(fs_at::openat2(
        root,
        safe_path(path)?,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(ReleaseError::PathConfinement(format!(
            "link or special file: {path}"
        )));
    }
    Ok((file, metadata))
}

fn check_mode(path: &str, metadata: &Metadata, mode: u32) -> Result<(), ReleaseError> {
    if metadata.mode() & 0o7777 != mode {
        return Err(invalid(format!(
            "mode mismatch for {path}: expected {mode:#o}"
        )));
    }
    Ok(())
}

fn check_size(artifact: &ReleaseArtifact, actual: u64) -> Result<(), ReleaseError> {
    if actual != artifact.size {
        return Err(ReleaseError::SizeMismatch {
            artifact: artifact.path.clone(),
            expected: artifact.size,
            actual,
        });
    }
    Ok(())
}

fn check_digest(
    artifact: &ReleaseArtifact,
    digest: sha2::digest::Output<Sha256>,
) -> Result<(), ReleaseError> {
    let expected = artifact.sha256.as_bytes();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if expected.len() != 64
        || !digest
            .iter()
            .zip(expected.as_chunks::<2>().0)
            .all(|(&byte, &pair)| pair == [HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])
    {
        return Err(ReleaseError::HashMismatch {
            artifact: artifact.path.clone(),
            expected: artifact.sha256.clone(),
            actual: format!("{digest:x}"),
        });
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlashRegion {
    start: u32,
    end: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirmwareArtifactEntry {
    name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirmwareRelease {
    schema_version: u32,
    purpose: String,
    tag: String,
    commit: String,
    profile: String,
    bootkey_sha256: String,
    firmware_region: FlashRegion,
    state_region: FlashRegion,
    storage_version: u32,
    usb_protocol_major: u32,
    artifacts: Vec<FirmwareArtifactEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OtpPolicyBounds {
    schema_version: u32,
    profile: String,
    steppings: serde_json::Value,
    flash: serde_json::Value,
    firmware_region: FlashRegion,
    state_region: FlashRegion,
    fields: serde_json::Value,
    page_locks: serde_json::Value,
    rma: bool,
    otp_access_keys: bool,
    storage_version: u32,
    usb_protocol_major: u32,
}

fn normalize_firmware_release(
    raw: &[u8],
    expected_bootkey_sha256: &str,
) -> Result<(String, Vec<ReleaseArtifact>), ReleaseError> {
    let release: FirmwareRelease =
        serde_json::from_slice(raw).map_err(|e| invalid(format!("firmware release JSON: {e}")))?;
    if release.schema_version != 1
        || release.purpose != FIRMWARE_RELEASE_PURPOSE
        || release.profile != FIRMWARE_PROFILE
    {
        return Err(invalid(
            "unsupported firmware release schema, purpose or profile",
        ));
    }
    if release.tag.is_empty()
        || release.tag.len() > 255
        || !release.tag.starts_with('v')
        || !release.tag.bytes().all(|b| (32..127).contains(&b))
    {
        return Err(invalid("invalid firmware release tag"));
    }
    if !matches!(release.commit.len(), 40 | 64)
        || !release
            .commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid firmware commit digest"));
    }
    if release.bootkey_sha256 != expected_bootkey_sha256 {
        return Err(ReleaseError::SignatureFailed(
            "firmware release bootkey_sha256 does not match authority".into(),
        ));
    }
    if release.firmware_region.start != FIRMWARE_START
        || release.firmware_region.end != FIRMWARE_END
        || release.state_region.start != FIRMWARE_END
        || release.state_region.end != STATE_END
        || release.storage_version != 2
        || release.usb_protocol_major != 1
    {
        return Err(invalid(
            "incompatible firmware flash region or storage policy",
        ));
    }
    if release.artifacts.len() != FIRMWARE_ARTIFACTS.len() {
        return Err(invalid("unexpected firmware artifact count"));
    }
    let mut seen = HashSet::new();
    let mut total_bytes = 0u64;
    let mut artifacts = Vec::with_capacity(release.artifacts.len());
    for entry in release.artifacts {
        safe_path(&entry.name)?;
        if entry.name.contains('/')
            || !FIRMWARE_ARTIFACTS.contains(&entry.name.as_str())
            || !seen.insert(entry.name.clone())
            || entry.size_bytes > MAX_FILE_BYTES
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid(format!(
                "invalid or duplicate firmware artifact {}",
                entry.name
            )));
        }
        total_bytes += entry.size_bytes;
        artifacts.push(ReleaseArtifact {
            name: entry.name.clone(),
            path: entry.name,
            size: entry.size_bytes,
            sha256: entry.sha256,
            mode: None,
        });
    }
    if total_bytes > MAX_BUNDLE_BYTES {
        return Err(invalid("firmware bundle exceeds size limit"));
    }
    Ok((release.tag, artifacts))
}

fn validate_otp_policy_bounds(raw: &[u8]) -> Result<(), ReleaseError> {
    let policy: OtpPolicyBounds =
        serde_json::from_slice(raw).map_err(|e| invalid(format!("otp-policy.json: {e}")))?;
    let _ = (
        &policy.steppings,
        &policy.flash,
        &policy.fields,
        &policy.page_locks,
    );
    if policy.schema_version != 1
        || policy.profile != FIRMWARE_PROFILE
        || policy.firmware_region.start != FIRMWARE_START
        || policy.firmware_region.end != FIRMWARE_END
        || policy.state_region.start != FIRMWARE_END
        || policy.state_region.end != STATE_END
        || policy.rma
        || policy.otp_access_keys
        || policy.storage_version != 2
        || policy.usb_protocol_major != 1
    {
        return Err(invalid("otp-policy.json flash region or profile mismatch"));
    }
    Ok(())
}

fn copy_artifact(
    root: &File,
    artifact: &ReleaseArtifact,
    mut destination: impl Write,
) -> Result<(), ReleaseError> {
    let (file, metadata) = open_bundle_file(root, &artifact.path)?;
    match artifact.mode.as_deref() {
        Some("0o644") => check_mode(&artifact.path, &metadata, 0o644)?,
        Some("0o755") => check_mode(&artifact.path, &metadata, 0o755)?,
        None => {
            if metadata.mode() & 0o022 != 0 {
                return Err(invalid(format!(
                    "unsafe writable mode for {}: {:#o}",
                    artifact.path,
                    metadata.mode() & 0o7777
                )));
            }
        }
        _ => return Err(invalid(format!("invalid mode for {}", artifact.path))),
    }
    check_size(artifact, metadata.len())?;
    if artifact.size > MAX_FILE_BYTES {
        return Err(invalid(format!(
            "artifact exceeds size limit: {}",
            artifact.path
        )));
    }
    let mut source = file.take(artifact.size);
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let count = source.read(&mut buf)?;
        if count == 0 {
            break;
        }
        hash.update(&buf[..count]);
        destination.write_all(&buf[..count])?;
    }
    check_size(artifact, artifact.size - source.limit())?;
    if source.into_inner().read(&mut buf[..1])? != 0 {
        check_size(artifact, artifact.size + 1)?;
    }
    check_digest(artifact, hash.finalize())
}

/// Copy to an unpublished destination; do not publish it unless verification succeeds.
pub(crate) fn copy_verified_artifact(
    bundle_root: &Path,
    artifact: &ReleaseArtifact,
    destination: impl Write,
) -> Result<(), ReleaseError> {
    copy_artifact(&open_bundle(bundle_root)?, artifact, destination)
}

fn scan_inventory(
    dir: &File,
    remaining: &mut HashSet<&str>,
    prefix: &mut String,
    directories_left: &mut usize,
) -> Result<(), ReleaseError> {
    let mut empty = true;
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        empty = false;
        let child = name
            .to_str()
            .map_err(|_| invalid("non-ASCII bundle path"))?;
        let base = prefix.len();
        if base != 0 {
            prefix.push('/');
        }
        prefix.push_str(child);
        safe_path(prefix)?;
        let kind = match entry.file_type() {
            FileType::Unknown => FileType::from_raw_mode(
                fs_at::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?.st_mode,
            ),
            kind => kind,
        };
        match kind {
            FileType::Directory => {
                *directories_left = directories_left
                    .checked_sub(1)
                    .ok_or_else(|| invalid("too many bundle directories"))?;
                let subdir = File::from(fs_at::openat(
                    dir,
                    name,
                    DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?);
                scan_inventory(&subdir, remaining, prefix, directories_left)?;
            }
            FileType::RegularFile if remaining.remove(prefix.as_str()) => {}
            _ => return Err(invalid(format!("unexpected bundle entry {prefix}"))),
        }
        prefix.truncate(base);
    }
    if empty && !prefix.is_empty() {
        return Err(invalid(format!("empty bundle directory {prefix}")));
    }
    Ok(())
}

fn verify_inventory(root: &File, artifacts: &[ReleaseArtifact]) -> Result<(), ReleaseError> {
    let mut remaining: HashSet<&str> = artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .chain([MANIFEST, MANIFEST_SIGNATURE])
        .collect();
    let mut directories_left = 1024;
    scan_inventory(
        root,
        &mut remaining,
        &mut String::new(),
        &mut directories_left,
    )?;
    if let Some(path) = remaining.iter().min() {
        return Err(invalid(format!("missing bundle entry {path}")));
    }
    for artifact in artifacts {
        copy_artifact(root, artifact, io::sink())?;
    }
    Ok(())
}

fn read_metadata(root: &File, path: &str) -> Result<Vec<u8>, ReleaseError> {
    let (file, metadata) = open_bundle_file(root, path)?;
    check_mode(path, &metadata, 0o644)?;
    read_bounded_metadata(file, &metadata, path)
}

fn read_firmware_metadata(root: &File, path: &str) -> Result<Vec<u8>, ReleaseError> {
    let (file, metadata) = open_bundle_file(root, path)?;
    if metadata.mode() & 0o022 != 0 {
        return Err(invalid(format!(
            "unsafe writable mode for {path}: {:#o}",
            metadata.mode() & 0o7777
        )));
    }
    read_bounded_metadata(file, &metadata, path)
}

fn read_bounded_metadata(
    file: File,
    metadata: &Metadata,
    path: &str,
) -> Result<Vec<u8>, ReleaseError> {
    if metadata.len() > MAX_METADATA_BYTES {
        return Err(invalid(format!("oversized metadata {path}")));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(invalid(format!("oversized metadata {path}")));
    }
    Ok(bytes)
}

fn load_and_verify_manifest_at(
    root: &File,
    trust: TrustRoots<'_>,
) -> Result<ReleaseManifest, ReleaseError> {
    let raw = read_metadata(root, MANIFEST)?;
    let signature = read_metadata(root, MANIFEST_SIGNATURE)?;
    let authority = read_metadata(root, AUTHORITY)?;
    let authority_signature = read_metadata(root, AUTHORITY_SIGNATURE)?;
    let certificate = read_metadata(root, CERTIFICATE)?;
    let firmware_key = read_metadata(root, FIRMWARE_KEY)?;

    let scratch = PrivateDir::new()?;
    let key = verify_authority(
        &scratch.0,
        &authority,
        &authority_signature,
        &certificate,
        trust,
    )?;
    if key.as_bytes() != firmware_key.as_slice() {
        return Err(ReleaseError::SignatureFailed(
            "distribution and firmware keys differ".into(),
        ));
    }
    verify_distribution_signature(&scratch.0, &signature, &raw)?;

    let manifest = normalize_distribution(&raw)?;
    // Bind the exact credential snapshots used above to the signed inventory.
    for (path, bytes) in [
        (AUTHORITY, authority.as_slice()),
        (AUTHORITY_SIGNATURE, authority_signature.as_slice()),
        (CERTIFICATE, certificate.as_slice()),
        (FIRMWARE_KEY, firmware_key.as_slice()),
    ] {
        let artifact = manifest.artifacts.iter().find(|a| a.path == path).unwrap();
        check_size(artifact, bytes.len() as u64)?;
        check_digest(artifact, Sha256::digest(bytes))?;
    }
    verify_inventory(root, &manifest.artifacts)?;
    Ok(manifest)
}

fn load_and_verify_firmware_at(
    root: &File,
    trust: TrustRoots<'_>,
) -> Result<VerifiedFirmware, ReleaseError> {
    let raw = read_firmware_metadata(root, FIRMWARE_RELEASE_MANIFEST)?;
    let signature = read_firmware_metadata(root, FIRMWARE_RELEASE_SIGNATURE)?;
    let authority = read_firmware_metadata(root, FIRMWARE_BOOT_AUTHORITY)?;
    let authority_sig = read_firmware_metadata(root, FIRMWARE_BOOT_AUTHORITY_SIG)?;
    let certificate = read_firmware_metadata(root, FIRMWARE_RELEASE_CERT)?;
    let signing_pem = read_firmware_metadata(root, FIRMWARE_SIGNING_PEM)?;
    let policy_raw = read_firmware_metadata(root, FIRMWARE_OTP_POLICY)?;

    let scratch = PrivateDir::new()?;
    let bootkey_sha256 = verify_firmware_authority(
        &scratch.0,
        &authority,
        &authority_sig,
        &certificate,
        &signing_pem,
        trust,
    )?;
    verify_firmware_signature(&scratch.0, &signature, &raw)?;
    let (version, artifacts) = normalize_firmware_release(&raw, &bootkey_sha256)?;
    validate_otp_policy_bounds(&policy_raw)?;

    for (path, bytes) in [
        (FIRMWARE_BOOT_AUTHORITY, authority.as_slice()),
        (FIRMWARE_BOOT_AUTHORITY_SIG, authority_sig.as_slice()),
        (FIRMWARE_RELEASE_CERT, certificate.as_slice()),
        (FIRMWARE_SIGNING_PEM, signing_pem.as_slice()),
        (FIRMWARE_OTP_POLICY, policy_raw.as_slice()),
    ] {
        let artifact = artifacts.iter().find(|a| a.path == path).unwrap();
        check_size(artifact, bytes.len() as u64)?;
        check_digest(artifact, Sha256::digest(bytes))?;
    }

    let mut remaining: HashSet<&str> = artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .chain([FIRMWARE_RELEASE_MANIFEST, FIRMWARE_RELEASE_SIGNATURE])
        .collect();
    let mut directories_left = 1024;
    scan_inventory(
        root,
        &mut remaining,
        &mut String::new(),
        &mut directories_left,
    )?;
    if let Some(path) = remaining.iter().min() {
        return Err(invalid(format!("missing firmware bundle entry {path}")));
    }

    let mut uf2_bytes = Vec::new();
    let mut uf2_sha256 = String::new();
    let mut elf_bytes = Vec::new();
    let mut elf_sha256 = String::new();
    for artifact in &artifacts {
        if artifact.path == FIRMWARE_SIGNED_UF2 {
            uf2_bytes.reserve_exact(artifact.size as usize);
            copy_artifact(root, artifact, &mut uf2_bytes)?;
            uf2_sha256 = artifact.sha256.clone();
        } else if artifact.path == FIRMWARE_SIGNED_ELF {
            elf_bytes.reserve_exact(artifact.size as usize);
            copy_artifact(root, artifact, &mut elf_bytes)?;
            elf_sha256 = artifact.sha256.clone();
        } else {
            copy_artifact(root, artifact, io::sink())?;
        }
    }

    Ok(VerifiedFirmware {
        version,
        bootkey_sha256,
        uf2_sha256,
        uf2_bytes,
        elf_sha256,
        elf_bytes,
    })
}

pub(crate) fn load_and_verify_firmware_with_trust(
    bundle_or_firmware_dir: &Path,
    trust: TrustRoots<'_>,
) -> Result<VerifiedFirmware, ReleaseError> {
    let root = open_bundle(bundle_or_firmware_dir)?;
    match fs_at::statat(&root, MANIFEST, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            let dist = load_and_verify_manifest_at(&root, trust)?;
            let fw_dir = File::from(fs_at::openat(
                &root,
                "firmware",
                DIRECTORY_FLAGS | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
            let fw = load_and_verify_firmware_at(&fw_dir, trust)?;
            let dist_uf2 = dist
                .artifacts
                .iter()
                .find(|a| a.path == FIRMWARE_IMAGE)
                .ok_or_else(|| invalid("missing firmware UF2 in distribution manifest"))?;
            let dist_elf = dist
                .artifacts
                .iter()
                .find(|a| a.path == FIRMWARE_ELF_IN_DIST)
                .ok_or_else(|| invalid("missing firmware ELF in distribution manifest"))?;
            if dist_uf2.sha256 != fw.uf2_sha256
                || dist_uf2.size != fw.uf2_bytes.len() as u64
                || dist_elf.sha256 != fw.elf_sha256
                || dist_elf.size != fw.elf_bytes.len() as u64
            {
                return Err(ReleaseError::SignatureFailed(
                    "distribution and firmware release manifests disagree on firmware digests"
                        .into(),
                ));
            }
            Ok(fw)
        }
        Err(rustix::io::Errno::NOENT) => {
            match fs_at::statat(&root, FIRMWARE_RELEASE_MANIFEST, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => load_and_verify_firmware_at(&root, trust),
                Err(rustix::io::Errno::NOENT) => Err(invalid(format!(
                    "no signed distribution.json or release.json manifest in {} (pass --firmware-dir DIR or stage a verified release bundle)",
                    bundle_or_firmware_dir.display()
                ))),
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

pub fn load_and_verify_firmware(
    bundle_or_firmware_dir: &Path,
) -> Result<VerifiedFirmware, ReleaseError> {
    load_and_verify_firmware_with_trust(bundle_or_firmware_dir, PRODUCTION_TRUST)
}

pub fn load_and_verify_manifest(bundle_root: &Path) -> Result<ReleaseManifest, ReleaseError> {
    let root = open_bundle(bundle_root)?;
    load_and_verify_manifest_at(&root, PRODUCTION_TRUST)
}

#[cfg(test)]
mod tests;
