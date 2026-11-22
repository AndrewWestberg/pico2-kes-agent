use super::{DISTRIBUTION_PURPOSE, ReleaseError};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// These are the primary and signing subkey pinned by tools/firmware.py.
const PRIMARY_FINGERPRINT: &str = "9FF957E79B5D853544805F4725491F18087931B6";
const SIGNER_FINGERPRINT: &str = "78C0F32094CD02A4BAFA444C684E37A210480F82";
const AUTHORITY_PURPOSE: &str = "pico2-kes-agent-distribution-authority-v1";
const FIRMWARE_AUTHORITY_PURPOSE: &str = "pico2-kes-firmware-boot-authority-v1";
const PROJECT: &str = "https://github.com/AndrewWestberg/pico2-kes-agent";
const SPKI_PREFIX: &[u8] = b"\x30\x56\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x42\x00\x04";
const OPENSSL: &str = "/usr/bin/openssl";

#[derive(Clone, Copy)]
pub(crate) struct TrustRoots<'a> {
    pub primary: &'a str,
    pub signer: &'a str,
}

pub(crate) const PRODUCTION_TRUST: TrustRoots<'static> = TrustRoots {
    primary: PRIMARY_FINGERPRINT,
    signer: SIGNER_FINGERPRINT,
};

pub(super) struct PrivateDir(pub(super) PathBuf);

impl PrivateDir {
    pub(super) fn new() -> io::Result<Self> {
        let mut template = *b"/tmp/p2kes-verify-XXXXXX\0";
        // mkdtemp creates the private directory atomically and changes only the Xs.
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        let path = CStr::from_bytes_until_nul(&template).unwrap();
        Ok(Self(std::ffi::OsStr::from_bytes(path.to_bytes()).into()))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    schema_version: u32,
    purpose: String,
    project: String,
    algorithm: String,
    public_key_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirmwareDelegation {
    schema_version: u32,
    purpose: String,
    project: String,
    algorithm: String,
    bootkey_slot: u32,
    bootkey_sha256: String,
    public_pem_sha256: String,
}

fn rejected(message: impl Into<String>) -> ReleaseError {
    ReleaseError::SignatureFailed(message.into())
}

fn system_tool(path: &str) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn checked_output(command: &mut Command, operation: &str) -> Result<Vec<u8>, ReleaseError> {
    let out = command
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| rejected(format!("{operation}: {e}")))?;
    if !out.status.success() {
        return Err(rejected(format!("{operation}: {}", out.status)));
    }
    Ok(out.stdout)
}

fn verify_gpg_status(status: &[u8], trust: TrustRoots<'_>) -> Result<(), ReleaseError> {
    let text = std::str::from_utf8(status).map_err(|_| rejected("invalid gpgv status"))?;
    let mut found = false;
    for line in text
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] "))
    {
        let mut fields = line.split_ascii_whitespace();
        match fields.next() {
            Some("VALIDSIG") => {
                if found
                    || fields.next() != Some(trust.signer)
                    || fields.nth(8) != Some(trust.primary)
                    || fields.next().is_some()
                {
                    return Err(rejected(
                        "authority is not signed by the pinned primary/subkey",
                    ));
                }
                found = true;
            }
            Some("REVKEYSIG" | "EXPKEYSIG" | "EXPSIG" | "BADSIG" | "ERRSIG") => {
                return Err(rejected(
                    "revoked, expired or invalid distribution authority",
                ));
            }
            _ => {}
        }
    }
    if !found {
        return Err(rejected("missing OpenPGP distribution authorization"));
    }
    Ok(())
}

fn verify_gpg_detached(
    scratch: &Path,
    statement: &[u8],
    signature: &[u8],
    certificate: &[u8],
    trust: TrustRoots<'_>,
) -> Result<(), ReleaseError> {
    let statement_file = scratch.join("authority.json");
    let signature_file = scratch.join("authority.json.asc");
    let certificate_file = scratch.join("certificate.asc");
    let keyring = scratch.join("authority.gpg");
    fs::write(&statement_file, statement)?;
    fs::write(&signature_file, signature)?;
    fs::write(&certificate_file, certificate)?;
    checked_output(
        system_tool("/usr/bin/gpg")
            .args(["--batch", "--no-options", "--homedir"])
            .arg(scratch)
            .args(["--dearmor", "--output"])
            .arg(&keyring)
            .arg(&certificate_file),
        "gpg could not decode the authority certificate",
    )?;
    let status = checked_output(
        system_tool("/usr/bin/gpgv")
            .arg("--homedir")
            .arg(scratch)
            .arg("--keyring")
            .arg(&keyring)
            .args(["--status-fd", "1"])
            .arg(&signature_file)
            .arg(&statement_file),
        "gpgv rejected the authority statement",
    )?;
    verify_gpg_status(&status, trust)
}

fn validate_secp256k1_public_pem(scratch: &Path, pem: &[u8]) -> Result<[u8; 64], ReleaseError> {
    let key = scratch.join("public.pem");
    fs::write(&key, pem)?;
    checked_output(
        system_tool(OPENSSL)
            .args(["pkey", "-pubin", "-pubcheck", "-noout", "-in"])
            .arg(&key),
        "OpenSSL rejected the authority public key",
    )?;
    let der = checked_output(
        system_tool(OPENSSL)
            .args(["pkey", "-pubin", "-outform", "DER", "-in"])
            .arg(&key),
        "OpenSSL could not decode the authority public key",
    )?;
    if der.len() != SPKI_PREFIX.len() + 64 || !der.starts_with(SPKI_PREFIX) {
        return Err(rejected(
            "authority must be an uncompressed secp256k1 public key",
        ));
    }
    Ok(der[SPKI_PREFIX.len()..].try_into().unwrap())
}

pub(super) fn verify_authority(
    scratch: &Path,
    statement: &[u8],
    signature: &[u8],
    certificate: &[u8],
    trust: TrustRoots<'_>,
) -> Result<String, ReleaseError> {
    verify_gpg_detached(scratch, statement, signature, certificate, trust)?;

    let delegation: Delegation = serde_json::from_slice(statement)
        .map_err(|e| rejected(format!("invalid distribution authority JSON: {e}")))?;
    if delegation.schema_version != 1
        || delegation.purpose != AUTHORITY_PURPOSE
        || delegation.project != PROJECT
        || delegation.algorithm != "secp256k1"
    {
        return Err(rejected("invalid distribution authority statement"));
    }
    validate_secp256k1_public_pem(scratch, delegation.public_key_pem.as_bytes())?;
    Ok(delegation.public_key_pem)
}

pub(super) fn verify_firmware_authority(
    scratch: &Path,
    statement: &[u8],
    signature: &[u8],
    certificate: &[u8],
    public_key_pem: &[u8],
    trust: TrustRoots<'_>,
) -> Result<String, ReleaseError> {
    verify_gpg_detached(scratch, statement, signature, certificate, trust)?;

    let delegation: FirmwareDelegation = serde_json::from_slice(statement)
        .map_err(|e| rejected(format!("invalid firmware authority JSON: {e}")))?;
    if delegation.schema_version != 1
        || delegation.purpose != FIRMWARE_AUTHORITY_PURPOSE
        || delegation.project != PROJECT
        || delegation.algorithm != "secp256k1"
        || delegation.bootkey_slot != 0
    {
        return Err(rejected("invalid firmware authority statement"));
    }
    let pem_sha256 = format!("{:x}", Sha256::digest(public_key_pem));
    if pem_sha256 != delegation.public_pem_sha256 {
        return Err(rejected("firmware public key PEM digest mismatch"));
    }
    let point = validate_secp256k1_public_pem(scratch, public_key_pem)?;
    let point_sha256 = format!("{:x}", Sha256::digest(point));
    if point_sha256 != delegation.bootkey_sha256 {
        return Err(rejected("firmware bootkey digest mismatch"));
    }
    Ok(delegation.bootkey_sha256)
}

pub(super) fn verify_distribution_signature(
    scratch: &Path,
    signature: &[u8],
    manifest: &[u8],
) -> Result<(), ReleaseError> {
    let signature_file = scratch.join("distribution.sig");
    fs::write(&signature_file, signature)?;
    let mut child = system_tool(OPENSSL)
        .args(["dgst", "-sha256", "-verify"])
        .arg(scratch.join("public.pem"))
        .arg("-signature")
        .arg(signature_file)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| rejected(format!("could not start OpenSSL: {e}")))?;
    let sent = {
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(DISTRIBUTION_PURPOSE.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.write_all(manifest))
    };
    if !child.wait()?.success() || sent.is_err() {
        return Err(rejected("OpenSSL rejected distribution.json signature"));
    }
    Ok(())
}

pub(super) fn verify_firmware_signature(
    scratch: &Path,
    signature: &[u8],
    manifest: &[u8],
) -> Result<(), ReleaseError> {
    let signature_file = scratch.join("release.sig");
    fs::write(&signature_file, signature)?;
    let mut child = system_tool(OPENSSL)
        .args(["dgst", "-sha256", "-verify"])
        .arg(scratch.join("public.pem"))
        .arg("-signature")
        .arg(signature_file)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| rejected(format!("could not start OpenSSL: {e}")))?;
    let sent = {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(manifest)
    };
    if !child.wait()?.success() || sent.is_err() {
        return Err(rejected("OpenSSL rejected release.json signature"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_public_delegation_and_fingerprints() {
        let statement = include_bytes!("../../../security/distribution-authority.json");
        let signature = include_bytes!("../../../security/distribution-authority.json.asc");
        let certificate = include_bytes!("../../../security/release-authority.asc");
        let scratch = PrivateDir::new().unwrap();
        let pem = verify_authority(
            &scratch.0,
            statement,
            signature,
            certificate,
            PRODUCTION_TRUST,
        )
        .unwrap();
        assert_eq!(
            pem,
            include_str!("../../../security/firmware-signing-public.pem")
        );
        assert!(
            verify_authority(
                &PrivateDir::new().unwrap().0,
                b"{}",
                signature,
                certificate,
                PRODUCTION_TRUST,
            )
            .is_err()
        );
        assert!(
            verify_gpg_status(
                b"[GNUPG:] VALIDSIG attacker 2026-01-01 0 0 4 0 1 10 00 attacker",
                PRODUCTION_TRUST,
            )
            .is_err()
        );
    }

    #[test]
    fn checks_firmware_boot_authority_and_fingerprints() {
        let statement = include_bytes!("../../../security/firmware-key.json");
        let signature = include_bytes!("../../../security/firmware-key.json.asc");
        let certificate = include_bytes!("../../../security/release-authority.asc");
        let pem = include_bytes!("../../../security/firmware-signing-public.pem");
        let scratch = PrivateDir::new().unwrap();
        let bootkey = verify_firmware_authority(
            &scratch.0,
            statement,
            signature,
            certificate,
            pem,
            PRODUCTION_TRUST,
        )
        .unwrap();
        assert_eq!(
            bootkey,
            "be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0"
        );
        assert!(
            verify_firmware_authority(
                &PrivateDir::new().unwrap().0,
                statement,
                signature,
                certificate,
                b"tampered",
                PRODUCTION_TRUST,
            )
            .is_err()
        );
        assert!(
            verify_firmware_authority(
                &PrivateDir::new().unwrap().0,
                statement,
                signature,
                certificate,
                pem,
                TrustRoots {
                    primary: "0000000000000000000000000000000000000000",
                    signer: SIGNER_FINGERPRINT,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn checks_signature_over_exact_domain_separated_bytes() {
        let scratch = PrivateDir::new().unwrap();
        let key = scratch.0.join("test-private.pem");
        assert!(
            system_tool(OPENSSL)
                .args(["ecparam", "-name", "secp256k1", "-genkey", "-noout", "-out"])
                .arg(&key)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            system_tool(OPENSSL)
                .args(["pkey", "-pubout", "-in"])
                .arg(&key)
                .arg("-out")
                .arg(scratch.0.join("public.pem"))
                .status()
                .unwrap()
                .success()
        );
        let data = scratch.0.join("message");
        let raw = b"{\"schema_version\":1}\n";
        let sign = |message: &[u8]| {
            fs::write(&data, message).unwrap();
            checked_output(
                system_tool(OPENSSL)
                    .args(["dgst", "-sha256", "-sign"])
                    .arg(&key)
                    .arg(&data),
                "sign ephemeral test message",
            )
            .unwrap()
        };
        let signature = sign(b"pico2-kes-agent-distribution-v1\n{\"schema_version\":1}\n");
        verify_distribution_signature(&scratch.0, &signature, raw).unwrap();
        assert!(
            verify_distribution_signature(&scratch.0, &signature, b"{\"schema_version\":1}")
                .is_err()
        );
        assert!(verify_distribution_signature(&scratch.0, &sign(raw), raw).is_err());

        let fw_sig = sign(raw);
        verify_firmware_signature(&scratch.0, &fw_sig, raw).unwrap();
        assert!(verify_firmware_signature(&scratch.0, &fw_sig, b"{\"schema_version\":1}").is_err());
        assert!(verify_firmware_signature(&scratch.0, &signature, raw).is_err());
    }
}
