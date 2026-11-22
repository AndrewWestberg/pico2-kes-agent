//! Native Rust firmware flasher (`p2kes-flash`).

pub mod picotool;
pub mod uf2;

use crate::release::{self, VerifiedFirmware};
use rustix::fs::{self as fs_at, CWD, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_FIRMWARE_DIR: &str = "/usr/local/share/pico2-kes-agent/firmware";
pub const DEFAULT_UF2_FILENAME: &str = "pico2-kes-firmware.signed.uf2";

pub fn default_picotool() -> PathBuf {
    PathBuf::from("/usr/local/share/pico2-kes-agent/picotool")
}

pub fn default_staged_uf2() -> PathBuf {
    Path::new(DEFAULT_FIRMWARE_DIR).join(DEFAULT_UF2_FILENAME)
}

pub fn manifest_dir_for_uf2(uf2_path: &Path) -> PathBuf {
    let parent = match uf2_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if parent.file_name().is_some_and(|n| n == "firmware")
        && let Some(grandparent) = parent.parent()
        && !grandparent.as_os_str().is_empty()
        && std::fs::symlink_metadata(grandparent.join("distribution.json"))
            .is_ok_and(|m| m.is_file())
    {
        return grandparent.to_path_buf();
    }
    parent.to_path_buf()
}

fn read_regular_uf2(path: &Path) -> Result<Vec<u8>, String> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = fs_at::openat(CWD, path, flags, Mode::empty())
        .map_err(|e| format!("failed to open UF2 {}: {e}", path.display()))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat UF2 {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("UF2 {} is not a regular file", path.display()));
    }
    if meta.len() > uf2::MAX_UF2_BYTES as u64 {
        return Err(format!(
            "UF2 {} exceeds 4 MiB limit ({} bytes)",
            path.display(),
            meta.len()
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(uf2::MAX_UF2_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read UF2 {}: {e}", path.display()))?;
    if bytes.len() > uf2::MAX_UF2_BYTES {
        return Err(format!("UF2 {} exceeds 4 MiB limit", path.display()));
    }
    Ok(bytes)
}

#[derive(Debug)]
struct AuthenticatedFirmware {
    version: String,
    blocks: usize,
    uf2_bytes: Vec<u8>,
    file_name: OsString,
}

fn verify_loaded_firmware(
    verified: VerifiedFirmware,
    uf2_path: Option<&Path>,
) -> Result<AuthenticatedFirmware, String> {
    let blocks = uf2::validate_signed_elf_and_uf2(&verified.elf_bytes, &verified.uf2_bytes)?;
    let file_name = if let Some(uf2) = uf2_path {
        let caller_bytes = read_regular_uf2(uf2)?;
        uf2::validate_uf2(&caller_bytes)?;
        let caller_sha256 = format!("{:x}", Sha256::digest(&caller_bytes));
        if caller_sha256 != verified.uf2_sha256 || caller_bytes != verified.uf2_bytes {
            return Err(format!(
                "UF2 {} sha256 {caller_sha256} does not match authenticated manifest ({})",
                uf2.display(),
                verified.uf2_sha256
            ));
        }
        uf2.file_name()
            .ok_or_else(|| format!("invalid UF2 filename: {}", uf2.display()))?
            .to_os_string()
    } else {
        OsString::from(DEFAULT_UF2_FILENAME)
    };
    Ok(AuthenticatedFirmware {
        version: verified.version,
        blocks,
        uf2_bytes: verified.uf2_bytes,
        file_name,
    })
}

fn authenticate_firmware(
    bundle_or_firmware_dir: &Path,
    uf2_path: Option<&Path>,
) -> Result<AuthenticatedFirmware, String> {
    let verified = release::load_and_verify_firmware(bundle_or_firmware_dir).map_err(|e| {
        format!(
            "firmware authentication failed in {}: {e}",
            bundle_or_firmware_dir.display()
        )
    })?;
    verify_loaded_firmware(verified, uf2_path)
}

pub fn cmd_verify(bundle_root: &Path, uf2_path: Option<&Path>) -> Result<(), String> {
    let auth = authenticate_firmware(bundle_root, uf2_path)?;
    println!(
        "verified signed firmware {} ({} blocks)",
        auth.version, auth.blocks
    );
    Ok(())
}

pub fn cmd_flash_from_dir(firmware_dir: &Path, uf2_path: Option<&Path>) -> Result<(), String> {
    let auth = authenticate_firmware(firmware_dir, uf2_path)?;
    let mount = uf2::find_bootsel_mount()
        .ok_or("no RP2350 BOOTSEL mass-storage device found (hold BOOTSEL and replug)")?;
    uf2::write_uf2_to_bootsel(&auth.uf2_bytes, &auth.file_name, &mount)?;
    println!(
        "flashed verified firmware {} ({} blocks) to {}",
        auth.version,
        auth.blocks,
        mount.display()
    );
    Ok(())
}

pub fn cmd_flash(uf2_path: &Path) -> Result<(), String> {
    let firmware_dir = manifest_dir_for_uf2(uf2_path);
    cmd_flash_from_dir(&firmware_dir, Some(uf2_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{TrustRoots, load_and_verify_firmware_with_trust};
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn build_minimal_elf(signed: bool) -> Vec<u8> {
        let mut image = vec![0u8; 0x104];
        let put_u32 = |buf: &mut [u8], off: usize, val: u32| {
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        };
        // Vector table at 0x1000_0000: SP = 0x2008_0000, Reset = 0x1000_0101
        put_u32(&mut image, 0x00, 0x2008_0000);
        put_u32(&mut image, 0x04, 0x1000_0101);
        // Discovery PICOBIN block at 0x1000_0008..0x1000_001c
        put_u32(&mut image, 0x08, 0xffff_ded3);
        put_u32(&mut image, 0x0c, 0x1021_0142);
        put_u32(&mut image, 0x10, 0x0000_01ff);
        put_u32(&mut image, 0x14, if signed { 20 } else { 0 });
        put_u32(&mut image, 0x18, 0xab12_3579);

        if signed {
            // Signed PICOBIN block at 0x1000_001c..0x1000_005c
            put_u32(&mut image, 0x1c, 0xffff_ded3);
            put_u32(&mut image, 0x20, 0x1821_0142); // IMAGE_TYPE + signed 0x800
            put_u32(&mut image, 0x24, 0x0000_0203); // VECTOR_TABLE
            put_u32(&mut image, 0x28, 0x1000_0000);
            put_u32(&mut image, 0x2c, 0x0000_0344); // ENTRY_POINT
            put_u32(&mut image, 0x30, 0x1000_0101);
            put_u32(&mut image, 0x34, 0x2008_0000);
            put_u32(&mut image, 0x38, 0x8100_0406); // LOAD_MAP (1 absolute entry)
            put_u32(&mut image, 0x3c, 0x1000_0000);
            put_u32(&mut image, 0x40, 0x1000_0000);
            put_u32(&mut image, 0x44, 0x1000_0104);
            put_u32(&mut image, 0x48, 0x0000_0209); // SIGNATURE
            put_u32(&mut image, 0x4c, 0xdead_beef);
            put_u32(&mut image, 0x50, 0x0000_0cff); // LAST (12 words)
            put_u32(&mut image, 0x54, (-20i32) as u32);
            put_u32(&mut image, 0x58, 0xab12_3579);
        }
        put_u32(&mut image, 0x100, 0x4770_4770);

        let mut elf = Vec::with_capacity(84 + image.len());
        elf.extend_from_slice(b"\x7fELF\x01\x01\x01");
        elf.resize(16, 0);
        elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf.extend_from_slice(&40u16.to_le_bytes()); // EM_ARM
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0x1000_0101u32.to_le_bytes()); // e_entry
        elf.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&0u16.to_le_bytes());
        elf.extend_from_slice(&0u16.to_le_bytes());
        elf.extend_from_slice(&0u16.to_le_bytes());
        // PT_LOAD
        elf.extend_from_slice(&1u32.to_le_bytes());
        elf.extend_from_slice(&84u32.to_le_bytes());
        elf.extend_from_slice(&uf2::FIRMWARE_START.to_le_bytes());
        elf.extend_from_slice(&uf2::FIRMWARE_START.to_le_bytes());
        elf.extend_from_slice(&(image.len() as u32).to_le_bytes());
        elf.extend_from_slice(&(image.len() as u32).to_le_bytes());
        elf.extend_from_slice(&5u32.to_le_bytes());
        elf.extend_from_slice(&4u32.to_le_bytes());
        elf.extend_from_slice(&image);
        elf
    }

    fn build_uf2_from_elf(elf_bytes: &[u8]) -> Vec<u8> {
        let segments = uf2::elf_segments(elf_bytes).unwrap();
        let pages = uf2::expected_pages(&segments).unwrap();
        let total = pages.len() as u32;
        let mut out = Vec::with_capacity(pages.len() * uf2::UF2_BLOCK_SIZE);
        for (idx, (&addr, page)) in pages.iter().enumerate() {
            let mut block = [0u8; uf2::UF2_BLOCK_SIZE];
            block[0..4].copy_from_slice(&uf2::UF2_MAGIC_START0.to_le_bytes());
            block[4..8].copy_from_slice(&uf2::UF2_MAGIC_START1.to_le_bytes());
            block[8..12].copy_from_slice(&uf2::UF2_FLAGS_FAMILY_ID_PRESENT.to_le_bytes());
            block[12..16].copy_from_slice(&addr.to_le_bytes());
            block[16..20].copy_from_slice(&uf2::UF2_PAGE_SIZE.to_le_bytes());
            block[20..24].copy_from_slice(&(idx as u32).to_le_bytes());
            block[24..28].copy_from_slice(&total.to_le_bytes());
            block[28..32].copy_from_slice(&uf2::UF2_FAMILY_RP2350_ARM_S.to_le_bytes());
            block[32..288].copy_from_slice(page);
            block[508..512].copy_from_slice(&uf2::UF2_MAGIC_END.to_le_bytes());
            out.extend_from_slice(&block);
        }
        out
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn authenticates_signed_firmware_bundle_and_writes_in_memory_uf2_to_bootsel() {
        let root = std::env::temp_dir().join(format!("p2kes-flash-auth-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let gnupg = root.join("gnupg");
        fs::create_dir_all(&gnupg).unwrap();
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700)).unwrap();

        let key_pem = root.join("key.pem");
        let fw_dir = root.join("firmware");
        fs::create_dir_all(&fw_dir).unwrap();
        let pub_pem = fw_dir.join("firmware-signing-public.pem");

        assert!(
            Command::new("/usr/bin/openssl")
                .args(["ecparam", "-name", "secp256k1", "-genkey", "-noout", "-out"])
                .arg(&key_pem)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/openssl")
                .args(["pkey", "-in"])
                .arg(&key_pem)
                .arg("-pubout")
                .arg("-out")
                .arg(&pub_pem)
                .status()
                .unwrap()
                .success()
        );
        let der = Command::new("/usr/bin/openssl")
            .args(["pkey", "-pubin", "-outform", "DER", "-in"])
            .arg(&pub_pem)
            .output()
            .unwrap()
            .stdout;
        let bootkey_sha256 = hex_sha256(&der[24..]);
        let pub_pem_bytes = fs::read(&pub_pem).unwrap();

        assert!(
            Command::new("/usr/bin/gpg")
                .env("GNUPGHOME", &gnupg)
                .args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    "Test Authority <test@example.invalid>",
                    "rsa2048",
                    "cert",
                    "0",
                ])
                .status()
                .unwrap()
                .success()
        );
        let list_out = String::from_utf8(
            Command::new("/usr/bin/gpg")
                .env("GNUPGHOME", &gnupg)
                .args(["--with-colons", "--list-keys"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let primary = list_out
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap()
            .to_owned();
        assert!(
            Command::new("/usr/bin/gpg")
                .env("GNUPGHOME", &gnupg)
                .args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-add-key",
                    &primary,
                    "rsa2048",
                    "sign",
                    "0",
                ])
                .status()
                .unwrap()
                .success()
        );
        let list_out = String::from_utf8(
            Command::new("/usr/bin/gpg")
                .env("GNUPGHOME", &gnupg)
                .args(["--with-colons", "--list-keys"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let fprs: Vec<&str> = list_out
            .lines()
            .filter(|l| l.starts_with("fpr:"))
            .map(|l| l.split(':').nth(9).unwrap())
            .collect();
        let signer = fprs[1].to_owned();

        let cert_bytes = Command::new("/usr/bin/gpg")
            .env("GNUPGHOME", &gnupg)
            .args(["--batch", "--armor", "--export", &primary])
            .output()
            .unwrap()
            .stdout;
        fs::write(fw_dir.join("release-authority.asc"), &cert_bytes).unwrap();

        let fw_key_doc = json!({
            "schema_version": 1,
            "purpose": "pico2-kes-firmware-boot-authority-v1",
            "project": "https://github.com/AndrewWestberg/pico2-kes-agent",
            "algorithm": "secp256k1",
            "bootkey_slot": 0,
            "bootkey_sha256": bootkey_sha256,
            "public_pem_sha256": hex_sha256(&pub_pem_bytes),
        });
        fs::write(
            fw_dir.join("firmware-key.json"),
            serde_json::to_vec_pretty(&fw_key_doc).unwrap(),
        )
        .unwrap();
        assert!(
            Command::new("/usr/bin/gpg")
                .env("GNUPGHOME", &gnupg)
                .args([
                    "--batch",
                    "--armor",
                    "--detach-sign",
                    "--local-user",
                    &format!("{signer}!"),
                    "--output",
                ])
                .arg(fw_dir.join("firmware-key.json.asc"))
                .arg(fw_dir.join("firmware-key.json"))
                .status()
                .unwrap()
                .success()
        );

        let elf_bytes = build_minimal_elf(true);
        let uf2_bytes = build_uf2_from_elf(&elf_bytes);
        fs::write(fw_dir.join("pico2-kes-firmware.signed.elf"), &elf_bytes).unwrap();
        fs::write(fw_dir.join("pico2-kes-firmware.signed.uf2"), &uf2_bytes).unwrap();
        fs::write(fw_dir.join("pico2-otp-permissions.elf"), b"helper").unwrap();
        fs::write(fw_dir.join("firmware.py"), b"# verifier\n").unwrap();
        fs::write(
            fw_dir.join("otp-policy.json"),
            include_bytes!("../../security/otp-policy.json"),
        )
        .unwrap();

        let write_signed_release = |dir: &Path| {
            let names = [
                "pico2-kes-firmware.signed.elf",
                "pico2-kes-firmware.signed.uf2",
                "pico2-otp-permissions.elf",
                "firmware.py",
                "otp-policy.json",
                "firmware-signing-public.pem",
                "firmware-key.json",
                "firmware-key.json.asc",
                "release-authority.asc",
            ];
            let artifacts: Vec<_> = names
                .iter()
                .map(|name| {
                    let b = fs::read(dir.join(name)).unwrap();
                    json!({
                        "name": name,
                        "size_bytes": b.len(),
                        "sha256": hex_sha256(&b),
                    })
                })
                .collect();
            let release_doc = json!({
                "schema_version": 1,
                "purpose": "pico2-kes-firmware-release-v1",
                "tag": "v0.1.0-rc.99",
                "commit": "a".repeat(40),
                "profile": "rp2350-signed-msd-v1",
                "bootkey_sha256": bootkey_sha256,
                "firmware_region": {"start": 0x1000_0000u32, "end": 0x1010_0000u32},
                "state_region": {"start": 0x1010_0000u32, "end": 0x1030_8000u32},
                "storage_version": 2,
                "usb_protocol_major": 1,
                "artifacts": artifacts,
            });
            let _ = fs::remove_file(dir.join("release.json.sig"));
            fs::write(
                dir.join("release.json"),
                serde_json::to_vec_pretty(&release_doc).unwrap(),
            )
            .unwrap();
            assert!(
                Command::new("/usr/bin/openssl")
                    .args(["dgst", "-sha256", "-sign"])
                    .arg(&key_pem)
                    .arg("-out")
                    .arg(dir.join("release.json.sig"))
                    .arg(dir.join("release.json"))
                    .status()
                    .unwrap()
                    .success()
            );
            for entry in fs::read_dir(dir).unwrap().flatten() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644)).unwrap();
            }
        };
        write_signed_release(&fw_dir);

        // Production entrypoints MUST reject ephemeral OpenPGP keys.
        let uf2_file = fw_dir.join("pico2-kes-firmware.signed.uf2");
        assert!(cmd_verify(&fw_dir, None).is_err());
        assert!(cmd_verify(&fw_dir, Some(&uf2_file)).is_err());
        assert!(cmd_flash(&uf2_file).is_err());

        // With injected test trust roots, valid signed firmware bundle authenticates cleanly.
        let test_trust = TrustRoots {
            primary: &primary,
            signer: &signer,
        };
        let verified = load_and_verify_firmware_with_trust(&fw_dir, test_trust).unwrap();
        let auth = verify_loaded_firmware(verified, Some(&uf2_file)).unwrap();
        assert_eq!(auth.version, "v0.1.0-rc.99");
        assert_eq!(auth.blocks, 2);

        // Even if the on-disk UF2 is overwritten after authentication, write_uf2_to_bootsel
        // writes the verified in-memory buffer directly.
        let bootsel = root.join("bootsel");
        fs::create_dir_all(&bootsel).unwrap();
        fs::write(bootsel.join("INFO_UF2.TXT"), b"UF2 Bootloader v1.0\n").unwrap();
        fs::write(&uf2_file, b"tampered after verification").unwrap();
        uf2::write_uf2_to_bootsel(&auth.uf2_bytes, &auth.file_name, &bootsel).unwrap();
        assert_eq!(
            fs::read(bootsel.join("pico2-kes-firmware.signed.uf2")).unwrap(),
            uf2_bytes
        );

        // Restore UF2, then sign a mismatched UF2 (valid RP2350 header, altered payload byte):
        // manifest signature passes, but ELF-to-UF2 page equality rejects it.
        let mut mismatched_uf2 = uf2_bytes.clone();
        mismatched_uf2[32] ^= 0xff;
        fs::write(&uf2_file, &mismatched_uf2).unwrap();
        write_signed_release(&fw_dir);
        let verified_mismatch = load_and_verify_firmware_with_trust(&fw_dir, test_trust).unwrap();
        let err = verify_loaded_firmware(verified_mismatch, Some(&uf2_file)).unwrap_err();
        assert!(
            err.contains("do not exactly match signed ELF pages"),
            "{err}"
        );

        // Unsigned ELF (missing signed PICOBIN metadata block) is rejected even if manifest is signed.
        let unsigned_elf = build_minimal_elf(false);
        let unsigned_uf2 = build_uf2_from_elf(&unsigned_elf);
        fs::write(fw_dir.join("pico2-kes-firmware.signed.elf"), &unsigned_elf).unwrap();
        fs::write(&uf2_file, &unsigned_uf2).unwrap();
        write_signed_release(&fw_dir);
        let verified_unsigned_elf =
            load_and_verify_firmware_with_trust(&fw_dir, test_trust).unwrap();
        assert!(verify_loaded_firmware(verified_unsigned_elf, Some(&uf2_file)).is_err());

        // Restore valid signed ELF + UF2 and verify a complete outer distribution bundle
        // (distribution.json + distribution.json.sig + firmware/release.json + firmware/release.json.sig).
        fs::write(fw_dir.join("pico2-kes-firmware.signed.elf"), &elf_bytes).unwrap();
        fs::write(&uf2_file, &uf2_bytes).unwrap();
        write_signed_release(&fw_dir);

        let dist_root = root.join("dist-bundle");
        let dist_fw = dist_root.join("firmware");
        fs::create_dir_all(&dist_fw).unwrap();
        for entry in fs::read_dir(&fw_dir).unwrap().flatten() {
            let dst = dist_fw.join(entry.file_name());
            fs::copy(entry.path(), &dst).unwrap();
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let dist_auth_doc = json!({
            "schema_version": 1,
            "purpose": "pico2-kes-agent-distribution-authority-v1",
            "project": "https://github.com/AndrewWestberg/pico2-kes-agent",
            "algorithm": "secp256k1",
            "public_key_pem": String::from_utf8(pub_pem_bytes.clone()).unwrap(),
        });
        fs::write(
            dist_root.join("distribution-authority.json"),
            serde_json::to_vec_pretty(&dist_auth_doc).unwrap(),
        )
        .unwrap();
        assert!(
            Command::new("/usr/bin/gpg")
                .env("GNUPGHOME", &gnupg)
                .args([
                    "--batch",
                    "--armor",
                    "--detach-sign",
                    "--local-user",
                    &format!("{signer}!"),
                    "--output",
                ])
                .arg(dist_root.join("distribution-authority.json.asc"))
                .arg(dist_root.join("distribution-authority.json"))
                .status()
                .unwrap()
                .success()
        );
        fs::set_permissions(
            dist_root.join("distribution-authority.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::set_permissions(
            dist_root.join("distribution-authority.json.asc"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let non_fw_paths = [
            ("bin/p2kesup", 0o755),
            ("bin/pico2-kes-agentd", 0o755),
            ("bin/p2kes", 0o755),
            ("bin/p2kes-flash", 0o755),
            ("tools/picotool", 0o755),
            ("tools/firmware.py", 0o644),
            ("deploy/pico2-kes-agentd.service", 0o644),
            ("deploy/70-pico2-kes-agent.rules", 0o644),
            ("deploy/pico2-kes-agent-host-check", 0o644),
            ("deploy/cardano-node-memory-hardening.conf", 0o644),
            ("licenses/picotool.txt", 0o644),
            ("licenses/mbedtls.txt", 0o644),
            ("licenses/libusb-1.0-0.txt", 0o644),
            ("licenses/libudev1.txt", 0o644),
            ("licenses/libstdc++6.txt", 0o644),
            ("licenses/libgcc-s1.txt", 0o644),
            ("runtime/libusb-1.0.so.0", 0o644),
            ("runtime/libudev.so.1", 0o644),
            ("runtime/libstdc++.so.6", 0o644),
            ("runtime/libgcc_s.so.1", 0o644),
            ("runtime/provenance.json", 0o644),
            ("install.sh", 0o644),
            ("install.sh.sig", 0o644),
        ];
        for (rel, mode) in non_fw_paths {
            let p = dist_root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"payload").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut all_rel: Vec<(String, u32)> = non_fw_paths
            .iter()
            .map(|(p, m)| ((*p).to_owned(), *m))
            .chain([
                ("distribution-authority.json".into(), 0o644),
                ("distribution-authority.json.asc".into(), 0o644),
            ])
            .collect();
        for entry in fs::read_dir(&dist_fw).unwrap().flatten() {
            all_rel.push((
                format!("firmware/{}", entry.file_name().to_str().unwrap()),
                0o644,
            ));
        }
        let dist_artifacts: Vec<_> = all_rel
            .iter()
            .map(|(rel, mode)| {
                let bytes = fs::read(dist_root.join(rel)).unwrap();
                let class = match rel.split('/').next().unwrap() {
                    "bin" => "bin",
                    "firmware" => "firmware",
                    "tools" => "tool",
                    "deploy" => "deployment",
                    "licenses" => "license",
                    "runtime" => "runtime",
                    _ => "bootstrap",
                };
                json!({
                    "path": rel,
                    "size_bytes": bytes.len(),
                    "sha256": hex_sha256(&bytes),
                    "class": class,
                    "mode": mode,
                })
            })
            .collect();
        let dist_doc = json!({
            "schema_version": 1,
            "purpose": "pico2-kes-agent-distribution-v1",
            "qualification": "candidate",
            "release": {"tag": "v0.1.0-rc.99", "version": "v0.1.0-rc.99"},
            "platform": {
                "target": "x86_64-unknown-linux-gnu",
                "glibc_min": "2.36",
                "systemd": true,
                "udev": true,
            },
            "compatibility": {"usb_profiles": ["usb-protocol-1"]},
            "components": [
                {"name": "manager", "version": "v0.1.0-rc.99", "artifact": "bin/p2kesup"},
                {"name": "daemon", "version": "v0.1.0-rc.99", "artifact": "bin/pico2-kes-agentd"},
                {"name": "cli", "version": "v0.1.0-rc.99", "artifact": "bin/p2kes"},
                {"name": "flash", "version": "v0.1.0-rc.99", "artifact": "bin/p2kes-flash"},
                {"name": "firmware", "version": "v0.1.0-rc.99", "artifact": "firmware/pico2-kes-firmware.signed.uf2"},
                {"name": "tool", "version": "v0.1.0-rc.99", "artifact": "tools/picotool"},
                {"name": "deployment", "version": "v0.1.0-rc.99", "artifact": "deploy/pico2-kes-agentd.service"},
            ],
            "artifacts": dist_artifacts,
        });
        let dist_raw = serde_json::to_vec_pretty(&dist_doc).unwrap();
        fs::write(dist_root.join("distribution.json"), &dist_raw).unwrap();
        fs::set_permissions(
            dist_root.join("distribution.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let dist_msg_path = root.join("dist-sign-input");
        let mut dist_msg = b"pico2-kes-agent-distribution-v1\n".to_vec();
        dist_msg.extend_from_slice(&dist_raw);
        fs::write(&dist_msg_path, &dist_msg).unwrap();
        assert!(
            Command::new("/usr/bin/openssl")
                .args(["dgst", "-sha256", "-sign"])
                .arg(&key_pem)
                .arg("-out")
                .arg(dist_root.join("distribution.json.sig"))
                .arg(&dist_msg_path)
                .status()
                .unwrap()
                .success()
        );
        fs::set_permissions(
            dist_root.join("distribution.json.sig"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let dist_uf2 = dist_fw.join("pico2-kes-firmware.signed.uf2");
        assert_eq!(manifest_dir_for_uf2(&dist_uf2), dist_root);
        let verified_dist = load_and_verify_firmware_with_trust(&dist_root, test_trust).unwrap();
        let dist_auth = verify_loaded_firmware(verified_dist, Some(&dist_uf2)).unwrap();
        assert_eq!(dist_auth.blocks, 2);

        fs::remove_dir_all(&root).unwrap();
    }
}
