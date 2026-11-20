use pico2_kes_agent::flash::uf2::{
    FIRMWARE_START, UF2_BLOCK_SIZE, UF2_MAGIC_END, UF2_MAGIC_START0, UF2_MAGIC_START1, validate_uf2,
};
use pico2_kes_agent::release::{ReleaseArtifact, ReleaseError, ReleaseManifest, ReleasePlatform};
use pico2_kes_agent::updater;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("p2kes-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_bundle(dir: &std::path::Path, version: &str, fw_version: &str, payload: &[u8]) {
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("p2kes"), payload).unwrap();
    let manifest = ReleaseManifest {
        schema_version: 2,
        version: version.into(),
        firmware_version: Some(fw_version.into()),
        usb_protocol_major: 1,
        platform: ReleasePlatform {
            arch: "x86_64".into(),
            os: "linux".into(),
            min_glibc: "2.36".into(),
        },
        artifacts: vec![ReleaseArtifact {
            name: "p2kes".into(),
            path: "bin/p2kes".into(),
            size: payload.len() as u64,
            sha256: sha256_hex(payload),
            mode: Some("0o755".into()),
        }],
    };
    fs::write(
        dir.join("release-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn updater_install_update_uninstall_and_tamper_rejection() {
    let bundle = temp_dir("bundle");
    let prefix = temp_dir("prefix");
    write_bundle(&bundle, "0.2.0", "0.2.0", b"binary-v1");

    let st = updater::install_or_update(&bundle, &prefix, false).unwrap();
    assert_eq!(st.version, "0.2.0");
    assert!(prefix.join("bin/p2kes").is_file());

    // Tamper artifact -> fail closed
    fs::write(bundle.join("bin/p2kes"), b"tampered!").unwrap();
    assert!(matches!(
        updater::install_or_update(&bundle, &prefix, true),
        Err(ReleaseError::HashMismatch { .. })
    ));

    // Valid update
    write_bundle(&bundle, "0.2.1", "0.2.1", b"binary-v2");
    let st2 = updater::install_or_update(&bundle, &prefix, true).unwrap();
    assert_eq!(st2.version, "0.2.1");
    assert_eq!(fs::read(prefix.join("bin/p2kes")).unwrap(), b"binary-v2");

    // Uninstall removes installed binaries and state
    updater::uninstall(&prefix).unwrap();
    assert!(!prefix.join("bin/p2kes").exists());
    assert!(updater::load_state(&prefix).unwrap().is_none());

    let _ = fs::remove_dir_all(&bundle);
    let _ = fs::remove_dir_all(&prefix);
}

#[test]
fn uf2_validation_accepts_valid_and_rejects_malformed() {
    assert!(validate_uf2(&[]).is_err());
    assert!(validate_uf2(&[0u8; 511]).is_err());

    let mut block = [0u8; UF2_BLOCK_SIZE];
    block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
    block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
    block[12..16].copy_from_slice(&FIRMWARE_START.to_le_bytes());
    block[16..20].copy_from_slice(&256u32.to_le_bytes());
    block[20..24].copy_from_slice(&0u32.to_le_bytes());
    block[24..28].copy_from_slice(&1u32.to_le_bytes());
    block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
    assert_eq!(validate_uf2(&block).unwrap(), 1);

    // Out-of-range target_addr
    block[12..16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    assert!(validate_uf2(&block).is_err());
}
