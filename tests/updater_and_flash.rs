use pico2_kes_agent::flash::uf2::{
    FIRMWARE_START, UF2_BLOCK_SIZE, UF2_MAGIC_END, UF2_MAGIC_START0, UF2_MAGIC_START1, validate_uf2,
};
use pico2_kes_agent::release::ReleaseError;
use pico2_kes_agent::updater;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("p2kes-test-{name}-{}", std::process::id()));
    fs::create_dir(&p).unwrap();
    p
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_unsigned_legacy_bundle(dir: &std::path::Path, payload: &[u8]) {
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("p2kes"), payload).unwrap();
    let manifest = serde_json::json!({
        "schema_version": 2,
        "version": "0.2.0",
        "firmware_version": "0.2.0",
        "usb_protocol_major": 1,
        "platform": {
            "arch": "x86_64",
            "os": "linux",
            "min_glibc": "2.36",
        },
        "artifacts": [{
            "name": "p2kes",
            "path": "bin/p2kes",
            "size": payload.len(),
            "sha256": sha256_hex(payload),
            "mode": "0o755",
        }],
    });
    fs::write(
        dir.join("release-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn updater_rejects_unsigned_legacy_manifest_without_installing() {
    let bundle = temp_dir("bundle");
    let prefix = temp_dir("prefix");
    write_unsigned_legacy_bundle(&bundle, b"unsigned binary");

    assert!(updater::install_or_update(&bundle, &prefix, false).is_err());
    assert_eq!(fs::read_dir(&prefix).unwrap().count(), 0);
    assert!(updater::load_state(&prefix).unwrap().is_none());

    fs::remove_dir_all(&bundle).unwrap();
    fs::remove_dir_all(&prefix).unwrap();
}

#[test]
fn uninstall_rejects_unmanaged_paths_before_removing_files() {
    let prefix = temp_dir("unmanaged");
    let managed = prefix.join("bin/p2kes");
    let unmanaged = prefix.join("install.sh");
    let state = updater::state_path(&prefix);
    fs::create_dir_all(managed.parent().unwrap()).unwrap();
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    fs::write(&managed, b"managed").unwrap();
    fs::write(&unmanaged, b"unmanaged").unwrap();
    fs::write(
        &state,
        br#"{"schema_version":2,"version":"0.2.0","firmware_version":null,"artifacts":["bin/p2kes","install.sh"]}"#,
    )
    .unwrap();

    assert!(matches!(
        updater::uninstall(&prefix),
        Err(ReleaseError::PathConfinement(_))
    ));
    assert!(managed.is_file());
    assert!(unmanaged.is_file());
    assert!(state.is_file());
    fs::remove_dir_all(&prefix).unwrap();
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
