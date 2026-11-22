use pico2_kes_agent::flash::uf2::{
    FIRMWARE_END, FIRMWARE_START, STATE_END, UF2_BLOCK_SIZE, UF2_FAMILY_RP2350_ARM_S,
    UF2_FLAGS_FAMILY_ID_PRESENT, UF2_MAGIC_END, UF2_MAGIC_START0, UF2_MAGIC_START1, UF2_PAGE_SIZE,
    validate_uf2,
};
use pico2_kes_agent::flash::{DEFAULT_FIRMWARE_DIR, DEFAULT_UF2_FILENAME, cmd_flash, cmd_verify};
use pico2_kes_agent::release::ReleaseError;
use pico2_kes_agent::updater;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

fn canonical_rp2350_uf2_block(
    target_addr: u32,
    block_no: u32,
    num_blocks: u32,
) -> [u8; UF2_BLOCK_SIZE] {
    let mut block = [0u8; UF2_BLOCK_SIZE];
    block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
    block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
    block[8..12].copy_from_slice(&UF2_FLAGS_FAMILY_ID_PRESENT.to_le_bytes());
    block[12..16].copy_from_slice(&target_addr.to_le_bytes());
    block[16..20].copy_from_slice(&UF2_PAGE_SIZE.to_le_bytes());
    block[20..24].copy_from_slice(&block_no.to_le_bytes());
    block[24..28].copy_from_slice(&num_blocks.to_le_bytes());
    block[28..32].copy_from_slice(&UF2_FAMILY_RP2350_ARM_S.to_le_bytes());
    block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
    block
}

fn build_unsigned_state_overwrite_uf2() -> [u8; UF2_BLOCK_SIZE] {
    let mut block = [0u8; UF2_BLOCK_SIZE];
    block[0..4].copy_from_slice(&0x0A32_4655u32.to_le_bytes());
    block[4..8].copy_from_slice(&0x9E5D_5157u32.to_le_bytes());
    block[8..12].copy_from_slice(&0x0000_0000u32.to_le_bytes());
    block[12..16].copy_from_slice(&0x1010_0000u32.to_le_bytes());
    block[16..20].copy_from_slice(&256u32.to_le_bytes());
    block[20..24].copy_from_slice(&0u32.to_le_bytes());
    block[24..28].copy_from_slice(&1u32.to_le_bytes());
    block[28..32].copy_from_slice(&0x0000_0000u32.to_le_bytes());
    let marker = b"HARMLESS_UNSIGNED_MARKER_NO_SIGNATURE";
    block[32..32 + marker.len()].copy_from_slice(marker);
    block[508..512].copy_from_slice(&0x0AB1_6F30u32.to_le_bytes());
    block
}

#[test]
fn uf2_validation_accepts_valid_and_rejects_malformed() {
    assert_eq!(FIRMWARE_START, 0x1000_0000);
    assert_eq!(FIRMWARE_END, 0x1010_0000);
    assert_eq!(STATE_END, 0x1030_8000);
    assert_eq!(
        DEFAULT_FIRMWARE_DIR,
        "/usr/local/share/pico2-kes-agent/firmware"
    );
    assert_eq!(DEFAULT_UF2_FILENAME, "pico2-kes-firmware.signed.uf2");

    assert!(validate_uf2(&[]).is_err());
    assert!(validate_uf2(&[0u8; 511]).is_err());

    let valid = canonical_rp2350_uf2_block(FIRMWARE_START, 0, 1);
    assert_eq!(validate_uf2(&valid).unwrap(), 1);
    let last_valid = canonical_rp2350_uf2_block(FIRMWARE_END - UF2_PAGE_SIZE, 0, 1);
    assert_eq!(validate_uf2(&last_valid).unwrap(), 1);

    // Missing family-ID flag (0x0000 instead of 0x2000)
    let mut bad_flags = valid;
    bad_flags[8..12].copy_from_slice(&0u32.to_le_bytes());
    assert!(validate_uf2(&bad_flags).is_err());

    // Wrong family IDs (zero and RP2040)
    for bad_family in [0x0000_0000u32, 0xe48b_ff56u32] {
        let mut wrong_family = valid;
        wrong_family[28..32].copy_from_slice(&bad_family.to_le_bytes());
        assert!(validate_uf2(&wrong_family).is_err());
    }

    // State-region and out-of-range target addresses MUST be rejected
    for bad_addr in [
        FIRMWARE_START - UF2_PAGE_SIZE,
        FIRMWARE_END,
        STATE_END - UF2_PAGE_SIZE,
        0x1038_0000,
        0x2000_0000,
    ] {
        let out_of_bounds = canonical_rp2350_uf2_block(bad_addr, 0, 1);
        assert!(
            validate_uf2(&out_of_bounds).is_err(),
            "expected 0x{bad_addr:08x} to be rejected"
        );
    }

    // Unaligned target_addr
    let unaligned = canonical_rp2350_uf2_block(FIRMWARE_START + 4, 0, 1);
    assert!(validate_uf2(&unaligned).is_err());

    // Non-256 payload_size
    for bad_size in [0u32, 128u32, 476u32] {
        let mut wrong_size = valid;
        wrong_size[16..20].copy_from_slice(&bad_size.to_le_bytes());
        assert!(validate_uf2(&wrong_size).is_err());
    }

    // Non-zero tail padding in [288..508)
    let mut nonzero_padding = valid;
    nonzero_padding[288] = 1;
    assert!(validate_uf2(&nonzero_padding).is_err());

    // Duplicate page target_addr across blocks
    let mut dup = Vec::new();
    dup.extend_from_slice(&canonical_rp2350_uf2_block(FIRMWARE_START, 0, 2));
    dup.extend_from_slice(&canonical_rp2350_uf2_block(FIRMWARE_START, 1, 2));
    assert!(validate_uf2(&dup).is_err());
}

#[test]
fn cmd_verify_and_cmd_flash_reject_unsigned_and_state_region_uf2() {
    let dir = temp_dir("unsigned-uf2");

    // 1. Exact proof payload: unsigned state-overwrite UF2 targeting 0x1010_0000
    let state_uf2 = dir.join("unsigned_state_overwrite.uf2");
    fs::write(&state_uf2, build_unsigned_state_overwrite_uf2()).unwrap();
    assert!(validate_uf2(&fs::read(&state_uf2).unwrap()).is_err());
    assert!(cmd_verify(&dir, Some(&state_uf2)).is_err());
    assert!(cmd_flash(&state_uf2).is_err());

    // 2. Canonical-header UF2 separated from any signed manifest directory fails closed
    // with actionable --firmware-dir guidance.
    let standalone = dir.join("standalone.uf2");
    fs::write(
        &standalone,
        canonical_rp2350_uf2_block(FIRMWARE_START, 0, 1),
    )
    .unwrap();
    let verify_err = cmd_verify(&dir, Some(&standalone)).unwrap_err();
    assert!(
        verify_err.contains("--firmware-dir"),
        "expected actionable --firmware-dir hint, got: {verify_err}"
    );
    let flash_err = cmd_flash(&standalone).unwrap_err();
    assert!(
        flash_err.contains("--firmware-dir"),
        "expected actionable --firmware-dir hint, got: {flash_err}"
    );

    // 3. Wrong family ID UF2
    let mut wrong_family_bytes = canonical_rp2350_uf2_block(FIRMWARE_START, 0, 1);
    wrong_family_bytes[28..32].copy_from_slice(&0xe48b_ff56u32.to_le_bytes());
    let wrong_family = dir.join("wrong_family.uf2");
    fs::write(&wrong_family, wrong_family_bytes).unwrap();
    assert!(cmd_verify(&dir, Some(&wrong_family)).is_err());
    assert!(cmd_flash(&wrong_family).is_err());

    // 4. Execute the p2kes-flash binary directly on unsigned_state_overwrite.uf2
    let bin = env!("CARGO_BIN_EXE_p2kes-flash");
    for subcmd in ["verify", "flash"] {
        let out = Command::new(bin)
            .arg(subcmd)
            .arg(&state_uf2)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "p2kes-flash {subcmd} unexpectedly succeeded on unsigned state-overwrite UF2"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("error:"),
            "expected error diagnostic on stderr, got: {stderr}"
        );
    }

    fs::remove_dir_all(&dir).unwrap();
}
