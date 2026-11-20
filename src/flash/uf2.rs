//! Native UF2 header/sector validation and BOOTSEL mass-storage discovery.

use std::fs;
use std::path::{Path, PathBuf};

pub const UF2_MAGIC_START0: u32 = 0x0A32_4655;
pub const UF2_MAGIC_START1: u32 = 0x9E5D_5157;
pub const UF2_MAGIC_END: u32 = 0x0AB1_6F30;
pub const UF2_BLOCK_SIZE: usize = 512;
pub const FIRMWARE_START: u32 = 0x1000_0000;
pub const FIRMWARE_END: u32 = 0x1040_0000;

pub fn validate_uf2(bytes: &[u8]) -> Result<usize, String> {
    if bytes.is_empty() || bytes.len() % UF2_BLOCK_SIZE != 0 {
        return Err("UF2 length must be a non-zero multiple of 512 bytes".into());
    }
    let blocks = bytes.len() / UF2_BLOCK_SIZE;
    for (idx, chunk) in bytes.chunks_exact(UF2_BLOCK_SIZE).enumerate() {
        let m0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let m1 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let target_addr = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        let payload_size = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
        let block_no = u32::from_le_bytes(chunk[20..24].try_into().unwrap());
        let num_blocks = u32::from_le_bytes(chunk[24..28].try_into().unwrap());
        let mend = u32::from_le_bytes(chunk[508..512].try_into().unwrap());
        if m0 != UF2_MAGIC_START0 || m1 != UF2_MAGIC_START1 || mend != UF2_MAGIC_END {
            return Err(format!("invalid UF2 magic in block {idx}"));
        }
        if block_no as usize != idx || num_blocks as usize != blocks {
            return Err(format!("UF2 block sequence mismatch at {idx}"));
        }
        if payload_size > 476 {
            return Err(format!("UF2 payload_size > 476 in block {idx}"));
        }
        if target_addr < FIRMWARE_START || target_addr >= FIRMWARE_END {
            return Err(format!(
                "UF2 target_addr 0x{target_addr:08x} outside RP2350 flash range"
            ));
        }
    }
    Ok(blocks)
}

pub fn find_bootsel_mount() -> Option<PathBuf> {
    for base in ["/media", "/mnt", "/run/media"] {
        let Ok(entries) = fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("INFO_UF2.TXT").is_file() {
                return Some(p);
            }
            if let Ok(sub) = fs::read_dir(&p) {
                for s in sub.flatten() {
                    if s.path().join("INFO_UF2.TXT").is_file() {
                        return Some(s.path());
                    }
                }
            }
        }
    }
    None
}

pub fn copy_uf2_to_bootsel(uf2_path: &Path, mount: &Path) -> Result<(), String> {
    let dst = mount.join(
        uf2_path
            .file_name()
            .ok_or("invalid UF2 filename")?,
    );
    fs::copy(uf2_path, &dst).map_err(|e| format!("failed to copy UF2 to {}: {e}", dst.display()))?;
    Ok(())
}
