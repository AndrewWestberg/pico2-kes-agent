//! Native Rust firmware flasher (`p2kes-flash`).

pub mod picotool;
pub mod uf2;

use crate::release;
use std::fs;
use std::path::{Path, PathBuf};

pub fn default_picotool() -> PathBuf {
    PathBuf::from("/usr/local/share/pico2-kes-agent/picotool")
}

pub fn cmd_verify(bundle_root: &Path, uf2_path: Option<&Path>) -> Result<(), String> {
    if let Some(uf2) = uf2_path {
        let bytes = fs::read(uf2).map_err(|e| e.to_string())?;
        let blocks = uf2::validate_uf2(&bytes)?;
        println!("verified UF2 {} ({blocks} blocks)", uf2.display());
    } else {
        let manifest = release::load_and_verify_manifest(bundle_root).map_err(|e| e.to_string())?;
        println!("verified release bundle {}", manifest.version);
    }
    Ok(())
}

pub fn cmd_flash(uf2_path: &Path) -> Result<(), String> {
    let file_name = uf2_path.file_name().ok_or("invalid UF2 filename")?;
    let bytes = fs::read(uf2_path).map_err(|e| e.to_string())?;
    uf2::validate_uf2(&bytes)?;
    let mount = uf2::find_bootsel_mount()?;
    uf2::copy_uf2_to_bootsel(&mount, file_name, &bytes)?;
    println!(
        "flashed {} to {}",
        uf2_path.display(),
        mount.path().display()
    );
    Ok(())
}
