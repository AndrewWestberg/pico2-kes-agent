//! Atomic `/usr/local` software updater (`p2kesup`).

use crate::release::{self, ReleaseError, ReleaseManifest};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_PREFIX: &str = "/usr/local";
pub const STATE_REL_PATH: &str = "share/pico2-kes-agent/installed.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledState {
    pub schema_version: u32,
    pub version: String,
    pub firmware_version: Option<String>,
    pub artifacts: Vec<String>,
}

pub fn state_path(prefix: &Path) -> PathBuf {
    prefix.join(STATE_REL_PATH)
}

pub fn load_state(prefix: &Path) -> Result<Option<InstalledState>, ReleaseError> {
    let p = state_path(prefix);
    if !p.exists() {
        return Ok(None);
    }
    let raw = fs::read(&p)?;
    let st: InstalledState = serde_json::from_slice(&raw)
        .map_err(|e| ReleaseError::InvalidManifest(format!("installed.json: {e}")))?;
    Ok(Some(st))
}

fn atomic_install_file(src: &Path, dst: &Path, mode: u32) -> io::Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dst.with_extension("tmp");
    fs::copy(src, &tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, dst)?;
    if let Some(parent) = dst.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn install_or_update(
    bundle_root: &Path,
    prefix: &Path,
    is_update: bool,
) -> Result<InstalledState, ReleaseError> {
    let prev = load_state(prefix)?;
    if is_update && prev.is_none() {
        return Err(ReleaseError::InvalidManifest(
            "not installed; run `p2kesup install` first".into(),
        ));
    }
    let manifest: ReleaseManifest = release::load_and_verify_manifest(bundle_root)?;
    let mut installed_paths = Vec::new();
    for art in &manifest.artifacts {
        let src = bundle_root.join(&art.path);
        let dst = prefix.join(&art.path);
        let mode = art
            .mode
            .as_deref()
            .and_then(|m| u32::from_str_radix(m.trim_start_matches("0o"), 8).ok())
            .unwrap_or(0o755);
        atomic_install_file(&src, &dst, mode)?;
        installed_paths.push(art.path.clone());
    }
    let state = InstalledState {
        schema_version: manifest.schema_version,
        version: manifest.version.clone(),
        firmware_version: manifest.firmware_version.clone(),
        artifacts: installed_paths,
    };
    let st_path = state_path(prefix);
    if let Some(parent) = st_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_st = st_path.with_extension("tmp");
    let json = serde_json::to_vec_pretty(&state)
        .map_err(|e| ReleaseError::InvalidManifest(e.to_string()))?;
    fs::write(&tmp_st, &json)?;
    File::open(&tmp_st)?.sync_all()?;
    fs::rename(&tmp_st, &st_path)?;

    println!("installed pico2-kes-agent {}", state.version);
    println!("next: sudo systemctl restart pico2-kes-agentd");
    if let Some(prev_st) = prev
        && prev_st.firmware_version != state.firmware_version
    {
        println!("firmware version changed; run: sudo p2kes-flash flash");
    }
    Ok(state)
}

pub fn uninstall(prefix: &Path) -> Result<(), ReleaseError> {
    let Some(state) = load_state(prefix)? else {
        println!("pico2-kes-agent is not installed");
        return Ok(());
    };
    for rel in &state.artifacts {
        let p = prefix.join(rel);
        if p.exists() {
            fs::remove_file(&p)?;
        }
    }
    let st_path = state_path(prefix);
    if st_path.exists() {
        fs::remove_file(&st_path)?;
    }
    println!("uninstalled pico2-kes-agent (preserved /etc/pico2-kes-agent and /var/lib/pico2-kes-agent)");
    Ok(())
}
