use crate::files::{open_owner_controlled_file, publish_no_clobber};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicReceipt {
    pub version: u8,
    pub request: Value,
    pub response: Option<Value>,
}

pub fn create(path: &Path, request: Value) -> io::Result<()> {
    let receipt = PublicReceipt {
        version: 1,
        request,
        response: None,
    };
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(io::Error::other)?;
    publish_no_clobber(path, &bytes, 0o600)
}

pub fn load(path: &Path) -> io::Result<PublicReceipt> {
    let mut file = open_owner_controlled_file(path)?;
    if file.metadata()?.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt exceeds 64 KiB",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub fn update(path: &Path, response: Value) -> io::Result<()> {
    let mut receipt = load(path)?;
    receipt.response = Some(response);
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(io::Error::other)?;
    replace(path, &bytes)
}

fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let existing = open_owner_controlled_file(path)?;
    let metadata = existing.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe receipt permissions",
        ));
    }
    drop(existing);
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid receipt path"))?;
    let temp_name = format!(
        ".{}-{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        TEMP.fetch_add(1, Ordering::Relaxed)
    );
    let temp_path: PathBuf = parent.join(temp_name);
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)?;
    let result = (|| {
        temp.write_all(bytes)?;
        temp.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}
