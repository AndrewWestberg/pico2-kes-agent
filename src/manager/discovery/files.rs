use super::read_file;
use serde_json::Value;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    ColdVkey,
    OpCert,
    Recipient,
    DeviceJson,
    Backup,
    Any,
}

pub fn find_candidates(kind: FileKind) -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".local/state")));
    let workspace = state.map(|p| p.join("p2kesup"));
    let cwd = std::env::current_dir().ok();
    let roots: Vec<&Path> = workspace
        .as_deref()
        .into_iter()
        .chain(home.as_deref())
        .chain(cwd.as_deref())
        .collect();
    find_candidates_in(kind, &roots)
}

pub fn find_candidates_in(kind: FileKind, roots: &[&Path]) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut budget = 4096usize;
    for root in roots {
        walk(root, 0, kind, &mut budget, &mut seen, &mut result);
    }
    result
}
fn walk(
    dir: &Path,
    depth: usize,
    kind: FileKind,
    budget: &mut usize,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
) {
    if *budget == 0
        || fs::symlink_metadata(dir).map_or(true, |m| !m.is_dir() || m.file_type().is_symlink())
    {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.take(*budget).flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() && depth < 2 {
            walk(&path, depth + 1, kind, budget, seen, out);
        } else if meta.is_file()
            && !meta.file_type().is_symlink()
            && matches_kind(&path, kind)
            && seen.insert(path.clone())
        {
            out.push(path);
        }
    }
}
fn matches_kind(path: &Path, kind: FileKind) -> bool {
    if kind == FileKind::Any {
        return true;
    }
    if kind == FileKind::Backup {
        return path.extension().is_some_and(|e| e == "kes-backup");
    }
    let Ok(bytes) = read_file(path, 64 * 1024) else {
        return false;
    };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    match kind {
        FileKind::ColdVkey => v["type"]
            .as_str()
            .is_some_and(|s| s.starts_with("StakePoolVerificationKey")),
        FileKind::OpCert => v["type"]
            .as_str()
            .is_some_and(|s| s.starts_with("NodeOperationalCertificate")),
        FileKind::Recipient => v["publicKey"].is_string() && v["recipientId"].is_string(),
        FileKind::DeviceJson => {
            v["device_id"].is_string()
                && v["identity_public_key"].is_string()
                && v["usb_serial"].is_string()
        }
        _ => false,
    }
}
pub fn device_for_serial(serial: &str) -> Option<PathBuf> {
    find_candidates(FileKind::DeviceJson).into_iter().find(|p| {
        read_file(p, 64 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| {
                v["usb_serial"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case(serial))
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_ranked_public_inputs_without_following_links() {
        let root = std::env::temp_dir().join(format!("p2-files-{}", std::process::id()));
        fs::create_dir_all(root.join("exports")).unwrap();
        fs::write(
            root.join("exports/cold.vkey"),
            r#"{"type":"StakePoolVerificationKey_ed25519"}"#,
        )
        .unwrap();
        fs::write(
            root.join("exports/node.cert"),
            r#"{"type":"NodeOperationalCertificate"}"#,
        )
        .unwrap();
        fs::write(
            root.join("exports/device.json"),
            r#"{"device_id":"id","identity_public_key":"key","usb_serial":"0123456789abcdef"}"#,
        )
        .unwrap();
        fs::write(
            root.join("exports/recipient.json"),
            r#"{"publicKey":"key","recipientId":"id"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("exports/cold.vkey"), root.join("link.vkey")).unwrap();
        for kind in [
            FileKind::ColdVkey,
            FileKind::OpCert,
            FileKind::DeviceJson,
            FileKind::Recipient,
        ] {
            assert_eq!(find_candidates_in(kind, &[&root]).len(), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }
}
