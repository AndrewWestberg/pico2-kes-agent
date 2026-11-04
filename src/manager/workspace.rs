//! Protected operator workspace in XDG state for plans, receipts, references, candidates, and exports.

use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceKind {
    Plans,
    Receipts,
    References,
    Candidates,
    Exports,
}

impl WorkspaceKind {
    pub fn subdir(self) -> &'static str {
        match self {
            Self::Plans => "plans",
            Self::Receipts => "receipts",
            Self::References => "references",
            Self::Candidates => "candidates",
            Self::Exports => "exports",
        }
    }
}

fn state_base() -> io::Result<PathBuf> {
    match std::env::var_os("XDG_STATE_HOME") {
        Some(value) if !value.is_empty() && Path::new(&value).is_absolute() => {
            Ok(PathBuf::from(value))
        }
        _ => {
            let home = std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
            let home = PathBuf::from(home);
            if !home.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HOME must be an absolute path",
                ));
            }
            Ok(home.join(".local/state"))
        }
    }
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workspace directory must be private (0700) and owned by current user",
        ));
    }
    Ok(())
}

pub fn root_dir() -> io::Result<PathBuf> {
    let base = state_base()?;
    fs::create_dir_all(&base)?;
    ensure_root_in(&base)
}

pub(crate) fn ensure_root_in(base: &Path) -> io::Result<PathBuf> {
    if !base.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace base must be absolute",
        ));
    }
    let root = base.join("p2kesup");
    ensure_private_dir(&root)?;
    Ok(root)
}

pub fn dir(kind: WorkspaceKind) -> io::Result<PathBuf> {
    let root = root_dir()?;
    dir_in(&root, kind)
}

pub(crate) fn dir_in(root: &Path, kind: WorkspaceKind) -> io::Result<PathBuf> {
    ensure_private_dir(root)?;
    let subdir = root.join(kind.subdir());
    ensure_private_dir(&subdir)?;
    Ok(subdir)
}

pub fn sanitize_stem(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(48));
    let mut last_dash = false;
    for ch in raw.chars() {
        if out.len() >= 48 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { "item".into() } else { out }
}

pub fn short_id(id: &str) -> String {
    let clean: String = id
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(8)
        .collect();
    if clean.is_empty() {
        "target".into()
    } else {
        clean.to_ascii_lowercase()
    }
}

/// Suggests a collision-free absolute file path inside the operator's private workspace.
/// Actual creation still uses no-clobber (`O_EXCL` / `publish_no_clobber`).
pub fn next_path(kind: WorkspaceKind, stem: &str, extension: &str) -> io::Result<PathBuf> {
    let root = root_dir()?;
    next_path_in(&root, kind, stem, extension)
}

pub(crate) fn next_path_in(
    root: &Path,
    kind: WorkspaceKind,
    stem: &str,
    extension: &str,
) -> io::Result<PathBuf> {
    let parent = dir_in(root, kind)?;
    let stem = sanitize_stem(stem);
    let ext = extension.trim_start_matches('.');
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for _ in 0..1024 {
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = if ext.is_empty() {
            format!("{secs}-{stem}-{seq}")
        } else {
            format!("{secs}-{stem}-{seq}.{ext}")
        };
        let candidate = parent.join(name);
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate unique workspace path",
    ))
}

/// Lists regular owner-controlled files in a workspace subdirectory, sorted newest-first.
pub fn list_files(kind: WorkspaceKind) -> io::Result<Vec<PathBuf>> {
    let root = match root_dir() {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    list_files_in(&root, kind)
}

pub(crate) fn list_files_in(root: &Path, kind: WorkspaceKind) -> io::Result<Vec<PathBuf>> {
    let subdir = root.join(kind.subdir());
    match fs::symlink_metadata(&subdir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
        Ok(meta) => {
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe workspace subdirectory",
                ));
            }
        }
    }
    let uid = rustix::process::geteuid().as_raw();
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(&subdir)?.enumerate() {
        if index >= 1024 {
            break;
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == uid
            && meta.mode() & 0o022 == 0
        {
            paths.push(path);
        }
    }
    paths.sort();
    paths.reverse();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            loop {
                let candidate = std::env::temp_dir().join(format!(
                    "p2kesup-ws-test-{}-{}",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ));
                match DirBuilder::new().mode(0o700).create(&candidate) {
                    Ok(()) => return Self(candidate),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("{e}"),
                }
            }
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn allocates_unique_paths_and_lists_private_files() {
        let tmp = TempRoot::new();
        let root = ensure_root_in(&tmp.0).unwrap();
        let first = next_path_in(&root, WorkspaceKind::Plans, "service start!", "json").unwrap();
        let second = next_path_in(&root, WorkspaceKind::Plans, "service start!", "json").unwrap();
        assert_ne!(first, second);
        assert!(first.to_string_lossy().contains("service-start"));
        crate::files::publish_no_clobber(&first, b"{}", 0o600).unwrap();
        crate::files::publish_no_clobber(&second, b"{}", 0o600).unwrap();

        let listed = list_files_in(&root, WorkspaceKind::Plans).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], second);
        assert_eq!(listed[1], first);
    }

    #[test]
    fn rejects_group_or_world_accessible_workspace() {
        let tmp = TempRoot::new();
        let root = ensure_root_in(&tmp.0).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            dir_in(&root, WorkspaceKind::Exports).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
