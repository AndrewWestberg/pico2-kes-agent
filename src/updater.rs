//! Atomic `/usr/local` software updater (`p2kesup`).

use crate::release::{self, ReleaseError, ReleaseManifest};
use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_PREFIX: &str = "/usr/local";
pub const STATE_REL_PATH: &str = "share/pico2-kes-agent/installed.json";
const SHARE: &str = "share/pico2-kes-agent/";
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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

fn trusted(meta: &std::fs::Metadata, sticky_ancestor: bool) -> bool {
    (meta.uid() == 0 || meta.uid() == rustix::process::geteuid().as_raw())
        && (meta.mode() & 0o022 == 0 || sticky_ancestor && meta.mode() & 0o1000 != 0)
}

fn unsafe_destination() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unsafe install destination",
    )
}

fn directories(root: &File, path: &Path, create: bool, sticky_ancestors: bool) -> io::Result<File> {
    let mut current = None;
    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name,
            Component::CurDir => continue,
            _ => return Err(unsafe_destination()),
        };
        let parent = current.as_ref().unwrap_or(root);
        if !trusted(&parent.metadata()?, sticky_ancestors) {
            return Err(unsafe_destination());
        }
        let fd = match fs::openat(parent, name, DIRECTORY, Mode::empty()) {
            Err(rustix::io::Errno::NOENT) if create => {
                match fs::mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => (),
                    Err(e) => return Err(e.into()),
                }
                fs::openat(parent, name, DIRECTORY, Mode::empty())?
            }
            result => result?,
        };
        current = Some(File::from(fd));
    }
    let dir = match current {
        Some(dir) => dir,
        None => root.try_clone()?,
    };
    if !trusted(&dir.metadata()?, false) {
        return Err(unsafe_destination());
    }
    Ok(dir)
}

fn prefix_dir(prefix: &Path, create: bool) -> io::Result<Option<File>> {
    let (base, path) = match prefix.strip_prefix("/") {
        Ok(relative) => ("/", relative),
        Err(_) => (".", prefix),
    };
    let base = File::from(fs::openat(CWD, base, DIRECTORY, Mode::empty())?);
    match directories(&base, path, create, true) {
        Ok(dir) => Ok(Some(dir)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn share_artifact(path: &str) -> bool {
    matches!(
        path.split_once('/'),
        Some(("firmware" | "tools" | "runtime" | "licenses" | "deploy", _))
    )
}

fn canonical_path(path: &str) -> Result<(), ReleaseError> {
    if path
        .split('/')
        .any(|part| matches!(part, "" | "." | "..") || part.contains('\0'))
    {
        return Err(ReleaseError::PathConfinement(path.into()));
    }
    Ok(())
}

fn load_state_at(root: &File) -> Result<Option<InstalledState>, ReleaseError> {
    let path = Path::new(STATE_REL_PATH);
    let file = (|| {
        let dir = directories(root, path.parent().unwrap(), false, false)?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        Ok::<_, io::Error>(File::from(fs::openat(
            &dir,
            path.file_name().unwrap(),
            flags,
            Mode::empty(),
        )?))
    })();
    let file = match file {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || !trusted(&meta, false) {
        return Err(unsafe_destination().into());
    }
    let state: InstalledState = serde_json::from_reader(BufReader::new(file))
        .map_err(|e| ReleaseError::InvalidManifest(format!("installed.json: {e}")))?;
    for path in &state.artifacts {
        canonical_path(path)?;
        if !path.starts_with("bin/") && !path.strip_prefix(SHARE).is_some_and(share_artifact) {
            return Err(ReleaseError::PathConfinement(path.clone()));
        }
    }
    Ok(Some(state))
}

pub fn load_state(prefix: &Path) -> Result<Option<InstalledState>, ReleaseError> {
    match prefix_dir(prefix, false)? {
        Some(dir) => load_state_at(&dir),
        None => Ok(None),
    }
}

struct StagedFile {
    dir: File,
    temp: String,
    destination: OsString,
}

impl StagedFile {
    fn create(root: &File, path: &Path) -> io::Result<(Self, File)> {
        let dir = directories(root, path.parent().unwrap(), true, false)?;
        let destination = path.file_name().unwrap();
        match fs::statat(&dir, destination, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(meta) if FileType::from_raw_mode(meta.st_mode) == FileType::RegularFile => (),
            Ok(_) => return Err(unsafe_destination()),
            Err(rustix::io::Errno::NOENT) => (),
            Err(e) => return Err(e.into()),
        }
        loop {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp = format!(".p2kesup-{}-{sequence}", std::process::id());
            let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC;
            match fs::openat(&dir, temp.as_str(), flags, Mode::from_raw_mode(0o600)) {
                Ok(fd) => {
                    return Ok((
                        Self {
                            dir,
                            temp,
                            destination: destination.into(),
                        },
                        File::from(fd),
                    ));
                }
                Err(rustix::io::Errno::EXIST) => (),
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn publish(mut self) -> io::Result<()> {
        fs::renameat(
            &self.dir,
            self.temp.as_str(),
            &self.dir,
            self.destination.as_os_str(),
        )?;
        self.temp.clear();
        self.dir.sync_all()
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.temp.is_empty() {
            let _ = fs::unlinkat(&self.dir, self.temp.as_str(), AtFlags::empty());
        }
    }
}

fn remove_file(root: &File, path: &Path) -> io::Result<()> {
    let result = (|| {
        let dir = directories(root, path.parent().unwrap(), false, false)?;
        fs::unlinkat(&dir, path.file_name().unwrap(), AtFlags::empty())?;
        dir.sync_all()
    })();
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn not_installed() -> ReleaseError {
    ReleaseError::InvalidManifest("not installed; run `p2kesup install` first".into())
}

pub fn install_or_update(
    bundle_root: &Path,
    prefix: &Path,
    is_update: bool,
) -> Result<InstalledState, ReleaseError> {
    let manifest = release::load_and_verify_manifest(bundle_root)?;
    install_verified(bundle_root, prefix, is_update, manifest)
}

fn install_verified(
    bundle_root: &Path,
    prefix: &Path,
    is_update: bool,
    manifest: ReleaseManifest,
) -> Result<InstalledState, ReleaseError> {
    let root = prefix_dir(prefix, !is_update)?.ok_or_else(not_installed)?;
    let prev = load_state_at(&root)?;
    if is_update && prev.is_none() {
        return Err(not_installed());
    }

    let mut installed_paths = Vec::new();
    let mut staged = Vec::new();
    for artifact in &manifest.artifacts {
        canonical_path(&artifact.path)?;
        let destination = if artifact.path.starts_with("bin/") {
            artifact.path.clone()
        } else if share_artifact(&artifact.path) {
            format!("{SHARE}{}", artifact.path)
        } else {
            continue;
        };
        let mode = match artifact.mode.as_deref() {
            Some("0o644") => 0o644,
            Some("0o755") => 0o755,
            _ => {
                return Err(ReleaseError::InvalidManifest(format!(
                    "invalid mode for {}",
                    artifact.path
                )));
            }
        };
        let (pending, file) = StagedFile::create(&root, Path::new(&destination))?;
        // Verify the exact bytes to publish, not a prior read of the user bundle.
        release::copy_verified_artifact(bundle_root, artifact, &file)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        staged.push(pending);
        installed_paths.push(destination);
    }
    let state = InstalledState {
        schema_version: manifest.schema_version,
        version: manifest.version,
        firmware_version: manifest.firmware_version,
        artifacts: installed_paths,
    };
    let (pending_state, mut file) = StagedFile::create(&root, Path::new(STATE_REL_PATH))?;
    let json = serde_json::to_vec_pretty(&state)
        .map_err(|e| ReleaseError::InvalidManifest(e.to_string()))?;
    file.write_all(&json)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    file.sync_all()?;

    for pending in staged {
        pending.publish()?;
    }
    if let Some(prev) = &prev {
        for path in &prev.artifacts {
            if !state.artifacts.contains(path) {
                remove_file(&root, Path::new(path))?;
            }
        }
    }
    pending_state.publish()?;

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
    let Some(root) = prefix_dir(prefix, false)? else {
        println!("pico2-kes-agent is not installed");
        return Ok(());
    };
    let Some(state) = load_state_at(&root)? else {
        println!("pico2-kes-agent is not installed");
        return Ok(());
    };
    for path in state.artifacts {
        remove_file(&root, Path::new(&path))?;
    }
    remove_file(&root, Path::new(STATE_REL_PATH))?;
    println!(
        "uninstalled pico2-kes-agent (preserved /etc/pico2-kes-agent and /var/lib/pico2-kes-agent)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{ReleaseArtifact, ReleasePlatform};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::symlink;

    fn artifact(bundle: &Path, path: &str, content: &[u8], mode: u32) -> ReleaseArtifact {
        let file = bundle.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, content).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(mode)).unwrap();
        ReleaseArtifact {
            name: path.into(),
            path: path.into(),
            size: content.len() as u64,
            sha256: format!("{:x}", Sha256::digest(content)),
            mode: Some(format!("{mode:#o}")),
        }
    }

    #[test]
    fn verified_install_projects_managed_inventory_and_checks_staged_bytes() {
        let root = std::env::temp_dir().join(format!("p2kes-install-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let bundle = root.join("bundle");
        let prefix = root.join("new-prefix");
        let paths = [
            ("bin/p2kes", 0o755),
            ("firmware/pico2-kes-firmware.signed.uf2", 0o644),
            ("tools/picotool", 0o755),
            ("runtime/libusb-1.0.so.0", 0o644),
            ("licenses/picotool.txt", 0o644),
            ("deploy/pico2-kes-agentd.service", 0o644),
        ];
        let bootstrap = [
            "install.sh",
            "install.sh.sig",
            "distribution-authority.json",
            "distribution-authority.json.asc",
        ];
        let manifest = ReleaseManifest {
            schema_version: 2,
            version: "v1.0.0-rc.1".into(),
            firmware_version: Some("v1.0.0-rc.1".into()),
            platform: ReleasePlatform {
                arch: "x86_64".into(),
                os: "linux".into(),
                min_glibc: "2.36".into(),
            },
            usb_protocol_major: 1,
            artifacts: paths
                .iter()
                .map(|(path, mode)| artifact(&bundle, path, b"first", *mode))
                .chain(
                    bootstrap
                        .iter()
                        .map(|path| artifact(&bundle, path, b"bootstrap", 0o644)),
                )
                .collect(),
        };

        let state = install_verified(&bundle, &prefix, false, manifest.clone()).unwrap();
        assert_eq!(state.version, "v1.0.0-rc.1");
        assert_eq!(state.artifacts.len(), paths.len());
        for (path, mode) in paths {
            let rel = if path.starts_with("bin/") {
                path.to_owned()
            } else {
                assert!(!prefix.join(path).exists());
                format!("share/pico2-kes-agent/{path}")
            };
            assert!(state.artifacts.contains(&rel));
            let file = prefix.join(rel);
            assert_eq!(fs::read(&file).unwrap(), b"first");
            assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, mode);
        }
        for path in bootstrap {
            assert!(!prefix.join(path).exists());
        }
        assert_eq!(load_state(&prefix).unwrap(), Some(state.clone()));

        let mut update = manifest;
        update.version = "v1.0.0-rc.2".into();
        update.artifacts[0] = artifact(&bundle, paths[0].0, b"second", 0o755);
        fs::write(bundle.join(paths[1].0), b"wrong").unwrap();
        assert!(matches!(
            install_verified(&bundle, &prefix, true, update.clone()),
            Err(ReleaseError::HashMismatch { .. })
        ));
        assert_eq!(fs::read(prefix.join("bin/p2kes")).unwrap(), b"first");
        assert_eq!(fs::read_dir(prefix.join("bin")).unwrap().count(), 1);
        assert_eq!(load_state(&prefix).unwrap(), Some(state));

        fs::write(bundle.join(paths[1].0), b"first").unwrap();
        update.artifacts.remove(4);
        let installed = install_verified(&bundle, &prefix, true, update.clone()).unwrap();
        assert_eq!(installed.version, "v1.0.0-rc.2");
        assert_eq!(fs::read(prefix.join("bin/p2kes")).unwrap(), b"second");
        assert!(
            !prefix
                .join("share/pico2-kes-agent/licenses/picotool.txt")
                .exists()
        );
        uninstall(&prefix).unwrap();
        for path in installed.artifacts {
            assert!(!prefix.join(path).exists());
        }
        assert!(load_state(&prefix).unwrap().is_none());

        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("p2kes"), b"outside").unwrap();
        fs::remove_dir(prefix.join("bin")).unwrap();
        symlink(&outside, prefix.join("bin")).unwrap();
        assert!(install_verified(&bundle, &prefix, false, update).is_err());
        assert_eq!(fs::read(outside.join("p2kes")).unwrap(), b"outside");
        assert!(load_state(&prefix).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
