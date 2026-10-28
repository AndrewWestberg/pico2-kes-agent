//! Owner-controlled file access and durable, no-clobber publication on Linux.

use rustix::fs::{self, AtFlags, CWD, Mode, OFlags, RenameFlags};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn owner_controlled(meta: &std::fs::Metadata) -> bool {
    meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o022 == 0
}

fn directory(path: &Path) -> io::Result<File> {
    let fd = fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let dir = File::from(fd);
    if !owner_controlled(&dir.metadata()?) {
        return Err(denied("directory is not owner-controlled"));
    }
    Ok(dir)
}

fn split(path: &Path) -> io::Result<(&Path, &OsStr)> {
    let name = match path.components().next_back() {
        Some(Component::Normal(name)) => name,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file name",
            ));
        }
    };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((parent, name))
}

/// Open and validate an owner-controlled regular file, without following the
/// final symlink. The returned descriptor pins the validated inode.
pub fn open_owner_controlled_file(path: &Path) -> io::Result<File> {
    let (parent, name) = split(path)?;
    let dir = directory(parent)?;
    let fd = fs::openat(
        &dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() || !owner_controlled(&metadata) {
        return Err(denied("file is not an owner-controlled regular file"));
    }
    Ok(file)
}

struct Unpublished<'a> {
    dir: &'a File,
    name: String,
    published: bool,
}
impl Drop for Unpublished<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::unlinkat(self.dir, self.name.as_str(), AtFlags::empty());
        }
    }
}

/// Write and sync a new file, atomically publish without replacing any existing
/// entry (including symlinks), then sync its directory. A directory sync error
/// is returned even though publication has already occurred; callers must
/// reconcile the existing destination rather than assume it is absent.
/// `mode` is the exact Unix permission bits, independent of the process umask.
pub fn publish_no_clobber(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    publish_with_sync(path, data, mode, |file, _directory| file.sync_all())
}

fn publish_with_sync(
    path: &Path,
    data: &[u8],
    mode: u32,
    sync: impl Fn(&File, bool) -> io::Result<()>,
) -> io::Result<()> {
    if mode & !0o777 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid file mode",
        ));
    }
    let (parent, destination) = split(path)?;
    let dir = directory(parent)?;
    let (mut file, mut temp) = loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".kes-tmp-{}-{sequence}", std::process::id());
        match fs::openat(
            &dir,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                break (
                    File::from(fd),
                    Unpublished {
                        dir: &dir,
                        name,
                        published: false,
                    },
                );
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    };
    file.write_all(data)?;
    fs::fchmod(&file, Mode::from_raw_mode(mode))?;
    sync(&file, false)?;
    fs::renameat_with(
        &dir,
        temp.name.as_str(),
        &dir,
        destination,
        RenameFlags::NOREPLACE,
    )?;
    temp.published = true;
    sync(&dir, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            loop {
                let name = format!(
                    "kes-files-test-{}-{}",
                    std::process::id(),
                    TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
                );
                let path = std::env::temp_dir().join(name);
                match std::fs::create_dir(&path) {
                    Ok(()) => {
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .unwrap();
                        return Self(path);
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("{e}"),
                }
            }
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn refuses_existing_and_symlink_and_validates_regular_files() {
        let dir = TestDir::new();
        let file = dir.0.join("out");
        publish_no_clobber(&file, b"original", 0o600).unwrap();
        assert_eq!(
            open_owner_controlled_file(&file)
                .unwrap()
                .metadata()
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            publish_no_clobber(&file, b"replacement", 0o644)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"original");
        let link = dir.0.join("link");
        symlink("missing", &link).unwrap();
        assert!(open_owner_controlled_file(&link).is_err());
        assert_eq!(
            publish_no_clobber(&link, b"x", 0o600).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn rejects_non_owner_controlled_paths() {
        let dir = TestDir::new();
        let path = dir.0.join("unsafe");
        std::fs::write(&path, b"public").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(open_owner_controlled_file(&path).is_err());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(publish_no_clobber(&dir.0.join("new"), b"x", 0o600).is_err());
    }

    #[test]
    fn concurrent_publication_has_exactly_one_winner() {
        let dir = TestDir::new();
        let path = dir.0.join("out");
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|n| {
                let barrier = barrier.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    publish_no_clobber(&path, &[n], 0o640)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| e.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn sync_failures_propagate_and_only_unpublished_temps_are_removed() {
        let dir = TestDir::new();
        let path = dir.0.join("out");
        let fail_file = |file: &File, directory: bool| {
            if directory {
                file.sync_all()
            } else {
                Err(io::Error::other("file sync"))
            }
        };
        assert_eq!(
            publish_with_sync(&path, b"x", 0o600, fail_file)
                .unwrap_err()
                .to_string(),
            "file sync"
        );
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
        let fail_directory = |file: &File, directory: bool| {
            if directory {
                Err(io::Error::other("directory sync"))
            } else {
                file.sync_all()
            }
        };
        assert_eq!(
            publish_with_sync(&path, b"x", 0o600, fail_directory)
                .unwrap_err()
                .to_string(),
            "directory sync"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    }
}
