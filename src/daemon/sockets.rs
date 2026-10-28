//! Runtime-directory locking and owned Unix socket lifecycle.

use crate::config::Config;
use rustix::fs::{self, AtFlags, CWD, FlockOperation, Gid, Mode, OFlags};
use std::{
    collections::HashMap,
    fs::File,
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    AlreadyRunning,
    LiveEndpoint(PathBuf),
    UnsafeStaleEndpoint(PathBuf),
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "socket I/O: {error}"),
            Self::AlreadyRunning => {
                formatter.write_str("another daemon owns the runtime directory")
            }
            Self::LiveEndpoint(path) => write!(
                formatter,
                "live endpoint already exists: {}",
                path.display()
            ),
            Self::UnsafeStaleEndpoint(path) => {
                write!(
                    formatter,
                    "refusing to remove unowned endpoint: {}",
                    path.display()
                )
            }
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy)]
struct OwnedInode {
    device: u64,
    inode: u64,
}

pub struct SocketRegistry {
    _lock: File,
    listeners: HashMap<PathBuf, UnixListener>,
    owned: HashMap<PathBuf, OwnedInode>,
}

impl SocketRegistry {
    pub fn bind(config: &Config) -> Result<Self, Error> {
        let lock_path = config.socket_directory.join(".pico2-kes-agent.lock");
        let lock_fd = fs::openat(
            CWD,
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io::Error::from)?;
        let lock = File::from(lock_fd);
        match fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => return Err(Error::AlreadyRunning),
            Err(error) => return Err(io::Error::from(error).into()),
        }

        let mut registry = Self {
            _lock: lock,
            listeners: HashMap::new(),
            owned: HashMap::new(),
        };
        registry.bind_one(&config.management_socket, config.socket_gid)?;
        for pool in &config.pools {
            registry.bind_one(&pool.socket_path, config.socket_gid)?;
        }
        Ok(registry)
    }

    pub fn listener(&self, path: &Path) -> Option<&UnixListener> {
        self.listeners.get(path)
    }

    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.listeners.keys().map(PathBuf::as_path)
    }

    fn bind_one(&mut self, path: &Path, gid: u32) -> Result<(), Error> {
        prepare_path(path)?;
        let listener = UnixListener::bind(path)?;
        if let Err(error) = configure_socket(path, gid) {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        let metadata = std::fs::symlink_metadata(path)?;
        let inode = OwnedInode {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        self.owned.insert(path.to_path_buf(), inode);
        self.listeners.insert(path.to_path_buf(), listener);
        Ok(())
    }
}

impl Drop for SocketRegistry {
    fn drop(&mut self) {
        self.listeners.clear();
        for (path, expected) in &self.owned {
            let Ok(metadata) = std::fs::symlink_metadata(path) else {
                continue;
            };
            if metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.dev() == expected.device
                && metadata.ino() == expected.inode
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn prepare_path(path: &Path) -> Result<(), Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::UnsafeStaleEndpoint(path.to_path_buf()));
    }
    match UnixStream::connect(path) {
        Ok(_) => return Err(Error::LiveEndpoint(path.to_path_buf())),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(_) => return Err(Error::LiveEndpoint(path.to_path_buf())),
    }
    std::fs::remove_file(path)?;
    Ok(())
}

fn configure_socket(path: &Path, gid: u32) -> Result<(), Error> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    fs::chownat(
        CWD,
        path,
        None,
        Some(Gid::from_raw(gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.mode() & 0o777 != 0o660
        || metadata.gid() != gid
    {
        return Err(Error::UnsafeStaleEndpoint(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, RunMode},
        daemon::usb::UsbSelection,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pico2-sockets-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn config(directory: &Path) -> Config {
        Config {
            mode: RunMode::Commissioning,
            pin: None,
            selected_serial: UsbSelection::new(b"0011223344556677").unwrap(),
            socket_directory: directory.to_path_buf(),
            socket_group: String::new(),
            socket_gid: rustix::process::getegid().as_raw(),
            management_socket: directory.join("management.sock"),
            state_directory: directory.to_path_buf(),
            networks: HashMap::new(),
            pools: Vec::new(),
        }
    }

    #[test]
    fn lock_excludes_second_owner_and_drop_removes_only_owned_socket() {
        let directory = TestDir::new();
        let config = config(&directory.0);
        let registry = SocketRegistry::bind(&config).unwrap();
        assert!(config.management_socket.exists());
        assert!(matches!(
            SocketRegistry::bind(&config),
            Err(Error::AlreadyRunning)
        ));
        drop(registry);
        assert!(!config.management_socket.exists());

        let stale = UnixListener::bind(&config.management_socket).unwrap();
        drop(stale);
        let registry = SocketRegistry::bind(&config).unwrap();
        assert!(config.management_socket.exists());
        drop(registry);
        assert!(!config.management_socket.exists());
    }
}
