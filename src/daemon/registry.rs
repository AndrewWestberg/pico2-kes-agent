use super::{node_service::PoolSubscription, sockets};
use kes_core::{identity::StorageSlot, operation::PoolTarget};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

struct Entry {
    target: PoolTarget,
    path: PathBuf,
    subscription: PoolSubscription,
}

pub struct PoolRegistry {
    gid: u32,
    entries: HashMap<kes_core::identity::PoolId, Entry>,
}

impl PoolRegistry {
    pub fn new(gid: u32) -> Self {
        Self {
            gid,
            entries: HashMap::with_capacity(usize::from(StorageSlot::CAPACITY)),
        }
    }

    pub fn upsert(
        &mut self,
        sockets: &mut sockets::SocketRegistry,
        target: PoolTarget,
        path: &Path,
    ) -> Result<bool, sockets::Error> {
        if self
            .entries
            .get(&target.pool)
            .is_some_and(|entry| entry.target == target && entry.path == path)
        {
            return Ok(false);
        }
        if let Some(previous) = self.entries.remove(&target.pool) {
            previous.subscription.stop();
            sockets.remove_dynamic(&previous.path)?;
        }
        if self.entries.len() >= usize::from(StorageSlot::CAPACITY) {
            return Err(sockets::Error::Io(std::io::Error::other(
                "dynamic pool registry capacity exceeded",
            )));
        }
        sockets.bind_dynamic(path, self.gid)?;
        self.entries.insert(
            target.pool,
            Entry {
                target,
                path: path.to_path_buf(),
                subscription: PoolSubscription::new(target),
            },
        );
        Ok(true)
    }

    pub fn remove(
        &mut self,
        sockets: &mut sockets::SocketRegistry,
        target: PoolTarget,
    ) -> Result<bool, sockets::Error> {
        let Some(entry) = self.entries.get(&target.pool) else {
            return Ok(false);
        };
        if entry.target != target {
            return Ok(false);
        }
        let entry = self.entries.remove(&target.pool).expect("entry checked");
        entry.subscription.stop();
        sockets.remove_dynamic(&entry.path)
    }

    pub fn subscription(&self, target: PoolTarget) -> Option<&PoolSubscription> {
        self.entries
            .get(&target.pool)
            .filter(|entry| entry.target == target)
            .map(|entry| &entry.subscription)
    }

    pub fn path(&self, target: PoolTarget) -> Option<&Path> {
        self.entries
            .get(&target.pool)
            .filter(|entry| entry.target == target)
            .map(|entry| entry.path.as_path())
    }

    pub fn targets(&self) -> impl Iterator<Item = PoolTarget> + '_ {
        self.entries.values().map(|entry| entry.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, RunMode},
        daemon::usb::UsbSelection,
    };
    use kes_core::identity::{IncarnationId, PoolId};
    use std::{
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn target(pool: u8, incarnation: u8) -> PoolTarget {
        PoolTarget {
            pool: PoolId::from_bytes([pool; 28]),
            incarnation: IncarnationId::from_bytes([incarnation; 16]),
        }
    }

    #[test]
    fn enrollment_replacement_and_deletion_reconcile_exact_bound_endpoints() {
        let root = std::env::temp_dir().join(format!(
            "pico2-registry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let gid = rustix::process::getegid().as_raw();
        let config = Config {
            mode: RunMode::Commissioning,
            pin: None,
            selected_serial: UsbSelection::new(b"0011223344556677").unwrap(),
            socket_directory: root.clone(),
            socket_group: String::new(),
            socket_gid: gid,
            management_socket: root.join("management.sock"),
            state_directory: root.clone(),
            networks: HashMap::new(),
            pools: Vec::new(),
        };
        let mut sockets = sockets::SocketRegistry::bind(&config).unwrap();
        let mut registry = PoolRegistry::new(gid);
        let first = target(1, 1);
        let first_path = root.join("custom.sock");
        assert!(registry.upsert(&mut sockets, first, &first_path).unwrap());
        let metadata = std::fs::symlink_metadata(&first_path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert_eq!(metadata.gid(), gid);
        assert_eq!(registry.subscription(first).unwrap().target(), first);
        assert!(!registry.upsert(&mut sockets, first, &first_path).unwrap());
        let moved_path = root.join("moved.sock");
        assert!(registry.upsert(&mut sockets, first, &moved_path).unwrap());
        assert!(!first_path.exists());
        assert_eq!(registry.path(first), Some(moved_path.as_path()));

        let replacement = target(1, 2);
        let replacement_path = root.join("replacement.sock");
        assert!(
            registry
                .upsert(&mut sockets, replacement, &replacement_path)
                .unwrap()
        );
        assert!(!moved_path.exists());
        assert!(registry.subscription(first).is_none());
        assert_eq!(
            registry.subscription(replacement).unwrap().target(),
            replacement
        );
        assert!(registry.remove(&mut sockets, replacement).unwrap());
        assert!(!replacement_path.exists());
        drop(sockets);
        std::fs::remove_dir_all(root).unwrap();
    }
}
