use super::{node_service::PoolSubscription, sockets};
use kes_core::{operation::PoolTarget, pool::MAX_POOLS};
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
    directory: PathBuf,
    gid: u32,
    entries: HashMap<kes_core::identity::PoolId, Entry>,
}

impl PoolRegistry {
    pub fn new(directory: PathBuf, gid: u32) -> Self {
        Self {
            directory,
            gid,
            entries: HashMap::with_capacity(MAX_POOLS),
        }
    }

    pub fn upsert(
        &mut self,
        sockets: &mut sockets::SocketRegistry,
        target: PoolTarget,
    ) -> Result<bool, sockets::Error> {
        if self
            .entries
            .get(&target.pool)
            .is_some_and(|entry| entry.target == target)
        {
            return Ok(false);
        }
        if let Some(previous) = self.entries.remove(&target.pool) {
            previous.subscription.stop();
            sockets.remove_dynamic(&previous.path)?;
        }
        if self.entries.len() >= MAX_POOLS {
            return Err(sockets::Error::Io(std::io::Error::other(
                "dynamic pool registry capacity exceeded",
            )));
        }
        let path = self.directory.join(format!("{}.sock", target.pool));
        sockets.bind_dynamic(&path, self.gid)?;
        self.entries.insert(
            target.pool,
            Entry {
                target,
                path,
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

    pub fn reconcile(
        &mut self,
        sockets: &mut sockets::SocketRegistry,
        desired: &[PoolTarget],
    ) -> Result<(), sockets::Error> {
        if desired.len() > MAX_POOLS {
            return Err(sockets::Error::Io(std::io::Error::other(
                "dynamic pool registry capacity exceeded",
            )));
        }
        let stale: Vec<_> = self
            .entries
            .values()
            .filter(|entry| !desired.contains(&entry.target))
            .map(|entry| entry.target)
            .collect();
        for target in stale {
            self.remove(sockets, target)?;
        }
        for target in desired {
            self.upsert(sockets, *target)?;
        }
        Ok(())
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
        let mut registry = PoolRegistry::new(root.clone(), gid);
        let first = target(1, 1);
        assert!(registry.upsert(&mut sockets, first).unwrap());
        let first_path = registry.path(first).unwrap().to_path_buf();
        let metadata = std::fs::symlink_metadata(&first_path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert_eq!(metadata.gid(), gid);
        assert_eq!(registry.subscription(first).unwrap().target(), first);

        let replacement = target(1, 2);
        assert!(registry.upsert(&mut sockets, replacement).unwrap());
        assert!(registry.subscription(first).is_none());
        assert_eq!(
            registry.subscription(replacement).unwrap().target(),
            replacement
        );
        assert!(registry.remove(&mut sockets, replacement).unwrap());
        assert!(!first_path.exists());
        drop(sockets);
        std::fs::remove_dir_all(root).unwrap();
    }
}
