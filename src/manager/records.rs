//! Protected, bounded public maintenance records.

use super::model::{
    MANAGER_SCHEMA_VERSION, MAX_MAINTENANCE_RECORD_BYTES, MAX_MAINTENANCE_STORE_BYTES,
    MaintenanceRecord,
};
use kes_core::identity::OperationId;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP: AtomicU64 = AtomicU64::new(0);

fn error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}
fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|_| error(io::ErrorKind::InvalidInput, "NUL in path"))
}
fn open_at(dir: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            cstr(name)?.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn directory(path: &Path, owner: u32, group: u32, mode: u32) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(error(
            io::ErrorKind::InvalidInput,
            "record store path must be absolute",
        ));
    }
    let mut dir = File::open("/")?;
    let parts: Vec<_> = path
        .components()
        .filter(|c| *c != Component::RootDir)
        .collect();
    if parts.is_empty() {
        return Err(error(
            io::ErrorKind::InvalidInput,
            "invalid record store path",
        ));
    }
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "unsafe record store ancestry",
            ));
        };
        let last = index + 1 == parts.len();
        let requested = if last { mode } else { 0o700 };
        let mut created = false;
        let next = match open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if unsafe { libc::mkdirat(dir.as_raw_fd(), cstr(name)?.as_ptr(), requested) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                created = true;
                open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
            }
            Err(e) => return Err(e),
        };
        if created {
            if unsafe { libc::fchown(next.as_raw_fd(), owner, if last { group } else { u32::MAX }) }
                != 0
                || unsafe { libc::fchmod(next.as_raw_fd(), requested) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            next.sync_all()?;
            dir.sync_all()?;
        }
        let m = next.metadata()?;
        if last {
            if m.uid() != owner || m.gid() != group || m.mode() & 0o7777 != mode {
                return Err(error(
                    io::ErrorKind::PermissionDenied,
                    "unsafe record directory ownership or mode",
                ));
            }
        } else if (m.uid() != 0 && m.uid() != owner)
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err(error(
                io::ErrorKind::PermissionDenied,
                "unsafe record directory ancestry",
            ));
        }
        dir = next;
    }
    Ok(dir)
}

/// A pinned protected directory; mutations must be performed by its owner.
pub struct RecordStore {
    dir: File,
    owner: u32,
    group: u32,
    file_mode: u32,
}

/// Unknown versions are retained as public diagnostic JSON, never as mutable records.
pub enum Record {
    Supported(Box<MaintenanceRecord>),
    Unknown(serde_json::Value),
}
impl Record {
    pub fn supported(self) -> io::Result<MaintenanceRecord> {
        match self {
            Self::Supported(record) => Ok(*record),
            Self::Unknown(_) => Err(error(
                io::ErrorKind::InvalidData,
                "unknown schema; read-only diagnostics only",
            )),
        }
    }
}

fn record_name(id: &OperationId) -> io::Result<String> {
    let name = id.to_string();
    if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(io::ErrorKind::InvalidInput, "invalid operation ID"));
    }
    Ok(format!("{name}.json"))
}
fn capacity(total: u64, old: u64, new: u64) -> io::Result<()> {
    if new > MAX_MAINTENANCE_RECORD_BYTES
        || total
            .checked_sub(old)
            .and_then(|n| n.checked_add(new))
            .is_none_or(|n| n > MAX_MAINTENANCE_STORE_BYTES)
    {
        return Err(error(
            io::ErrorKind::StorageFull,
            "record capacity exceeded; export and archive records explicitly before mutation",
        ));
    }
    Ok(())
}
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl RecordStore {
    fn open(
        path: &Path,
        owner: u32,
        group: u32,
        dir_mode: u32,
        file_mode: u32,
    ) -> io::Result<Self> {
        let store = Self {
            dir: directory(path, owner, group, dir_mode)?,
            owner,
            group,
            file_mode,
        };
        if unsafe { libc::geteuid() } == owner {
            drop(store.lock()?);
        }
        Ok(store)
    }
    /// Opens the root-owned host store, using the existing authorized operator group.
    pub fn open_host(operator_group: u32) -> io::Result<Self> {
        directory(Path::new("/var/lib/p2kesup"), 0, 0, 0o755)?;
        Self::open(
            Path::new("/var/lib/p2kesup/records"),
            0,
            operator_group,
            0o750,
            0o640,
        )
    }
    /// Opens the current user's backup-local XDG state store.
    pub fn open_backup() -> io::Result<Self> {
        let base = match std::env::var_os("XDG_STATE_HOME") {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => PathBuf::from(
                std::env::var_os("HOME")
                    .ok_or_else(|| error(io::ErrorKind::NotFound, "HOME is not set"))?,
            )
            .join(".local/state"),
        };
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        directory(&base.join("p2kesup"), uid, gid, 0o700)?;
        Self::open(&base.join("p2kesup/records"), uid, gid, 0o700, 0o600)
    }
    fn checked_file(&self, name: &OsStr) -> io::Result<File> {
        let file = open_at(&self.dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != self.owner
            || m.gid() != self.group
            || m.mode() & 0o7777 != self.file_mode
            || m.nlink() != 1
        {
            return Err(error(
                io::ErrorKind::PermissionDenied,
                "unsafe record file ownership or mode",
            ));
        }
        Ok(file)
    }
    fn lock(&self) -> io::Result<Lock> {
        let name = OsStr::new(".lock");
        let file = match self.checked_file(name) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => match open_at(
                &self.dir,
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(file) => {
                    if unsafe { libc::fchown(file.as_raw_fd(), self.owner, self.group) } != 0
                        || unsafe { libc::fchmod(file.as_raw_fd(), self.file_mode) } != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    file.sync_all()?;
                    self.dir.sync_all()?;
                    file
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => self.checked_file(name)?,
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock(file))
    }
    fn read(&self, name: &OsStr) -> io::Result<(Record, u64)> {
        let file = self.checked_file(name)?;
        let size = file.metadata()?.len();
        if size > MAX_MAINTENANCE_RECORD_BYTES {
            return Err(error(io::ErrorKind::InvalidData, "record exceeds 1 MiB"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_MAINTENANCE_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MAINTENANCE_RECORD_BYTES {
            return Err(error(io::ErrorKind::InvalidData, "record exceeds 1 MiB"));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let version = value
            .get("schema_version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| error(io::ErrorKind::InvalidData, "missing record schema"))?;
        let record = if version == MANAGER_SCHEMA_VERSION {
            let record: MaintenanceRecord =
                serde_json::from_value(value).map_err(io::Error::other)?;
            if OsStr::new(&record_name(&record.operation_id)?) != name {
                return Err(error(
                    io::ErrorKind::InvalidData,
                    "record identity does not match filename",
                ));
            }
            Record::Supported(Box::new(record))
        } else {
            Record::Unknown(value)
        };
        Ok((record, bytes.len() as u64))
    }
    fn entries(&self) -> io::Result<Vec<std::ffi::OsString>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))? {
            let name = entry?.file_name();
            if name == ".lock" {
                continue;
            }
            entries.push(name);
        }
        entries.sort();
        Ok(entries)
    }
    /// Lists all original records, including unknown-schema diagnostics.
    pub fn list(&self) -> io::Result<Vec<Record>> {
        let _lock = self.lock()?;
        self.entries()?
            .iter()
            .filter(|n| !n.as_bytes().starts_with(b".tmp-"))
            .map(|n| self.read(n).map(|r| r.0))
            .collect()
    }
    pub fn load(&self, id: &OperationId) -> io::Result<Record> {
        let _lock = self.lock()?;
        self.read(OsStr::new(&record_name(id)?)).map(|r| r.0)
    }
    /// Lists host maintenance records read-only without creating directories or lock files.
    pub fn list_host_readonly() -> io::Result<Vec<Record>> {
        Self::list_readonly_at(Path::new("/var/lib/p2kesup/records"), 0, 0o750, 0o640)
    }
    /// Lists backup-local maintenance records read-only without creating directories or lock files.
    pub fn list_backup_readonly() -> io::Result<Vec<Record>> {
        let base = match std::env::var_os("XDG_STATE_HOME") {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => match std::env::var_os("HOME") {
                Some(home) if !home.is_empty() => PathBuf::from(home).join(".local/state"),
                _ => return Ok(Vec::new()),
            },
        };
        let uid = unsafe { libc::geteuid() };
        Self::list_readonly_at(&base.join("p2kesup/records"), uid, 0o700, 0o600)
    }
    pub(crate) fn list_readonly_at(
        path: &Path,
        owner: u32,
        dir_mode: u32,
        file_mode: u32,
    ) -> io::Result<Vec<Record>> {
        if !path.is_absolute() {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "record store path must be absolute",
            ));
        }
        let mut dir = File::open("/")?;
        let parts: Vec<_> = path
            .components()
            .filter(|c| *c != Component::RootDir)
            .collect();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(name) = part else {
                return Err(error(
                    io::ErrorKind::InvalidInput,
                    "unsafe record store ancestry",
                ));
            };
            let next = match open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(e),
            };
            let m = next.metadata()?;
            let last = index + 1 == parts.len();
            if last {
                if m.uid() != owner || m.mode() & 0o7777 != dir_mode {
                    return Err(error(
                        io::ErrorKind::PermissionDenied,
                        "unsafe record directory ownership or mode",
                    ));
                }
            } else if (m.uid() != 0 && m.uid() != owner)
                || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
            {
                return Err(error(
                    io::ErrorKind::PermissionDenied,
                    "unsafe record directory ancestry",
                ));
            }
            dir = next;
        }
        let group = dir.metadata()?.gid();
        let store = Self {
            dir,
            owner,
            group,
            file_mode,
        };
        let mut records = Vec::new();
        for name in store.entries()? {
            if name.as_bytes().starts_with(b".tmp-") {
                continue;
            }
            if let Ok((record, _)) = store.read(&name) {
                records.push(record);
            }
        }
        Ok(records)
    }
    fn usage(&self) -> io::Result<u64> {
        let mut total = 0u64;
        for name in self.entries()? {
            let size = if name.as_bytes().starts_with(b".tmp-") {
                self.checked_file(&name)?.metadata()?.len()
            } else {
                let (record, size) = self.read(&name)?;
                record.supported()?;
                size
            };
            total = total.checked_add(size).ok_or_else(|| {
                error(
                    io::ErrorKind::StorageFull,
                    "record capacity exceeded; export and archive records explicitly",
                )
            })?;
        }
        Ok(total)
    }
    /// Durably creates the original operation without replacing any existing entry.
    pub fn create(&self, record: &MaintenanceRecord) -> io::Result<()> {
        self.write(record, false)
    }
    /// Atomically advances an existing operation, retaining its confirmed evidence.
    pub fn update(&self, record: &MaintenanceRecord) -> io::Result<()> {
        self.write(record, true)
    }
    fn write(&self, record: &MaintenanceRecord, update: bool) -> io::Result<()> {
        if unsafe { libc::geteuid() } != self.owner {
            return Err(error(
                io::ErrorKind::PermissionDenied,
                "only the store owner may mutate records",
            ));
        }
        if record.schema_version != MANAGER_SCHEMA_VERSION {
            return Err(error(
                io::ErrorKind::InvalidData,
                "unknown schema; read-only diagnostics only",
            ));
        }
        let _lock = self.lock()?;
        let name = record_name(&record.operation_id)?;
        let total = self.usage()?;
        let old_size = if update {
            let (old, size) = self.read(OsStr::new(&name))?;
            preserve(&old.supported()?, record)?;
            size
        } else {
            0
        };
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        capacity(total, old_size, bytes.len() as u64)?;
        let temp_name = format!(
            ".tmp-{}-{}",
            std::process::id(),
            TEMP.fetch_add(1, Ordering::Relaxed)
        );
        let temp = OsStr::new(&temp_name);
        let mut file = open_at(
            &self.dir,
            temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let result = (|| {
            if unsafe { libc::fchown(file.as_raw_fd(), self.owner, self.group) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), self.file_mode) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            file.write_all(&bytes)?;
            file.sync_all()?;
            let source = cstr(temp)?;
            let dest = cstr(OsStr::new(&name))?;
            let rc = if update {
                unsafe {
                    libc::renameat(
                        self.dir.as_raw_fd(),
                        source.as_ptr(),
                        self.dir.as_raw_fd(),
                        dest.as_ptr(),
                    )
                }
            } else {
                unsafe {
                    libc::renameat2(
                        self.dir.as_raw_fd(),
                        source.as_ptr(),
                        self.dir.as_raw_fd(),
                        dest.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                }
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            self.dir.sync_all()
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), cstr(temp)?.as_ptr(), 0);
            }
        }
        result
    }
}

fn preserve(old: &MaintenanceRecord, new: &MaintenanceRecord) -> io::Result<()> {
    let mut before = serde_json::to_value(old).map_err(io::Error::other)?;
    let mut after = serde_json::to_value(new).map_err(io::Error::other)?;
    for key in ["checkpoints", "post_observations", "outcome"] {
        before.as_object_mut().unwrap().remove(key);
        after.as_object_mut().unwrap().remove(key);
    }
    let old_checkpoints = serde_json::to_value(&old.checkpoints).map_err(io::Error::other)?;
    let new_checkpoints = serde_json::to_value(&new.checkpoints).map_err(io::Error::other)?;
    let prefix = new_checkpoints
        .as_array()
        .unwrap()
        .starts_with(old_checkpoints.as_array().unwrap());
    if before != after || !prefix || !new.post_observations.starts_with(&old.post_observations) {
        return Err(error(
            io::ErrorKind::InvalidInput,
            "record update would rewrite confirmed evidence or original intent",
        ));
    }
    let rank = |s: &str| match s {
        "planned" => Some(0),
        "approved" => Some(1),
        "staged-authenticated" => Some(2),
        "intent-durable" => Some(3),
        "service-quiesced" => Some(4),
        "activated" => Some(5),
        "post-check" => Some(6),
        "completed" => Some(7),
        _ => None,
    };
    if old.outcome != new.outcome
        && (matches!(
            old.outcome.as_str(),
            "completed" | "cancelled" | "failed-known"
        ) || matches!((rank(&old.outcome), rank(&new.outcome)), (Some(a), Some(b)) if b < a)
            || matches!((rank(&old.outcome), rank(&new.outcome)), (None, Some(b)) if b < 6))
    {
        return Err(error(
            io::ErrorKind::InvalidInput,
            "record outcome regression",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn store() -> (RecordStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "p2kes-records-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = RecordStore::open(
            &path,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
            0o600,
        )
        .unwrap();
        (store, path)
    }
    fn record() -> MaintenanceRecord {
        serde_json::from_value(serde_json::json!({"schema_version":1,"operation_id":"00000000000000000000000000000000","action":"upgrade","plan_digest":"0000000000000000000000000000000000000000000000000000000000000000","selected":null,"approved_scope":[],"previous_service_state":null,"pre_observations":[],"checkpoints":[{"name":"intent","observed_at_unix_us":1,"evidence":"confirmed"}],"post_observations":[],"outcome":"planned","bundle_digest":null,"image_digest":null,"physical_selection":null})).unwrap()
    }
    #[test]
    fn no_clobber_and_preserve_evidence() {
        let (store, path) = store();
        let original = record();
        store.create(&original).unwrap();
        assert!(store.create(&original).is_err());
        let mut changed = original.clone();
        changed.checkpoints[0].evidence = "rewritten".into();
        assert!(store.update(&changed).is_err());
        changed = original.clone();
        changed.checkpoints.clear();
        assert!(store.update(&changed).is_err());
        assert_eq!(
            store
                .load(&original.operation_id)
                .unwrap()
                .supported()
                .unwrap()
                .checkpoints[0]
                .evidence,
            "confirmed"
        );
        changed = original.clone();
        changed
            .checkpoints
            .push(super::super::model::MaintenanceCheckpoint {
                name: "approved".into(),
                observed_at_unix_us: 2,
                evidence: "confirmed".into(),
            });
        changed.outcome = "approved".into();
        store.update(&changed).unwrap();
        assert_eq!(
            store
                .load(&original.operation_id)
                .unwrap()
                .supported()
                .unwrap()
                .checkpoints
                .len(),
            2
        );
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn capacity_and_unknown_schema_refuse_mutation() {
        let (store, path) = store();
        let mut oversized = record();
        oversized.action = "x".repeat(MAX_MAINTENANCE_RECORD_BYTES as usize);
        assert!(
            store
                .create(&oversized)
                .unwrap_err()
                .to_string()
                .contains("archive")
        );
        let mut value = serde_json::to_value(record()).unwrap();
        value["schema_version"] = 2.into();
        let name = record_name(&record().operation_id).unwrap();
        std::fs::write(path.join(&name), serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(
            path.join(&name),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            store.load(&record().operation_id).unwrap(),
            Record::Unknown(_)
        ));
        assert!(store.update(&record()).is_err());
        assert!(capacity(MAX_MAINTENANCE_STORE_BYTES, 0, 1).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn readonly_listing_does_not_create_missing_and_rejects_unsafe_modes() {
        let missing = std::env::temp_dir().join(format!(
            "p2kes-records-missing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let uid = unsafe { libc::geteuid() };
        assert!(
            RecordStore::list_readonly_at(&missing, uid, 0o700, 0o600)
                .unwrap()
                .is_empty()
        );
        assert!(!missing.exists());

        let (store, path) = store();
        let original = record();
        store.create(&original).unwrap();
        let listed = RecordStore::list_readonly_at(&path, uid, 0o700, 0o600).unwrap();
        assert_eq!(listed.len(), 1);

        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o777))
            .unwrap();
        assert!(RecordStore::list_readonly_at(&path, uid, 0o700, 0o600).is_err());
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }
}
