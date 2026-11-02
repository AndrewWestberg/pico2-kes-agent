//! Explicit, narrowly scoped producer drop-in installation.
use super::{
    host,
    model::MaintenanceRecord,
    records::{Record, RecordStore},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};

const FILE: &str = "pico2-kes-memory.conf";
const SOURCE: &[u8] = include_bytes!("../../deploy/cardano-node-memory-hardening.conf");
// shortcut: existing files over 4096 bytes are refused; upgrade if larger policies must be reviewed.
const MAX_EXISTING: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Existing {
    pub device: u64,
    pub inode: u64,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub contents: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub unit: String,
    pub existing: Option<Existing>,
    pub restart: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub policy_sha256: String,
    pub targets: Vec<Target>,
}

pub fn policy_sha256() -> String {
    format!("{:x}", Sha256::digest(SOURCE))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedDestination {
    pub unit: String,
    pub path: PathBuf,
    pub policy_sha256: String,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub outcome: String,
}

/// Protected records contain intent as well as completed publications, so uncertain
/// destinations are listed even if an interrupted action never reached its result.
pub fn retained_destinations(store: &RecordStore) -> io::Result<Vec<RetainedDestination>> {
    let mut retained = Vec::new();
    for entry in store.list()? {
        let record = match entry {
            Record::Supported(record) => record,
            Record::Unknown(_) => {
                return Err(io::Error::other("unknown maintenance record schema"));
            }
        };
        let mut current = std::collections::BTreeMap::new();
        for checkpoint in &record.checkpoints {
            if checkpoint.name != "producer-retained" {
                continue;
            }
            let item: RetainedDestination =
                serde_json::from_str(&checkpoint.evidence).map_err(io::Error::other)?;
            if destination(&item.unit)? != item.path
                || item.owner != 0
                || item.group != 0
                || item.mode != 0o644
                || !matches!(item.outcome.as_str(), "possible" | "installed")
                || item.policy_sha256.len() != 64
                || !item
                    .policy_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid retained producer evidence",
                ));
            }
            current.insert(item.path.clone(), item);
        }
        retained.extend(current.into_values());
    }
    Ok(retained)
}

pub fn valid_unit(unit: &str) -> bool {
    let b = unit.as_bytes();
    if b.len() > 255 || !unit.ends_with(".service") || unit.starts_with('-') || unit.contains("..")
    {
        return false;
    }
    let stem = &b[..b.len() - 8];
    if stem.is_empty() {
        return false;
    }
    let mut at = None;
    let mut i = 0;
    while i < stem.len() {
        match stem[i] {
            b'@' if at.is_none() => {
                at = Some(i);
                i += 1;
            }
            b'\\'
                if i + 3 < stem.len()
                    && stem[i + 1] == b'x'
                    && stem[i + 2].is_ascii_hexdigit()
                    && stem[i + 3].is_ascii_hexdigit() =>
            {
                i += 4;
            }
            c if c.is_ascii_alphanumeric() || matches!(c, b':' | b'_' | b'.' | b'-') => i += 1,
            _ => return false,
        }
    }
    !matches!(at, Some(0)) && !at.is_some_and(|n| n + 1 == stem.len())
}
impl Request {
    pub fn validate(&self) -> io::Result<()> {
        let mut names = HashSet::new();
        if self.policy_sha256 != policy_sha256()
            || self.targets.is_empty()
            || self.targets.len() > 64
            || self.targets.iter().any(|t| {
                destination(&t.unit).is_err()
                    || !names.insert(&t.unit)
                    || t.existing
                        .as_ref()
                        .is_some_and(|e| e.contents.len() as u64 > MAX_EXISTING)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid producer targets or reviewed file",
            ));
        }
        Ok(())
    }
}
pub fn destination(unit: &str) -> io::Result<PathBuf> {
    // The required .d directory must also fit a filesystem component.
    if !valid_unit(unit) || unit.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid or too-long concrete service destination",
        ));
    }
    Ok(Path::new("/etc/systemd/system")
        .join(format!("{unit}.d"))
        .join(FILE))
}
fn directory(path: &Path) -> io::Result<()> {
    host::trusted_ancestry(path)?;
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe systemd drop-in directory",
        ));
    }
    Ok(())
}
pub fn inspect(unit: &str) -> io::Result<Option<Existing>> {
    let path = destination(unit)?;
    let dir = path.parent().unwrap();
    match directory(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    snapshot(&path)
}
fn snapshot(path: &Path) -> io::Result<Option<Existing>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || m.len() > MAX_EXISTING
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe or oversized existing drop-in",
        ));
    }
    let mut contents = Vec::new();
    file.take(MAX_EXISTING + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_EXISTING {
        return Err(io::Error::other("existing drop-in grew during review"));
    }
    Ok(Some(Existing {
        device: m.dev(),
        inode: m.ino(),
        owner: m.uid(),
        group: m.gid(),
        mode: m.mode() & 0o7777,
        contents,
    }))
}
fn source(reviewed_sha256: &str) -> io::Result<()> {
    let registry = host::installation_registry()?;
    let component = registry
        .current
        .as_ref()
        .and_then(|s| s.components.iter().find(|c| c.component == "deployment"))
        .ok_or_else(|| io::Error::other("installed deployment selection unavailable"))?;
    let path = Path::new("/usr/lib/pico2-kes-agent/components/deployment")
        .join(component.digest.to_string())
        .join("cardano-node-memory-hardening.conf");
    let entry = registry
        .files
        .iter()
        .find(|e| e.path == path && e.component == "deployment")
        .ok_or_else(|| io::Error::other("authenticated producer drop-in unavailable"))?;
    host::trusted_ancestry(&path)?;
    host::check_owned_file(&path, Some(entry))?;
    let bytes = fs::read(path)?;
    if bytes != SOURCE || format!("{:x}", Sha256::digest(&bytes)) != reviewed_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated producer policy differs from reviewed policy",
        ));
    }
    Ok(())
}
fn note(
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    name: &str,
    evidence: String,
) -> io::Result<()> {
    record.checkpoints.push(host::checkpoint(name, evidence));
    store.update(record)
}
fn stage(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    file.write_all(SOURCE)?;
    file.sync_all()?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o644
        || m.len() != SOURCE.len() as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "staged producer file ownership or mode changed",
        ));
    }
    Ok(())
}
fn rollback_race(tmp: &Path, path: &Path) -> io::Result<()> {
    let a = CString::new(tmp.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let b = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn publish(target: &Target, operation: &str) -> io::Result<String> {
    let path = destination(&target.unit)?;
    let dir = path.parent().unwrap();
    match directory(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if target.existing.is_some() {
                return Err(io::Error::other("reviewed directory disappeared"));
            }
            fs::DirBuilder::new().mode(0o755).create(dir)?;
            directory(dir)?;
            File::open(dir.parent().unwrap())?.sync_all()?;
        }
        Err(e) => return Err(e),
    }
    if snapshot(&path)? != target.existing {
        return Err(io::Error::other("destination changed since review"));
    }
    if target
        .existing
        .as_ref()
        .is_some_and(|e| e.contents == SOURCE && e.owner == 0 && e.group == 0 && e.mode == 0o644)
    {
        return Ok("already installed unchanged".into());
    }
    let tmp = dir.join(format!(".pico2-kes-{operation}.tmp"));
    stage(&tmp).map_err(|e| {
        io::Error::other(format!(
            "staging failed: {e}; possible staged file retained at {}",
            tmp.display()
        ))
    })?;
    if snapshot(&path)? != target.existing {
        return Err(io::Error::other(format!(
            "destination changed since review; staged file retained at {}",
            tmp.display()
        )));
    }
    let staged =
        snapshot(&tmp)?.ok_or_else(|| io::Error::other("staged producer file disappeared"))?;
    if staged.owner != 0 || staged.group != 0 || staged.mode != 0o644 || staged.contents != SOURCE {
        return Err(io::Error::other(format!(
            "staged file changed; retained at {}",
            tmp.display()
        )));
    }
    let a = CString::new(tmp.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let b = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let flags = if target.existing.is_none() {
        libc::RENAME_NOREPLACE
    } else {
        libc::RENAME_EXCHANGE
    };
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(io::Error::other(format!(
            "publication failed: {}; staged file retained at {}",
            io::Error::last_os_error(),
            tmp.display()
        )));
    }
    if target.existing.is_some() {
        if snapshot(&tmp).ok().flatten() != target.existing {
            let rollback = rollback_race(&tmp, &path);
            let _ = File::open(dir).and_then(|d| d.sync_all());
            return Err(io::Error::other(format!(
                "destination raced; rollback {} and outcome uncertain; both destination and {} retained",
                if rollback.is_ok() {
                    "exchanged paths"
                } else {
                    "failed"
                },
                tmp.display()
            )));
        }
        fs::remove_file(&tmp)?;
    }
    File::open(dir)?.sync_all()?;
    Ok("installed root:root mode 0644".into())
}
fn approved_policy(existing: &Option<Existing>) -> bool {
    existing
        .as_ref()
        .is_some_and(|e| e.contents == SOURCE && e.owner == 0 && e.group == 0 && e.mode == 0o644)
}

fn recovery_destination(original: &Option<Existing>, current: &Option<Existing>) -> bool {
    current == original || approved_policy(current)
}

fn original(
    store: &RecordStore,
    id: &str,
    digest: &str,
) -> io::Result<(MaintenanceRecord, Request)> {
    let id = kes_core::identity::OperationId::parse_hex(id)
        .map_err(|_| io::Error::other("invalid original operation"))?;
    let record = store.load(&id)?.supported()?;
    if record.action != "producer-hardening"
        || record.plan_digest.to_string() != digest
        || host::maintenance_outcome_allows_new_action(&record.outcome)
    {
        return Err(io::Error::other(
            "original producer operation is not pending",
        ));
    }
    let action: host::HostAction = serde_json::from_str(
        record
            .approved_scope
            .first()
            .ok_or_else(|| io::Error::other("missing original approval"))?,
    )
    .map_err(io::Error::other)?;
    let host::HostAction::ProducerHardening { request } = action else {
        return Err(io::Error::other(
            "original approval is not producer hardening",
        ));
    };
    request.validate()?;
    Ok((record, request))
}

struct RecoveryObservation {
    digest: String,
    lines: Vec<String>,
    request: Request,
    states: Vec<String>,
}

fn recovery_observation(
    id: &str,
    digest: &str,
    original: &Request,
) -> io::Result<RecoveryObservation> {
    source(&original.policy_sha256)?;
    let mut request = original.clone();
    let mut states = Vec::new();
    let mut lines = vec![
        format!("Original operation {id}; original plan {digest}; policy SHA-256 {}", original.policy_sha256),
        "Only the original approved destinations and restart approvals are in scope. The original daemon-reload and approved try-restart commands may be repeated; stopped units are never started.".into(),
        "A successful try-restart may have been skipped and does not prove a restart occurred.".into(),
    ];
    for target in &mut request.targets {
        let current = inspect(&target.unit)?;
        if !recovery_destination(&target.existing, &current) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "unapproved change at {}",
                    destination(&target.unit)?.display()
                ),
            ));
        }
        let state = host::service_state(&target.unit)?;
        let description = match &current {
            None => "absent".into(),
            Some(e) => format!(
                "device {} inode {} owner {} group {} mode {:04o} contents {}",
                e.device,
                e.inode,
                e.owner,
                e.group,
                e.mode,
                e.contents
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
        };
        lines.push(format!(
            "{}: {description}; state {state}; original restart approval {}",
            destination(&target.unit)?.display(),
            target.restart
        ));
        target.existing = current;
        states.push(state);
    }
    let encoded = serde_json::to_vec(&(id, digest, &request, &states)).map_err(io::Error::other)?;
    Ok(RecoveryObservation {
        digest: format!("{:x}", Sha256::digest(encoded)),
        lines,
        request,
        states,
    })
}

pub struct ProducerRecoveryReview {
    pub action: host::HostAction,
    pub lines: Vec<String>,
}

pub fn review_recovery(id: &str, digest: &str) -> io::Result<ProducerRecoveryReview> {
    let store = host::existing_record_store()?;
    let (_, request) = original(&store, id, digest)?;
    let observation = recovery_observation(id, digest, &request)?;
    Ok(ProducerRecoveryReview {
        action: host::HostAction::ProducerRecovery {
            operation_id: id.into(),
            original_plan_digest: digest.into(),
            observed_digest: observation.digest,
        },
        lines: observation.lines,
    })
}

pub(super) fn recover(
    id: &str,
    digest: &str,
    observed_digest: &str,
    store: &RecordStore,
) -> io::Result<()> {
    let (mut record, original_request) = original(store, id, digest)?;
    let observation = recovery_observation(id, digest, &original_request)?;
    if observation.digest != observed_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "producer recovery observations changed after review",
        ));
    }
    record.outcome = "uncertain".into();
    note(
        store,
        &mut record,
        "producer-recovery-approved",
        format!("observation {observed_digest}; original plan {digest}"),
    )?;
    let result = apply_inner(
        &observation.request,
        store,
        &mut record,
        Some(&observation.states),
    )?;
    for target in &observation.request.targets {
        if !approved_policy(&inspect(&target.unit)?) {
            return Err(io::Error::other(format!(
                "producer post-check failed: {}",
                target.unit
            )));
        }
        host::service_state(&target.unit)?;
    }
    note(store, &mut record, "producer-recovery-post-check", result)?;
    record.outcome = "completed".into();
    store.update(&record)
}

pub(super) fn apply(
    request: &Request,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
) -> io::Result<String> {
    apply_inner(request, store, record, None)
}

fn apply_inner(
    request: &Request,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    reviewed_states: Option<&[String]>,
) -> io::Result<String> {
    request.validate()?;
    if !rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root required",
        ));
    }
    source(&request.policy_sha256)?;
    let mut outcomes = Vec::new();
    let mut failed = false;
    let mut installed = Vec::new();
    for target in &request.targets {
        let path = destination(&target.unit)?;
        let reviewed = target
            .existing
            .as_ref()
            .map(|e| {
                format!(
                    "dev={} inode={} uid={} gid={} mode={:04o} sha256={:x}",
                    e.device,
                    e.inode,
                    e.owner,
                    e.group,
                    e.mode,
                    Sha256::digest(&e.contents)
                )
            })
            .unwrap_or_else(|| "absent".into());
        let attempt = format!("{}-{}", record.operation_id, record.checkpoints.len());
        let temporary = path
            .parent()
            .unwrap()
            .join(format!(".pico2-kes-{attempt}.tmp"));
        note(
            store,
            record,
            "producer-file-starting",
            format!(
                "{}; reviewed {reviewed}; possible staging path {}",
                path.display(),
                temporary.display()
            ),
        )?;
        let mut retained = RetainedDestination {
            unit: target.unit.clone(),
            path: path.clone(),
            policy_sha256: request.policy_sha256.clone(),
            owner: 0,
            group: 0,
            mode: 0o644,
            outcome: "possible".into(),
        };
        note(
            store,
            record,
            "producer-retained",
            serde_json::to_string(&retained).map_err(io::Error::other)?,
        )?;
        let result = publish(target, &attempt);
        installed.push(result.is_ok());
        if result.is_ok() {
            retained.outcome = "installed".into();
            note(
                store,
                record,
                "producer-retained",
                serde_json::to_string(&retained).map_err(io::Error::other)?,
            )?;
        }
        let outcome = match result {
            Ok(s) => s,
            Err(e) => {
                failed = true;
                format!("FAILED or uncertain: {e}")
            }
        };
        let line = format!("{}: {outcome}", path.display());
        note(store, record, "producer-file", line.clone())?;
        outcomes.push(line);
    }
    if reviewed_states.is_some() {
        for target in &request.targets {
            if !approved_policy(&inspect(&target.unit)?) {
                return Err(io::Error::other(format!(
                    "producer file changed before reload: {}",
                    target.unit
                )));
            }
        }
    }
    note(
        store,
        record,
        "producer-reload-starting",
        "systemctl daemon-reload".into(),
    )?;
    let reload = host::systemctl(&["daemon-reload"]);
    let reload_ok = reload.as_ref().is_ok_and(|o| o.status.success());
    if !reload_ok {
        failed = true;
    }
    let line = match reload {
        Ok(o) => format!("daemon-reload exit: {}", o.status),
        Err(e) => format!("daemon-reload failed: {e}"),
    };
    note(store, record, "producer-reload", line.clone())?;
    outcomes.push(line);
    for (index, (target, installed)) in request.targets.iter().zip(installed).enumerate() {
        let state = host::service_state(&target.unit);
        let line = match state {
            Ok(s) if reviewed_states.is_some_and(|states| states[index] != s) => {
                failed = true;
                format!(
                    "{}: state changed to {s} since recovery review; not restarted",
                    target.unit
                )
            }
            Ok(s) if target.restart && s == "active" && reload_ok && installed => {
                note(
                    store,
                    record,
                    "producer-restart-starting",
                    target.unit.clone(),
                )?;
                match host::systemctl(&["try-restart", "--", &target.unit]) {
                    Ok(o) if o.status.success() => format!(
                        "{}: try-restart exit {}; may have been skipped if unit stopped",
                        target.unit, o.status
                    ),
                    Ok(o) => {
                        failed = true;
                        format!("{}: restart FAILED exit {}", target.unit, o.status)
                    }
                    Err(e) => {
                        failed = true;
                        format!("{}: restart FAILED: {e}", target.unit)
                    }
                }
            }
            Ok(s) => format!(
                "{}: state {s}; not restarted; policy applies on next start/restart",
                target.unit
            ),
            Err(e) => {
                failed = true;
                format!("{}: state query FAILED: {e}; not restarted", target.unit)
            }
        };
        note(store, record, "producer-service", line.clone())?;
        outcomes.push(line);
    }
    let result = outcomes.join("; ");
    if failed {
        Err(io::Error::other(result))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_accepts_only_original_or_exact_approved_policy() {
        let original = Some(Existing {
            device: 1,
            inode: 2,
            owner: 0,
            group: 0,
            mode: 0o644,
            contents: b"old".to_vec(),
        });
        let mut installed = original.clone().unwrap();
        installed.inode = 3;
        installed.contents = SOURCE.to_vec();
        assert!(recovery_destination(&original, &original));
        assert!(recovery_destination(&original, &Some(installed.clone())));
        assert!(recovery_destination(&None, &None));
        assert!(!recovery_destination(&original, &None));
        installed.group = 1;
        assert!(!recovery_destination(&original, &Some(installed.clone())));
        installed.group = 0;
        installed.contents.push(0);
        assert!(!recovery_destination(&original, &Some(installed)));
    }
    #[test]
    fn concrete_names_and_paths() {
        for name in [
            "cardano-node.service",
            "node@pool.service",
            r"node@pool\x2d1.service",
        ] {
            assert!(valid_unit(name));
            assert!(
                destination(name)
                    .unwrap()
                    .starts_with("/etc/systemd/system")
            );
        }
        for name in [
            "",
            ".service",
            "@x.service",
            "node@.service",
            "node@@x.service",
            "-node.service",
            "../node.service",
            "a/b.service",
            "a\n.service",
            r"a\x2.service",
            "node.socket",
        ] {
            assert!(!valid_unit(name), "{name}");
        }
        assert!(valid_unit(&format!("{}.service", "a".repeat(245))));
        assert!(valid_unit(&format!("{}.service", "a".repeat(247))));
        assert!(destination(&format!("{}.service", "a".repeat(247))).is_err());
        assert!(!valid_unit(&format!("{}.service", "a".repeat(248))));
        assert!(
            Request {
                policy_sha256: policy_sha256(),
                targets: vec![]
            }
            .validate()
            .is_err()
        );
        assert!(
            Request {
                policy_sha256: policy_sha256(),
                targets: (0..65)
                    .map(|i| Target {
                        unit: format!("n{i}.service"),
                        existing: None,
                        restart: false
                    })
                    .collect()
            }
            .validate()
            .is_err()
        );
        let mut request = Request {
            policy_sha256: policy_sha256(),
            targets: vec![Target {
                unit: "node.service".into(),
                existing: None,
                restart: false,
            }],
        };
        assert!(request.validate().is_ok());
        request.policy_sha256 = "0".repeat(64);
        assert!(request.validate().is_err());
    }
    #[test]
    fn raced_rollback_retains_displaced_file() {
        let dir =
            std::env::temp_dir().join(format!("p2kesup-producer-race-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let destination = dir.join("destination");
        let temporary = dir.join("temporary");
        fs::write(&temporary, b"first concurrent edit").unwrap();
        fs::write(&destination, b"second concurrent edit").unwrap();
        rollback_race(&temporary, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"first concurrent edit");
        assert_eq!(fs::read(&temporary).unwrap(), b"second concurrent edit");
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn stage_sets_root_group_under_setgid_parent() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("p2kesup-producer-stage-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let dir_name = CString::new(dir.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(dir_name.as_ptr(), 0, 1) }, 0);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o2755)).unwrap();
        let path = dir.join("staged");
        stage(&path).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
            (0, 0, 0o644)
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
