//! Reviewed removal of registered host files; operator and device state is retained.
use super::{
    host::{self, HostAction, ServiceAction},
    model::{
        INSTALLATION_REGISTRY, InstallationRegistry, InstallationRole, MaintenanceRecord,
        ManagedFile,
    },
    producer,
    records::RecordStore,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const ROOT: &str = "/usr/lib/pico2-kes-agent";
const NAMES: &[&str] = &["manager", "daemon", "cli", "firmware", "tool", "deployment"];

pub struct UninstallReview {
    pub action: HostAction,
    pub paths: Vec<PathBuf>,
    pub details: Vec<String>,
    pub retained: Vec<String>,
}

struct Removal {
    files: Vec<ManagedFile>,
    links: BTreeMap<PathBuf, PathBuf>,
    directories: Vec<PathBuf>,
    full: bool,
}
fn denied(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}
fn component(file: &ManagedFile) -> Option<&str> {
    let root = Path::new(ROOT).join("components");
    if let Ok(relative) = file.path.strip_prefix(root) {
        return relative
            .components()
            .next()?
            .as_os_str()
            .to_str()
            .filter(|name| NAMES.contains(name));
    }
    (file.component == "deployment"
        && matches!(
            file.path.to_str(),
            Some(
                "/usr/libexec/pico2-kes-agent-host-check"
                    | "/usr/lib/systemd/system/pico2-kes-agentd.service"
                    | "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules"
            )
        ))
    .then_some("deployment")
}
fn dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(denied(format!("unsafe directory: {}", path.display())));
    }
    Ok(())
}
fn check_link(path: &Path, target: &Path) -> io::Result<()> {
    host::trusted_ancestry(path)?;
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_symlink() || m.uid() != 0 || fs::read_link(path)? != target {
        return Err(denied(format!("managed link changed: {}", path.display())));
    }
    Ok(())
}
fn check_tree(path: &Path, files: &[ManagedFile]) -> io::Result<()> {
    dir(path)?;
    for item in fs::read_dir(path)? {
        let path = item?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            if !files.iter().any(|f| f.path.starts_with(&path)) {
                return Err(denied(format!(
                    "external directory collision: {}",
                    path.display()
                )));
            }
            check_tree(&path, files)?;
        } else if !metadata.is_file() || !files.iter().any(|f| f.path == path) {
            return Err(denied(format!(
                "external installation collision: {}",
                path.display()
            )));
        }
    }
    Ok(())
}
fn inventory(registry: &InstallationRegistry, selected: &[String]) -> io::Result<Removal> {
    let wanted: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
    if wanted.is_empty()
        || wanted.len() != selected.len()
        || wanted.iter().any(|n| !NAMES.contains(n))
    {
        return Err(denied("invalid or duplicate component selection"));
    }
    let installed: BTreeSet<&str> = registry.files.iter().filter_map(component).collect();
    if !wanted.is_subset(&installed) {
        return Err(denied("selected component has no registered files"));
    }
    if registry
        .files
        .iter()
        .any(|f| component(f).is_none() && !f.path.starts_with("/etc/systemd/system"))
    {
        return Err(denied("unrecognized registered installation file"));
    }
    let full = wanted == installed;
    let mut files = Vec::new();
    for f in &registry.files {
        if component(f).is_some_and(|n| wanted.contains(n)) {
            if f.owner != 0 || f.group != 0 || f.mode & 0o022 != 0 {
                return Err(denied("unsafe registered ownership"));
            }
            host::trusted_ancestry(&f.path)?;
            host::check_owned_file(&f.path, Some(f))?;
            files.push(f.clone());
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    for name in &wanted {
        let path = Path::new(ROOT).join("components").join(name);
        if files.iter().any(|f| f.path.starts_with(&path)) {
            check_tree(&path, &files)?;
        }
    }
    if wanted.contains("daemon") || wanted.contains("deployment") {
        for path in [
            "/etc/systemd/system/multi-user.target.wants/pico2-kes-agentd.service",
            "/etc/systemd/system/default.target.wants/pico2-kes-agentd.service",
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(denied(format!(
                        "external service enablement collision: {path}"
                    )));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    let mut links = BTreeMap::new();
    for (name, binary) in [
        ("manager", "p2kesup"),
        ("daemon", "pico2-kes-agentd"),
        ("cli", "pico2-kes-agent-cli"),
    ] {
        if wanted.contains(name) {
            host::trusted_component(name, binary)?;
            let path = Path::new("/usr/bin").join(binary);
            let target = Path::new(ROOT).join("current").join(name).join(binary);
            check_link(&path, &target)?;
            links.insert(path, target);
        }
    }
    let generations = Path::new(ROOT).join("generations");
    dir(&generations)?;
    for item in fs::read_dir(&generations)? {
        let generation = item?.path();
        dir(&generation)?;
        for item in fs::read_dir(&generation)? {
            let item = item?;
            let path = item.path();
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| denied("invalid generation component name"))?;
            if !wanted.contains(name) {
                continue;
            }
            let target = fs::read_link(&path)?;
            let base = Path::new(ROOT).join("components").join(name);
            let relative = target
                .strip_prefix(&base)
                .map_err(|_| denied("generation target outside component"))?;
            if relative.components().count() != 1
                || !registry
                    .files
                    .iter()
                    .any(|f| f.path.starts_with(&target) && component(f) == Some(name))
            {
                return Err(denied("unregistered generation target"));
            }
            check_link(&path, &target)?;
            links.insert(path, target);
        }
    }
    if full {
        let path = Path::new(ROOT).join("current");
        let target = fs::read_link(&path)?;
        let mut parts = target.components();
        if parts.next() != Some(std::path::Component::Normal("generations".as_ref()))
            || !matches!(parts.next(), Some(std::path::Component::Normal(_)))
            || parts.next().is_some()
        {
            return Err(denied("unsafe current generation pointer"));
        }
        check_link(&path, &target)?;
        links.insert(path, target);
    }
    // Never walk or delete retained authenticated source trees or unregistered files.
    let mut directories = BTreeSet::new();
    for path in files.iter().map(|f| &f.path).chain(links.keys()) {
        if path.starts_with(ROOT) {
            let mut parent = path.parent();
            while let Some(p) = parent {
                if p == Path::new(ROOT) {
                    break;
                }
                dir(p)?;
                directories.insert(p.to_path_buf());
                parent = p.parent();
            }
        }
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    Ok(Removal {
        files,
        links,
        directories,
        full,
    })
}
fn hash_inventory(
    registry_digest: &str,
    files: &[ManagedFile],
    links: &BTreeMap<PathBuf, PathBuf>,
) -> io::Result<String> {
    let mut hash = Sha256::new();
    hash.update(registry_digest.as_bytes());
    hash.update(serde_json::to_vec(files).map_err(io::Error::other)?);
    for (path, target) in links {
        hash.update(path.as_os_str().as_encoded_bytes());
        hash.update([0]);
        hash.update(target.as_os_str().as_encoded_bytes());
        hash.update([0]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn inventory_digest(removal: &Removal) -> io::Result<String> {
    hash_inventory(&host::registry_digest()?, &removal.files, &removal.links)
}
fn service_needed(registry: &InstallationRegistry, selected: &[String]) -> bool {
    registry.role == InstallationRole::Primary
        && selected.iter().any(|s| s == "daemon" || s == "deployment")
}
fn service_review(
    registry: &InstallationRegistry,
    selected: &[String],
    stop: bool,
) -> io::Result<Option<String>> {
    if !service_needed(registry, selected) {
        if stop {
            return Err(denied("service stop is not relevant to this selection"));
        }
        return Ok(None);
    }
    if host::service_state("pico2-kes-agent-commission.service")? != "inactive" {
        return Err(denied("stop commissioning before removing the agent"));
    }
    match fs::symlink_metadata("/run/systemd/system/pico2-kes-agent-commission.service") {
        Ok(_) => {
            return Err(denied(
                "remove the restricted commissioning service separately first",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let unit = Path::new("/usr/lib/systemd/system/pico2-kes-agentd.service");
    if !registry.files.iter().any(|f| f.path == unit) {
        for path in [
            unit,
            Path::new("/etc/systemd/system/pico2-kes-agentd.service"),
            Path::new("/run/systemd/system/pico2-kes-agentd.service"),
            Path::new("/etc/systemd/system/pico2-kes-agentd.service.d"),
            Path::new("/run/systemd/system/pico2-kes-agentd.service.d"),
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(denied(format!(
                        "external service collision: {}",
                        path.display()
                    )));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let state = host::service_state("pico2-kes-agentd.service")?;
        if state != "inactive" && state != "failed" {
            return Err(denied("unregistered service is not stopped"));
        }
        return Ok(Some(format!("unit-absent;state={state}")));
    }
    let token = host::observed_service_state(false)?;
    if token.starts_with("state=active;") && !stop {
        return Err(denied(
            "active managed service requires explicit stop approval",
        ));
    }
    Ok(Some(token))
}
/// Review only explicitly selected installed components and exact ownership evidence.
pub fn review_uninstall(
    mut selected: Vec<String>,
    stop_service: bool,
) -> io::Result<UninstallReview> {
    selected.sort();
    let registry = host::installation_registry()?;
    let removal = inventory(&registry, &selected)?;
    let expected_service_state = service_review(&registry, &selected, stop_service)?;
    let store = host::existing_record_store()?;
    let mut retained = vec![
        "/etc/pico2-kes-agent (configuration and identity/pin)".into(),
        "/var/lib/pico2-kes-agent (journal, receipts and state)".into(),
        "/var/lib/p2kesup (maintenance, OTP and firmware records)".into(),
        format!("{ROOT}/sources (retained source material; not removed or reverified here)"),
        "user XDG state and receipt references".into(),
        "service user and group".into(),
        "all device storage".into(),
        "all producer drop-ins and services".into(),
    ];
    for item in producer::retained_destinations(&store)? {
        retained.push(format!(
            "producer {}: {} sha256={} owner={}:{} mode={:04o} outcome={}",
            item.unit,
            item.path.display(),
            item.policy_sha256,
            item.owner,
            item.group,
            item.mode,
            item.outcome
        ));
    }
    retained.extend(
        registry
            .files
            .iter()
            .filter(|f| f.path.starts_with("/etc/systemd/system"))
            .map(|f| {
                format!(
                    "registered retained file {} sha256={} owner={}:{} mode={:04o}",
                    f.path.display(),
                    f.digest,
                    f.owner,
                    f.group,
                    f.mode
                )
            }),
    );
    let mut paths: Vec<_> = removal
        .files
        .iter()
        .map(|f| f.path.clone())
        .chain(removal.links.keys().cloned())
        .chain(removal.directories.iter().cloned())
        .collect();
    paths.sort();
    let mut details: Vec<_> = removal
        .files
        .iter()
        .map(|f| {
            format!(
                "{} sha256={} owner={}:{} mode={:04o}",
                f.path.display(),
                f.digest,
                f.owner,
                f.group,
                f.mode
            )
        })
        .collect();
    details.extend(
        removal
            .links
            .iter()
            .map(|(p, t)| format!("{} -> {} owner=0", p.display(), t.display())),
    );
    details.extend(
        removal
            .directories
            .iter()
            .map(|path| format!("remove directory if empty: {}", path.display())),
    );
    retained.extend(
        registry
            .preserved_paths
            .iter()
            .map(|path| path.display().to_string()),
    );
    details.push(format!("Update registry {INSTALLATION_REGISTRY}; signed selection provenance remains unchanged, removed files are no longer registered"));
    let digest = inventory_digest(&removal)?;
    Ok(UninstallReview {
        action: HostAction::Uninstall {
            selected_components: selected,
            registry_digest: digest,
            expected_service_state,
            stop_service,
        },
        paths,
        details,
        retained,
    })
}

pub(super) fn uninstall(
    selected: &[String],
    expected_registry: &str,
    expected_service: Option<&str>,
    stop_service: bool,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    let mut registry = host::installation_registry()?;
    let removal = inventory(&registry, selected)?;
    let registry_raw_digest = host::registry_digest()?;
    if hash_inventory(&registry_raw_digest, &removal.files, &removal.links)? != expected_registry {
        return Err(denied("removal inventory changed after approval"));
    }
    if service_review(&registry, selected, stop_service)?.as_deref() != expected_service {
        return Err(denied("service identity changed after review"));
    }
    let evidence = serde_json::to_string(&serde_json::json!({
        "registry": &registry,
        "files": &removal.files,
        "links": removal.links.iter().collect::<Vec<_>>(),
        "full": removal.full,
        "registry_raw_digest": registry_raw_digest,
        "approved_inventory_digest": expected_registry,
    }))
    .map_err(io::Error::other)?;
    record
        .checkpoints
        .push(host::checkpoint("removal-inventory", evidence));
    store.update(record)?;
    if let Some(expected) = expected_service
        && expected.starts_with("state=active;")
    {
        host::run_service(ServiceAction::Stop, expected, effects)?;
        record.checkpoints.push(host::checkpoint(
            "service-quiesced",
            "approved managed service stopped".into(),
        ));
        store.update(record)?;
    }
    // Publish ownership change before unlinking: interruption must not claim absent files remain installed.
    *effects = true;
    registry
        .files
        .retain(|f| !removal.files.iter().any(|removed| removed.path == f.path));
    let bytes = serde_json::to_vec_pretty(&registry).map_err(io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("registry too large"));
    }
    let temp = Path::new("/var/lib/p2kesup").join(format!(".uninstall-{}", record.operation_id));
    crate::files::publish_no_clobber(&temp, &bytes, 0o644)?;
    fs::rename(temp, INSTALLATION_REGISTRY)?;
    File::open("/var/lib/p2kesup")?.sync_all()?;
    record.checkpoints.push(host::checkpoint(
        "ownership-updated",
        "registry no longer claims selected files".into(),
    ));
    store.update(record)?;
    for (path, target) in &removal.links {
        check_link(path, target)?;
        fs::remove_file(path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
        record.checkpoints.push(host::checkpoint(
            "removed-managed-link",
            path.display().to_string(),
        ));
        store.update(record)?;
    }
    for entry in &removal.files {
        host::trusted_ancestry(&entry.path)?;
        host::check_owned_file(&entry.path, Some(entry))?;
        fs::remove_file(&entry.path)?;
        File::open(entry.path.parent().unwrap())?.sync_all()?;
        record.checkpoints.push(host::checkpoint(
            "removed-managed-file",
            entry.path.display().to_string(),
        ));
        store.update(record)?;
    }
    for path in &removal.directories {
        match fs::remove_dir(path) {
            Ok(()) => File::open(path.parent().unwrap())?.sync_all()?,
            Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
            Err(e) => return Err(e),
        }
    }
    if registry.role == InstallationRole::Primary && selected.iter().any(|s| s == "deployment") {
        if !host::systemctl(&["daemon-reload"])?.status.success() {
            return Err(io::Error::other("systemd reload after removal failed"));
        }
        let udev = if Path::new("/usr/bin/udevadm").exists() {
            "/usr/bin/udevadm"
        } else {
            "/usr/sbin/udevadm"
        };
        host::fixed_command(udev, &["control", "--reload-rules"])?;
    }
    Ok("selected registered host components removed; retained state and source material preserved; removal is not secure erasure or revocation".into())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalInventory {
    registry: InstallationRegistry,
    files: Vec<ManagedFile>,
    links: Vec<(PathBuf, PathBuf)>,
    full: bool,
    registry_raw_digest: String,
    approved_inventory_digest: String,
}

/// A missing path is an observation, not evidence that this operation removed it.
pub fn observe_recovery_file(entry: &ManagedFile) -> io::Result<bool> {
    match fs::symlink_metadata(&entry.path) {
        Ok(_) => {
            host::check_owned_file(&entry.path, Some(entry))?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn trusted_existing_parent(path: &Path) -> io::Result<()> {
    let mut parent = path.parent().ok_or_else(|| denied("path has no parent"))?;
    loop {
        match fs::symlink_metadata(parent) {
            Ok(_) => {
                host::trusted_ancestry(&parent.join("entry"))?;
                dir(parent)?;
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                parent = parent
                    .parent()
                    .ok_or_else(|| denied("no existing ancestor"))?
            }
            Err(e) => return Err(e),
        }
    }
}

fn original(
    store: &RecordStore,
    id: &str,
    digest: &str,
    completed: bool,
) -> io::Result<(MaintenanceRecord, OriginalInventory, Vec<String>)> {
    let id = kes_core::identity::OperationId::parse_hex(id)
        .map_err(|_| denied("invalid original operation"))?;
    let record = store.load(&id)?.supported()?;
    if record.action != "uninstall"
        || record.plan_digest.to_string() != digest
        || (completed && record.outcome != "completed")
        || (!completed
            && matches!(
                record.outcome.as_str(),
                "completed" | "cancelled" | "failed-known"
            ))
    {
        return Err(denied("original uninstall is not in the required state"));
    }
    let action: HostAction = serde_json::from_str(
        record
            .approved_scope
            .first()
            .ok_or_else(|| denied("missing original approval"))?,
    )
    .map_err(io::Error::other)?;
    let HostAction::Uninstall {
        selected_components,
        registry_digest,
        ..
    } = action
    else {
        return Err(denied("original action is not uninstall"));
    };
    let mut checkpoints = record
        .checkpoints
        .iter()
        .filter(|c| c.name == "removal-inventory");
    let evidence: OriginalInventory = serde_json::from_str(
        &checkpoints
            .next()
            .ok_or_else(|| denied("original removal inventory missing"))?
            .evidence,
    )
    .map_err(io::Error::other)?;
    if checkpoints.next().is_some() {
        return Err(denied("ambiguous original inventory"));
    }
    let links: BTreeMap<_, _> = evidence.links.iter().cloned().collect();
    if links.len() != evidence.links.len()
        || evidence.approved_inventory_digest != registry_digest
        || hash_inventory(&evidence.registry_raw_digest, &evidence.files, &links)?
            != registry_digest
    {
        return Err(denied("original inventory does not match approval"));
    }
    let selected: BTreeSet<_> = selected_components.iter().map(String::as_str).collect();
    let installed: BTreeSet<_> = evidence
        .registry
        .files
        .iter()
        .filter_map(component)
        .collect();
    if selected.len() != selected_components.len()
        || selected.is_empty()
        || !selected.is_subset(&installed)
        || evidence.full != (selected == installed)
        || evidence.files.len()
            != evidence
                .registry
                .files
                .iter()
                .filter(|f| component(f).is_some_and(|n| selected.contains(n)))
                .count()
        || evidence.files.iter().any(|f| {
            !selected.contains(component(f).unwrap_or(""))
                || !evidence.registry.files.iter().any(|original| {
                    serde_json::to_value(original).ok() == serde_json::to_value(f).ok()
                })
        })
    {
        return Err(denied(
            "original inventory differs from registered selection",
        ));
    }
    Ok((record, evidence, selected_components))
}

fn post_registry(evidence: &OriginalInventory) -> InstallationRegistry {
    let mut registry = evidence.registry.clone();
    registry
        .files
        .retain(|f| !evidence.files.iter().any(|removed| removed.path == f.path));
    registry
}
fn same_registry(a: &InstallationRegistry, b: &InstallationRegistry) -> io::Result<bool> {
    Ok(serde_json::to_value(a).map_err(io::Error::other)?
        == serde_json::to_value(b).map_err(io::Error::other)?)
}

struct RecoveryObservation {
    digest: String,
    lines: Vec<String>,
    original_registry: bool,
}
fn recovery_observation(
    evidence: &OriginalInventory,
    selected: &[String],
) -> io::Result<RecoveryObservation> {
    let registry = host::installation_registry()?;
    let previous = same_registry(&registry, &evidence.registry)?;
    if !previous && !same_registry(&registry, &post_registry(evidence))? {
        return Err(denied(
            "registry differs from both original and recorded removal",
        ));
    }
    let mut lines = vec![format!(
        "Registry: {}",
        if previous {
            "original ownership still recorded"
        } else {
            "selected ownership removed"
        }
    )];
    let mut hash = Sha256::new();
    hash.update(host::registry_digest()?.as_bytes());
    if service_needed(&evidence.registry, selected) {
        let commission = host::service_state("pico2-kes-agent-commission.service")?;
        let state = host::service_state("pico2-kes-agentd.service")?;
        if commission != "inactive" || !matches!(state.as_str(), "inactive" | "failed") {
            return Err(denied(
                "recovery never stops a service; stop affected agent and commissioning separately",
            ));
        }
        for path in [
            "/etc/systemd/system/pico2-kes-agentd.service",
            "/run/systemd/system/pico2-kes-agentd.service",
            "/etc/systemd/system/pico2-kes-agentd.service.d",
            "/run/systemd/system/pico2-kes-agentd.service.d",
            "/run/systemd/system/pico2-kes-agent-commission.service",
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => return Err(denied(format!("service collision: {path}"))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        hash.update(state.as_bytes());
        hash.update(commission.as_bytes());
        lines.push(format!(
            "Agent service {state}; commissioning {commission}; recovery will not stop either"
        ));
    }
    for f in &evidence.files {
        trusted_existing_parent(&f.path)?;
        let present = observe_recovery_file(f)?;
        hash.update(f.path.as_os_str().as_encoded_bytes());
        hash.update([present as u8]);
        lines.push(format!(
            "{}: {} sha256={} owner={}:{} mode={:04o}",
            f.path.display(),
            if present {
                "verified remaining; remove"
            } else {
                "already absent; cause unknown"
            },
            f.digest,
            f.owner,
            f.group,
            f.mode
        ));
    }
    for (path, target) in &evidence.links {
        trusted_existing_parent(path)?;
        let present = match fs::symlink_metadata(path) {
            Ok(_) => {
                check_link(path, target)?;
                true
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        };
        hash.update(path.as_os_str().as_encoded_bytes());
        hash.update([present as u8]);
        lines.push(format!(
            "{} -> {}: {}",
            path.display(),
            target.display(),
            if present {
                "verified remaining; remove"
            } else {
                "already absent; cause unknown"
            }
        ));
    }
    Ok(RecoveryObservation {
        digest: format!("{:x}", hash.finalize()),
        lines,
        original_registry: previous,
    })
}

pub struct UninstallRecoveryReview {
    pub action: HostAction,
    pub lines: Vec<String>,
}
pub fn review_uninstall_recovery(
    operation_id: &str,
    original_plan_digest: &str,
) -> io::Result<UninstallRecoveryReview> {
    let store = host::existing_record_store()?;
    let (_, evidence, selected) = original(&store, operation_id, original_plan_digest, false)?;
    let observation = recovery_observation(&evidence, &selected)?;
    Ok(UninstallRecoveryReview {
        action: HostAction::UninstallRecovery {
            operation_id: operation_id.into(),
            original_plan_digest: original_plan_digest.into(),
            observed_digest: observation.digest,
            bootstrap: None,
            bootstrap_manifest_digest: None,
            candidate_accepted: false,
        },
        lines: observation.lines,
    })
}

pub(super) fn recover_uninstall(
    operation_id: &str,
    original_plan_digest: &str,
    observed_digest: &str,
    store: &RecordStore,
) -> io::Result<()> {
    let (mut record, evidence, selected) =
        original(store, operation_id, original_plan_digest, false)?;
    let observation = recovery_observation(&evidence, &selected)?;
    if observation.digest != observed_digest {
        return Err(denied("recovery observations changed after approval"));
    }
    if observation.original_registry {
        let bytes =
            serde_json::to_vec_pretty(&post_registry(&evidence)).map_err(io::Error::other)?;
        let temp = Path::new("/var/lib/p2kesup")
            .join(format!(".uninstall-recovery-{}", record.operation_id));
        crate::files::publish_no_clobber(&temp, &bytes, 0o644)?;
        fs::rename(temp, INSTALLATION_REGISTRY)?;
        File::open("/var/lib/p2kesup")?.sync_all()?;
        record.checkpoints.push(host::checkpoint(
            "ownership-updated",
            "recovery removed selected ownership claims".into(),
        ));
        store.update(&record)?;
    }
    for (path, target) in &evidence.links {
        trusted_existing_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                check_link(path, target)?;
                fs::remove_file(path)?;
                File::open(path.parent().unwrap())?.sync_all()?;
                record.checkpoints.push(host::checkpoint(
                    "removed-managed-link",
                    path.display().to_string(),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => record
                .post_observations
                .push(format!("already absent; cause unknown: {}", path.display())),
            Err(e) => return Err(e),
        }
        store.update(&record)?;
    }
    for file in &evidence.files {
        trusted_existing_parent(&file.path)?;
        if observe_recovery_file(file)? {
            fs::remove_file(&file.path)?;
            File::open(file.path.parent().unwrap())?.sync_all()?;
            record.checkpoints.push(host::checkpoint(
                "removed-managed-file",
                file.path.display().to_string(),
            ));
        } else {
            record.post_observations.push(format!(
                "already absent; cause unknown: {}",
                file.path.display()
            ));
        }
        store.update(&record)?;
    }
    let mut directories = BTreeSet::new();
    for path in evidence
        .files
        .iter()
        .map(|f| &f.path)
        .chain(evidence.links.iter().map(|(path, _)| path))
    {
        if path.starts_with(ROOT) {
            let mut parent = path.parent();
            while let Some(p) = parent {
                if p == Path::new(ROOT) {
                    break;
                }
                directories.insert(p.to_path_buf());
                parent = p.parent();
            }
        }
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for path in directories {
        trusted_existing_parent(&path)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                dir(&path)?;
                match fs::remove_dir(&path) {
                    Ok(()) => File::open(path.parent().unwrap())?.sync_all()?,
                    Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                    Err(e) => return Err(e),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if evidence.registry.role == InstallationRole::Primary
        && selected.iter().any(|s| s == "deployment")
    {
        if !host::systemctl(&["daemon-reload"])?.status.success() {
            return Err(io::Error::other("systemd reload after recovery failed"));
        }
        let udev = if Path::new("/usr/bin/udevadm").exists() {
            "/usr/bin/udevadm"
        } else {
            "/usr/sbin/udevadm"
        };
        host::fixed_command(udev, &["control", "--reload-rules"])?;
    }
    for path in evidence
        .files
        .iter()
        .map(|f| &f.path)
        .chain(evidence.links.iter().map(|(path, _)| path))
    {
        trusted_existing_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(denied(format!(
                    "removed path reappeared: {}",
                    path.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    record.checkpoints.push(host::checkpoint(
        "post-check",
        "original removal reconciled; absent paths do not prove who removed them".into(),
    ));
    record.outcome = "completed".into();
    store.update(&record)
}

/// A completed full removal and unchanged registry prove only retained installation provenance.
pub(super) fn retained_installation(
    store: &RecordStore,
    registry: &InstallationRegistry,
) -> io::Result<bool> {
    for entry in store.list()? {
        let record = match entry {
            super::records::Record::Supported(record) => record,
            super::records::Record::Unknown(_) => {
                return Err(denied("unknown maintenance record schema"));
            }
        };
        if record.action != "uninstall" || record.outcome != "completed" {
            continue;
        }
        let (_, evidence, _) = original(
            store,
            &record.operation_id.to_string(),
            &record.plan_digest.to_string(),
            true,
        )?;
        if !evidence.full || !same_registry(registry, &post_registry(&evidence))? {
            continue;
        }
        for path in evidence
            .files
            .iter()
            .map(|f| &f.path)
            .chain(evidence.links.iter().map(|(path, _)| path))
        {
            trusted_existing_parent(path)?;
            match fs::symlink_metadata(path) {
                Ok(_) => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        return Ok(true);
    }
    Ok(false)
}
