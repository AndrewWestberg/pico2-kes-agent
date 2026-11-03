use super::{foreground, public_fields, review, setup};
use crate::manager::{
    host::{self, HostAction},
    model::{InstallationRegistry, InstallationRole, Qualification},
    observe::{Snapshot, Worker},
    release::{self, Admission, VerifiedBundle},
    release_discovery::{self, Offer},
    terminal::TerminalOwner,
};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Browse,
    Refresh,
    Prerelease,
    Offline,
    Select,
    FirmwarePreview,
    FirmwareUpdate,
    Inspect,
    RecoverFirmware,
    Fallback,
    Reexec,
    Remove,
}
pub(super) const PRIMARY_ACTIONS: &[Action] = &[
    Action::Browse,
    Action::Refresh,
    Action::Prerelease,
    Action::Offline,
    Action::Select,
    Action::FirmwarePreview,
    Action::FirmwareUpdate,
    Action::Inspect,
    Action::RecoverFirmware,
    Action::Fallback,
    Action::Reexec,
    Action::Remove,
];
pub(super) const BACKUP_ACTIONS: &[Action] = &[
    Action::Browse,
    Action::Refresh,
    Action::Prerelease,
    Action::Offline,
    Action::Select,
    Action::Inspect,
    Action::Fallback,
    Action::Reexec,
    Action::Remove,
];
impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::Browse => "Inspect authenticated release inventory and freshness",
            Self::Refresh => "Refresh qualified releases / reverify offline cache",
            Self::Prerelease => "Toggle signed prerelease opt-in (never candidates)",
            Self::Offline => "Toggle online / offline discovery",
            Self::Select => "Review independent host component versions",
            Self::FirmwarePreview => "Preview authenticated firmware transfer (no writes)",
            Self::FirmwareUpdate => "Review attended pinned firmware update",
            Self::Inspect => "Inspect original host plan (never replay)",
            Self::RecoverFirmware => "Reconcile original firmware update",
            Self::Fallback => "Review original host update / compatible binary fallback",
            Self::Reexec => "Explicitly re-exec installed manager",
            Self::Remove => "Remove one cached release (keep operational records)",
        }
    }
}

pub(super) struct State {
    pub offers: Vec<Offer>,
    pub status: String,
    cache: Option<PathBuf>,
    worker: Option<release_discovery::Worker>,
    prerelease: bool,
    online: bool,
}
impl State {
    pub fn new() -> Self {
        let (cache, status) = match release_discovery::default_cache() {
            Ok(path) => (Some(path), "Release discovery has not completed".into()),
            Err(error) => (None, error.to_string()),
        };
        let mut state = Self {
            offers: Vec::new(),
            status,
            cache,
            worker: None,
            prerelease: false,
            online: true,
        };
        state.refresh();
        state
    }
    pub fn pause(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            worker.stop();
            self.status =
                "Discovery paused; retained offers are not a new freshness reading".into();
        }
    }
    pub fn refresh(&mut self) {
        self.pause();
        let Some(cache) = &self.cache else {
            return;
        };
        match release_discovery::start(cache.clone(), self.prerelease, self.online) {
            Ok(worker) => {
                self.worker = Some(worker);
                self.status = "Checking qualified releases (independent 10-second deadline)".into();
            }
            Err(error) => self.status = error.to_string(),
        }
    }
    pub fn resume(&mut self) {
        if self.worker.is_none() {
            self.refresh();
        }
    }
    pub fn poll(&mut self) -> bool {
        let Some(result) = self.worker.as_mut().and_then(|worker| worker.poll()) else {
            return false;
        };
        self.pause();
        match result {
            Ok(result) => {
                self.offers = result.offers;
                self.status = result.notice.unwrap_or_else(|| "Discovery completed; cache age does not establish current revocation/latest status".into());
            }
            Err(error) => {
                self.status = format!(
                    "Discovery unavailable: {error}; retained offers may be stale. Select offline mode to reverify cache."
                )
            }
        }
        true
    }
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            self.status.clone(),
            format!(
                "Network: {}; prerelease opt-in: {}; candidates are never discovered",
                self.online, self.prerelease
            ),
            Offer::PROVENANCE.into(),
        ];
        for (index, offer) in self.offers.iter().enumerate() {
            lines.push(format!(
                "{}: {} [{}] source={} age={}s manifest={} bundle={}",
                index + 1,
                offer.selection.tag,
                offer.selection.channel,
                offer.source,
                offer.age().as_secs(),
                offer.selection.manifest_digest,
                offer.bundle.display()
            ));
        }
        lines
    }
    pub fn toggle_prerelease(&mut self) {
        self.prerelease = !self.prerelease;
        self.refresh();
    }
    pub fn toggle_offline(&mut self) {
        self.online = !self.online;
        self.refresh();
    }
    pub fn remove(&mut self, terminal: &mut TerminalOwner) -> io::Result<()> {
        let mut lines = self.lines();
        lines.push("Remove only a selected release-cache entry. Installed components, receipts and operational records remain.".into());
        review(terminal, "Release-cache inventory", lines, None)?;
        let Some(values) = public_fields(
            terminal,
            "Remove cached bundle",
            &[("Exact cached manifest digest", "")],
        )?
        else {
            return Ok(());
        };
        if !review(
            terminal,
            "Confirm cache removal",
            vec![
                format!("Manifest {}", values[0]),
                "Offline use of this bundle will require reacquiring authenticated bytes.".into(),
            ],
            Some(&values[0]),
        )? {
            return Ok(());
        }
        self.pause();
        release_discovery::remove(
            self.cache
                .as_deref()
                .ok_or_else(|| io::Error::other("release cache unavailable"))?,
            &values[0],
        )?;
        self.offers
            .retain(|offer| offer.selection.manifest_digest.to_string() != values[0]);
        self.refresh();
        Ok(())
    }
}

fn absolute(value: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        ));
    }
    Ok(path)
}
fn candidate_review(
    terminal: &mut TerminalOwner,
    path: &Path,
    launched: Option<&PathBuf>,
) -> io::Result<bool> {
    if launched.map(PathBuf::as_path) != Some(path) {
        return Ok(false);
    }
    review(terminal, "Explicit disposable candidate acceptance", vec![format!("Only this launched local bundle may introduce candidate components: {}", path.display()), "Signature, exact tuple, persistent-state readability, hardware and independent postchecks remain mandatory. Candidate is not qualified.".into()], Some("DISPOSABLE CANDIDATE"))
}
fn verified(path: &Path, candidate: bool) -> io::Result<VerifiedBundle> {
    release::verify_bundle(
        path,
        if candidate {
            Admission::AttendedCandidate
        } else {
            Admission::Qualified
        },
    )
}

pub(super) fn resume_upgrade_direct(
    terminal: &mut TerminalOwner,
    action: HostAction,
    executable: PathBuf,
    operation: &str,
) -> io::Result<()> {
    let plan = host::HostPlan::new(action)?;
    let mut lines: Vec<String> = serde_json::to_string_pretty(&plan)
        .map_err(io::Error::other)?.lines().map(str::to_owned).collect();
    lines.push("Reconcile only the original operation, without reflashing or rolling back device state. A stopped service may be started temporarily for validation and will be restored to its original state.".into());
    if !review(terminal, "Recover original upgrade", lines, Some(&format!("RECOVER {operation}")))? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "recovery cancelled"));
    }
    let path = release_discovery::default_cache()?.join(format!("upgrade-recovery-plan-{}.json", plan.plan_id));
    crate::files::publish_no_clobber(&path, &serde_json::to_vec(&plan).map_err(io::Error::other)?, 0o600)?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/pkexec");
        command.arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&path);
    let mut worker = None;
    let status = foreground(terminal, &mut worker, Path::new("/run/pico2-kes-agent/management.sock"), &mut command, true)?;
    if !status.success() {
        return Err(io::Error::other(format!("recovery failed or remains uncertain ({status}); retain original operation {operation}")));
    }
    Ok(())
}

pub(super) fn upgrade_direct(
    terminal: &mut TerminalOwner,
    path: PathBuf,
    bundle: VerifiedBundle,
    registry_digest: String,
    registry: InstallationRegistry,
    service: Option<String>,
) -> io::Result<()> {
    let role = registry.role;
    let candidate = bundle.selection().qualification == Qualification::Candidate;
    if candidate && !review(
        terminal,
        "Explicit candidate admission",
        vec!["This signed candidate is not qualified. Proceed only on a disposable host; all state and hardware checks remain mandatory.".into()],
        Some("DISPOSABLE CANDIDATE"),
    )? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "candidate not accepted"));
    }
    let socket = Path::new("/run/pico2-kes-agent/management.sock");
    let mut worker = None;
    let preview = if role == InstallationRole::Primary {
        Some(capture_firmware_review(
            terminal, &mut worker, socket,
            service.as_deref().ok_or_else(|| io::Error::other("service observation unavailable"))?,
        )?.ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "pre-state review cancelled"))?)
    } else {
        None
    };
    let temporary_validation = preview.as_ref().is_some_and(|p| !p.service_state.starts_with("state=active;"));
    let record = if preview.is_some() {
        Some(Path::new("/var/lib/p2kesup/firmware").join(format!("{}.json", new_id()?)))
    } else {
        None
    };
    let action = HostAction::Upgrade {
        bundle: path,
        manifest_digest: bundle.selection().manifest_digest.to_string(),
        candidate_accepted: candidate,
        expected_registry_digest: registry_digest,
        expected_service_state: preview.as_ref().map(|p| p.service_state.clone()).or(service),
        pre_state: preview.as_ref().map(|p| p.evidence.clone()),
        temporary_validation,
        serial: preview.as_ref().map(|p| p.serial.clone()),
        device_id: preview.as_ref().map(|p| p.device_id.clone()),
        identity_public_key: preview.as_ref().map(|p| p.identity_public_key.clone()),
        record,
    };
    let plan = host::HostPlan::new(action)?;
    let cache = release_discovery::default_cache()?;
    let plan_path = cache.join(format!("upgrade-plan-{}.json", plan.plan_id));
    let current = registry.current.as_ref().ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    let mut lines = vec![
        format!("Installed release: {}", current.tag),
        format!("Selected release: {} ({:?}); source {}", bundle.selection().tag, bundle.selection().qualification, bundle.selection().source_commit),
        format!("Installation role: {role:?}"),
    ];
    for next in &bundle.selection().components {
        let previous = current.components.iter().find(|c| c.component == next.component)
            .ok_or_else(|| io::Error::other("installed component missing"))?;
        lines.push(format!("{}: {} -> {}", next.component, previous.version, next.version));
    }
    lines.extend(serde_json::to_string_pretty(&plan).map_err(io::Error::other)?.lines().map(str::to_owned));
    lines.push("The complete signed tuple is installed together. Physical firmware transfer is attended; interrupted operations retain their original record. Device state is never rolled back.".into());
    lines.push(format!("Original plan: {}. If interrupted, use p2kesup upgrade --resume with this path.", plan_path.display()));
    if !review(terminal, "Review complete upgrade", lines, Some("UPGRADE"))? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "upgrade cancelled"));
    }
    crate::files::publish_no_clobber(&plan_path, &serde_json::to_vec(&plan).map_err(io::Error::other)?, 0o600)?;
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/pkexec");
        command.arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&plan_path);
    let status = foreground(terminal, &mut worker, socket, &mut command, true)?;
    if !status.success() {
        return Err(io::Error::other(format!("upgrade failed or was interrupted ({status}); retain original plan {}", plan_path.display())));
    }
    Ok(())
}

pub(super) fn component_update(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    launched: Option<&PathBuf>,
    state: &State,
    snapshot: Option<&Snapshot>,
    role: InstallationRole,
) -> io::Result<()> {
    let (registry_digest, registry, service, retained) = host::update_review()?;
    if registry.role != role {
        return Err(io::Error::other(
            "launch role differs from the managed installation role",
        ));
    }
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    let default = launched
        .map(PathBuf::as_path)
        .or_else(|| state.offers.first().map(|offer| offer.bundle.as_path()))
        .and_then(Path::to_str)
        .unwrap_or("");
    review(
        terminal,
        "Authenticated release inventory",
        state.lines(),
        None,
    )?;
    let Some(values) = public_fields(
        terminal,
        "Select signed compatibility authority and sources",
        &[
            ("Authorizing bundle directory", default),
            (
                "Additional absolute source directories, separated by semicolons (optional)",
                "",
            ),
        ],
    )?
    else {
        return Ok(());
    };
    let authorizing_path = absolute(&values[0])?;
    let mut paths = vec![authorizing_path.clone()];
    for path in retained.into_iter().chain(
        values[1]
            .split(';')
            .filter(|value| !value.is_empty())
            .map(absolute)
            .collect::<io::Result<Vec<_>>>()?,
    ) {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.len() > 16 {
        return Err(io::Error::other(
            "at most 16 authenticated source bundles may be selected",
        ));
    }
    let candidate_source = if let Some(path) = launched.filter(|path| paths.contains(path)) {
        candidate_review(terminal, path, launched)?.then(|| path.clone())
    } else {
        None
    };
    let authorizing = verified(
        &authorizing_path,
        candidate_source.as_ref() == Some(&authorizing_path),
    )?;
    let mut sources = vec![authorizing];
    let mut source_paths = vec![authorizing_path.clone()];
    for path in paths.into_iter().filter(|path| path != &authorizing_path) {
        let installed_source = current.components.iter().any(|component| {
            path == Path::new("/usr/lib/pico2-kes-agent/sources")
                .join(component.manifest_digest.to_string())
        });
        if installed_source {
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
                Ok(_) => {}
            }
        }
        let source = verified(
            &path,
            candidate_source.as_ref() == Some(&path) || installed_source,
        )?;
        if sources.iter().any(|other: &VerifiedBundle| {
            other.selection().manifest_digest == source.selection().manifest_digest
        }) {
            continue;
        }
        source_paths.push(path);
        sources.push(source);
    }
    let mut lines = vec!["Choose one source/version per component. Only an explicitly signed exact tuple is admissible; no semantic-version inference.".into()];
    for (index, source) in sources.iter().enumerate() {
        lines.push(format!(
            "Source {}: {} {:?}, manifest {}",
            index + 1,
            source.selection().tag,
            source.selection().qualification,
            source.selection().manifest_digest
        ));
        for component in &source.selection().components {
            lines.push(format!(
                "  {} {} build={} inventory={} source={}",
                component.component,
                component.version,
                component.build_id,
                component.digest,
                component.source_commit
            ));
        }
    }
    lines.push("An existing candidate component may only carry forward unchanged; changing candidate components requires the explicitly launched bundle.".into());
    review(
        terminal,
        "Deliberate component source selection",
        lines,
        None,
    )?;
    let names = ["manager", "daemon", "cli", "tool", "deployment"];
    let defaults: Vec<String> = names
        .iter()
        .map(|name| {
            current
                .components
                .iter()
                .find(|component| component.component == *name)
                .and_then(|component| {
                    sources.iter().position(|source| {
                        source.selection().manifest_digest == component.manifest_digest
                    })
                })
                .map_or_else(|| "1".into(), |index| (index + 1).to_string())
        })
        .collect();
    let labels: Vec<String> = names
        .iter()
        .map(|name| format!("{name}: source number (1-{})", sources.len()))
        .collect();
    let fields: Vec<(&str, &str)> = labels
        .iter()
        .zip(&defaults)
        .map(|(label, default)| (label.as_str(), default.as_str()))
        .collect();
    let Some(values) = public_fields(terminal, "Select each component independently", &fields)?
    else {
        return Ok(());
    };
    let firmware = current
        .components
        .iter()
        .find(|component| component.component == "firmware")
        .ok_or_else(|| io::Error::other("installed firmware selection unavailable"))?;
    let mut choices =
        BTreeMap::from([("firmware".to_owned(), firmware.manifest_digest.to_string())]);
    for (name, value) in names.iter().zip(values) {
        let index = value
            .parse::<usize>()
            .ok()
            .and_then(|index| index.checked_sub(1))
            .filter(|index| *index < sources.len())
            .ok_or_else(|| io::Error::other("source number is outside the reviewed inventory"))?;
        let source = &sources[index];
        let component = source
            .selection()
            .components
            .iter()
            .find(|component| component.component == *name)
            .ok_or_else(|| io::Error::other("source component missing"))?;
        if source.selection().qualification == Qualification::Candidate
            && candidate_source.as_ref() != Some(&source_paths[index])
            && !current.components.iter().any(|old| {
                old.component == *name
                    && old.digest == component.digest
                    && old.manifest_digest == component.manifest_digest
            })
        {
            return Err(io::Error::other(
                "new candidate component is not from the explicitly accepted launched bundle",
            ));
        }
        choices.insert(
            (*name).to_owned(),
            source.selection().manifest_digest.to_string(),
        );
    }
    let references: Vec<&VerifiedBundle> = sources.iter().collect();
    let selection = release::select_components(&sources[0], &references, &choices)?;
    let mut lines = vec![format!("Current selection: {}", serde_json::to_string(current).map_err(io::Error::other)?), format!("Selected exact tuple: {}", serde_json::to_string(&selection).map_err(io::Error::other)?), format!("Service before: {}", service.as_deref().unwrap_or("backup role: no agent service")), "Host changes preserve configuration, journals, receipts, pins and device storage. Firmware is unchanged; select it through the separate attended firmware workflow.".into(), "The old manager keeps running until an explicitly reviewed re-exec. Stopped services stay stopped.".into()];
    if let Some(snapshot) = snapshot {
        lines.push(format!(
            "Affected managed service pools: membership {:?}, observation age {}s",
            snapshot.membership.state,
            snapshot.captured_at.elapsed().as_secs()
        ));
        lines.extend(snapshot.pools.iter().map(|pool| {
            format!(
                "  {} / {} [{:?}]",
                pool.pool_id, pool.incarnation_id, pool.observation.state
            )
        }));
    } else {
        lines.push("Pool impact is unavailable; any daemon interruption affects all pools served by it, not just a selected row.".into());
    }
    if !review(
        terminal,
        "Version-change impact and preservation",
        lines,
        Some("REVIEW EXACT TUPLE"),
    )? {
        return Ok(());
    }
    let stop_service = if registry.role == InstallationRole::Primary {
        review(terminal, "Daemon interruption approval", vec!["Allow the helper to stop the managed daemon if selected daemon/deployment changes require it? A previously running service is restored only after checks; stopped stays stopped.".into(), "Cancel declines interruption; manager-only changes can still proceed without stopping the daemon.".into()], Some("ALLOW AGENT STOP"))?
    } else {
        false
    };
    let disruptive = registry.role == InstallationRole::Primary
        && selection.components.iter().any(|component| {
            matches!(component.component.as_str(), "daemon" | "deployment")
                && current
                    .components
                    .iter()
                    .find(|old| old.component == component.component)
                    .is_none_or(|old| old.digest != component.digest)
        });
    let (pre_state, temporary_validation) = if disruptive {
        let Some(preview) = capture_firmware_review(
            terminal,
            worker,
            socket,
            service
                .as_deref()
                .ok_or_else(|| io::Error::other("service observation unavailable"))?,
        )?
        else {
            return Ok(());
        };
        let temporary = !preview.service_state.starts_with("state=active;");
        (Some(preview.evidence), temporary)
    } else {
        (None, false)
    };
    setup::apply(
        terminal,
        worker,
        socket,
        HostAction::Update {
            authorizing_bundle: authorizing_path,
            sources: source_paths,
            candidate_source,
            selection,
            expected_registry_digest: registry_digest,
            expected_service_state: service,
            stop_service,
            pre_state,
            temporary_validation,
        },
        None,
    )
}

pub(super) fn reexec(terminal: &mut TerminalOwner) -> io::Result<Option<PathBuf>> {
    let path = host::trusted_manager()?;
    let current = crate::build_info::identity("p2kesup");
    let lines = vec![format!("Running manager: {} build={} source={}", current.version, current.build_id, current.source_commit), format!("Authenticated installed manager: {}", path.display()), "Close this terminal session's workers, restore terminal state, and replace this process with the installed manager. Role, socket and explicit bundle arguments are preserved; candidate approval is not carried into the new session.".into()];
    Ok(review(
        terminal,
        "Explicit manager re-exec",
        lines,
        Some("REEXEC INSTALLED MANAGER"),
    )?
    .then_some(path))
}

fn new_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    use std::fmt::Write;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        write!(&mut id, "{byte:02x}").expect("string write");
    }
    Ok(id)
}

pub(super) fn firmware_preview(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    launched: Option<&PathBuf>,
) -> io::Result<()> {
    let Some((_, bundle, _)) = setup::bundle(terminal, launched)? else {
        return Ok(());
    };
    let Some(values) = public_fields(
        terminal,
        "Firmware transfer preview only",
        &[(
            "Previously pinned application serial (16 lowercase hex)",
            "",
        )],
    )?
    else {
        return Ok(());
    };
    let record = std::env::temp_dir().join(format!("p2kesup-preview-{}.json", new_id()?));
    let mut command = Command::new("/usr/bin/python3");
    command
        .arg("-I")
        .arg(bundle.root().join("tools/firmware.py"))
        .arg("update")
        .arg("--bundle")
        .arg(bundle.root().join("firmware"))
        .arg("--serial")
        .arg(&values[0])
        .arg("--record")
        .arg(record)
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", bundle.root().join("tools").display()),
        )
        .env("LD_LIBRARY_PATH", bundle.root().join("runtime"));
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    review(terminal, "Firmware preview result", vec![format!("Foreground preview exit: {status}"), "No transfer, service change or new firmware record was requested. A supplied serial is not proof of live pin/board identity; apply requires separate protected pre-state and physical attendance.".into()], None)?;
    Ok(())
}

fn root_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    host::trusted_ancestry(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o640
        || metadata.nlink() != 1
        || metadata.len() > 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe protected public review",
        ));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("oversized protected public review"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn capture_firmware_review(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    service: &str,
) -> io::Result<Option<host::FirmwareReview>> {
    let temporary = !service.starts_with("state=active;");
    let mut lines = vec![format!("Observed managed service: {service}"), "Read complete pinned public pre-state through the sole authenticated daemon. No flash, lifecycle mutation or pin replacement is requested.".into()];
    if temporary {
        lines.push("The service is stopped: explicitly permit temporary normal-service start for observation, then restore stopped state. Failure to restore remains an uncertain original record.".into());
    }
    if !review(
        terminal,
        "Protected maintenance pre-state",
        lines,
        Some(if temporary {
            "TEMPORARY AGENT VALIDATION"
        } else {
            "READ PINNED PRESTATE"
        }),
    )? {
        return Ok(None);
    }
    let id = new_id()?;
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/pkexec");
        command.arg(executable);
        command
    };
    command.args(["host-firmware-preview", "--id", &id]);
    if temporary {
        command.args(["--temporary-state", service]);
    }
    let status = foreground(terminal, worker, socket, &mut command, false)?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "protected pre-state helper exited {status}; retain its original record"
        )));
    }
    let path = Path::new("/var/lib/p2kesup/reviews").join(format!("{id}.json"));
    let preview: host::FirmwareReview = root_json(&path)?;
    let mut lines = vec![format!("Protected review: {}", path.display())];
    lines.extend(
        serde_json::to_string_pretty(&preview)
            .map_err(io::Error::other)?
            .lines()
            .map(str::to_owned),
    );
    if !review(
        terminal,
        "Exact pinned maintenance pre-state",
        lines,
        Some(&preview.serial),
    )? {
        return Ok(None);
    }
    Ok(Some(preview))
}

pub(super) fn firmware_update(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    launched: Option<&PathBuf>,
) -> io::Result<()> {
    let Some((path, bundle, candidate_accepted)) = setup::bundle(terminal, launched)? else {
        return Ok(());
    };
    let (_, registry, service, retained) = host::update_review()?;
    if registry.role != InstallationRole::Primary {
        return Err(io::Error::other(
            "firmware update requires a managed primary installation",
        ));
    }
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    let mut sources = Vec::new();
    for source_path in retained {
        let source = verified(&source_path, true)?;
        if source.selection().manifest_digest != bundle.selection().manifest_digest
            && !sources.iter().any(|old: &VerifiedBundle| {
                old.selection().manifest_digest == source.selection().manifest_digest
            })
        {
            sources.push(source);
        }
    }
    let mut references: Vec<&VerifiedBundle> = sources.iter().collect();
    references.push(&bundle);
    let mut choices: BTreeMap<String, String> = current
        .components
        .iter()
        .map(|component| {
            (
                component.component.clone(),
                component.manifest_digest.to_string(),
            )
        })
        .collect();
    choices.insert(
        "firmware".into(),
        bundle.selection().manifest_digest.to_string(),
    );
    let target_selection = release::select_components(&bundle, &references, &choices)?;
    let selected_tool = current
        .components
        .iter()
        .find(|component| component.component == "tool")
        .ok_or_else(|| io::Error::other("installed tool unavailable"))?;
    if !bundle
        .selection()
        .components
        .iter()
        .any(|component| component.component == "tool" && component.digest == selected_tool.digest)
    {
        return Err(io::Error::other(
            "update the authenticated tool separately using an authorized intermediate tuple before firmware transfer",
        ));
    }
    let Some(preview) = capture_firmware_review(
        terminal,
        worker,
        socket,
        service
            .as_deref()
            .ok_or_else(|| io::Error::other("managed service observation unavailable"))?,
    )?
    else {
        return Ok(());
    };
    let temporary_validation = !preview.service_state.starts_with("state=active;");
    let record = Path::new("/var/lib/p2kesup/firmware").join(format!("{}.json", new_id()?));
    let lines = vec![format!("Target selection: {}", serde_json::to_string(&target_selection).map_err(io::Error::other)?), format!("Original transfer record: {}", record.display()), "Approve stopping the managed daemon and direct attended firmware-only transfer. Required hardware/tool/image qualification is checked by the foreground tool. No erase, OTP, re-pin or recommission.".into(), "Copy/flush is not completion: same pin, selected live build/storage and explained forward state are required. Interrupted work reopens its original record; never reflash under a new identity.".into(), format!("Restore prior service state: {}; temporary validation approved: {temporary_validation}", preview.service_state)];
    if !review(
        terminal,
        "Attended existing-device firmware update",
        lines,
        Some(&format!("UPDATE {}", preview.serial)),
    )? {
        return Ok(());
    }
    setup::apply(
        terminal,
        worker,
        socket,
        HostAction::FirmwareUpdate {
            bundle: path,
            manifest_digest: bundle.selection().manifest_digest.to_string(),
            candidate_accepted,
            serial: preview.serial,
            device_id: preview.device_id,
            identity_public_key: preview.identity_public_key,
            record,
            apply: true,
            expected_service_state: preview.service_state,
            pre_state: preview.evidence,
            temporary_validation,
            target_selection,
        },
        None,
    )
}

fn original_record(
    terminal: &mut TerminalOwner,
) -> io::Result<Option<crate::manager::model::MaintenanceRecord>> {
    let Some(values) = public_fields(
        terminal,
        "Reopen original maintenance",
        &[("Original operation ID (32 lowercase hex)", "")],
    )?
    else {
        return Ok(None);
    };
    let id = kes_core::identity::OperationId::parse_hex(&values[0])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid operation ID"))?;
    let path = Path::new("/var/lib/p2kesup/records").join(format!("{id}.json"));
    let record: crate::manager::model::MaintenanceRecord = root_json(&path)?;
    crate::manager::model::require_supported_schema(record.schema_version)
        .map_err(io::Error::other)?;
    if record.operation_id != id {
        return Err(io::Error::other("original record identity mismatch"));
    }
    review(
        terminal,
        "Original maintenance evidence",
        serde_json::to_string_pretty(&record)
            .map_err(io::Error::other)?
            .lines()
            .map(str::to_owned)
            .collect(),
        None,
    )?;
    Ok(Some(record))
}

pub(super) fn recover_firmware(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
) -> io::Result<()> {
    let Some(record) = original_record(terminal)? else {
        return Ok(());
    };
    if record.action != "firmware-update" {
        return Err(io::Error::other("original record is not a firmware update"));
    }
    let Some(values) = public_fields(
        terminal,
        "Accounted lifecycle transitions",
        &[(
            "Original reconciliable receipt paths, separated by semicolons (optional)",
            "",
        )],
    )?
    else {
        return Ok(());
    };
    let receipts = values[0]
        .split(';')
        .filter(|value| !value.is_empty())
        .map(|value| crate::manager::setup::review_public_input(&absolute(value)?))
        .collect::<io::Result<Vec<_>>>()?;
    let expected_service_state = host::observed_service_state(false)?;
    let temporary_validation = needs_temporary_service(
        &expected_service_state,
        record.previous_service_state.as_deref(),
    );
    if !review(terminal, "Original firmware recovery observation", vec![format!("Original {} plan {}", record.operation_id, record.plan_digest), format!("Service now: {expected_service_state}; original: {:?}", record.previous_service_state), format!("Temporary startup or restoration to original stopped state approved: {temporary_validation}"), "Reconcile only this original record using current pin/build/storage and accounted public forward transitions. Receipt outcomes are independently checked; missing context remains uncertain. No transfer, flash reset, re-pin, recommission or OTP.".into()], Some(&format!("RECONCILE {}", record.operation_id)))? { return Ok(()); }
    setup::apply(
        terminal,
        worker,
        socket,
        HostAction::FirmwareRecovery {
            operation_id: record.operation_id.to_string(),
            original_plan_digest: record.plan_digest.to_string(),
            receipts,
            expected_service_state,
            temporary_validation,
        },
        None,
    )
}

pub(super) fn fallback(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
) -> io::Result<()> {
    let Some(record) = original_record(terminal)? else {
        return Ok(());
    };
    if record.action != "update" {
        return Err(io::Error::other("original record is not a host update"));
    }
    let mut action = host::review_update_recovery(
        &record.operation_id.to_string(),
        &record.plan_digest.to_string(),
    )?;
    if let HostAction::UpdateRecovery {
        stop_service,
        expected_service_state: Some(service),
        temporary_validation,
        restore_deployment,
        ..
    } = &mut action
    {
        *stop_service = review(terminal, "Original update recovery disruption", vec![format!("Service: {service}"), "Approve stopping the managed daemon only if an independently compatible binary fallback requires it. Missing current-data readability or incompatible state blocks fallback. No config, journal, period or flash snapshot is restored.".into()], Some("ALLOW RECOVERY STOP"))?;
        if needs_temporary_service(service, record.previous_service_state.as_deref()) {
            *temporary_validation = review(terminal, "Temporary original-operation validation", vec![format!("Current service: {service}; original: {:?}", record.previous_service_state), "Allow the original authenticated daemon to run temporarily through the finite recovery unit, then restore the original running/stopped state. This belongs to the original update, not a replacement operation.".into()], Some("ALLOW TEMPORARY RECOVERY"))?;
        }
        *restore_deployment = review(terminal, "Restore authenticated release-owned deployment assets", vec!["If the original and selected deployment differ, restore only the authenticated prior /usr/lib/systemd/system/pico2-kes-agentd.service, /usr/libexec/pico2-kes-agent-host-check and /usr/lib/udev/rules.d/70-pico2-kes-agent.rules, with systemd/udev reloads.".into(), "Original or signed target bytes are required; unrelated or modified third-party bytes block recovery. Operator configuration, journals, identities and all device state remain untouched.".into()], Some("RESTORE RELEASE DEPLOYMENT"))?;
    }
    setup::apply(terminal, worker, socket, action, None)
}

fn needs_temporary_service(current: &str, original: Option<&str>) -> bool {
    !current.starts_with("state=active;")
        || original.is_some_and(|state| !state.starts_with("state=active;"))
}

#[cfg(test)]
mod tests {
    use super::needs_temporary_service;
    #[test]
    fn recovery_approval_includes_restoring_originally_stopped_service() {
        assert!(needs_temporary_service(
            "state=active;pid=42",
            Some("state=inactive;pid=0")
        ));
        assert!(!needs_temporary_service(
            "state=active;pid=42",
            Some("state=active;pid=41")
        ));
        assert!(needs_temporary_service(
            "state=inactive;pid=0",
            Some("state=active;pid=41")
        ));
    }
}
