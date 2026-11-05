use super::{
    foreground, review, setup,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::manager::{
    host::{self, HostAction},
    model::{InstallationRegistry, InstallationRole, MaintenanceRecord, Qualification},
    observe::{Snapshot, Worker},
    records::{Record, RecordStore},
    release::{self, Admission, VerifiedBundle},
    release_discovery::{self, Offer},
    terminal::TerminalOwner,
    workspace::{self, WorkspaceKind},
};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

fn release_status(qualification: Qualification) -> &'static str {
    match qualification {
        Qualification::Candidate => "candidate",
        Qualification::Qualified => "approved",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    TupleUpgrade,
    Browse,
    Refresh,
    Prerelease,
    Offline,
    Select,
    FirmwarePreview,
    FirmwareUpdate,
    Reexec,
    Remove,
}
pub(super) const PRIMARY_ACTIONS: &[Action] = &[
    Action::TupleUpgrade,
    Action::Browse,
    Action::Refresh,
    Action::Prerelease,
    Action::Offline,
    Action::Select,
    Action::FirmwarePreview,
    Action::FirmwareUpdate,
    Action::Reexec,
    Action::Remove,
];
pub(super) const BACKUP_ACTIONS: &[Action] = &[
    Action::TupleUpgrade,
    Action::Browse,
    Action::Refresh,
    Action::Prerelease,
    Action::Offline,
    Action::Select,
    Action::Reexec,
    Action::Remove,
];
impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::TupleUpgrade => "Upgrade or switch complete release tuple (recommended)",
            Self::Browse => "Inspect authenticated release inventory & freshness",
            Self::Refresh => "Refresh approved releases / reverify offline cache",
            Self::Prerelease => "Toggle signed prerelease opt-in (never candidates)",
            Self::Offline => "Toggle online / offline discovery",
            Self::Select => "Select independent host component versions (advanced)",
            Self::FirmwarePreview => "Preview authenticated firmware transfer (read-only)",
            Self::FirmwareUpdate => "Update pinned Pico 2 firmware only",
            Self::Reexec => "Re-exec installed p2kesup manager",
            Self::Remove => "Remove cached release bundle (preserves records)",
        }
    }
}

pub(super) struct State {
    pub offers: Vec<Offer>,
    pub status: String,
    cache: Option<PathBuf>,
    worker: Option<release_discovery::Worker>,
    pub(super) prerelease: bool,
    pub(super) online: bool,
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
                self.status = "Checking approved releases (independent 10-second deadline)".into();
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
                self.status = result.notice.unwrap_or_else(|| {
                    "Discovery completed; cache age does not establish current revocation/latest status".into()
                });
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
                "Mode: {}; prerelease opt-in: {}; candidates are never auto-discovered",
                if self.online { "online" } else { "offline" },
                self.prerelease
            ),
            Offer::PROVENANCE.into(),
        ];
        if self.offers.is_empty() {
            lines.push("No cached or discovered release offers.".into());
        }
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
        if self.offers.is_empty() {
            review(
                terminal,
                "Remove cached release bundle",
                vec![
                    "No cached release bundles are currently discovered.".into(),
                    "Refresh release inventory first if you expected cached bundles.".into(),
                ],
            )?;
            return Ok(());
        }
        let owned_opts: Vec<(String, String)> = self
            .offers
            .iter()
            .map(|o| {
                let d = o.selection.manifest_digest.to_string();
                let desc = format!(
                    "{} [{}] age={}s ({})",
                    o.selection.tag,
                    o.selection.channel,
                    o.age().as_secs(),
                    workspace::short_id(&d)
                );
                (d, desc)
            })
            .collect();
        let select_opts: Vec<(&str, &str)> = owned_opts
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let specs = [FieldSpec::select(
            "Cached release bundle to remove",
            select_opts[0].0,
            &select_opts,
        )];
        let Some(digest) = form_validated(terminal, "Remove cached release bundle", &specs, |v| {
            Ok(v[0].trim().to_owned())
        })?
        else {
            return Ok(());
        };
        if !review_mode(
            terminal,
            "Confirm cache removal",
            vec![
                format!("Manifest SHA-256: {digest}"),
                "Removes only this cached release entry. Installed binaries, configs, receipts, and maintenance records remain untouched."
                    .into(),
                "Offline installation/upgrade of this release will require reacquiring authenticated bundle bytes."
                    .into(),
            ],
            ConfirmMode::YesNo { danger: true },
        )? {
            return Ok(());
        }
        self.pause();
        release_discovery::remove(
            self.cache
                .as_deref()
                .ok_or_else(|| io::Error::other("release cache unavailable"))?,
            &digest,
        )?;
        self.offers
            .retain(|offer| offer.selection.manifest_digest.to_string() != digest);
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
    review_mode(
        terminal,
        "Explicit disposable candidate acceptance",
        vec![
            format!(
                "Only this launched local bundle may introduce candidate components: {}",
                path.display()
            ),
            "Signature, exact tuple, persistent-state readability, hardware, and independent postchecks remain mandatory. This candidate is not an approved release."
                .into(),
        ],
        ConfirmMode::YesNo { danger: false },
    )
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

pub(super) fn tuple_upgrade(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    launched: Option<&PathBuf>,
    state: &State,
    role: InstallationRole,
) -> io::Result<Option<PathBuf>> {
    let store = RecordStore::open_host(crate::manager::setup::service_identity()?.1)?;
    if store.list()?.iter().any(|record| match record {
        Record::Supported(record) => !host::maintenance_outcome_allows_new_action(&record.outcome),
        Record::Unknown(_) => true,
    }) {
        return Err(io::Error::other(
            "unresolved maintenance record blocks upgrade; open Activity (6) to reconcile the original operation first",
        ));
    }
    let (digest, registry, service, _) = host::update_review()?;
    if registry.role != role {
        return Err(io::Error::other(
            "launch role differs from the managed installation role",
        ));
    }
    host::verify_installed_ownership()?;

    let mut owned_opts: Vec<(String, String)> = Vec::new();
    if let Some(path) = launched {
        let p = path.to_string_lossy().into_owned();
        owned_opts.push((p.clone(), format!("Launched --bundle ({p})")));
    }
    for offer in &state.offers {
        let p = offer.bundle.to_string_lossy().into_owned();
        if !owned_opts.iter().any(|(k, _)| k == &p) {
            owned_opts.push((
                p,
                format!(
                    "{} [{}] ({}, age {}s)",
                    offer.selection.tag,
                    offer.selection.channel,
                    offer.source,
                    offer.age().as_secs()
                ),
            ));
        }
    }
    owned_opts.push((
        "custom".into(),
        "Specify another local release bundle directory...".into(),
    ));
    let select_opts: Vec<(&str, &str)> = owned_opts
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let custom_default = launched.and_then(|p| p.to_str()).unwrap_or("");
    let specs = [
        FieldSpec::select("Release bundle source", select_opts[0].0, &select_opts),
        FieldSpec::text_hint(
            "Custom bundle directory (used only when source = custom)",
            custom_default,
            "Absolute path to unpacked signed release bundle",
        ),
    ];
    let Some((bundle_path, allow_candidate)) =
        form_validated(terminal, "Coordinated release tuple upgrade", &specs, |v| {
            let chosen = if v[0] == "custom" {
                v[1].trim()
            } else {
                v[0].trim()
            };
            let path = absolute(chosen).map_err(|e| (Some(1), e.to_string()))?;
            let explicit = v[0] == "custom" || launched.is_some_and(|l| l == &path);
            Ok((path, explicit))
        })?
    else {
        return Ok(None);
    };

    let verified_bundle = release::verify_bundle(
        &bundle_path,
        if allow_candidate {
            Admission::AttendedCandidate
        } else {
            Admission::Qualified
        },
    )?;
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    if host::same_selection(current, verified_bundle.selection()) {
        review(
            terminal,
            "Release tuple already installed",
            vec![
                format!(
                    "Managed {:?} installation is already on {}.",
                    registry.role, current.tag
                ),
                "No host or firmware changes were staged.".into(),
            ],
        )?;
        return Ok(None);
    }

    upgrade_direct_with_worker(
        terminal,
        worker,
        socket,
        bundle_path,
        verified_bundle,
        digest,
        registry,
        service,
    )?;

    reexec(terminal)
}

pub(super) fn recover_upgrade_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    operation_id: &str,
    plan_digest: &str,
) -> io::Result<()> {
    let mut action = host::review_upgrade_recovery(operation_id, plan_digest)?;
    let HostAction::UpgradeRecovery {
        temporary_validation,
        ..
    } = &mut action
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upgrade recovery review",
        ));
    };
    *temporary_validation = true;
    let executable = host::trusted_upgrade_recovery_manager(operation_id, plan_digest)?;
    resume_upgrade_with_worker(terminal, worker, socket, action, executable, operation_id)
}

pub(super) fn resume_upgrade_direct(
    terminal: &mut TerminalOwner,
    action: HostAction,
    executable: PathBuf,
    operation: &str,
) -> io::Result<()> {
    let mut worker = None;
    resume_upgrade_with_worker(
        terminal,
        &mut worker,
        Path::new("/run/pico2-kes-agent/management.sock"),
        action,
        executable,
        operation,
    )
}

fn resume_upgrade_with_worker(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    action: HostAction,
    executable: PathBuf,
    operation: &str,
) -> io::Result<()> {
    let plan = host::HostPlan::new(action)?;
    let path = workspace::next_path(WorkspaceKind::Plans, "upgrade-recovery-plan", "json")?;
    let mut lines = vec![
        format!("Original operation : {operation}"),
        format!("Recovery plan file : {}", path.display()),
        format!("Plan SHA-256       : {}", plan.approved_digest),
        String::new(),
        "Reconciles only the original upgrade operation without reflashing or rolling back Pico 2 state."
            .into(),
        "A stopped service may be started temporarily for validation and will be restored to its original state."
            .into(),
        String::new(),
    ];
    lines.extend(
        serde_json::to_string_pretty(&plan)
            .map_err(io::Error::other)?
            .lines()
            .map(str::to_owned),
    );
    if !review_mode(
        terminal,
        "Recover original upgrade",
        lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recovery cancelled",
        ));
    }
    crate::files::publish_no_clobber(
        &path,
        &serde_json::to_vec_pretty(&plan).map_err(io::Error::other)?,
        0o600,
    )?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&path);
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "recovery failed or remains uncertain ({status}); retain original operation {operation}"
        )));
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
    let mut worker = None;
    upgrade_direct_with_worker(
        terminal,
        &mut worker,
        Path::new("/run/pico2-kes-agent/management.sock"),
        path,
        bundle,
        registry_digest,
        registry,
        service,
    )
}

#[allow(clippy::too_many_arguments)]
fn upgrade_direct_with_worker(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    path: PathBuf,
    bundle: VerifiedBundle,
    registry_digest: String,
    registry: InstallationRegistry,
    service: Option<String>,
) -> io::Result<()> {
    let role = registry.role;
    let candidate = bundle.selection().qualification == Qualification::Candidate;
    if candidate
        && !review_mode(
            terminal,
            "Explicit candidate admission",
            vec![
                "This signed candidate is not an approved release. Proceed only on a disposable host; all state and hardware checks remain mandatory."
                    .into(),
            ],
            ConfirmMode::YesNo { danger: false },
        )?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "candidate not accepted",
        ));
    }
    let preview = if role == InstallationRole::Primary {
        Some(
            capture_firmware_review(
                terminal,
                worker,
                socket,
                service
                    .as_deref()
                    .ok_or_else(|| io::Error::other("service observation unavailable"))?,
            )?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "pre-state review cancelled",
                )
            })?,
        )
    } else {
        None
    };
    let temporary_validation = preview
        .as_ref()
        .is_some_and(|p| !p.service_state.starts_with("state=active;"));
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
        expected_service_state: preview
            .as_ref()
            .map(|p| p.service_state.clone())
            .or(service),
        pre_state: preview.as_ref().map(|p| p.evidence.clone()),
        temporary_validation,
        serial: preview.as_ref().map(|p| p.serial.clone()),
        device_id: preview.as_ref().map(|p| p.device_id.clone()),
        identity_public_key: preview.as_ref().map(|p| p.identity_public_key.clone()),
        record,
    };
    let plan = host::HostPlan::new(action)?;
    let plan_path = workspace::next_path(WorkspaceKind::Plans, "upgrade-plan", "json")?;
    let current = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("installed selection unavailable"))?;
    let mut lines = vec![
        format!("Installed release : {}", current.tag),
        format!(
            "Selected release  : {} ({}); source {}",
            bundle.selection().tag,
            release_status(bundle.selection().qualification),
            bundle.selection().source_commit
        ),
        format!("Installation role : {role:?}"),
        format!("Retained plan     : {}", plan_path.display()),
        format!("Plan SHA-256      : {}", plan.approved_digest),
        String::new(),
        "Component transitions:".into(),
    ];
    for next in &bundle.selection().components {
        let previous = current
            .components
            .iter()
            .find(|c| c.component == next.component)
            .ok_or_else(|| io::Error::other("installed component missing"))?;
        lines.push(format!(
            "  {:<12}: {} -> {}",
            next.component, previous.version, next.version
        ));
    }
    lines.push(String::new());
    lines.push(
        "The complete signed tuple is installed together. Physical firmware transfer is attended; interrupted operations retain their original record in Activity (6) or via p2kesup upgrade --resume."
            .into(),
    );
    lines.push(String::new());
    lines.extend(
        serde_json::to_string_pretty(&plan)
            .map_err(io::Error::other)?
            .lines()
            .map(str::to_owned),
    );
    if !review_mode(
        terminal,
        "Review complete tuple upgrade",
        lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upgrade cancelled",
        ));
    }
    crate::files::publish_no_clobber(
        &plan_path,
        &serde_json::to_vec_pretty(&plan).map_err(io::Error::other)?,
        0o600,
    )?;
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.arg("host-apply").arg("--plan").arg(&plan_path);
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "upgrade failed or was interrupted ({status}); reconcile in Activity (6) or retain original plan {}",
            plan_path.display()
        )));
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
    let specs = [
        FieldSpec::text("Authorizing bundle directory", default),
        FieldSpec::text_hint(
            "Additional source bundle directories (semicolon-separated, optional)",
            "",
            "Installed retained sources are included automatically",
        ),
    ];
    let Some((authorizing_path, extra_paths)) = form_validated(
        terminal,
        "Select signed compatibility authority & sources",
        &specs,
        |v| {
            let auth = absolute(v[0].trim()).map_err(|e| (Some(0), e.to_string()))?;
            let mut extras = Vec::new();
            for item in v[1].split(';').map(str::trim).filter(|s| !s.is_empty()) {
                extras.push(absolute(item).map_err(|e| (Some(1), e.to_string()))?);
            }
            Ok((auth, extras))
        },
    )?
    else {
        return Ok(());
    };
    let mut paths = vec![authorizing_path.clone()];
    for path in retained.into_iter().chain(extra_paths) {
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

    let names = ["manager", "daemon", "cli", "tool", "deployment"];
    let source_choice_owned: Vec<Vec<(String, String)>> = names
        .iter()
        .map(|name| {
            sources
                .iter()
                .enumerate()
                .map(|(idx, src)| {
                    let ver = src
                        .selection()
                        .components
                        .iter()
                        .find(|c| c.component == *name)
                        .map_or("?", |c| c.version.as_str());
                    (
                        idx.to_string(),
                        format!(
                            "Source {}: {} ({} {})",
                            idx + 1,
                            ver,
                            src.selection().tag,
                            release_status(src.selection().qualification)
                        ),
                    )
                })
                .collect()
        })
        .collect();
    let source_choice_refs: Vec<Vec<(&str, &str)>> = source_choice_owned
        .iter()
        .map(|opts| opts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
        .collect();
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
                .unwrap_or(0)
                .to_string()
        })
        .collect();
    let stop_opts = if registry.role == InstallationRole::Primary {
        &[
            (
                "yes",
                "Allow stopping/restarting pico2-kes-agentd if daemon/deployment changes",
            ),
            (
                "no",
                "Decline service stop (only non-disruptive changes can proceed)",
            ),
        ][..]
    } else {
        &[("no", "Backup role has no agent service")][..]
    };
    let mut comp_specs: Vec<FieldSpec<'_>> = names
        .iter()
        .enumerate()
        .map(|(i, name)| FieldSpec::select(name, &defaults[i], &source_choice_refs[i]))
        .collect();
    comp_specs.push(FieldSpec::select(
        "Daemon interruption policy",
        stop_opts[0].0,
        stop_opts,
    ));

    let Some((selection, stop_service)) = form_validated(
        terminal,
        "Select exact signed component tuple",
        &comp_specs,
        |values| {
            let firmware = current
                .components
                .iter()
                .find(|component| component.component == "firmware")
                .ok_or_else(|| (None, "Installed firmware selection unavailable".into()))?;
            let mut choices =
                BTreeMap::from([("firmware".to_owned(), firmware.manifest_digest.to_string())]);
            for (field_i, (name, value)) in names.iter().zip(&values[..names.len()]).enumerate() {
                let index = value
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < sources.len())
                    .ok_or_else(|| (Some(field_i), "Invalid source selection".into()))?;
                let source = &sources[index];
                let component = source
                    .selection()
                    .components
                    .iter()
                    .find(|component| component.component == *name)
                    .ok_or_else(|| (Some(field_i), "Source component missing".into()))?;
                if source.selection().qualification == Qualification::Candidate
                    && candidate_source.as_ref() != Some(&source_paths[index])
                    && !current.components.iter().any(|old| {
                        old.component == *name
                            && old.digest == component.digest
                            && old.manifest_digest == component.manifest_digest
                    })
                {
                    return Err((
                        Some(field_i),
                        "New candidate component requires the explicitly accepted launched bundle"
                            .into(),
                    ));
                }
                choices.insert(
                    (*name).to_owned(),
                    source.selection().manifest_digest.to_string(),
                );
            }
            let references: Vec<&VerifiedBundle> = sources.iter().collect();
            let sel = release::select_components(&sources[0], &references, &choices)
                .map_err(|e| (None, e.to_string()))?;
            let stop = values[names.len()] == "yes" && registry.role == InstallationRole::Primary;
            Ok((sel, stop))
        },
    )?
    else {
        return Ok(());
    };

    let mut lines = vec![
        format!(
            "Service before : {}",
            service
                .as_deref()
                .unwrap_or("backup role: no agent service")
        ),
        format!("Allow stop     : {stop_service}"),
        "Component tuple transitions (firmware unchanged):".into(),
    ];
    for next in &selection.components {
        let prev = current
            .components
            .iter()
            .find(|c| c.component == next.component)
            .map_or("?", |c| c.version.as_str());
        lines.push(format!(
            "  {:<12}: {} -> {}",
            next.component, prev, next.version
        ));
    }
    lines.push(String::new());
    lines.push(
        "Host changes preserve configuration, journals, receipts, pins, and Pico 2 storage. The current p2kesup process continues running until you explicitly re-exec."
            .into(),
    );
    if let Some(snapshot) = snapshot {
        lines.push(format!(
            "Observed service pools ({:?}, age {}s): {}",
            snapshot.membership.state,
            snapshot.captured_at.elapsed().as_secs(),
            snapshot.pools.len()
        ));
    }
    if !review_mode(
        terminal,
        "Review host component update",
        lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(());
    }

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
    let lines = vec![
        format!(
            "Running manager process : {} (build={}, commit={})",
            current.version, current.build_id, current.source_commit
        ),
        format!("Installed manager binary: {}", path.display()),
        String::new(),
        "Replaces this process with the authenticated installed p2kesup binary, preserving --role, --socket, and --bundle arguments."
            .into(),
    ];
    Ok(review_mode(
        terminal,
        "Re-exec installed p2kesup manager",
        lines,
        ConfirmMode::YesNo { danger: false },
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
    snapshot: Option<&Snapshot>,
) -> io::Result<()> {
    let Some((_, bundle, _)) = setup::bundle(terminal, launched)? else {
        return Ok(());
    };
    let serial = snapshot
        .and_then(|s| s.local.value.as_ref())
        .and_then(|l| l.config_summary.value.as_ref())
        .filter(|c| c.pinned_device_id.is_some())
        .and_then(|c| c.usb_serial.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Pinned device serial is unavailable",
            )
        })?;
    let record = std::env::temp_dir().join(format!("p2kesup-preview-{}.json", new_id()?));
    let mut command = Command::new("/usr/bin/python3");
    command
        .arg("-I")
        .arg(bundle.root().join("tools/firmware.py"))
        .arg("update")
        .arg("--bundle")
        .arg(bundle.root().join("firmware"))
        .arg("--serial")
        .arg(&serial)
        .arg("--record")
        .arg(record)
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", bundle.root().join("tools").display()),
        )
        .env("LD_LIBRARY_PATH", bundle.root().join("runtime"));
    let status = foreground(terminal, worker, socket, &mut command, true)?;
    review(
        terminal,
        "Firmware preview result",
        vec![
            format!("Foreground preview exit: {status}"),
            "No transfer, service change, or new firmware record was requested.".into(),
        ],
    )?;
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
    let mut lines = vec![
        format!("Observed managed service: {service}"),
        "Reads complete pinned public pre-state through the sole authenticated daemon (no flash, lifecycle mutation, or pin replacement)."
            .into(),
    ];
    if temporary {
        lines.push(
            "Service is currently stopped: this step temporarily starts the normal service for pre-state observation and restores its stopped state afterward."
                .into(),
        );
    }
    if !review_mode(
        terminal,
        "Capture protected maintenance pre-state",
        lines,
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(None);
    }
    let id = new_id()?;
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
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
    let mut lines = vec![
        format!("Protected review : {}", path.display()),
        format!("Pinned device ID : {}", preview.device_id),
        format!("Pinned serial    : {}", preview.serial),
        String::new(),
    ];
    lines.extend(
        serde_json::to_string_pretty(&preview)
            .map_err(io::Error::other)?
            .lines()
            .map(str::to_owned),
    );
    if !review_mode(
        terminal,
        "Verify observed pinned pre-state",
        lines,
        ConfirmMode::YesNo { danger: false },
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
            "update the authenticated tool separately (or use Upgrade complete release tuple) before firmware-only transfer",
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
    let lines = vec![
        format!("Target release    : {}", target_selection.tag),
        format!("Pinned USB serial : {}", preview.serial),
        format!("Pinned device ID  : {}", preview.device_id),
        format!("Transfer record   : {}", record.display()),
        format!(
            "Prior service     : {} (temporary validation={temporary_validation})",
            preview.service_state
        ),
        String::new(),
        "Stops pico2-kes-agentd for attended firmware-only transfer and verifies identical pin, live build, storage, and forward state afterward. Interrupted work reconciles in Activity (6)."
            .into(),
    ];
    if !review_mode(
        terminal,
        "Attended existing-device firmware update",
        lines,
        ConfirmMode::YesNo { danger: false },
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

pub(super) fn recover_firmware_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    record: &MaintenanceRecord,
) -> io::Result<()> {
    if record.action != "firmware-update" {
        return Err(io::Error::other("original record is not a firmware update"));
    }
    let paths = workspace::list_files(WorkspaceKind::Receipts)?;
    let labels: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let options: Vec<(&str, &str)> = labels.iter().map(|p| (p.as_str(), "")).collect();
    let specs = [FieldSpec::multiselect(
        "Accounted lifecycle receipts",
        "",
        &options,
    )];
    let Some(receipts) = form_validated(
        terminal,
        "Accounted lifecycle transitions",
        &specs,
        |values| {
            let mut list = Vec::new();
            for item in values[0]
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let p = absolute(item).map_err(|e| (Some(0), e.to_string()))?;
                let input = crate::manager::setup::review_public_input(&p)
                    .map_err(|e| (Some(0), e.to_string()))?;
                list.push(input);
            }
            Ok(list)
        },
    )?
    else {
        return Ok(());
    };
    let expected_service_state = host::observed_service_state(false)?;
    let temporary_validation = needs_temporary_service(
        &expected_service_state,
        record.previous_service_state.as_deref(),
    );
    if !review_mode(
        terminal,
        "Original firmware recovery observation",
        vec![
            format!("Original operation : {}", record.operation_id),
            format!("Original plan SHA  : {}", record.plan_digest),
            format!(
                "Service now        : {expected_service_state} (original: {:?})",
                record.previous_service_state
            ),
            format!("Temporary startup  : {temporary_validation}"),
            String::new(),
            "Reconciles only this original record using current pin/build/storage and accounted public forward transitions (no flash writes, reset, re-pin, or OTP)."
                .into(),
        ],
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(());
    }
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

pub(super) fn recover_update_record(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    record: &MaintenanceRecord,
) -> io::Result<()> {
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
        let need_temp = needs_temporary_service(service, record.previous_service_state.as_deref());
        let yes_no = [
            ("yes", "Approve if required for compatible recovery"),
            ("no", "Decline"),
        ];
        let mut specs = vec![
            FieldSpec::readonly("Current service state", service),
            FieldSpec::select(
                "Allow stopping pico2-kes-agentd for compatible binary fallback",
                "yes",
                &yes_no,
            ),
            FieldSpec::select(
                "Restore release-owned deployment units/rules if changed",
                "yes",
                &yes_no,
            ),
        ];
        if need_temp {
            specs.push(FieldSpec::select(
                "Allow temporary service run for validation",
                "yes",
                &yes_no,
            ));
        }
        let Some(choices) =
            form_validated(terminal, "Host update recovery options", &specs, |v| {
                Ok((
                    v[1] == "yes",
                    v[2] == "yes",
                    need_temp && v.get(3).is_some_and(|s| s == "yes"),
                ))
            })?
        else {
            return Ok(());
        };
        *stop_service = choices.0;
        *restore_deployment = choices.1;
        if need_temp {
            *temporary_validation = choices.2;
        }
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
