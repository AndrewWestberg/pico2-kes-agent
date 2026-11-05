//! Complete-tuple upgrade: no service runs against a partially selected release.
use super::*;
use crate::manager::{
    maintenance,
    model::ReleaseSelection,
    release::{self, VerifiedBundle},
};

const ROOT: &str = "/usr/lib/pico2-kes-agent";
const DEPLOYMENT: [(&str, &str); 3] = [
    (
        "pico2-kes-agent-host-check",
        "/usr/libexec/pico2-kes-agent-host-check",
    ),
    (
        "pico2-kes-agentd.service",
        "/usr/lib/systemd/system/pico2-kes-agentd.service",
    ),
    (
        "70-pico2-kes-agent.rules",
        "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules",
    ),
];

fn component<'a>(
    selection: &'a ReleaseSelection,
    name: &str,
) -> io::Result<&'a crate::manager::model::SelectedComponent> {
    selection
        .components
        .iter()
        .find(|c| c.component == name)
        .ok_or_else(|| io::Error::other(format!("selected {name} missing")))
}

pub fn verify_installed_ownership() -> io::Result<()> {
    let registry = installation_registry()?;
    for entry in &registry.files {
        trusted_ancestry(&entry.path)?;
        check_owned_file(&entry.path, Some(entry))?;
    }
    trusted_manager()?;
    trusted_cli()?;
    trusted_component("daemon", "pico2-kes-agentd")?;
    trusted_firmware_tool()?;
    let selection = registry
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("no managed installation"))?;
    let current = Path::new(ROOT).join("current");
    let metadata = fs::symlink_metadata(&current)?;
    if !metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(io::Error::other("unsafe current generation"));
    }
    verify_generation(&fs::canonicalize(current)?, selection)?;
    verify_component_versions(selection)
}

fn check_pin(action: &HostAction) -> io::Result<()> {
    let HostAction::Upgrade {
        serial: Some(serial),
        device_id: Some(device),
        identity_public_key: Some(key),
        ..
    } = action
    else {
        return Err(io::Error::other(
            "primary upgrade requires the reviewed device pin",
        ));
    };
    let (actual_serial, actual_device, actual_key, _) = commissioned_config()?;
    if (&actual_serial, &actual_device, &actual_key) != (serial, device, key) {
        return Err(io::Error::other(
            "configured device pin changed after upgrade review",
        ));
    }
    Ok(())
}

pub(super) fn apply(
    plan: &HostPlan,
    bundle: &VerifiedBundle,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    let HostAction::Upgrade {
        bundle: path,
        candidate_accepted,
        expected_registry_digest,
        expected_service_state,
        pre_state,
        temporary_validation,
        ..
    } = &plan.action
    else {
        return Err(io::Error::other("invalid upgrade action"));
    };
    let registry = installation_registry()?;
    if registry.role == InstallationRole::Primary {
        check_pin(&plan.action)?;
    } else if pre_state.is_some() || expected_service_state.is_some() {
        return Err(io::Error::other(
            "backup upgrade cannot request a device or service",
        ));
    }
    let update = HostPlan {
        schema_version: plan.schema_version,
        plan_id: plan.plan_id.clone(),
        approved_digest: plan.approved_digest.clone(),
        action: HostAction::Update {
            authorizing_bundle: path.clone(),
            sources: vec![path.clone()],
            candidate_source: candidate_accepted.then(|| path.clone()),
            selection: bundle.selection().clone(),
            expected_registry_digest: expected_registry_digest.clone(),
            expected_service_state: expected_service_state.clone(),
            stop_service: true,
            pre_state: pre_state.clone(),
            temporary_validation: *temporary_validation,
        },
    };
    update_bundle(&update, store, record, effects, Some(plan), false)
}

fn verify_generation(path: &Path, selection: &ReleaseSelection) -> io::Result<()> {
    trusted_ancestry(path)?;
    if fs::read_dir(path)?.count() != 6 || selection.components.len() != 6 {
        return Err(io::Error::other(
            "generation must contain the complete tuple",
        ));
    }
    for item in &selection.components {
        let link = path.join(&item.component);
        let metadata = fs::symlink_metadata(&link)?;
        let target = Path::new(ROOT)
            .join("components")
            .join(&item.component)
            .join(item.digest.to_string());
        if !metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || fs::read_link(link)? != target
        {
            return Err(io::Error::other(
                "generation differs from the authenticated complete tuple",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn activate_prepared(
    plan: &HostPlan,
    bundle: &VerifiedBundle,
    prior: InstallationRegistry,
    selection: ReleaseSelection,
    additions: Vec<ManagedFile>,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    if !same_selection(&selection, bundle.selection()) {
        return Err(io::Error::other(
            "upgrade requires the release's complete signed tuple",
        ));
    }
    let mut target = prior.clone();
    for entry in additions {
        if !target.files.iter().any(|old| old.path == entry.path) {
            target.files.push(entry);
        }
    }
    target.current = Some(selection.clone());
    if prior.role == InstallationRole::Primary {
        let deployment = component(&selection, "deployment")?;
        for (name, destination) in DEPLOYMENT {
            let source = Path::new(ROOT)
                .join("components/deployment")
                .join(deployment.digest.to_string())
                .join(name);
            let signed = target
                .files
                .iter()
                .find(|e| e.path == source)
                .ok_or_else(|| io::Error::other("staged deployment missing"))?
                .clone();
            let entry = target
                .files
                .iter_mut()
                .find(|e| e.path == Path::new(destination))
                .ok_or_else(|| io::Error::other("deployment not manager-owned"))?;
            entry.digest = signed.digest;
            entry.mode = signed.mode;
        }
    }
    let generation = Path::new(ROOT)
        .join("generations")
        .join(record.plan_digest.to_string());
    root_directory(&generation, 0o755)?;
    for item in &selection.components {
        std::os::unix::fs::symlink(
            Path::new(ROOT)
                .join("components")
                .join(&item.component)
                .join(item.digest.to_string()),
            generation.join(&item.component),
        )?;
    }
    File::open(&generation)?.sync_all()?;
    File::open(generation.parent().unwrap())?.sync_all()?;
    verify_generation(&generation, &selection)?;
    let bytes = serde_json::to_vec_pretty(&target).map_err(io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("target registry too large"));
    }
    let staged = Path::new("/var/lib/p2kesup/staging").join(record.operation_id.to_string());
    crate::files::publish_no_clobber(&staged.join("target-registry.json"), &bytes, 0o600)?;
    record.checkpoints.push(checkpoint(
        "upgrade-ready",
        format!("{:x}", Sha256::digest(&bytes)),
    ));
    store.update(record)?;
    if prior.role == InstallationRole::Primary {
        check_pin(&plan.action)?;
        let state = observed_service_state(false)?;
        if service_state_matches(&state, "active") {
            run_service(ServiceAction::Stop, &state, effects)?;
        } else if !service_state_matches(&state, "inactive") {
            return Err(io::Error::other("upgrade requires a quiescent daemon"));
        }
        record
            .checkpoints
            .push(checkpoint("service-quiesced", state));
        store.update(record)?;
        inhibit_service(store, record)?;
        if firmware_changes(&prior, &target)? {
            transfer(plan, bundle, store, record)?;
        }
    }
    finish(
        plan,
        &plan.action,
        &prior,
        &target,
        bundle,
        store,
        record,
        effects,
    )
}

fn firmware_changes(
    prior: &InstallationRegistry,
    target: &InstallationRegistry,
) -> io::Result<bool> {
    let old = prior
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("prior tuple missing"))?;
    let new = target
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("target tuple missing"))?;
    Ok(component(old, "firmware")?.digest != component(new, "firmware")?.digest)
}

fn transfer(
    plan: &HostPlan,
    bundle: &VerifiedBundle,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
) -> io::Result<()> {
    let HostAction::Upgrade {
        serial: Some(serial),
        record: Some(tool_record),
        ..
    } = &plan.action
    else {
        return Err(io::Error::other("firmware target missing"));
    };
    root_directory(Path::new("/var/lib/p2kesup/firmware"), 0o700)?;
    if tool_record.try_exists()? {
        return Err(io::Error::other(
            "original firmware record already exists; do not replay transfer",
        ));
    }
    let image = bundle
        .manifest()
        .artifacts
        .iter()
        .find(|a| a.path == "firmware/pico2-kes-firmware.signed.uf2")
        .ok_or_else(|| io::Error::other("firmware image missing"))?;
    if record.image_digest.as_deref() != Some(image.sha256.as_str()) {
        return Err(io::Error::other(
            "selected image differs from the original immutable intent",
        ));
    }
    record.checkpoints.push(checkpoint(
        "upgrade-transfer-starting",
        tool_record.display().to_string(),
    ));
    store.update(record)?;
    let python = Path::new("/usr/bin/python3");
    trusted_ancestry(python)?;
    trusted_ancestry(&fs::canonicalize(python)?)?;
    let metadata = fs::metadata(python)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other("unsafe Python"));
    }
    let tool = component(bundle.selection(), "tool")?;
    let tool_dir = Path::new(ROOT)
        .join("components/tool")
        .join(tool.digest.to_string());
    let status = Command::new(python)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", tool_dir.display()))
        .env("LD_LIBRARY_PATH", tool_dir.join("runtime"))
        .arg("-I")
        .arg(bundle.root().join("tools/firmware.py"))
        .arg("update")
        .arg("--bundle")
        .arg(bundle.root().join("firmware"))
        .arg("--serial")
        .arg(serial)
        .arg("--record")
        .arg(tool_record)
        .arg("--apply")
        .status()?;
    if !status.success() {
        if fs::symlink_metadata(tool_record)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        {
            record.checkpoints.push(checkpoint(
                "upgrade-transfer-not-started",
                "child exited without creating its write-ahead transfer record".into(),
            ));
            store.update(record)?;
        }
        return Err(io::Error::other(
            "firmware transfer failed or was declined; reconcile the original upgrade plan",
        ));
    }
    require_transfer(&plan.action, record)?;
    record.checkpoints.push(checkpoint(
        "upgrade-transfer-flushed",
        tool_record.display().to_string(),
    ));
    store.update(record)
}

const SERVICE_GATE: &str = "/etc/systemd/system/pico2-kes-agentd.service";

fn service_gate(record: &MaintenanceRecord) -> io::Result<bool> {
    for path in [
        "/run/systemd/system/pico2-kes-agentd.service",
        "/etc/systemd/system/pico2-kes-agentd.service.d",
        "/run/systemd/system/pico2-kes-agentd.service.d",
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "external service override blocks upgrade recovery",
                ));
            }
        }
    }
    trusted_ancestry(Path::new(SERVICE_GATE))?;
    match fs::symlink_metadata(SERVICE_GATE) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
        Ok(meta)
            if meta.file_type().is_symlink()
                && meta.uid() == 0
                && meta.gid() == 0
                && fs::read_link(SERVICE_GATE)? == Path::new("/dev/null")
                && record.checkpoints.iter().any(|c| {
                    c.name == "upgrade-service-inhibit-starting"
                        && c.evidence == record.plan_digest.to_string()
                }) =>
        {
            Ok(true)
        }
        Ok(_) => Err(io::Error::other(
            "service mask is not owned by the original upgrade",
        )),
    }
}

fn inhibit_service(store: &RecordStore, record: &mut MaintenanceRecord) -> io::Result<()> {
    if !service_gate(record)? {
        record.checkpoints.push(checkpoint(
            "upgrade-service-inhibit-starting",
            record.plan_digest.to_string(),
        ));
        store.update(record)?;
        std::os::unix::fs::symlink("/dev/null", SERVICE_GATE)?;
        File::open("/etc/systemd/system")?.sync_all()?;
    }
    if !systemctl(&["daemon-reload"])?.status.success() {
        return Err(io::Error::other(
            "persistent upgrade service mask reload failed",
        ));
    }
    Ok(())
}

fn release_service_gate(record: &MaintenanceRecord) -> io::Result<()> {
    if service_gate(record)? {
        fs::remove_file(SERVICE_GATE)?;
        File::open("/etc/systemd/system")?.sync_all()?;
        if !systemctl(&["daemon-reload"])?.status.success() {
            return Err(io::Error::other(
                "upgrade service mask removal reload failed",
            ));
        }
    }
    Ok(())
}

fn can_abandon(checkpoints: &[MaintenanceCheckpoint]) -> bool {
    !checkpoints.iter().any(|c| {
        matches!(
            c.name.as_str(),
            "upgrade-publish-starting" | "upgrade-transfer-flushed"
        )
    }) && checkpoints
        .iter()
        .rev()
        .find(|c| {
            matches!(
                c.name.as_str(),
                "upgrade-transfer-starting" | "upgrade-transfer-not-started"
            )
        })
        .is_none_or(|c| c.name == "upgrade-transfer-not-started")
}

fn read_protected(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    trusted_ancestry(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err(io::Error::other("unsafe upgrade recovery evidence"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("upgrade evidence exceeds bound"));
    }
    Ok(bytes)
}

fn require_transfer(action: &HostAction, record: &MaintenanceRecord) -> io::Result<()> {
    let HostAction::Upgrade {
        serial: Some(serial),
        record: Some(path),
        ..
    } = action
    else {
        return Err(io::Error::other("original firmware target missing"));
    };
    if *path != Path::new("/var/lib/p2kesup/firmware").join(format!("{}.json", record.operation_id))
    {
        return Err(io::Error::other("original transfer identity differs"));
    }
    let value = serde_json::from_slice(&read_protected(path, 8 * 1024 * 1024)?)
        .map_err(io::Error::other)?;
    if !transfer_flushed(
        &value,
        &record.operation_id.to_string(),
        serial,
        record.image_digest.as_deref(),
    ) {
        return Err(io::Error::other(
            "original firmware transfer/flush is unproven; refusing replay or software rollback",
        ));
    }
    Ok(())
}

fn check_files(prior: &InstallationRegistry, target: &InstallationRegistry) -> io::Result<()> {
    for entry in &target.files {
        trusted_ancestry(&entry.path)?;
        if prior.role == InstallationRole::Primary
            && DEPLOYMENT
                .iter()
                .any(|(_, path)| entry.path == Path::new(path))
        {
            let old = prior
                .files
                .iter()
                .find(|e| e.path == entry.path)
                .ok_or_else(|| io::Error::other("original deployment entry missing"))?;
            if check_owned_file(&entry.path, Some(old)).is_ok() {
                continue;
            }
        }
        check_owned_file(&entry.path, Some(entry))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish(
    plan: &HostPlan,
    original: &HostAction,
    prior: &InstallationRegistry,
    target: &InstallationRegistry,
    bundle: &VerifiedBundle,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    let selection = target
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("target tuple missing"))?;
    if !same_selection(selection, bundle.selection()) {
        return Err(io::Error::other("target tuple is not authenticated"));
    }
    check_files(prior, target)?;
    let old = prior
        .current
        .as_ref()
        .ok_or_else(|| io::Error::other("prior tuple missing"))?;
    let generation = Path::new(ROOT)
        .join("generations")
        .join(record.plan_digest.to_string());
    verify_generation(&generation, selection)?;
    let link = Path::new("generations").join(record.plan_digest.to_string());
    let current = Path::new(ROOT).join("current");
    let (_, old_link): (ReleaseSelection, PathBuf) = serde_json::from_str(
        record
            .pre_observations
            .first()
            .ok_or_else(|| io::Error::other("original generation missing"))?,
    )
    .map_err(io::Error::other)?;
    let metadata = fs::symlink_metadata(&current)?;
    let observed = fs::read_link(&current)?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || (observed != link && observed != old_link)
    {
        return Err(io::Error::other(
            "current generation is neither original nor target",
        ));
    }
    let bytes = serde_json::to_vec_pretty(target).map_err(io::Error::other)?;
    let prior_bytes = serde_json::to_vec_pretty(prior).map_err(io::Error::other)?;
    let current_registry = installation_registry()?;
    let current_bytes = serde_json::to_vec_pretty(&current_registry).map_err(io::Error::other)?;
    if current_bytes != bytes && current_bytes != prior_bytes {
        return Err(io::Error::other("registry is neither original nor target"));
    }
    if prior.role == InstallationRole::Primary {
        check_pin(original)?;
        if firmware_changes(prior, target)? {
            require_transfer(original, record)?;
        }
        service_gate(record)?;
        let state = observed_service_state_inner(false)?;
        if service_state_matches(&state, "active") {
            let pid: u32 = state
                .split(';')
                .find_map(|s| s.strip_prefix("pid="))
                .ok_or_else(|| io::Error::other("service PID missing"))?
                .parse()
                .map_err(io::Error::other)?;
            let executable = fs::canonicalize(format!("/proc/{pid}/exe"))?;
            let known = [old, selection].iter().any(|s| {
                component(s, "daemon").is_ok_and(|c| {
                    executable
                        == Path::new(ROOT)
                            .join("components/daemon")
                            .join(c.digest.to_string())
                            .join("pico2-kes-agentd")
                })
            });
            if !known {
                return Err(io::Error::other(
                    "running service is not an original or selected daemon",
                ));
            }
            if !systemctl(&["stop", "pico2-kes-agentd.service"])?
                .status
                .success()
            {
                return Err(io::Error::other("upgrade daemon stop failed"));
            }
        }
        if service_state("pico2-kes-agentd.service")? != "inactive" {
            return Err(io::Error::other("daemon is not quiescent"));
        }
        inhibit_service(store, record)?;
    }
    record.checkpoints.push(checkpoint(
        "upgrade-publish-starting",
        plan.approved_digest.clone(),
    ));
    store.update(record)?;
    *effects = true;
    if prior.role == InstallationRole::Primary {
        let deployment = component(selection, "deployment")?;
        for (name, destination) in DEPLOYMENT {
            let entry = target
                .files
                .iter()
                .find(|e| e.path == Path::new(destination))
                .ok_or_else(|| io::Error::other("target deployment missing"))?;
            if check_owned_file(&entry.path, Some(entry)).is_ok() {
                continue;
            }
            let old_entry = prior
                .files
                .iter()
                .find(|e| e.path == entry.path)
                .ok_or_else(|| io::Error::other("original deployment missing"))?;
            check_owned_file(&entry.path, Some(old_entry))?;
            let source = Path::new(ROOT)
                .join("components/deployment")
                .join(deployment.digest.to_string())
                .join(name);
            let temporary = entry
                .path
                .with_file_name(format!(".p2kesup-upgrade-{}-{name}", plan.plan_id));
            write_immutable(&source, &temporary, entry.mode)?;
            let mut proof = entry.clone();
            proof.path = temporary.clone();
            check_owned_file(&temporary, Some(&proof))?;
            fs::rename(&temporary, &entry.path)?;
            File::open(entry.path.parent().unwrap())?.sync_all()?;
        }
        if !systemctl(&["daemon-reload"])?.status.success() {
            return Err(io::Error::other("upgrade systemd reload failed"));
        }
        let udev = if Path::new("/usr/bin/udevadm").exists() {
            "/usr/bin/udevadm"
        } else {
            "/usr/sbin/udevadm"
        };
        fixed_command(udev, &["control", "--reload-rules"])?;
    }
    if observed != link {
        let temporary = Path::new(ROOT).join(format!(".upgrade-{}", plan.plan_id));
        std::os::unix::fs::symlink(&link, &temporary)?;
        fs::rename(&temporary, &current)?;
        File::open(ROOT)?.sync_all()?;
    }
    if current_bytes != bytes {
        let temporary = Path::new("/var/lib/p2kesup").join(format!(".upgrade-{}", plan.plan_id));
        crate::files::publish_no_clobber(&temporary, &bytes, 0o644)?;
        fs::rename(&temporary, INSTALLATION_REGISTRY)?;
        File::open("/var/lib/p2kesup")?.sync_all()?;
    }
    record.checkpoints.push(checkpoint(
        "upgrade-activated",
        record.plan_digest.to_string(),
    ));
    store.update(record)?;
    verify_installed_ownership()?;
    if prior.role == InstallationRole::Primary {
        let HostAction::Upgrade {
            pre_state: Some(before),
            expected_service_state: Some(original_state),
            temporary_validation,
            ..
        } = original
        else {
            return Err(io::Error::other("original device review missing"));
        };
        if !service_state_matches(original_state, "active") && !temporary_validation {
            return Err(io::Error::other("temporary validation was not approved"));
        }
        release_service_gate(record)?;
        let result = (|| -> io::Result<()> {
            let state = observed_service_state(false)?;
            run_service(ServiceAction::Start, &state, effects)?;
            let (serial, _, _, socket) = commissioned_config()?;
            let after = normal_snapshot(&socket)?;
            let firmware = component(selection, "firmware")?;
            let storage = before.device_info["storage_version"]
                .as_u64()
                .ok_or_else(|| io::Error::other("original storage version missing"))?;
            maintenance::postcheck(before, &after, &firmware.build_id, storage)
                .map_err(io::Error::other)?;
            maintenance::admit_firmware(&after, &serial, selection, bundle.manifest())
                .map_err(io::Error::other)?;
            if after.device_info["version"] != firmware.version
                || after.device_info["source_commit"] != firmware.source_commit
            {
                return Err(io::Error::other(
                    "live firmware provenance differs from selected release",
                ));
            }
            record
                .post_observations
                .push(serde_json::to_string(&after).map_err(io::Error::other)?);
            Ok(())
        })();
        if result.is_err() || service_state_matches(original_state, "inactive") {
            let mut gate = if result.is_err() {
                inhibit_service(store, record)
            } else {
                Ok(())
            };
            let stopped = (|| -> io::Result<()> {
                if !systemctl(&["stop", "pico2-kes-agentd.service"])?
                    .status
                    .success()
                    || service_state("pico2-kes-agentd.service")? != "inactive"
                {
                    return Err(io::Error::other("validation daemon could not be stopped"));
                }
                Ok(())
            })();
            if result.is_ok() && stopped.is_err() {
                gate = inhibit_service(store, record);
            }
            if gate.is_err() || stopped.is_err() {
                return Err(io::Error::other(format!(
                    "validation: {result:?}; persistent service inhibition: {gate:?}; stop: {stopped:?}"
                )));
            }
        }
        result?;
        record
            .post_observations
            .push(final_service_observation(original_state)?);
    }
    Ok(if prior.role == InstallationRole::Backup { "Backup host upgraded; complete host tuple verified, no device action performed." } else { "System upgraded; complete host tuple, live firmware, pinned identity and retained forward state verified; original service state restored." }.into())
}

fn original(
    store: &RecordStore,
    operation_id: &str,
    digest: &str,
) -> io::Result<(MaintenanceRecord, HostAction, ReleaseSelection)> {
    let id = OperationId::parse_hex(operation_id)
        .map_err(|_| io::Error::other("invalid original operation"))?;
    let record = store.load(&id)?.supported()?;
    if record.action != "upgrade" || record.plan_digest.to_string() != digest {
        return Err(io::Error::other("original upgrade identity differs"));
    }
    let action: HostAction = serde_json::from_str(
        record
            .approved_scope
            .first()
            .ok_or_else(|| io::Error::other("original approval missing"))?,
    )
    .map_err(io::Error::other)?;
    if !matches!(action, HostAction::Upgrade { .. }) {
        return Err(io::Error::other("original action is not an upgrade"));
    }
    let (previous, _): (ReleaseSelection, PathBuf) = serde_json::from_str(
        record
            .pre_observations
            .first()
            .ok_or_else(|| io::Error::other("original tuple missing"))?,
    )
    .map_err(io::Error::other)?;
    Ok((record, action, previous))
}

pub fn trusted_upgrade_recovery_manager(operation_id: &str, digest: &str) -> io::Result<PathBuf> {
    let (_, _, previous) = original(&existing_record_store()?, operation_id, digest)?;
    let manager = component(&previous, "manager")?;
    let path = Path::new(ROOT)
        .join("components/manager")
        .join(manager.digest.to_string())
        .join("p2kesup");
    trusted_ancestry(&path)?;
    check_owned_file(
        &path,
        Some(&ManagedFile {
            path: path.clone(),
            digest: manager.entrypoint_digest,
            mode: 0o755,
            owner: 0,
            group: 0,
            component: "manager".into(),
        }),
    )?;
    Ok(path)
}

pub fn review_upgrade_recovery(operation_id: &str, digest: &str) -> io::Result<HostAction> {
    let (_, action, _) = original(&existing_record_store()?, operation_id, digest)?;
    let primary = matches!(
        action,
        HostAction::Upgrade {
            expected_service_state: Some(_),
            ..
        }
    );
    Ok(HostAction::UpgradeRecovery {
        operation_id: operation_id.into(),
        original_plan_digest: digest.into(),
        expected_service_state: if primary {
            Some(observed_service_state_inner(false)?)
        } else {
            None
        },
        temporary_validation: false,
    })
}

pub(super) fn recover(plan: &HostPlan, store: &RecordStore) -> io::Result<()> {
    let HostAction::UpgradeRecovery {
        operation_id,
        original_plan_digest,
        expected_service_state,
        temporary_validation,
    } = &plan.action
    else {
        return Err(io::Error::other("invalid upgrade recovery"));
    };
    let (mut record, action, _) = original(store, operation_id, original_plan_digest)?;
    if record.outcome == "completed" {
        println!("Original upgrade already completed; no work repeated.");
        return Ok(());
    }
    if maintenance_outcome_allows_new_action(&record.outcome) {
        return Err(io::Error::other(
            "original upgrade is resolved without completion; a new reviewed upgrade is permitted",
        ));
    }
    let HostAction::Upgrade {
        expected_registry_digest,
        expected_service_state: original_service,
        candidate_accepted,
        ..
    } = &action
    else {
        unreachable!()
    };
    let actual_service = if original_service.is_some() {
        Some(observed_service_state_inner(false)?)
    } else {
        None
    };
    if actual_service != *expected_service_state {
        return Err(io::Error::other("service changed after recovery review"));
    }
    if original_service.is_some() && !temporary_validation {
        return Err(io::Error::other(
            "forward recovery validation requires explicit approval",
        ));
    }
    if can_abandon(&record.checkpoints) {
        if let HostAction::Upgrade {
            record: Some(path), ..
        } = &action
        {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::other(
                        "transfer evidence exists; refusing pre-transfer recovery",
                    ));
                }
            }
        }
        if registry_digest()? != *expected_registry_digest {
            return Err(io::Error::other("pre-transfer registry changed"));
        }
        verify_installed_ownership()?;
        let (_, old_link): (ReleaseSelection, PathBuf) =
            serde_json::from_str(&record.pre_observations[0]).map_err(io::Error::other)?;
        if fs::read_link(Path::new(ROOT).join("current"))? != old_link {
            return Err(io::Error::other("pre-transfer generation changed"));
        }
        let mut effects = false;
        if let Some(state) = original_service {
            release_service_gate(&record)?;
            let now = observed_service_state(false)?;
            if service_state_matches(state, "active") && service_state_matches(&now, "inactive") {
                run_service(ServiceAction::Start, &now, &mut effects)?;
            }
            record
                .post_observations
                .push(final_service_observation(state)?);
        }
        record.checkpoints.push(checkpoint(
            "upgrade-not-transferred",
            plan.approved_digest.clone(),
        ));
        record.outcome = "failed-known".into();
        store.update(&record)?;
        println!(
            "Original upgrade stopped before transfer/activation; original installation and service retained. Run a new upgrade when ready."
        );
        return Ok(());
    }
    let staging = Path::new("/var/lib/p2kesup/staging").join(operation_id);
    let prior_bytes = read_protected(&staging.join("prior-registry.json"), 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(&prior_bytes)) != *expected_registry_digest {
        return Err(io::Error::other("original registry evidence changed"));
    }
    let prior: InstallationRegistry =
        serde_json::from_slice(&prior_bytes).map_err(io::Error::other)?;
    let target_bytes = read_protected(&staging.join("target-registry.json"), 1024 * 1024)?;
    let target_digest = format!("{:x}", Sha256::digest(&target_bytes));
    if !record
        .checkpoints
        .iter()
        .any(|c| c.name == "upgrade-ready" && c.evidence == target_digest)
    {
        return Err(io::Error::other("prepared target registry is unproven"));
    }
    let target: InstallationRegistry =
        serde_json::from_slice(&target_bytes).map_err(io::Error::other)?;
    if prior.schema_version != 1 || target.schema_version != 1 || prior.role != target.role {
        return Err(io::Error::other("original/target role or schema differs"));
    }
    let bundle = release::verify_bundle(
        &staging.join("authorization"),
        if *candidate_accepted {
            release::Admission::AttendedCandidate
        } else {
            release::Admission::Qualified
        },
    )?;
    let selected = record
        .selected
        .as_ref()
        .ok_or_else(|| io::Error::other("original target missing"))?;
    if !same_selection(selected, bundle.selection()) {
        return Err(io::Error::other("original authenticated target changed"));
    }
    if prior.role == InstallationRole::Primary && firmware_changes(&prior, &target)? {
        require_transfer(&action, &record)?;
        if !record
            .checkpoints
            .iter()
            .any(|c| c.name == "upgrade-transfer-flushed")
        {
            let path = Path::new("/var/lib/p2kesup/firmware").join(format!("{operation_id}.json"));
            record.checkpoints.push(checkpoint(
                "upgrade-transfer-flushed",
                path.display().to_string(),
            ));
            store.update(&record)?;
        }
    }
    let mut effects = false;
    match finish(
        plan,
        &action,
        &prior,
        &target,
        &bundle,
        store,
        &mut record,
        &mut effects,
    ) {
        Ok(message) => {
            println!("{message}");
            record.post_observations.push(message);
            record.outcome = "completed".into();
            store.update(&record)
        }
        Err(error) => {
            record.post_observations.push(error.to_string());
            record.outcome = "uncertain".into();
            store.update(&record)?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_proven_prewrite_cancellation_can_restore_the_old_service() {
        let mut history = vec![checkpoint("upgrade-ready", "prepared".into())];
        assert!(can_abandon(&history));
        history.push(checkpoint("upgrade-transfer-starting", "original".into()));
        assert!(!can_abandon(&history));
        history.push(checkpoint(
            "upgrade-transfer-not-started",
            "exited before write-ahead intent".into(),
        ));
        assert!(can_abandon(&history));
        history.push(checkpoint(
            "upgrade-transfer-starting",
            "unexpected second handoff".into(),
        ));
        assert!(!can_abandon(&history));
        history.push(checkpoint("upgrade-transfer-not-started", "exited".into()));
        history.push(checkpoint("upgrade-transfer-flushed", "original".into()));
        assert!(!can_abandon(&history));
        assert!(!can_abandon(&[checkpoint(
            "upgrade-publish-starting",
            "backup host".into()
        )]));
    }

    #[test]
    fn upgrade_plans_reject_partial_primary_identity() {
        let action = HostAction::Upgrade {
            bundle: PathBuf::from("/tmp/authenticated-bundle"),
            manifest_digest: "a".repeat(64),
            candidate_accepted: true,
            expected_registry_digest: "b".repeat(64),
            expected_service_state: None,
            pre_state: None,
            temporary_validation: false,
            serial: Some("a".repeat(16)),
            device_id: None,
            identity_public_key: None,
            record: None,
        };
        let plan = HostPlan::new(action).unwrap();
        assert!(plan.validate().is_err());
    }
}
