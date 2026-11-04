//! Attended, forward-only board wipe and host-state archival.
use super::*;
use crate::manager::{maintenance::WipeEvidence, setup};

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(super) fn valid_evidence(serial: &str, e: &WipeEvidence) -> bool {
    let hex = |value: &str, size| {
        value.len() == size
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    hex(&e.config_sha256, 64)
        && e.state_directory.is_absolute()
        && e.state_directory.components().count() >= 3
        && e.state_directory
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && e.device_info["usb_serial"] == serial
        && e.security["usb_serial"] == serial
        && e.security["profile"] == "unlocked"
        && e.security["redundancy_ok"] == true
        && e.security["critical"] == 0
        && e.security["bootkey0"]
            == "0000000000000000000000000000000000000000000000000000000000000000"
        && e.status["commissioning_state"] == "committed"
        && e.status["health"] == "ready"
        && e.status["revision"].as_u64().is_some()
        && e.device_info["device_id"]
            .as_str()
            .is_some_and(|id| hex(id, 32))
        && e.status["device_id"] == e.device_info["device_id"]
        && e.inventory["device_id"] == e.device_info["device_id"]
        && e.inventory["revision"].as_u64().is_some()
        && e.inventory["pools"].as_array().is_some_and(|p| {
            p.len() <= 64
                && p.iter().all(|pool| {
                    pool["pool_id"].as_str().is_some_and(|s| {
                        s.len() == 56
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }) && pool["incarnation_id"].as_str().is_some_and(|s| {
                        s.len() == 32
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }) && pool["revision"].as_u64().is_some()
                })
        })
        && e.status["receipt_pending"] == false
}

fn observed(serial: &str) -> io::Result<WipeEvidence> {
    let (config_sha256, bytes) =
        setup::current_config_review()?.ok_or_else(|| denied("wipe configuration unavailable"))?;
    let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let state_directory = PathBuf::from(
        config["state_directory"]
            .as_str()
            .ok_or_else(|| denied("state directory unavailable"))?,
    );
    let normal = config["device"]["id"].is_string();
    let (socket, peer, pinned_id) = if normal {
        let (configured_serial, device, _, socket) = commissioned_config()?;
        if configured_serial != serial
            || service_state("pico2-kes-agentd.service")? != "active"
            || service_state("pico2-kes-agent-commission.service")? != "inactive"
        {
            return Err(denied(
                "wipe requires the sole normal daemon for the configured board",
            ));
        }
        (
            socket,
            (
                authenticated_running_daemon_pid()?,
                setup::service_identity()?.0,
            ),
            Some(device),
        )
    } else {
        (
            setup::commissioning_socket(serial)?,
            restricted_daemon_identity()?,
            None,
        )
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let info = setup::observation(&socket, "device.info", deadline, peer)?;
    let security = setup::observation(&socket, "device.security", deadline, peer)?;
    let status = setup::observation(&socket, "device.status", deadline, peer)?;
    let inventory = setup::observation(&socket, "device.inventory", deadline, peer)?;
    let inventory_after = setup::observation(&socket, "device.inventory", deadline, peer)?;
    let after = setup::observation(&socket, "device.status", deadline, peer)?;
    let current_peer = if normal {
        (
            authenticated_running_daemon_pid()?,
            setup::service_identity()?.0,
        )
    } else {
        restricted_daemon_identity()?
    };
    if status != after
        || inventory != inventory_after
        || current_peer != peer
        || setup::current_config_review()?.map(|(digest, _)| digest) != Some(config_sha256.clone())
        || pinned_id
            .as_ref()
            .is_some_and(|pin| info["device_id"] != *pin)
    {
        return Err(denied(
            "device or configuration changed during wipe admission",
        ));
    }
    Ok(WipeEvidence {
        config_sha256,
        state_directory,
        device_info: info,
        security,
        inventory,
        status,
    })
}

fn done(record: &MaintenanceRecord, name: &str) -> bool {
    record.checkpoints.iter().any(|c| c.name == name)
}
fn mark(
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    name: &str,
    evidence: String,
) -> io::Result<()> {
    record.checkpoints.push(checkpoint(name, evidence));
    store.update(record)
}

fn archive_move(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let src = fs::symlink_metadata(source);
    let dst = fs::symlink_metadata(target);
    match (src, dst) {
        (Err(a), Err(b))
            if a.kind() == io::ErrorKind::NotFound && b.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        (Err(a), Ok(_)) if a.kind() == io::ErrorKind::NotFound => return Ok(()),
        (Ok(meta), Err(b)) if b.kind() == io::ErrorKind::NotFound => {
            if meta.file_type().is_symlink() || !(meta.is_file() || meta.is_dir()) {
                return Err(denied("unsafe host state to archive"));
            }
        }
        _ => return Err(denied("archive collision or inaccessible source")),
    }
    let src = std::ffi::CString::new(source.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let dst = std::ffi::CString::new(target.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // shortcut: archive moves require one filesystem; add verified copy-and-unlink if split mounts are supported.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    File::open(source.parent().unwrap())?.sync_all()?;
    File::open(target.parent().unwrap())?.sync_all()
}

fn tool_record_verified(path: &Path, serial: &str) -> io::Result<bool> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > 8 * 1024 * 1024
    {
        return Err(denied("unsafe erase record"));
    }
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    Ok(verified_erase(&v, serial))
}

fn verified_erase(v: &serde_json::Value, serial: &str) -> bool {
    let erased = serde_json::json!({"erased_range":{"start":0x10100000u64,"end":0x10308000u64}});
    v["schema_version"] == 2
        && v["serial"] == serial
        && v["pending"].is_null()
        && v["actions"].as_array().is_some_and(|a| {
            a.iter().any(|x| {
                x["step"] == "erase_state"
                    && x["state"] == "verified"
                    && x["observed"] == erased
                    && x["expected"] == erased
            })
        })
}

fn advance(
    serial: &str,
    expected: &WipeEvidence,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    if !done(record, "wipe-admitted") {
        if !valid_evidence(serial, expected) || observed(serial)? != *expected {
            return Err(denied("board or revision changed after wipe review"));
        }
        mark(store, record, "wipe-admitted", serial.into())?;
    }
    if !done(record, "wipe-erased") {
        checked_service()?;
        ensure_no_commission_overrides()?;
        if service_state("pico2-kes-agent-commission.service")? == "active" {
            verify_commissioning_file(&commissioning_unit()?)?;
        }
        *effects = true;
        for unit in [
            "pico2-kes-agentd.service",
            "pico2-kes-agent-commission.service",
        ] {
            if service_state(unit)? != "inactive" && !systemctl(&["stop", unit])?.status.success() {
                return Err(io::Error::other("cannot stop service for wipe"));
            }
            if service_state(unit)? != "inactive" {
                return Err(denied("service not stopped"));
            }
        }
        if !done(record, "wipe-services-stopped") {
            mark(
                store,
                record,
                "wipe-services-stopped",
                "both daemon services stopped".into(),
            )?;
        }
    }
    let archive = Path::new("/var/lib/p2kesup/archive");
    root_directory(archive, 0o700)?;
    let dir = archive.join(record.operation_id.to_string());
    root_directory(&dir, 0o700)?;
    if !done(record, "wipe-archived") {
        let config = Path::new("/etc/pico2-kes-agent/config.json");
        let archived_config = dir.join("config.json");
        trusted_ancestry(config)?;
        trusted_ancestry(&expected.state_directory)?;
        let retained = if fs::symlink_metadata(config).is_ok() {
            config
        } else {
            &archived_config
        };
        if setup::review_public_input(retained)?.sha256 != expected.config_sha256 {
            return Err(denied("configuration changed since wipe approval"));
        }
        match fs::symlink_metadata(&expected.state_directory) {
            Ok(meta)
                if meta.is_dir()
                    && meta.uid() == setup::service_identity()?.0
                    && meta.mode() & 0o077 == 0 => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(denied("unsafe configured agent state directory")),
        }
        *effects = true;
        archive_move(
            Path::new("/etc/pico2-kes-agent/config.json"),
            &dir.join("config.json"),
        )?;
        archive_move(&expected.state_directory, &dir.join("agent-state"))?;
        mark(store, record, "wipe-archived", dir.display().to_string())?;
    }
    let tool_record = dir.join("erase.json");
    if !done(record, "wipe-erased") {
        let recorded = match fs::symlink_metadata(&tool_record) {
            Ok(_) => {
                if !tool_record_verified(&tool_record, serial)? {
                    return Err(denied(
                        "erase outcome uncertain; retain original record, never replay",
                    ));
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        if !recorded {
            let tool = trusted_firmware_tool()?;
            let registry = installation_registry()?;
            let selected = registry
                .current
                .as_ref()
                .ok_or_else(|| denied("selected tool unavailable"))?;
            let component = selected
                .components
                .iter()
                .find(|c| c.component == "tool")
                .ok_or_else(|| denied("selected tool unavailable"))?;
            let tool_dir = PathBuf::from(format!(
                "/usr/lib/pico2-kes-agent/components/tool/{}",
                component.digest
            ));
            for item in registry
                .files
                .iter()
                .filter(|f| f.path.starts_with(&tool_dir))
            {
                trusted_ancestry(&item.path)?;
                check_owned_file(&item.path, Some(item))?;
            }
            let picotool = tool_dir.join("picotool");
            let entry = registry
                .files
                .iter()
                .find(|f| {
                    f.path == picotool
                        && f.component == "tool"
                        && f.digest == component.entrypoint_digest
                })
                .ok_or_else(|| denied("selected picotool unavailable"))?;
            check_owned_file(&picotool, Some(entry))?;
            let python = Path::new("/usr/bin/python3");
            trusted_ancestry(python)?;
            let m = fs::metadata(python)?;
            if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(denied("unsafe system Python"));
            }
            println!("Unplug the board, hold BOOTSEL, plug it back in, then press Enter.");
            if !matches!(
                read_confirmation(io::stdin().lock())?.as_str(),
                "\n" | "\r\n"
            ) {
                return Err(denied("BOOTSEL transition cancelled"));
            }
            mark(
                store,
                record,
                "wipe-erase-starting",
                tool_record.display().to_string(),
            )?;
            *effects = true;
            let status = Command::new(python)
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", tool_dir.display()))
                .env("LD_LIBRARY_PATH", tool_dir.join("runtime"))
                .arg("-I")
                .arg(tool)
                .arg("erase-state")
                .arg("--serial")
                .arg(serial)
                .arg("--record")
                .arg(&tool_record)
                .arg("--apply")
                .status()?;
            if !status.success() {
                return Err(io::Error::other(
                    "erase tool failed; original record must be recovered",
                ));
            }
            if !tool_record_verified(&tool_record, serial)? {
                return Err(denied("verified erase evidence unavailable"));
            }
        }
        mark(
            store,
            record,
            "wipe-erased",
            "tool verified erased state region".into(),
        )?;
    }
    if !done(record, "wipe-blank-postcheck") {
        println!("Unplug and reconnect the board in application mode, then press Enter.");
        if !matches!(
            read_confirmation(io::stdin().lock())?.as_str(),
            "\n" | "\r\n"
        ) {
            return Err(denied("application transition cancelled"));
        }
        let (uid, gid) = setup::service_identity()?;
        agent_directory(Path::new("/var/lib/pico2-kes-agent"), 0o700, uid, gid)?;
        let spec = crate::manager::config_builder::CommissioningSpec {
            usb_serial: serial.into(),
            ..Default::default()
        };
        let bytes = crate::manager::config_builder::build_commissioning_bytes(&spec)?;
        let candidate = dir.join("commission-candidate.json");
        match crate::files::publish_no_clobber(&candidate, &bytes, 0o600) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let meta = fs::symlink_metadata(&candidate)?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
            || setup::review_public_input(&candidate)?.sha256
                != format!("{:x}", Sha256::digest(&bytes))
        {
            return Err(denied("commissioning candidate changed"));
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let config = Path::new("/etc/pico2-kes-agent/config.json");
        match fs::symlink_metadata(config) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut runtime = false;
                setup::apply_configuration(
                    &candidate,
                    &digest,
                    None,
                    true,
                    (&[], &[]),
                    effects,
                    &mut runtime,
                )?;
            }
            Ok(meta)
                if meta.is_file()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0
                    && meta.nlink() == 1
                    && setup::review_public_input(config)?.sha256 == digest => {}
            Ok(_) => return Err(denied("unexpected commissioning configuration")),
            Err(error) => return Err(error),
        }
        if service_state("pico2-kes-agent-commission.service")? != "active" {
            let state = observed_service_state(true)?;
            run_commission_service(true, &state, effects)?;
        }
        let socket = setup::commissioning_socket(serial)?;
        let peer = restricted_daemon_identity()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let info = setup::observation(&socket, "device.info", deadline, peer)?;
        let security = setup::observation(&socket, "device.security", deadline, peer)?;
        let status = setup::observation(&socket, "device.status", deadline, peer)?;
        if info["usb_serial"] != serial
            || info["device_id"] != serde_json::Value::Null
            || [
                "version",
                "build_id",
                "source_commit",
                "storage_version",
                "protocol_major",
            ]
            .iter()
            .any(|field| info[*field].is_null() || info[*field] != expected.device_info[*field])
            || security["usb_serial"] != serial
            || security["profile"] != "unlocked"
            || security["storage_blank_at_boot"] != true
            || status["commissioning_state"] != "blank"
            || status["health"] != "ready"
            || restricted_daemon_identity()? != peer
        {
            return Err(denied("blank-at-boot postcheck unavailable"));
        }
        mark(store, record, "wipe-blank-postcheck", serial.into())?;
    }
    Ok(format!(
        "Board {serial} erased and observed blank; host state archived at {}",
        dir.display()
    ))
}

pub(super) fn apply(
    serial: &str,
    expected: &WipeEvidence,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    advance(serial, expected, store, record, effects)
}

pub(super) fn recover(plan: &HostPlan, store: &RecordStore) -> io::Result<()> {
    let HostAction::WipeRecovery {
        operation_id,
        original_plan_digest,
    } = &plan.action
    else {
        unreachable!()
    };
    let id = OperationId::parse_hex(operation_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid wipe operation ID"))?;
    let mut record = store.load(&id)?.supported()?;
    if record.action != "wipe-board"
        || record.plan_digest.to_string() != *original_plan_digest
        || record.outcome == "completed"
        || record.approved_scope.len() != 1
    {
        return Err(denied("wipe recovery does not match original record"));
    }
    let original: HostAction =
        serde_json::from_str(&record.approved_scope[0]).map_err(io::Error::other)?;
    let HostAction::WipeBoard {
        serial,
        expected_state,
    } = original
    else {
        return Err(denied("invalid original wipe scope"));
    };
    mark(
        store,
        &mut record,
        "wipe-recovery-approval",
        plan.approved_digest.clone(),
    )?;
    let mut effects = true;
    match advance(&serial, &expected_state, store, &mut record, &mut effects) {
        Ok(evidence) => {
            record.post_observations.push(evidence);
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
    use serde_json::json;

    #[test]
    fn wipe_requires_exact_unlocked_serial_and_revision() {
        let serial = "0123456789abcdef";
        let mut evidence = WipeEvidence {
            config_sha256: "0".repeat(64),
            state_directory: "/var/lib/pico2-kes-agent".into(),
            device_info: json!({"usb_serial":serial,"device_id":"a".repeat(32)}),
            security: json!({"usb_serial":serial,"profile":"unlocked","redundancy_ok":true,"critical":0,"bootkey0":"0".repeat(64)}),
            status: json!({"device_id":"a".repeat(32),"commissioning_state":"committed","health":"ready","revision":3,"receipt_pending":false}),
            inventory: json!({"device_id":"a".repeat(32),"revision":4,"pools":[]}),
        };
        assert!(valid_evidence(serial, &evidence));
        evidence.security["profile"] = json!("locked");
        assert!(!valid_evidence(serial, &evidence));
        evidence.security["profile"] = json!("unlocked");
        evidence.inventory["revision"] = serde_json::Value::Null;
        assert!(!valid_evidence(serial, &evidence));
        assert!(!valid_evidence("fedcba9876543210", &evidence));
    }

    #[test]
    fn recovery_only_accepts_verified_original_erase() {
        let erased = json!({"erased_range":{"start":0x10100000u64,"end":0x10308000u64}});
        let mut record = json!({"schema_version":2,"serial":"0123456789abcdef","pending":null,
            "actions":[{"step":"erase_state","state":"verified","observed":erased,"expected":erased}]});
        assert!(verified_erase(&record, "0123456789abcdef"));
        assert!(!verified_erase(&record, "fedcba9876543210"));
        record["pending"] = json!({"step":"erase_state"});
        assert!(!verified_erase(&record, "0123456789abcdef"));
        record["pending"] = serde_json::Value::Null;
        record["actions"][0]["state"] = json!("pending");
        assert!(!verified_erase(&record, "0123456789abcdef"));
    }

    #[test]
    fn archive_move_is_no_clobber_and_resumes_after_rename() {
        let root = std::env::temp_dir().join(format!(
            "p2kesup-archive-{}",
            crate::manager::lifecycle::new_admission_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("state");
        let target = root.join("archived");
        fs::write(&source, b"original").unwrap();
        fs::write(&target, b"retained").unwrap();
        assert!(archive_move(&source, &target).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"original");
        assert_eq!(fs::read(&target).unwrap(), b"retained");
        fs::remove_file(&target).unwrap();
        archive_move(&source, &target).unwrap();
        archive_move(&source, &target).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        fs::remove_dir_all(root).unwrap();
    }
}
