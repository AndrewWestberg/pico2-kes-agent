//! Attended handoff to the existing firmware provisioner; it owns OTP records.
use super::{
    host,
    model::{InstallationRole, MaintenanceRecord},
    records::RecordStore,
    release::{self, Admission},
    setup::{self, PublicInput},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Preview,
    Reopen,
    Prepare,
    Enable,
    Lock,
    Resume,
    Reconcile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: Action,
    pub bundle: PathBuf,
    pub manifest_digest: String,
    pub candidate_accepted: bool,
    pub original_operation: Option<String>,
    pub serial: String,
    pub evidence: Option<PublicInput>,
    pub normal_state: String,
    pub commissioning_state: String,
    pub stop_normal: bool,
    pub stop_commissioning: bool,
}

fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
const MAX_TOOL_RECORD_BYTES: u64 = 8 * 1024 * 1024;
fn requires_blank_admission(action: Action) -> bool {
    matches!(action, Action::Enable | Action::Lock)
}
fn blank_security(security: &serde_json::Value, serial: &str) -> bool {
    security["usb_serial"] == serial && security["storage_blank_at_boot"] == true
}
impl Request {
    pub fn validate(&self) -> io::Result<()> {
        if self
            .original_operation
            .as_ref()
            .is_some_and(|s| !hex(s, 32))
            || (matches!(
                self.action,
                Action::Resume | Action::Reconcile | Action::Reopen
            ) != self.original_operation.is_some())
            || !self.bundle.is_absolute()
            || self
                .bundle
                .components()
                .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
            || !hex(&self.serial, 16)
            || !hex(&self.manifest_digest, 64)
            || (matches!(
                self.action,
                Action::Prepare | Action::Enable | Action::Lock | Action::Resume
            ) && self.evidence.is_none())
            || (requires_blank_admission(self.action) && !self.stop_commissioning)
            || self.evidence.as_ref().is_some_and(|e| {
                !hex(&e.sha256, 64)
                    || !e.path.is_absolute()
                    || e.path
                        .components()
                        .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
            })
            || [&self.normal_state, &self.commissioning_state]
                .iter()
                .any(|s| {
                    s.is_empty() || s.len() > 512 || !s.bytes().all(|b| (32..127).contains(&b))
                })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid provisioning request",
            ));
        }
        Ok(())
    }
}

fn record_path(serial: &str) -> PathBuf {
    Path::new("/var/lib/p2kesup/provisioning").join(format!("{serial}.json"))
}

fn original(path: &Path) -> io::Result<Option<serde_json::Value>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > MAX_TOOL_RECORD_BYTES
    {
        return Err(denied("unsafe original provisioning record"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOOL_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TOOL_RECORD_BYTES {
        return Err(denied("original record too large"));
    }
    Ok(Some(
        serde_json::from_slice(&bytes).map_err(io::Error::other)?,
    ))
}

fn check_record(
    action: Action,
    serial: &str,
    record: Option<&serde_json::Value>,
) -> io::Result<()> {
    if action == Action::Prepare && record.is_some() {
        return Err(denied("original record exists; never replay preparation"));
    }
    if matches!(
        action,
        Action::Enable | Action::Lock | Action::Resume | Action::Reconcile | Action::Reopen
    ) {
        let r = record.ok_or_else(|| denied("original provisioning record is missing"))?;
        if r["schema_version"] != 2 || r["serial"] != serial {
            return Err(denied(
                "original provisioning record identity or schema mismatch",
            ));
        }
        if matches!(action, Action::Enable | Action::Lock | Action::Resume)
            && !r["pending"].is_null()
        {
            return Err(denied(
                "pending uncertain write blocks advancement and replay",
            ));
        }
        match action {
            Action::Enable if r["completed_stage"] != "prepare" => {
                return Err(denied("prepare not observed complete"));
            }
            Action::Lock if r["completed_stage"] != "enable" => {
                return Err(denied("enable not observed complete"));
            }
            Action::Resume
                if !r["completed_stage"].is_null()
                    || r["observations"].as_array().map(|v| v.len()) != Some(2) =>
            {
                return Err(denied("not the admitted pre-OTP checkpoint"));
            }
            Action::Reconcile if r["pending"]["step"] != "page2_page63_permissions" => {
                return Err(denied("no admitted permission-helper reconciliation"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Recovery can refer only to the original protected manager and tool records.
pub(super) fn recovery_matches(
    request: &Request,
    original_record: &MaintenanceRecord,
) -> io::Result<bool> {
    request.validate()?;
    if request.original_operation.as_deref()
        != Some(original_record.operation_id.to_string().as_str())
        || original_record.action != "provisioning"
    {
        return Ok(false);
    }
    let path = record_path(&request.serial);
    let binding = format!("{}; manifest {}", path.display(), request.manifest_digest);
    if !original_record
        .checkpoints
        .iter()
        .any(|c| c.name == "provisioning-original" && c.evidence == binding)
    {
        return Ok(false);
    }
    host::trusted_ancestry(&path)?;
    let existing = original(&path)?;
    check_record(request.action, &request.serial, existing.as_ref())?;
    Ok(true)
}

fn run(command: &mut Command, label: &str) -> io::Result<()> {
    if command.status()?.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{label} failed or was interrupted; preserve the original record"
        )))
    }
}

/// Called under the host transaction lock with inherited terminal streams.
pub(super) fn apply(
    request: &Request,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
) -> io::Result<String> {
    request.validate()?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(denied("provisioning requires root"));
    }
    if !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) } != unsafe { libc::getpgrp() }
    {
        return Err(denied("provisioning requires a direct foreground terminal"));
    }
    let admission = if request.candidate_accepted {
        Admission::AttendedCandidate
    } else {
        Admission::Qualified
    };
    let bundle = release::verify_bundle(&request.bundle, admission)?;
    if bundle.selection().manifest_digest.to_string() != request.manifest_digest {
        return Err(denied("bundle changed after approval"));
    }
    host::check_platform(bundle.manifest())?;
    host::require_installed_tuple(&bundle)?;
    let registry = host::installation_registry()?;
    if registry.role != InstallationRole::Primary {
        return Err(denied("provisioning requires primary role"));
    }
    if let Some(evidence) = &request.evidence {
        setup::verify_public_inputs(std::slice::from_ref(evidence))?;
        if fs::metadata(&evidence.path)?.len() == 0 {
            return Err(denied("qualification evidence is empty"));
        }
    }
    let tool = host::trusted_firmware_tool()?;
    let artifact = bundle
        .manifest()
        .artifacts
        .iter()
        .find(|a| a.path == "tools/firmware.py")
        .ok_or_else(|| denied("firmware tool absent"))?;
    if !registry
        .files
        .iter()
        .any(|f| f.path == tool && f.digest.to_string() == artifact.sha256)
    {
        return Err(denied("firmware tool differs from authenticated bundle"));
    }
    let component = bundle
        .selection()
        .components
        .iter()
        .find(|c| c.component == "tool")
        .ok_or_else(|| denied("tool component absent"))?;
    let tool_dir =
        Path::new("/usr/lib/pico2-kes-agent/components/tool").join(component.digest.to_string());
    for file in registry
        .files
        .iter()
        .filter(|f| f.path.starts_with(&tool_dir))
    {
        host::trusted_ancestry(&file.path)?;
        host::check_owned_file(&file.path, Some(file))?;
    }
    let picotool = tool_dir.join("picotool");
    let entry = registry
        .files
        .iter()
        .find(|f| {
            f.path == picotool && f.component == "tool" && f.digest == component.entrypoint_digest
        })
        .ok_or_else(|| denied("selected picotool missing"))?;
    host::check_owned_file(&picotool, Some(entry))?;
    let cli = host::trusted_component("cli", "pico2-kes-agent-cli")?;
    let python = Path::new("/usr/bin/python3");
    host::trusted_ancestry(python)?;
    host::trusted_ancestry(&fs::canonicalize(python)?)?;
    let meta = fs::metadata(python)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(denied("unsafe system Python"));
    }
    host::root_directory(Path::new("/var/lib/p2kesup/provisioning"), 0o700)?;
    let tool_record = record_path(&request.serial);
    let existing = original(&tool_record)?;
    if request.original_operation.is_some() && !recovery_matches(request, record)? {
        return Err(denied(
            "original manager operation does not bind this record and bundle",
        ));
    }
    check_record(request.action, &request.serial, existing.as_ref())?;
    if request.action == Action::Reopen {
        println!(
            "Original protected firmware tool record {}:\n{}",
            tool_record.display(),
            serde_json::to_string_pretty(existing.as_ref().unwrap()).map_err(io::Error::other)?
        );
        return Ok(
            "original record reopened without modifying it; pending writes remain blocked".into(),
        );
    }
    setup::require_firmware_default_socket()?;
    let normal = host::observed_service_state(false)?;
    let commission = host::observed_service_state(true)?;
    if normal != request.normal_state || commission != request.commissioning_state {
        return Err(denied("daemon state changed after review"));
    }
    record.checkpoints.push(host::checkpoint(
        "provisioning-original",
        format!(
            "{}; manifest {}",
            tool_record.display(),
            request.manifest_digest
        ),
    ));
    record.checkpoints.push(host::checkpoint(
        "provisioning-review",
        format!(
            "normal: {normal}; commissioning: {commission}; qualification {:?}",
            request.evidence
        ),
    ));
    store.update(record)?;
    if requires_blank_admission(request.action) {
        let socket = setup::commissioning_socket(&request.serial)?;
        let peer = host::restricted_daemon_identity()?;
        setup::admit_commissioning_from_pid(&socket, &request.serial, &bundle, peer.0, peer.1)?;
        let security = setup::observation(
            &socket,
            "device.security",
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            peer,
        )?;
        setup::admit_commissioning_from_pid(&socket, &request.serial, &bundle, peer.0, peer.1)?;
        if !blank_security(&security, &request.serial)
            || host::restricted_daemon_identity()? != peer
            || host::observed_service_state(true)? != commission
        {
            return Err(denied(
                "fresh exact-serial blank application admission unavailable or changed",
            ));
        }
        record.checkpoints.push(host::checkpoint(
            "provisioning-blank-admission",
            format!(
                "serial {}; manifest {}; daemon pid {}; blank-at-boot and uncommissioned observed",
                request.serial, request.manifest_digest, peer.0
            ),
        ));
        store.update(record)?;
    }
    let mut effects = false;
    if request.stop_normal {
        let state = host::run_service(host::ServiceAction::Stop, &normal, &mut effects)?;
        record.checkpoints.push(host::checkpoint(
            "provisioning-service-stop",
            format!("approved normal service stop: {state}"),
        ));
        store.update(record)?;
    }
    if request.stop_commissioning {
        let state = host::pause_commission_service(&commission, &mut effects)?;
        record.checkpoints.push(host::checkpoint(
            "provisioning-service-stop",
            format!(
                "approved restricted service stop: {state}; unit retained for attended transitions"
            ),
        ));
        store.update(record)?;
    }
    let normal_now = host::service_state("pico2-kes-agentd.service")?;
    let commission_now = host::service_state("pico2-kes-agent-commission.service")?;
    if normal_now != "inactive"
        || (request.action != Action::Resume && commission_now != "inactive")
        || (request.action == Action::Resume && commission_now != "active")
    {
        return Err(denied(
            "required sole daemon state unavailable; no USB handoff",
        ));
    }
    if request.action == Action::Prepare {
        setup::commissioning_socket(&request.serial)?;
        let mut unit_changed = false;
        host::ensure_commission_handoff_unit(&mut unit_changed)?;
        if unit_changed {
            record.checkpoints.push(host::checkpoint("provisioning-service-unit", "restricted observation unit verified or installed and daemon reloaded without starting the service".into()));
            store.update(record)?;
        }
    }
    if request.action == Action::Resume {
        setup::commissioning_socket(&request.serial)?;
    }
    let make = || {
        let mut c = Command::new(python);
        c.env_clear()
            .env(
                "PATH",
                format!(
                    "{}:{}:/usr/bin:/bin",
                    tool_dir.display(),
                    cli.parent().unwrap().display()
                ),
            )
            .env("LD_LIBRARY_PATH", tool_dir.join("runtime"))
            .arg("-I")
            .arg(&tool);
        c
    };
    let firmware = bundle.root().join("firmware");
    run(
        make().arg("verify").arg("--bundle").arg(&firmware),
        "firmware verification",
    )?;
    if request.action != Action::Resume {
        if request.action == Action::Reconcile {
            println!(
                "The same board must already be available in BOOTSEL for this read-only assessment; do not reset or replay an uncertain write."
            );
        } else {
            println!(
                "With both daemon modes stopped, physically select the exact board in BOOTSEL before inspection."
            );
        }
        print!("Press Enter when the board is in BOOTSEL: ");
        io::stdout().flush()?;
        if !matches!(
            host::read_confirmation(io::stdin().lock())?.as_str(),
            "\n" | "\r\n"
        ) {
            return Err(denied("physical selection cancelled"));
        }
        if host::service_state("pico2-kes-agentd.service")? != "inactive"
            || host::service_state("pico2-kes-agent-commission.service")? != "inactive"
        {
            return Err(denied("daemon started during physical selection"));
        }
    }
    run(
        make().arg("inspect").arg("--serial").arg(&request.serial),
        "device inspection",
    )?;
    let stage = match request.action {
        Action::Enable => "enable",
        Action::Lock => "lock",
        _ => "prepare",
    };
    if request.action != Action::Reconcile {
        run(
            make()
                .arg("provision")
                .arg("--distribution")
                .arg("--stage")
                .arg(stage)
                .arg("--serial")
                .arg(&request.serial)
                .arg("--bundle")
                .arg(&firmware)
                .arg("--record")
                .arg(&tool_record),
            "read-only provisioning preview",
        )?;
    }
    if request.action == Action::Preview {
        return Ok("read-only preview only; BOOTSEL cannot prove flash or blank storage".into());
    }
    if let Some(evidence) = &request.evidence {
        println!(
            "Review qualification evidence {:?} (SHA-256 {}) against the observed hardware, picotool SHA-256 {}, provisioner SHA-256 {}, and authenticated image in the verified manifest. A4 remains physically unqualified unless independently qualified. No erase or record repair is offered.",
            evidence.path, evidence.sha256, entry.digest, artifact.sha256
        );
        if !host::ask_yes_no(&format!(
            "Is the physical, tool and image evidence qualified for board {}?",
            request.serial
        ))? {
            return Err(denied("matching qualification not confirmed"));
        }
        setup::verify_public_inputs(std::slice::from_ref(evidence))?;
    }
    if host::service_state("pico2-kes-agentd.service")? != "inactive"
        || host::service_state("pico2-kes-agent-commission.service")?
            != if request.action == Action::Resume {
                "active"
            } else {
                "inactive"
            }
    {
        return Err(denied("daemon ownership changed before tool handoff"));
    }
    setup::require_firmware_default_socket()?;
    check_record(
        request.action,
        &request.serial,
        original(&tool_record)?.as_ref(),
    )?;
    host::root_directory(Path::new("/var/lib/p2kesup/provisioning"), 0o700)?;
    record.checkpoints.push(host::checkpoint(
        "tool-handoff",
        format!(
            "{}; stage {:?}; original {}",
            request.serial,
            request.action,
            tool_record.display()
        ),
    ));
    record.outcome = "uncertain".into();
    store.update(record)?;
    let mut command = make();
    if request.action == Action::Reconcile {
        command.arg("reconcile-prepare");
    } else {
        command.arg("provision").arg("--stage").arg(stage);
    }
    command
        .arg("--distribution")
        .arg("--serial")
        .arg(&request.serial)
        .arg("--bundle")
        .arg(&firmware)
        .arg("--record")
        .arg(&tool_record)
        .arg("--apply");
    if request.action == Action::Resume {
        command.arg("--resume");
    }
    run(&mut command, "attended provisioning tool")?;
    let after = original(&tool_record)?
        .ok_or_else(|| denied("original provisioning record unavailable after handoff"))?;
    if request.action == Action::Reconcile {
        return Ok(format!(
            "read-only assessment only; original {} retains pending uncertainty and cannot advance",
            tool_record.display()
        ));
    }
    if after["serial"] != request.serial
        || !after["pending"].is_null()
        || after["completed_stage"] != stage
    {
        return Err(denied(
            "tool did not retain a complete stage; no advancement",
        ));
    }
    Ok(format!(
        "{stage} observed complete in original {}; application reports are not independent attestation; qualification remains separate. Commission only as a separate ordinary action after lock; no daemon restart is automatic",
        tool_record.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_blocks_stage_and_record_cannot_be_replaced() {
        let r = serde_json::json!({"schema_version":2,"serial":"0123456789abcdef","completed_stage":"prepare","pending":{"step":"write"}});
        assert!(check_record(Action::Enable, "0123456789abcdef", Some(&r)).is_err());
        assert!(check_record(Action::Prepare, "0123456789abcdef", Some(&r)).is_err());
        assert!(check_record(Action::Reconcile, "0123456789abcdef", Some(&r)).is_err());
    }
    #[test]
    fn irreversible_later_stages_require_fresh_blank_admission() {
        assert!(requires_blank_admission(Action::Enable));
        assert!(requires_blank_admission(Action::Lock));
        assert!(!requires_blank_admission(Action::Preview));
        assert!(!requires_blank_admission(Action::Reconcile));
    }
    #[test]
    fn security_admission_rejects_wrong_or_nonblank_target() {
        let serial = "0123456789abcdef";
        let mut security = serde_json::json!({"usb_serial": serial, "storage_blank_at_boot": true});
        assert!(blank_security(&security, serial));
        security["storage_blank_at_boot"] = false.into();
        assert!(!blank_security(&security, serial));
        security["storage_blank_at_boot"] = true.into();
        security["usb_serial"] = "fedcba9876543210".into();
        assert!(!blank_security(&security, serial));
    }
    #[test]
    fn tool_record_limit_accepts_more_than_one_mib() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let path =
            std::env::temp_dir().join(format!("p2kesup-provision-record-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let payload = serde_json::json!({"padding": "x".repeat(1024 * 1024)}).to_string();
        file.write_all(payload.as_bytes()).unwrap();
        assert!(original(&path).unwrap().is_some());
        file.set_len(MAX_TOOL_RECORD_BYTES + 1).unwrap();
        assert!(original(&path).is_err());
        drop(file);
        fs::remove_file(path).unwrap();
    }
}
