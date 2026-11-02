use pico2_kes_agent::memory;
use rustix::process::{Resource, getrlimit};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const CHILD: &str = "PICO2_KES_HOST_MEMORY_CHILD";

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pico2-kes-host-security-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bootstrap_verifier_bounds_running_processes() {
    let script = include_str!("../install.sh");
    let helper = script
        .split_once("verifier_code=$(cat <<'PY'\n")
        .unwrap()
        .1
        .split_once("\nPY\n")
        .unwrap()
        .0;
    let exercise = r#"
import sys
python = sys.executable
assert bounded_command([python, '-c', "import sys; assert sys.stdin.read() == ''; sys.stderr.write('ignored'); sys.stdout.write('ok')"]) == b'ok'
assert len(bounded_command([python, '-c', "import sys; sys.stdout.write('x'*65536)"])) == 65536
assert bounded_command([python, '-c', "import os; print(os.environ['BOUND_TEST'])"], env={'BOUND_TEST':'isolated'}, limit=1048576) == b'isolated\n'
try:
    bounded_command([python, '-c', "import os; os.write(1,b'x'*65537); import time; time.sleep(60)"])
    raise AssertionError('overflow accepted')
except ValueError:
    pass
for child in ("import time; time.sleep(60)", "import os,time; os.close(1); time.sleep(60)"):
    try:
        bounded_command([python, '-c', child], timeout=0.2)
        raise AssertionError('timeout accepted')
    except subprocess.TimeoutExpired:
        pass
try:
    bounded_command([python, '-c', "raise SystemExit(7)"])
    raise AssertionError('failure accepted')
except subprocess.CalledProcessError as error:
    assert error.returncode == 7
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-I", "-c", &format!("{helper}\n{exercise}")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn uninstall_file_review_rejects_modified_or_replaced_owned_files() {
    use kes_core::identity::Digest32;
    use pico2_kes_agent::manager::uninstall::observe_recovery_file;
    use pico2_kes_agent::manager::{host::check_owned_file, model::ManagedFile};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{MetadataExt, symlink};

    let dir = TestDir::new();
    let file = dir.0.join("component");
    fs::write(&file, b"authenticated component").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let meta = fs::metadata(&file).unwrap();
    let entry = ManagedFile {
        path: file.clone(),
        digest: Digest32::parse_hex(&format!("{:x}", Sha256::digest(b"authenticated component")))
            .unwrap(),
        mode: 0o600,
        owner: meta.uid(),
        group: meta.gid(),
        component: "manager".into(),
    };
    assert!(check_owned_file(&file, Some(&entry)).is_ok());
    assert!(observe_recovery_file(&entry).unwrap());
    fs::write(&file, b"modified component").unwrap();
    assert!(check_owned_file(&file, Some(&entry)).is_err());
    assert!(observe_recovery_file(&entry).is_err());
    fs::remove_file(&file).unwrap();
    assert!(!observe_recovery_file(&entry).unwrap());
    let external = dir.0.join("external");
    fs::write(&external, b"authenticated component").unwrap();
    symlink(&external, &file).unwrap();
    assert!(check_owned_file(&file, Some(&entry)).is_err());
    assert!(observe_recovery_file(&entry).is_err());
    assert_eq!(fs::read(&external).unwrap(), b"authenticated component");
}

#[test]
fn daemon_process_memory_is_locked_nondumpable_and_coreless() {
    if std::env::var_os(CHILD).is_some() {
        memory::protect_process().expect("host must provide the configured lock allowance");
        let mut retained_key = memory::SecretBuffer::new(4_096).unwrap();
        retained_key.as_mut_slice().fill(0xa5);
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
        let core = getrlimit(Resource::Core);
        assert_eq!(core.current, Some(0));
        assert_eq!(core.maximum, Some(0));
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let locked_kib = status
            .lines()
            .find_map(|line| line.strip_prefix("VmLck:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap();
        assert!(locked_kib > 0, "mlockall left no process pages locked");
        std::process::exit(0);
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "daemon_process_memory_is_locked_nondumpable_and_coreless",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn recipient_prompt_protects_process_before_accepting_passphrase() {
    const CHILD: &str = "PICO2_KES_RECIPIENT_PROMPT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};

        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes both descriptors; optional terminal settings are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: these fresh descriptors are uniquely owned by the files.
        let mut master = unsafe { fs::File::from_raw_fd(master) };
        let slave = unsafe { fs::File::from_raw_fd(slave) };
        // SAFETY: this isolated child acquires its own session and controlling terminal.
        unsafe {
            assert!(libc::setsid() >= 0);
            assert_eq!(libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0), 0);
            assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 1), 0);
        }
        let observer = std::thread::spawn(move || {
            let mut event = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: event is initialized and writable for the duration of poll.
            if unsafe { libc::poll(&mut event, 1, 5_000) } != 1 {
                std::process::exit(1);
            }
            let mut prompt = [0; b"Recipient passphrase: ".len()];
            master.read_exact(&mut prompt).unwrap();
            // SAFETY: PR_GET_DUMPABLE takes no pointer arguments and observes this process.
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
            let core = getrlimit(Resource::Core);
            master.write_all(b"disposable test passphrase\n").unwrap();
            (master, prompt, dumpable, core)
        });
        let passphrase = pico2_kes_agent::backup::recipient::prompt_existing_passphrase().unwrap();
        let (_master, prompt, dumpable, core) = observer.join().unwrap();
        assert_eq!(&prompt, b"Recipient passphrase: ");
        assert_eq!(passphrase.as_slice(), b"disposable test passphrase");
        assert_eq!(dumpable, 0);
        assert_eq!(core.current, Some(0));
        assert_eq!(core.maximum, Some(0));
        std::process::exit(0);
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recipient_prompt_protects_process_before_accepting_passphrase",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn deployment_preflight_enforces_host_node_snapshot_and_backup_boundaries() {
    let dir = TestDir::new();
    let policy = dir.0.join("host-security.env");
    let swaps = dir.0.join("swaps");
    let systemctl = dir.0.join("systemctl");
    fs::write(
        &policy,
        b"SNAPSHOT_POLICY=disabled-or-encrypted-off-host\nNODE_MEMORY_POLICY=core-and-swap-disabled\nBACKUP_PRIVATE_POLICY=off-primary\n",
    )
    .unwrap();
    fs::write(&swaps, b"Filename Type Size Used Priority\n").unwrap();
    fs::write(
        &systemctl,
        b"#!/bin/sh\ncase \"$1\" in\n  is-enabled) echo masked ;;\n  show) echo 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o700)).unwrap();

    let checker =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/pico2-kes-agent-host-check");
    let run = || {
        Command::new(&checker)
            .env("PICO2_KES_HOST_POLICY", &policy)
            .env("PICO2_KES_PROC_SWAPS", &swaps)
            .env("PICO2_KES_SYSTEMCTL", &systemctl)
            .output()
            .unwrap()
    };
    assert!(run().status.success());

    fs::write(
        &swaps,
        b"Filename Type Size Used Priority\n/dev/zram0 partition 1 0 1\n",
    )
    .unwrap();
    let active_swap = run();
    assert!(!active_swap.status.success());
    assert!(String::from_utf8_lossy(&active_swap.stderr).contains("active swap"));

    fs::write(&swaps, b"Filename Type Size Used Priority\n").unwrap();
    fs::write(
        &policy,
        b"SNAPSHOT_POLICY=disabled-or-encrypted-off-host\nNODE_MEMORY_POLICY=core-and-swap-disabled\n",
    )
    .unwrap();
    let primary_private_key = run();
    assert!(!primary_private_key.status.success());
    assert!(String::from_utf8_lossy(&primary_private_key.stderr).contains("off-primary"));
}

#[test]
fn commissioning_preflight_needs_no_node_but_retains_host_protections() {
    let dir = TestDir::new();
    let policy = dir.0.join("host-security.env");
    let swaps = dir.0.join("swaps");
    let systemctl = dir.0.join("systemctl");
    let acknowledgements =
        b"SNAPSHOT_POLICY=disabled-or-encrypted-off-host\nBACKUP_PRIVATE_POLICY=off-primary\n";
    fs::write(&policy, acknowledgements).unwrap();
    fs::write(&swaps, b"Filename Type Size Used Priority\n").unwrap();
    fs::write(
        &systemctl,
        b"#!/bin/sh\ncase \"$1:$2\" in\n  is-enabled:*) echo masked ;;\n  show:pico2-kes-agentd.service) echo 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o700)).unwrap();
    let checker =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/pico2-kes-agent-host-check");
    let run = |arguments: &[&str]| {
        Command::new(&checker)
            .args(arguments)
            .env("PICO2_KES_HOST_POLICY", &policy)
            .env("PICO2_KES_PROC_SWAPS", &swaps)
            .env("PICO2_KES_SYSTEMCTL", &systemctl)
            .output()
            .unwrap()
    };
    assert!(run(&["--commission"]).status.success());
    for state in [
        "masked-runtime",
        "static",
        "disabled",
        "enabled",
        "unknown",
        "",
    ] {
        fs::write(
            &systemctl,
            format!(
                "#!/bin/sh\ncase \"$1:$2\" in\n  is-enabled:*) printf '%s\\n' '{state}' ;;\n  show:pico2-kes-agentd.service) echo 0 ;;\n  *) exit 1 ;;\nesac\n"
            ),
        )
        .unwrap();
        assert_eq!(
            run(&["--commission"]).status.success(),
            state == "masked-runtime",
            "sleep target state: {state:?}"
        );
    }
    fs::write(
        &systemctl,
        b"#!/bin/sh\ncase \"$1:$2\" in\n  is-enabled:*) echo masked-runtime ;;\n  show:pico2-kes-agentd.service) echo 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    assert!(!run(&[]).status.success());
    fs::write(
        &policy,
        [
            acknowledgements.as_slice(),
            b"NODE_MEMORY_POLICY=core-and-swap-disabled\n",
        ]
        .concat(),
    )
    .unwrap();
    assert!(
        !run(&[]).status.success(),
        "missing node must fail normal mode"
    );
    assert!(run(&["--commission"]).status.success());
    assert_eq!(run(&["--unknown"]).status.code(), Some(2));
    assert_eq!(
        run(&["--commission", "--commission"]).status.code(),
        Some(2)
    );

    fs::write(
        &swaps,
        b"Filename Type Size Used Priority\n/dev/zram0 partition 1 0 1\n",
    )
    .unwrap();
    assert!(!run(&["--commission"]).status.success());
    fs::write(&swaps, b"Filename Type Size Used Priority\n").unwrap();
    fs::write(
        &systemctl,
        b"#!/bin/sh\ncase \"$1\" in\n  is-enabled) echo enabled ;;\n  show) echo 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    assert!(!run(&["--commission"]).status.success());
    fs::write(
        &systemctl,
        b"#!/bin/sh\ncase \"$1\" in\n  is-enabled) echo masked ;;\n  show) echo infinity ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    assert!(!run(&["--commission"]).status.success());
    fs::write(
        &systemctl,
        b"#!/bin/sh\ncase \"$1:$2\" in\n  is-enabled:*) echo masked ;;\n  show:pico2-kes-agentd.service) echo 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    fs::write(&policy, b"SNAPSHOT_POLICY=disabled-or-encrypted-off-host\n").unwrap();
    assert!(!run(&["--commission"]).status.success());
    fs::write(&policy, b"BACKUP_PRIVATE_POLICY=off-primary\n").unwrap();
    assert!(!run(&["--commission"]).status.success());
}

#[test]
fn invalid_setup_candidate_does_not_modify_working_config() {
    use pico2_kes_agent::{config::RunMode, manager::setup};
    use std::os::unix::fs::MetadataExt;

    let dir = TestDir::new();
    let working = dir.0.join("config.json");
    let candidate = dir.0.join("candidate.json");
    fs::write(&working, b"operator configuration\n").unwrap();
    fs::set_permissions(&working, fs::Permissions::from_mode(0o640)).unwrap();
    fs::write(&candidate, b"{\"version\":999}").unwrap();
    let before = fs::metadata(&working).unwrap();
    assert!(setup::review_config(&candidate, RunMode::Normal).is_err());
    let after = fs::metadata(&working).unwrap();
    assert_eq!(fs::read(&working).unwrap(), b"operator configuration\n");
    assert_eq!(
        (before.mode(), before.uid(), before.gid()),
        (after.mode(), after.uid(), after.gid())
    );
}

#[test]
fn external_and_modified_files_are_not_adopted() {
    use kes_core::identity::Digest32;
    use pico2_kes_agent::manager::host::check_owned_file;
    use pico2_kes_agent::manager::model::ManagedFile;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;

    let dir = TestDir::new();
    let path = dir.0.join("managed");
    fs::write(&path, b"original").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let meta = fs::metadata(&path).unwrap();
    let digest: [u8; 32] = Sha256::digest(b"original").into();
    let entry = ManagedFile {
        path: path.clone(),
        digest: Digest32::from_bytes(digest),
        mode: 0o644,
        owner: meta.uid(),
        group: meta.gid(),
        component: "test".into(),
    };
    assert!(check_owned_file(&path, None).is_err());
    assert!(check_owned_file(&path, Some(&entry)).is_ok());
    fs::write(&path, b"modified").unwrap();
    assert!(check_owned_file(&path, Some(&entry)).is_err());
    fs::write(&path, b"original").unwrap();
    let hardlink = dir.0.join("hardlink");
    fs::hard_link(&path, &hardlink).unwrap();
    assert!(check_owned_file(&path, Some(&entry)).is_err());
    fs::remove_file(&hardlink).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&hardlink, b"original").unwrap();
    std::os::unix::fs::symlink(&hardlink, &path).unwrap();
    assert!(check_owned_file(&path, Some(&entry)).is_err());
}

#[test]
fn host_plan_approval_expires_when_scope_changes() {
    use pico2_kes_agent::manager::{
        host::{HostAction, HostPlan},
        model::InstallationRole,
    };
    let action = HostAction::Install {
        bundle: PathBuf::from("/tmp/bundle"),
        role: InstallationRole::Backup,
        manifest_digest: "a".repeat(64),
        candidate_accepted: false,
    };
    let mut plan = HostPlan::new(action).unwrap();
    assert!(plan.validate().is_ok());
    let mut changed_identity = plan.clone();
    changed_identity.plan_id = if changed_identity.plan_id == "c".repeat(32) {
        "d".repeat(32)
    } else {
        "c".repeat(32)
    };
    assert!(changed_identity.validate().is_err());
    if let HostAction::Install { role, .. } = &mut plan.action {
        *role = InstallationRole::Primary;
    }
    assert!(plan.validate().is_err());
}

#[test]
fn blank_admission_rejects_unavailable_or_wrong_device() {
    use pico2_kes_agent::manager::setup::validate_blank_observation;
    use serde_json::json;
    let status = json!({"commissioning_state":"blank","health":"ready"});
    let info = json!({"schema_version":1,"device_id":null,"usb_serial":"0123456789abcdef",
        "version":"1.0","build_id":"ab","source_commit":"cd",
        "protocol_major":1,"storage_version":2,"security_profile":"profile"});
    let firmware = pico2_kes_agent::manager::release::Component {
        name: "firmware".into(),
        version: "1.0".into(),
        build_id: "ab".into(),
        artifact: "firmware/pico2-kes-agent.uf2".into(),
        digest: "00".repeat(32),
    };
    assert!(
        validate_blank_observation(
            &status,
            &info,
            "0123456789abcdef",
            &firmware,
            "cd",
            &[2],
            &["profile".into()]
        )
        .is_ok()
    );
    let mut wrong = info.clone();
    wrong["device_id"] = json!("existing");
    assert!(
        validate_blank_observation(
            &status,
            &wrong,
            "0123456789abcdef",
            &firmware,
            "cd",
            &[2],
            &["profile".into()]
        )
        .is_err()
    );
    assert!(
        validate_blank_observation(
            &json!({"health":"unavailable"}),
            &info,
            "0123456789abcdef",
            &firmware,
            "cd",
            &[2],
            &["profile".into()]
        )
        .is_err()
    );
    assert!(
        validate_blank_observation(
            &status,
            &info,
            "ffffffffffffffff",
            &firmware,
            "cd",
            &[2],
            &["profile".into()]
        )
        .is_err()
    );
}

#[test]
fn reviewed_public_genesis_input_rejects_substitution() {
    use pico2_kes_agent::manager::setup::{review_public_input, verify_public_inputs};
    let dir = TestDir::new();
    let path = dir.0.join("genesis.json");
    fs::write(&path, b"first").unwrap();
    let input = review_public_input(&path).unwrap();
    assert!(verify_public_inputs(std::slice::from_ref(&input)).is_ok());
    fs::write(path, b"changed").unwrap();
    assert!(verify_public_inputs(&[input]).is_err());
}

#[test]
fn uninstall_approval_is_bound_to_registry_and_selected_components() {
    use pico2_kes_agent::manager::host::{HostAction, HostPlan};
    let mut plan = HostPlan::new(HostAction::Uninstall {
        selected_components: vec!["manager".into(), "cli".into()],
        registry_digest: "a".repeat(64),
        expected_service_state: None,
        stop_service: false,
    })
    .unwrap();
    assert!(plan.validate().is_ok());
    if let HostAction::Uninstall {
        registry_digest, ..
    } = &mut plan.action
    {
        *registry_digest = "b".repeat(64);
    }
    assert!(plan.validate().is_err());
}

#[test]
fn service_hidden_genesis_rejection_preserves_working_config_and_allows_new_action() {
    use pico2_kes_agent::manager::{host, setup};
    use std::os::unix::fs::MetadataExt;
    let dir = TestDir(PathBuf::from(format!(
        "/tmp/p2kesup-sandbox-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&dir.0).unwrap();
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();
    let working = dir.0.join("working.json");
    let genesis = dir.0.join("genesis.json");
    fs::write(&working, b"working").unwrap();
    fs::set_permissions(&working, fs::Permissions::from_mode(0o640)).unwrap();
    fs::write(&genesis, b"public").unwrap();
    let before = fs::metadata(&working).unwrap();
    let input = setup::review_public_input(&genesis).unwrap();
    assert!(host::validate_service_input_visibility(&[input]).is_err());
    let after = fs::metadata(&working).unwrap();
    assert_eq!(fs::read(&working).unwrap(), b"working");
    assert_eq!(
        (before.mode(), before.uid(), before.gid()),
        (after.mode(), after.uid(), after.gid())
    );
    assert!(host::maintenance_outcome_allows_new_action("failed-known"));
    assert!(!host::maintenance_outcome_allows_new_action("uncertain"));
}
