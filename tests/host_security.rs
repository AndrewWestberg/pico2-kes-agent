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
    let acknowledgements = b"SNAPSHOT_POLICY=disabled-or-encrypted-off-host\nBACKUP_PRIVATE_POLICY=off-primary\n";
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
    for state in ["masked-runtime", "static", "disabled", "enabled", "unknown", ""] {
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
        [acknowledgements.as_slice(), b"NODE_MEMORY_POLICY=core-and-swap-disabled\n"].concat(),
    )
    .unwrap();
    assert!(!run(&[]).status.success(), "missing node must fail normal mode");
    assert!(run(&["--commission"]).status.success());
    assert_eq!(run(&["--unknown"]).status.code(), Some(2));
    assert_eq!(run(&["--commission", "--commission"]).status.code(), Some(2));

    fs::write(&swaps, b"Filename Type Size Used Priority\n/dev/zram0 partition 1 0 1\n")
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
