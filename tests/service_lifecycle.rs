use std::{
    ffi::CStr,
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "pico2-kes-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let run = root.join("run");
        let state = root.join("state");
        fs::create_dir_all(&run).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = run.join("management.sock");
        let config = serde_json::json!({
            "version": 1,
            "device": { "usb_serial": "absent-board0001" },
            "socket_directory": run,
            "socket_group": current_group(),
            "socket_mode": "0660",
            "management_socket": socket,
            "state_directory": state,
            "networks": {},
            "pools": [],
        });
        fs::write(
            root.join("config.json"),
            serde_json::to_vec_pretty(&config).unwrap(),
        )
        .unwrap();
        Self { root }
    }

    fn socket(&self) -> PathBuf {
        self.root.join("run/management.sock")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn current_group() -> String {
    // SAFETY: `getgrgid` returns process-owned static storage; the name is read
    // immediately and copied while the pointer is valid.
    unsafe {
        let group = libc::getgrgid(libc::getgid());
        assert!(!group.is_null());
        CStr::from_ptr((*group).gr_name)
            .to_str()
            .unwrap()
            .to_owned()
    }
}

#[test]
fn absent_device_mutation_does_not_leave_recovery_pending_across_restart() {
    use pico2_kes_agent::{cli::client, daemon::journal::Journal};
    use serde_json::{Value, json};

    let fixture = Fixture::new();
    let request = serde_json::to_vec(&json!({
        "version": 1,
        "request_id": "11".repeat(16),
        "operation_id": "22".repeat(16),
        "expected_revision": 0,
        "action": "device.commission",
        "arguments": { "usb_serial": "absent-board0001" }
    }))
    .unwrap();
    for _ in 0..2 {
        let mut daemon = Daemon(
            Command::new(env!("CARGO_BIN_EXE_pico2-kes-agentd"))
                .args([
                    "--config",
                    fixture.root.join("config.json").to_str().unwrap(),
                    "--commission",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fixture.socket().exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let response: Value =
            serde_json::from_slice(&client::request(&fixture.socket(), &request).unwrap()).unwrap();
        assert_eq!(response["error"]["code"], "device_unavailable");
        let status: Value = serde_json::from_slice(
            &client::request(
                &fixture.socket(),
                &serde_json::to_vec(&json!({
                    "version": 1, "request_id": "33".repeat(16),
                    "action": "device.status", "arguments": {}
                }))
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(status["result"]["health"], "disconnected");
        // SAFETY: the PID belongs to the retained child.
        assert_eq!(
            unsafe { libc::kill(daemon.0.id() as i32, libc::SIGTERM) },
            0
        );
        assert!(daemon.0.wait().unwrap().success());
        let journal = Journal::open(&fixture.root.join("state/operations.journal")).unwrap();
        assert!(journal.pending().is_none());
        assert_eq!(journal.next_sequence(), 0);
    }
}

#[test]
fn seventeenth_idle_management_connection_is_rejected_busy_before_admission() {
    let fixture = Fixture::new();
    let child = Command::new(env!("CARGO_BIN_EXE_pico2-kes-agentd"))
        .args([
            "--config",
            fixture.root.join("config.json").to_str().unwrap(),
            "--commission",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !fixture.socket().exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        fixture.socket().exists(),
        "daemon did not bind management socket"
    );

    let mut idle = Vec::new();
    for _ in 0..16 {
        idle.push(UnixStream::connect(fixture.socket()).unwrap());
    }
    std::thread::sleep(Duration::from_millis(200));

    let mut saturated = UnixStream::connect(fixture.socket()).unwrap();
    saturated
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut header = [0; 4];
    saturated.read_exact(&mut header).unwrap();
    let mut body = vec![0; u32::from_be_bytes(header) as usize];
    saturated.read_exact(&mut body).unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["outcome"], "rejected");
    assert_eq!(response["error"]["code"], "busy");

    drop(idle);
    // SAFETY: the PID belongs to the child retained above.
    assert_eq!(
        unsafe { libc::kill(daemon.0.id() as i32, libc::SIGTERM) },
        0
    );
    let status = daemon.0.wait().unwrap();
    assert!(status.success());
}

#[test]
fn configured_custom_pool_socket_serves_service_v2_without_default_socket() {
    let fixture = Fixture::new();
    let byron = r#"{"startTime":10,"protocolConsts":{"k":3,"protocolMagic":42},"blockVersionData":{"slotDuration":100}}"#;
    let shelley =
        r#"{"networkMagic":42,"slotLength":1,"slotsPerKESPeriod":100,"maxKESEvolutions":64}"#;
    let byron_path = fixture.root.join("byron.json");
    let shelley_path = fixture.root.join("shelley.json");
    fs::write(&byron_path, byron).unwrap();
    fs::write(&shelley_path, shelley).unwrap();
    let digest: String = Sha256::digest(shelley.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let config_path = fixture.root.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    let custom = fixture.root.join("run/custom.sock");
    let pool = "01".repeat(28);
    config["device"]["id"] = "02".repeat(16).into();
    config["device"]["identity_public_key"] = "03".repeat(32).into();
    config["networks"] = serde_json::json!({
        "test": {
            "byron_genesis_file": byron_path,
            "shelley_genesis_file": shelley_path,
            "byron_to_shelley_epochs": 0,
            "genesis_digest": digest,
            "max_context_age_ms": 30000
        }
    });
    config["pools"] = serde_json::json!([{
        "pool_id": pool,
        "incarnation_id": "04".repeat(16),
        "socket_path": custom,
        "network": "test"
    }]);
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_pico2-kes-agentd"))
        .args(["--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !custom.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        custom.exists(),
        "daemon did not bind custom pool socket: {:?}",
        daemon.0.try_wait()
    );
    let mut stream = UnixStream::connect(&custom).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut offer = [0; 36];
    stream.read_exact(&mut offer).unwrap();
    let mut service = [0; 32];
    service[..11].copy_from_slice(b"Service:2.0");
    assert_eq!(&offer[..4], &1u32.to_be_bytes());
    assert_eq!(&offer[4..], &service);
    stream.write_all(&[1]).unwrap();
    stream.write_all(&service).unwrap();
    let mut selected = [0; 32];
    stream.read_exact(&mut selected).unwrap();
    assert_eq!(selected, service);
    assert!(
        !fixture
            .root
            .join("run")
            .join(format!("{pool}.sock"))
            .exists()
    );
}
