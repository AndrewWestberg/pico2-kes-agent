use std::{
    ffi::CStr,
    fs,
    io::Read,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

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
