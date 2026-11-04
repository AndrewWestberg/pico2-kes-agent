//! Bounded, read-only observations for the manager.
use super::model::{
    ComponentBuild, ComponentObservation, INSTALLATION_REGISTRY, InstallationRegistry, Observation,
    ObservationState, Ownership,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SCAN: Duration = Duration::from_secs(8);
const REFRESH: Duration = Duration::from_secs(2);
const FRESH: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigAccess {
    Readable,
    Absent,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceState {
    pub load: String,
    pub active: String,
    pub main_pid: Option<u32>,
}

fn parse_service(text: &str) -> Result<ServiceState, String> {
    let property = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name).filter(|value| !value.is_empty()))
    };
    let load = property("LoadState=").ok_or("missing LoadState")?;
    let active = property("ActiveState=").ok_or("missing ActiveState")?;
    let pid = property("MainPID=")
        .ok_or("missing MainPID")?
        .parse::<u32>()
        .map_err(|_| "invalid MainPID")?;
    Ok(ServiceState {
        load: load.into(),
        active: active.into(),
        main_pid: (pid != 0).then_some(pid),
    })
}
fn config_access(result: &std::io::Result<PathBuf>) -> Result<ConfigAccess, String> {
    match result {
        Ok(_) => Ok(ConfigAccess::Readable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigAccess::Absent),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(ConfigAccess::Denied),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSummary {
    pub pinned_device_id: Option<String>,
    pub usb_serial: Option<String>,
    pub networks: Vec<String>,
    pub configured_pools: usize,
    pub config_identity: Option<String>,
    pub validated_networks: HashMap<String, crate::daemon::context::NetworkConfig>,
}

#[derive(Clone, Debug)]
pub struct LocalOverview {
    pub own_executable: Observation<PathBuf>,
    pub path_candidates: Observation<Vec<PathBuf>>,
    pub service: Observation<String>,
    pub service_state: Observation<ServiceState>,
    pub config: Observation<PathBuf>,
    pub config_access: Observation<ConfigAccess>,
    pub config_ownership: Observation<String>,
    pub config_summary: Observation<ConfigSummary>,
    pub swap_free: Observation<bool>,
    pub support: String,
    pub registry: Observation<InstallationRegistry>,
    pub components: Vec<ComponentObservation>,
    pub usb_mode: Observation<super::model::DeviceMode>,
}
#[derive(Clone, Debug)]
pub struct JoinedPool {
    pub pool_id: String,
    pub incarnation_id: String,
    pub membership: Option<Value>,
    pub host: Option<Value>,
    pub observation: Observation<Value>,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub captured_at: Instant,
    pub local: Observation<LocalOverview>,
    pub host: Observation<Value>,
    pub device: Observation<Value>,
    pub membership: Observation<Vec<Value>>,
    pub pools: Vec<JoinedPool>,
}
#[derive(Clone)]
struct Track<T> {
    observation: Observation<T>,
    last: Option<Instant>,
}
impl<T: Clone> Track<T> {
    fn new(source: &str) -> Self {
        Self {
            observation: Observation {
                source: source.into(),
                value: None,
                observed_at_unix_us: None,
                age: None,
                state: ObservationState::Unknown,
                public_error: None,
            },
            last: None,
        }
    }
    fn success(&mut self, value: T, now: Instant) {
        self.last = Some(now);
        self.observation.value = Some(value);
        self.observation.observed_at_unix_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_micros()).ok());
        self.observation.age = Some(Duration::ZERO);
        self.observation.state = ObservationState::Fresh;
        self.observation.public_error = None;
    }
    fn fail(&mut self, error: String) {
        self.observation.state = if error == "unsupported" {
            ObservationState::Unsupported
        } else if self.last.is_some() {
            ObservationState::Stale
        } else {
            ObservationState::Unavailable
        };
        self.observation.public_error = Some(error);
    }
    fn get(&self, now: Instant) -> Observation<T> {
        let mut o = self.observation.clone();
        o.age = self.last.map(|t| now.saturating_duration_since(t));
        if o.state == ObservationState::Fresh && o.age.is_some_and(|a| a >= FRESH) {
            o.state = ObservationState::Stale;
        }
        o
    }
}
struct Pool {
    pool_id: String,
    incarnation_id: String,
    membership: Option<Value>,
    host: Option<Value>,
    observation: Track<Value>,
}
struct State {
    local: Track<LocalOverview>,
    host: Track<Value>,
    device: Track<Value>,
    membership: Track<Vec<Value>>,
    membership_device: Option<String>,
    pools: Vec<Pool>,
    published: Option<Arc<Snapshot>>,
}
impl State {
    fn new() -> Self {
        let mut s = Self {
            local: Track::new("local"),
            host: Track::new("host.observe"),
            device: Track::new("device.info"),
            membership: Track::new("device.inventory"),
            membership_device: None,
            pools: Vec::new(),
            published: None,
        };
        s.publish();
        s
    }
    fn snapshot(&self) -> Snapshot {
        let now = Instant::now();
        Snapshot {
            captured_at: now,
            local: self.local.get(now),
            host: self.host.get(now),
            device: self.device.get(now),
            membership: self.membership.get(now),
            pools: self
                .pools
                .iter()
                .map(|p| JoinedPool {
                    pool_id: p.pool_id.clone(),
                    incarnation_id: p.incarnation_id.clone(),
                    membership: p.membership.clone(),
                    host: p.host.clone(),
                    observation: p.observation.get(now),
                })
                .collect(),
        }
    }
    fn publish(&mut self) {
        self.published = Some(Arc::new(self.snapshot()));
    }
}
pub struct Worker {
    state: Arc<Mutex<State>>,
    tx: SyncSender<()>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Worker {
    pub fn start(socket: PathBuf, config: Option<PathBuf>) -> Self {
        let state = Arc::new(Mutex::new(State::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        let s = state.clone();
        let flag = stop.clone();
        let thread = thread::spawn(move || run(s, flag, rx, socket, config));
        Self {
            state,
            tx,
            stop,
            thread: Some(thread),
        }
    }
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.state
            .lock()
            .unwrap()
            .published
            .as_ref()
            .unwrap()
            .clone()
    }
    pub fn refresh(&self) {
        let _ = self.tx.try_send(());
    }
    pub fn shutdown(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.tx.try_send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.tx.try_send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
fn local_item<T: Clone>(name: &str, result: Result<T, String>) -> Observation<T> {
    let mut t = Track::new(name);
    match result {
        Ok(v) => t.success(v, Instant::now()),
        Err(e) => t.fail(e),
    };
    t.get(Instant::now())
}
fn retain_local<T: Clone>(new: &mut Observation<T>, old: &Observation<T>, elapsed: Duration) {
    if new.value.is_none() && old.value.is_some() {
        new.value = old.value.clone();
        new.observed_at_unix_us = old.observed_at_unix_us;
        new.age = old.age.map(|age| age.saturating_add(elapsed));
        new.state = ObservationState::Stale;
    }
}
fn local(config: Option<&Path>) -> LocalOverview {
    let own_executable = local_item(
        "own executable",
        std::env::current_exe().map_err(|e| e.to_string()),
    );
    let path_candidates = local_item(
        "PATH",
        std::env::var_os("PATH")
            .ok_or_else(|| "PATH unavailable".to_string())
            .and_then(|paths| {
                let mut found = Vec::new();
                for (index, dir) in std::env::split_paths(&paths).enumerate() {
                    if index >= 64 {
                        return Err("PATH directory capacity exceeded".into());
                    }
                    for name in ["pico2-kes-agentd", "pico2-kes-agent-cli", "p2kesup"] {
                        let p = dir.join(name);
                        match fs::metadata(&p) {
                            Ok(_) if found.len() < 64 => found.push(p),
                            Ok(_) => return Err("PATH candidate capacity exceeded".into()),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                }
                Ok(found)
            }),
    );
    let config_path = config.unwrap_or_else(|| Path::new("/etc/pico2-kes-agent/config.json"));
    let config_ownership = local_item(
        "config filesystem metadata (not installation authority)",
        fs::symlink_metadata(config_path)
            .map(|m| {
                format!(
                    "uid={} gid={} mode={:04o} regular={}",
                    m.uid(),
                    m.gid(),
                    m.mode() & 0o7777,
                    m.is_file()
                )
            })
            .map_err(|e| e.to_string()),
    );
    let mut parsed_summary: Result<ConfigSummary, String> = Err("config unreadable".into());
    let config_result = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(config_path)
        .and_then(|file| {
            if file.metadata()?.is_file() {
                let mut bytes = Vec::new();
                file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                if bytes.len() <= 1024 * 1024 {
                    parsed_summary = serde_json::from_slice::<Value>(&bytes)
                        .map_err(|e| e.to_string())
                        .map(|val| {
                            let pinned_device_id = val
                                .pointer("/device/id")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                            let usb_serial = val
                                .pointer("/device/usb_serial")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                            let mut networks: Vec<String> = val
                                .get("networks")
                                .and_then(Value::as_object)
                                .map(|m| m.keys().cloned().collect())
                                .unwrap_or_default();
                            networks.sort();
                            let configured_pools = val
                                .get("pools")
                                .and_then(Value::as_array)
                                .map_or(0, Vec::len);
                            let mode = if pinned_device_id.is_some() {
                                crate::config::RunMode::Normal
                            } else {
                                crate::config::RunMode::Commissioning
                            };
                            let (config_identity, validated_networks) =
                                match crate::config::Config::inspect_bytes(&bytes, mode) {
                                    Ok(cfg) => (Some(cfg.identity_hex()), cfg.networks),
                                    Err(_) => (None, HashMap::new()),
                                };
                            ConfigSummary {
                                pinned_device_id,
                                usb_serial,
                                networks,
                                configured_pools,
                                config_identity,
                                validated_networks,
                            }
                        });
                }
                Ok(config_path.to_owned())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "configuration is not a regular file",
                ))
            }
        });
    let config_access = local_item("config access", config_access(&config_result));
    let config = local_item(
        "config read access",
        config_result.map_err(|e| e.to_string()),
    );
    let config_summary = local_item("config public summary", parsed_summary);
    let swap_free = local_item(
        "/proc/swaps",
        public_text(Path::new("/proc/swaps"), 64 * 1024)
            .map(|text| text.lines().skip(1).all(|line| line.trim().is_empty())),
    );
    let service = local_item("systemd", service());
    let service_state = local_item(
        "systemd properties",
        service
            .value
            .as_deref()
            .ok_or_else(|| {
                service
                    .public_error
                    .clone()
                    .unwrap_or_else(|| "systemd unavailable".into())
            })
            .and_then(parse_service),
    );
    let registry = registry();
    let components = components(&registry, &path_candidates);
    let support = public_text(Path::new("/etc/os-release"), 16 * 1024)
        .map(|text| platform_support(&text, std::env::consts::ARCH))
        .unwrap_or_else(|error| format!("Unknown platform: {error}"));
    let usb_mode = local_item(
        "USB sysfs candidates (not authenticated device identity)",
        usb_mode(),
    );
    LocalOverview {
        own_executable,
        path_candidates,
        service,
        service_state,
        config,
        config_access,
        config_ownership,
        config_summary,
        swap_free,
        registry,
        components,
        support,
        usb_mode,
    }
}

pub fn local_snapshot() -> LocalOverview {
    local(None)
}

fn public_text(path: &Path, limit: u64) -> Result<String, String> {
    let mut text = String::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > limit {
        return Err("public observation exceeds limit".into());
    }
    Ok(text)
}

fn platform_support(release: &str, arch: &str) -> String {
    let field = |name| {
        release
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim_matches('"'))
            .unwrap_or("unknown")
    };
    let id = field("ID=");
    let version = field("VERSION_ID=");
    let selected = arch == "x86_64"
        && matches!(
            (id, version),
            ("debian", "12") | ("ubuntu", "24.04") | ("ubuntu", "26.04")
        );
    format!(
        "{id} {version} / {arch}: {}",
        if selected {
            "selected support target; installation prerequisites and release qualification not established"
        } else {
            "unsupported installation platform; read-only diagnostics only"
        }
    )
}

fn candidate_mode(application: usize, bootloader: usize) -> super::model::DeviceMode {
    use super::model::DeviceMode;
    match (application, bootloader) {
        (0, 0) => DeviceMode::Absent,
        (1, 0) => DeviceMode::Application,
        (0, 1) => DeviceMode::Bootloader,
        _ => DeviceMode::Ambiguous,
    }
}

fn usb_mode() -> Result<super::model::DeviceMode, String> {
    let mut application = 0;
    let mut bootloader = 0;
    for (index, entry) in fs::read_dir("/sys/bus/usb/devices")
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if index >= 1024 {
            return Err("USB candidate observation capacity exceeded".into());
        }
        let path = entry.map_err(|e| e.to_string())?.path();
        let vendor = match fs::File::open(path.join("idVendor")) {
            Ok(file) => {
                let mut text = String::new();
                file.take(16)
                    .read_to_string(&mut text)
                    .map_err(|e| e.to_string())?;
                text
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        };
        if !matches!(vendor.trim(), "1209" | "2e8a") {
            continue;
        }
        let product = public_text(&path.join("idProduct"), 16)?;
        match (vendor.trim(), product.trim()) {
            ("1209", "4b45") => application += 1,
            ("2e8a", "000f") => bootloader += 1,
            _ => {}
        }
    }
    Ok(candidate_mode(application, bootloader))
}
fn trusted_ancestry(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    for part in path.parent().ok_or("missing parent")?.components().skip(1) {
        current.push(part);
        let m = fs::symlink_metadata(&current).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("untrusted path ancestry".into());
        }
    }
    Ok(())
}
fn registry() -> Observation<InstallationRegistry> {
    local_item(
        "installation registry",
        (|| {
            let path = Path::new(INSTALLATION_REGISTRY);
            trusted_ancestry(path)?;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
                .map_err(|e| e.to_string())?;
            let m = file.metadata().map_err(|e| e.to_string())?;
            if !m.is_file()
                || m.uid() != 0
                || m.mode() & 0o7777 != 0o644
                || m.nlink() != 1
                || m.len() > 1024 * 1024
            {
                return Err("unsafe installation registry".into());
            }
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 1024 * 1024 {
                return Err("installation registry exceeds limit".into());
            }
            let value: InstallationRegistry = serde_json::from_slice(&bytes)
                .map_err(|_| "invalid installation registry".to_string())?;
            if value.schema_version != 1
                || value
                    .current
                    .as_ref()
                    .is_some_and(|s| s.components.len() > 64)
            {
                return Err("unsupported or oversized installation registry".into());
            }
            let mut files = HashSet::new();
            if value.files.iter().any(|entry| !files.insert(&entry.path)) {
                return Err("duplicate installation registry path".into());
            }
            if let Some(current) = &value.current {
                let mut names = HashSet::new();
                if current
                    .components
                    .iter()
                    .any(|entry| !names.insert(&entry.component))
                {
                    return Err("duplicate selected component".into());
                }
            }
            Ok(value)
        })(),
    )
}
fn approved(path: &Path) -> bool {
    path.starts_with("/usr/lib/pico2-kes-agent")
        || [
            "/usr/bin/p2kesup",
            "/usr/bin/pico2-kes-agentd",
            "/usr/bin/pico2-kes-agent-cli",
            "/usr/lib/systemd/system/pico2-kes-agentd.service",
            "/usr/lib/udev/rules.d/70-pico2-kes-agent.rules",
            "/usr/libexec/pico2-kes-agent-host-check",
        ]
        .iter()
        .any(|p| path == Path::new(p))
}
fn components(
    registry: &Observation<InstallationRegistry>,
    paths: &Observation<Vec<PathBuf>>,
) -> Vec<ComponentObservation> {
    let mut result = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    if let Some(registry) = &registry.value {
        for item in &registry.files {
            let selection = registry
                .current
                .as_ref()
                .and_then(|s| s.components.iter().find(|c| c.component == item.component));
            let selected = selection.map(|s| ComponentBuild {
                version: s.version.clone(),
                build_id: s.build_id.clone(),
                digest: Some(s.entrypoint_digest),
                path: item.path.clone(),
            });
            let check = (|| {
                if item.owner != 0
                    || item.mode & 0o022 != 0
                    || !item.path.is_absolute()
                    || item.path.components().any(|c| {
                        matches!(
                            c,
                            std::path::Component::ParentDir | std::path::Component::CurDir
                        )
                    })
                    || !approved(&item.path)
                {
                    return Err("registry path or ownership outside approved policy".into());
                }
                trusted_ancestry(&item.path)?;
                let resolved = fs::canonicalize(&item.path).map_err(|e| e.to_string())?;
                if !approved(&resolved) {
                    return Err("resolved path outside approved roots".into());
                }
                trusted_ancestry(&resolved)?;
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(&resolved)
                    .map_err(|e| e.to_string())?;
                let m = file.metadata().map_err(|e| e.to_string())?;
                if !m.is_file()
                    || m.uid() != item.owner
                    || m.gid() != item.group
                    || m.mode() & 0o7777 != item.mode
                    || m.len() > 256 * 1024 * 1024
                {
                    return Err("managed file metadata mismatch".into());
                }
                let mut digest = Sha256::new();
                let mut buffer = [0; 16384];
                loop {
                    if Instant::now() >= deadline {
                        return Err("component digest deadline".into());
                    }
                    let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    digest.update(&buffer[..n]);
                }
                if digest.finalize().as_slice() != item.digest.as_bytes() {
                    return Err("managed file digest mismatch".into());
                }
                let matching = selection.filter(|s| s.entrypoint_digest == item.digest);
                Ok(ComponentBuild {
                    version: matching.map_or("unknown", |s| s.version.as_str()).into(),
                    build_id: matching.map_or("unknown", |s| s.build_id.as_str()).into(),
                    digest: Some(item.digest),
                    path: item.path.clone(),
                })
            })();
            let ownership = if check.is_ok() {
                Ownership::Managed
            } else {
                Ownership::Unknown
            };
            result.push(ComponentObservation {
                component: item.component.clone(),
                ownership,
                installed: local_item("installed component", check),
                running: local_item(
                    "running component",
                    Err("running identity not established by file metadata".into()),
                ),
                selected,
                provenance: Some(INSTALLATION_REGISTRY.into()),
            });
        }
    }
    if let Some(paths) = &paths.value {
        for path in paths {
            if result
                .iter()
                .any(|c| c.installed.value.as_ref().is_some_and(|b| b.path == *path))
            {
                continue;
            }
            if result.len() >= 64 {
                break;
            }
            let missing = registry
                .public_error
                .as_deref()
                .is_some_and(|e| e.contains("No such file or directory"));
            result.push(ComponentObservation {
                component: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                ownership: if missing {
                    Ownership::External
                } else {
                    Ownership::Unknown
                },
                installed: local_item("PATH candidate", Err("version not authenticated".into())),
                running: local_item("running component", Err("running identity unknown".into())),
                selected: None,
                provenance: Some(path.display().to_string()),
            });
        }
    }
    result
}
fn service() -> Result<String, String> {
    let mut child = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "pico2-kes-agentd.service",
            "--property=LoadState,ActiveState,ExecStart,MainPID",
            "--no-pager",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                if !status.success() {
                    return Err("systemd query failed".into());
                }
                let mut text = String::from_utf8(out.stdout)
                    .map_err(|_| "invalid systemd output".to_string())?;
                if text.len() > 8192 {
                    return Err("systemd output exceeds limit".into());
                }
                if let Some(pid) = text
                    .lines()
                    .find_map(|s| s.strip_prefix("MainPID="))
                    .and_then(|s| s.parse::<u32>().ok())
                    .filter(|p| *p != 0)
                {
                    match fs::read_link(format!("/proc/{pid}/exe")) {
                        Ok(path) => {
                            text.push_str(&format!("Running executable: {}\n", path.display()))
                        }
                        Err(e) => text.push_str(&format!("Running executable unknown: {e}\n")),
                    }
                }
                return Ok(text);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("systemd query timed out".into());
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.to_string());
            }
        }
    }
}
fn request(
    socket: &Path,
    action: &str,
    arguments: Value,
    deadline: Instant,
) -> Result<Value, String> {
    let id = "00000000000000000000000000000001";
    let bytes = serde_json::to_vec(
        &json!({"version":1,"request_id":id,"action":action,"arguments":arguments}),
    )
    .map_err(|e| e.to_string())?;
    let response = crate::cli::client::request_until(socket, &bytes, deadline)
        .map_err(|e| e.into_io().to_string())?;
    kes_protocol::management::Message::decode(&response)
        .map_err(|_| "invalid management response".to_string())?;
    let v: Value =
        serde_json::from_slice(&response).map_err(|_| "invalid management response".to_string())?;
    if v["request_id"] != id {
        return Err("response request identity mismatch".into());
    }
    if v["outcome"] != "success" {
        return Err(v["error"]["code"]
            .as_str()
            .unwrap_or("management request failed")
            .to_string());
    }
    Ok(v["result"].clone())
}
fn identity(v: &Value) -> Result<(String, String), String> {
    let p = v["pool_id"].as_str().ok_or("missing pool identity")?;
    let i = v["incarnation_id"]
        .as_str()
        .ok_or("missing incarnation identity")?;
    if p.len() != 56
        || i.len() != 32
        || !p
            .bytes()
            .chain(i.bytes())
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("invalid pool identity".into());
    }
    Ok((p.into(), i.into()))
}
fn membership(v: &Value) -> Result<Vec<Value>, String> {
    let entries = v["pools"].as_array().ok_or("missing inventory")?;
    if entries.len() > 64 || v["device_id"].as_str().is_none() || v["revision"].as_u64().is_none() {
        return Err("invalid inventory".into());
    }
    let mut ids = HashSet::new();
    for e in entries {
        if !ids.insert(identity(e)?) || e["revision"].as_u64().is_none() {
            return Err("duplicate or invalid inventory entry".into());
        }
    }
    Ok(entries.clone())
}
fn host(socket: &Path, deadline: Instant) -> Result<Value, String> {
    loop {
        let mut cursor: Option<String> = None;
        let mut snapshot: Option<String> = None;
        let mut entries = Vec::new();
        let mut first = None;
        let mut seen = HashSet::new();
        let mut configured = 0;
        let mut effective = 0;
        loop {
            let mut args = json!({"page_size":16});
            if let Some(c) = &cursor {
                args["cursor"] = json!(c);
            }
            if let Some(s) = &snapshot {
                args["snapshot_id"] = json!(s);
            }
            let page = match request(socket, "host.observe", args, deadline) {
                Err(e) if e == "revision_conflict" && Instant::now() < deadline => break,
                other => other?,
            };
            let sid = page["snapshot_id"]
                .as_str()
                .ok_or("missing snapshot identity")?
                .to_string();
            if snapshot.as_ref().is_some_and(|s| *s != sid) {
                return Err("snapshot identity changed".into());
            }
            snapshot = Some(sid);
            if first.is_none() {
                first = Some(page.clone());
            }
            let items = page["bindings"].as_array().ok_or("missing bindings")?;
            if items.len() > 16 {
                return Err("oversized page".into());
            }
            for item in items {
                let key = identity(item)?;
                if !seen.insert(key) {
                    return Err("duplicate binding".into());
                }
                configured += usize::from(item["configured"].as_bool().ok_or("invalid binding")?);
                effective += usize::from(item["effective"].as_bool().ok_or("invalid binding")?);
                if configured > 64 || effective > 64 || entries.len() >= 128 {
                    return Err("binding capacity exceeded".into());
                }
                entries.push(item.clone());
            }
            let total = page["total"].as_u64().ok_or("missing total")? as usize;
            if total > 128
                || entries.len() > total
                || first.as_ref().and_then(|v: &Value| v["total"].as_u64()) != Some(total as u64)
            {
                return Err("invalid binding total".into());
            }
            match &page["next_cursor"] {
                Value::Null => {
                    if entries.len() != total {
                        return Err("incomplete host snapshot".into());
                    }
                    let mut result = first.ok_or("missing first page")?;
                    result["bindings"] = json!(entries);
                    result["next_cursor"] = Value::Null;
                    return Ok(result);
                }
                Value::String(next)
                    if !next.is_empty() && cursor.as_ref() != Some(next) && !items.is_empty() =>
                {
                    cursor = Some(next.clone())
                }
                _ => return Err("invalid pagination cursor".into()),
            }
        }
        if Instant::now() >= deadline {
            return Err("snapshot conflict deadline".into());
        }
    }
}
fn join(state: &mut State) -> Result<(), String> {
    let mut all = Vec::new();
    if let Some(entries) = &state.membership.observation.value {
        for e in entries {
            all.push((identity(e)?, Some(e.clone()), None));
        }
    }
    if let Some(host) = &state.host.observation.value
        && let Some(entries) = host["bindings"].as_array()
    {
        for e in entries {
            let id = identity(e)?;
            if let Some(row) = all.iter_mut().find(|row| row.0 == id) {
                row.2 = Some(e.clone());
            } else {
                all.push((id, None, Some(e.clone())));
            }
        }
    }
    if all.len() > 192 {
        return Err("joined capacity exceeded".into());
    }
    let mut old = std::mem::take(&mut state.pools);
    state.pools = all
        .into_iter()
        .map(|((pool_id, incarnation_id), membership, host)| {
            let observation = old
                .iter()
                .position(|p| p.pool_id == pool_id && p.incarnation_id == incarnation_id)
                .map(|i| old.swap_remove(i).observation)
                .unwrap_or_else(|| Track::new("pool.observe"));
            Pool {
                pool_id,
                incarnation_id,
                membership,
                host,
                observation,
            }
        })
        .collect();
    Ok(())
}
fn run(
    state: Arc<Mutex<State>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    rx: Receiver<()>,
    socket: PathBuf,
    config: Option<PathBuf>,
) {
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let started = Instant::now();
        let deadline = started + SCAN;
        let mut local = local(config.as_deref());
        {
            let mut s = state.lock().unwrap();
            let now = Instant::now();
            if let Some(old) = &s.local.observation.value {
                let elapsed = s
                    .local
                    .last
                    .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
                retain_local(&mut local.own_executable, &old.own_executable, elapsed);
                retain_local(&mut local.path_candidates, &old.path_candidates, elapsed);
                retain_local(&mut local.config, &old.config, elapsed);
                retain_local(&mut local.config_access, &old.config_access, elapsed);
                retain_local(&mut local.config_ownership, &old.config_ownership, elapsed);
                retain_local(&mut local.config_summary, &old.config_summary, elapsed);
                retain_local(&mut local.swap_free, &old.swap_free, elapsed);
                retain_local(&mut local.service, &old.service, elapsed);
                retain_local(&mut local.service_state, &old.service_state, elapsed);
                retain_local(&mut local.registry, &old.registry, elapsed);
                retain_local(&mut local.usb_mode, &old.usb_mode, elapsed);
            }
            s.local.success(local, now);
            s.publish();
        }
        let result = host(&socket, deadline);
        {
            let mut s = state.lock().unwrap();
            match result {
                Ok(v) => s.host.success(v, Instant::now()),
                Err(e) => s.host.fail(e),
            };
            if let Err(error) = join(&mut s) {
                s.host.fail(error);
            }
            s.publish();
        }
        let result = request(&socket, "device.info", json!({}), deadline);
        let info_id = result
            .as_ref()
            .ok()
            .and_then(|v| v["device_id"].as_str())
            .map(str::to_owned);
        {
            let mut s = state.lock().unwrap();
            match result {
                Ok(v) => s.device.success(v, Instant::now()),
                Err(e) => s.device.fail(e),
            };
            s.publish();
        }
        let result = request(&socket, "device.inventory", json!({}), deadline).and_then(|v| {
            let id = v["device_id"]
                .as_str()
                .ok_or("missing inventory device identity")?
                .to_owned();
            if info_id.as_ref().is_some_and(|expected| *expected != id) {
                return Err("inventory device identity mismatch".into());
            }
            Ok((id, membership(&v)?))
        });
        let device_id = result.as_ref().ok().map(|(id, _)| id.clone());
        {
            let mut s = state.lock().unwrap();
            match result {
                Ok((id, v)) => {
                    if s.membership_device.as_ref().is_some_and(|old| *old != id) {
                        for pool in &mut s.pools {
                            pool.observation = Track::new("pool.observe");
                        }
                    }
                    s.membership_device = Some(id);
                    s.membership.success(v, Instant::now());
                }
                Err(e) => {
                    s.membership.fail(e.clone());
                    for p in &mut s.pools {
                        if p.membership.is_some() {
                            p.observation.fail(e.clone());
                        }
                    }
                }
            };
            if let Err(error) = join(&mut s) {
                s.membership.fail(error);
            }
            s.publish();
        }
        let targets: Vec<_> = {
            let s = state.lock().unwrap();
            s.pools
                .iter()
                .filter(|p| device_id.is_some() && p.membership.is_some())
                .map(|p| {
                    (
                        p.pool_id.clone(),
                        p.incarnation_id.clone(),
                        p.membership.as_ref().and_then(|m| m["revision"].as_u64()),
                    )
                })
                .collect()
        };
        for (p, i, revision) in targets {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let result = request(
                &socket,
                "pool.observe",
                json!({"pool_id":p,"incarnation_id":i}),
                deadline,
            )
            .and_then(|v| {
                if identity(&v)? != (p.clone(), i.clone())
                    || device_id
                        .as_deref()
                        .is_some_and(|id| v["device_id"].as_str() != Some(id))
                {
                    return Err("pool response identity mismatch".into());
                }
                if revision != v["revision"].as_u64() {
                    return Err("pool changed during scan; inventory is partial".into());
                }
                Ok(v)
            });
            let mut s = state.lock().unwrap();
            if result
                .as_ref()
                .err()
                .is_some_and(|e| e == "pool changed during scan; inventory is partial")
            {
                s.membership
                    .fail("pool changed during scan; inventory is partial".into());
            }
            if let Some(pool) = s
                .pools
                .iter_mut()
                .find(|x| x.pool_id == p && x.incarnation_id == i)
            {
                match result {
                    Ok(v) => pool.observation.success(v, Instant::now()),
                    Err(e) => pool.observation.fail(e),
                }
            }
            s.publish();
        }
        let wait = REFRESH.saturating_sub(started.elapsed());
        let _ = rx.recv_timeout(wait);
    }
}
/// Public-only bounded history. Raw subprocess/socket payloads never enter it.
#[derive(Default)]
pub struct Diagnostics {
    lines: std::collections::VecDeque<String>,
    seen: std::collections::BTreeMap<String, (Option<u64>, ObservationState, String)>,
}

fn diagnostic_text(text: &str) -> String {
    text.chars()
        .take(256)
        .flat_map(char::escape_default)
        .collect()
}

fn diagnostic_fields(line: &mut String, value: &Value) {
    use std::fmt::Write;
    for key in [
        "device_id",
        "usb_serial",
        "build_id",
        "source_commit",
        "config_identity",
        "journal_position",
        "snapshot_id",
        "pool_id",
        "incarnation_id",
        "generation_id",
        "revision",
        "health",
        "failure",
        "period_floor",
        "period",
        "certificate_expiry",
    ] {
        match &value[key] {
            Value::String(s) => {
                let _ = write!(line, " {key}={}", diagnostic_text(s));
            }
            Value::Number(n) => {
                let _ = write!(line, " {key}={n}");
            }
            Value::Bool(b) => {
                let _ = write!(line, " {key}={b}");
            }
            _ => {}
        }
    }
}

impl Diagnostics {
    fn begin<T>(&mut self, label: &str, observation: &Observation<T>) -> Option<String> {
        let error = observation
            .public_error
            .as_deref()
            .map(diagnostic_text)
            .unwrap_or_default();
        let signature = (observation.observed_at_unix_us, observation.state, error);
        if self.seen.get(label) == Some(&signature) {
            return None;
        }
        if self.seen.len() == 256 && !self.seen.contains_key(label) {
            self.seen.clear();
        }
        let line = format!(
            "{} source={} observed_unix_us={:?} age_us={:?} state={:?} error={}",
            diagnostic_text(label),
            diagnostic_text(&observation.source),
            signature.0,
            observation.age.map(|age| age.as_micros()),
            signature.1,
            signature.2,
        );
        self.seen.insert(label.to_owned(), signature);
        Some(line)
    }

    fn push(&mut self, mut line: String) {
        if line.len() > 4096 {
            // All added text is ASCII-escaped, so this is also a character boundary.
            line.truncate(4096);
            line.push_str(" [truncated]");
        }
        if self.lines.len() == 256 {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    pub fn record(&mut self, snapshot: &Snapshot) {
        if let Some(line) = self.begin("local", &snapshot.local) {
            self.push(line);
        }
        if let Some(local) = &snapshot.local.value
            && let Some(mut line) = self.begin("agent service", &local.service)
        {
            if let Some(value) = &local.service.value {
                line.push_str(" observed=");
                line.push_str(&diagnostic_text(value));
            }
            self.push(line);
        }
        for (label, observation) in [("host", &snapshot.host), ("device", &snapshot.device)] {
            if let Some(mut line) = self.begin(label, observation) {
                if let Some(value) = &observation.value {
                    diagnostic_fields(&mut line, value);
                }
                self.push(line);
            }
        }
        if let Some(line) = self.begin("membership", &snapshot.membership) {
            self.push(line);
        }
        for pool in &snapshot.pools {
            let label = format!("pool {}/{}", pool.pool_id, pool.incarnation_id);
            if let Some(mut line) = self.begin(&label, &pool.observation) {
                if let Some(value) = &pool.observation.value {
                    diagnostic_fields(&mut line, value);
                    for role in ["active", "staged"] {
                        if value[role].is_object() {
                            line.push_str(&format!(" {role}:"));
                            diagnostic_fields(&mut line, &value[role]);
                        }
                    }
                }
                self.push(line);
            }
        }
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().map(String::as_str)
    }

    pub fn export(&self, path: &Path) -> std::io::Result<()> {
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "diagnostic destination must be absolute",
            ));
        }
        let mut text = String::with_capacity(self.lines.iter().map(|line| line.len() + 1).sum());
        for line in &self.lines {
            text.push_str(line);
            text.push('\n');
        }
        crate::files::publish_no_clobber(path, text.as_bytes(), 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structured_service_and_config_access() {
        let service = parse_service("ActiveState=active\nMainPID=42\nLoadState=loaded\n").unwrap();
        assert_eq!(service.load, "loaded");
        assert_eq!(service.active, "active");
        assert_eq!(service.main_pid, Some(42));
        assert!(parse_service("LoadState=loaded\nActiveState=active\nMainPID=bad\n").is_err());
        assert!(parse_service("ActiveState=active\nMainPID=0\n").is_err());
        let absent = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        let denied = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(config_access(&absent), Ok(ConfigAccess::Absent));
        assert_eq!(config_access(&denied), Ok(ConfigAccess::Denied));
        assert_eq!(
            config_access(&Ok(PathBuf::from("/config"))),
            Ok(ConfigAccess::Readable)
        );
    }
    #[test]
    fn stale_after_observation_failure() {
        let t = Instant::now();
        let mut x = Track::new("test");
        x.success(7, t);
        let stamp = x.observation.observed_at_unix_us;
        x.fail("lost".into());
        let o = x.get(t + Duration::from_secs(1));
        assert_eq!(o.state, ObservationState::Stale);
        assert_eq!(o.value, Some(7));
        assert_eq!(o.observed_at_unix_us, stamp);
        assert_eq!(o.age, Some(Duration::from_secs(1)));
    }
    #[test]
    fn freshness_boundary() {
        let t = Instant::now();
        let mut x = Track::new("test");
        x.success(7, t);
        assert_eq!(
            x.get(t + FRESH - Duration::from_nanos(1)).state,
            ObservationState::Fresh
        );
        assert_eq!(x.get(t + FRESH).state, ObservationState::Stale);
    }
    #[test]
    fn unmatched_join() {
        let mut s = State::new();
        let a = "aa".repeat(28);
        let b = "bb".repeat(28);
        let i = "01".repeat(16);
        s.membership.success(
            vec![json!({"pool_id":a,"incarnation_id":i,"revision":1})],
            Instant::now(),
        );
        s.host.success(
            json!({"bindings":[{"pool_id":b,"incarnation_id":i}]}),
            Instant::now(),
        );
        join(&mut s).unwrap();
        assert_eq!(s.pools.len(), 2);
        assert!(
            s.pools
                .iter()
                .any(|p| p.membership.is_some() && p.host.is_none())
        );
        assert!(
            s.pools
                .iter()
                .any(|p| p.host.is_some() && p.membership.is_none())
        );
    }
    #[test]
    fn ambiguous_usb_never_selects_a_target() {
        use super::super::model::DeviceMode;
        assert_eq!(candidate_mode(0, 0), DeviceMode::Absent);
        assert_eq!(candidate_mode(1, 0), DeviceMode::Application);
        assert_eq!(candidate_mode(0, 1), DeviceMode::Bootloader);
        for (application, bootloader) in [(2, 0), (0, 2), (1, 1)] {
            assert_eq!(
                candidate_mode(application, bootloader),
                DeviceMode::Ambiguous
            );
        }
    }

    #[test]
    fn diagnostics_exclude_unknown_payloads_escape_controls_and_evict_old_entries() {
        let mut state = State::new();
        state.device.success(
            json!({
                "device_id": "public-device",
                "private_key": "MUST_NOT_BE_RETAINED",
                "raw_current": "MUST_NOT_BE_RETAINED",
            }),
            Instant::now(),
        );
        state.device.fail("disconnected\u{1b}[2J".into());
        let mut log = Diagnostics::default();
        log.record(&state.snapshot());
        let output = log.lines().collect::<Vec<_>>().join("\n");
        assert!(output.contains("public-device"));
        assert!(output.contains("disconnected\\u{1b}[2J"));
        assert!(!output.contains("MUST_NOT_BE_RETAINED"));
        assert!(!output.contains('\u{1b}'));
        for i in 0..300 {
            log.push(format!("event-{i}"));
        }
        assert_eq!(log.lines().next(), Some("event-44"));
        assert_eq!(log.lines().last(), Some("event-299"));
    }
}
