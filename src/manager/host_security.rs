//! Attended host memory-boundary review and forward-only application.
use super::{host, model::MaintenanceRecord, producer, records::RecordStore, setup};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    process::{Command, Stdio},
};

fn trusted_program(path: &Path) -> io::Result<()> {
    host::trusted_ancestry(path)?;
    let resolved = fs::canonicalize(path)?;
    host::trusted_ancestry(&resolved)?;
    let metadata = fs::metadata(&resolved)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe executable: {}", path.display()),
        ));
    }
    Ok(())
}

fn diagnostic(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

const POLICY: &str = "/etc/pico2-kes-agent/host-security.env";
const SLEEP: [&str; 4] = [
    "sleep.target",
    "suspend.target",
    "hibernate.target",
    "hybrid-sleep.target",
];
const MAX_INPUT: u64 = 65536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEvidence {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    contents: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitSource {
    path: String,
    file: FileEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    fstab: Option<FileEvidence>,
    crypttab: Option<FileEvidence>,
    swaps: Vec<String>,
    units: Vec<String>,
    masks: Vec<bool>,
    sources: Vec<UnitSource>,
    policy: Option<FileEvidence>,
    group: u32,
    node_policy: Option<producer::Existing>,
    node_state: String,
    node_invocation: String,
    agent_limits: String,
    node_limits: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub commissioning: bool,
    pub snapshot_policy_acknowledged: bool,
    pub backup_private_off_primary: bool,
    pub node_memory_acknowledged: bool,
    evidence: Evidence,
}

pub struct Review {
    pub ready: bool,
    pub lines: Vec<String>,
    pub request: Request,
}

impl Request {
    pub fn validate(&self) -> bool {
        self.snapshot_policy_acknowledged
            && self.backup_private_off_primary
            && (self.commissioning || self.node_memory_acknowledged)
            && self.evidence.units.len() <= 128
            && self.evidence.swaps.len() <= 128
            && self.evidence.units.len() == self.evidence.masks.len()
            && self.evidence.units.iter().all(|unit| valid_unit(unit))
            && self.evidence.sources.len() <= 256
            && self
                .evidence
                .sources
                .iter()
                .all(|s| valid_source(&s.path) && s.file.contents.len() <= MAX_INPUT as usize)
            && self.evidence.swaps.iter().all(|path| {
                path.starts_with('/') && path.len() <= 4096 && !path.chars().any(char::is_control)
            })
            && [
                &self.evidence.fstab,
                &self.evidence.crypttab,
                &self.evidence.policy,
            ]
            .iter()
            .all(|f| {
                f.as_ref()
                    .is_none_or(|f| f.contents.len() <= MAX_INPUT as usize)
            })
    }

    pub fn lines(&self) -> Vec<String> {
        let e = &self.evidence;
        let mut lines = vec![
            format!("Active swap to turn off: {}", if e.swaps.is_empty() { "none".into() } else { e.swaps.join(", ") }),
            format!("Persistent /dev/null systemd masks: {}", e.units.join(", ")),
            format!("Current agent limits: {}; node limits: {}", e.agent_limits, if self.commissioning { "not checked" } else { &e.node_limits }),
            format!("Current policy: {}", e.policy.as_ref().map(|f| diagnostic(&f.contents)).unwrap_or_else(|| "(absent)".into())),
            "Existing fstab and unrelated policy lines are retained; no fstab editing.".into(),
            "Scope is discovered systemd-managed swap sources; future administrator changes invalidate readiness.".into(),
            "Acknowledge snapshot/crashdump protection and backup private material off the primary host; these assertions cannot be verified.".into(),
            "Publish /etc/pico2-kes-agent/host-security.env as root:pico2-kes-agent mode 0640 after approval.".into(),
            "Set SNAPSHOT_POLICY=disabled-or-encrypted-off-host and BACKUP_PRIVATE_POLICY=off-primary.".into(),
        ];
        if !self.commissioning {
            lines.push(format!("Install authenticated memory drop-in for cardano-node.service; current state {}. An active node is explicitly approved for try-restart; a stopped node is never started.", e.node_state));
            lines.push("Acknowledge NODE_MEMORY_POLICY=core-and-swap-disabled.".into());
        }
        lines
    }
}

fn valid_unit(unit: &str) -> bool {
    unit.len() <= 255
        && (unit.ends_with(".swap") || SLEEP.contains(&unit) || unit == "swap.target")
        && unit
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:@\\-".contains(&c))
}

fn bounded_command(program: &str, args: &[&str]) -> io::Result<String> {
    trusted_program(Path::new("/usr/bin/timeout"))?;
    trusted_program(Path::new(program))?;
    let mut command = Command::new("/usr/bin/timeout");
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["--kill-after=2s", "15s", program]);
    if program == "/usr/bin/systemctl" {
        command.arg("--no-ask-password");
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("command output unavailable"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("command diagnostics unavailable"))?;
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        (&mut stdout)
            .take(MAX_INPUT + 1)
            .read_to_end(&mut b)
            .map(|_| b)
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        (&mut stderr).take(4097).read_to_end(&mut b).map(|_| b)
    });
    let status = child.wait()?;
    let out = out
        .join()
        .map_err(|_| io::Error::other("command reader failed"))??;
    let err = err
        .join()
        .map_err(|_| io::Error::other("command reader failed"))??;
    if !status.success() || out.len() as u64 > MAX_INPUT {
        return Err(io::Error::other(format!(
            "{program} failed or exceeded output limit ({status}): {}",
            diagnostic(&err[..err.len().min(4096)])
        )));
    }
    String::from_utf8(out).map_err(io::Error::other)
}

fn node_state() -> io::Result<String> {
    let state = bounded_command(
        "/usr/bin/systemctl",
        &[
            "show",
            "cardano-node.service",
            "--property=ActiveState",
            "--value",
        ],
    )?;
    let state = state.trim();
    if !matches!(state, "active" | "inactive" | "failed") {
        return Err(io::Error::other(
            "producer state is unknown or transitioning",
        ));
    }
    Ok(state.into())
}

fn snapshot(path: &Path) -> io::Result<Option<FileEvidence>> {
    host::trusted_ancestry(path)?;
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
        || m.nlink() != 1
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || m.len() > MAX_INPUT
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe or oversized file: {}", path.display()),
        ));
    }
    let mut contents = Vec::new();
    file.take(MAX_INPUT + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_INPUT {
        return Err(io::Error::other("file grew during review"));
    }
    Ok(Some(FileEvidence {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        contents,
    }))
}

fn masked(unit: &str) -> io::Result<bool> {
    let path = Path::new("/etc/systemd/system").join(unit);
    host::trusted_ancestry(&path)?;
    mask_path(&path)
}

fn mask_path(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
        Ok(m)
            if m.file_type().is_symlink()
                && m.uid() == 0
                && fs::read_link(path)? == Path::new("/dev/null") =>
        {
            Ok(true)
        }
        Ok(_) => Err(io::Error::other(format!(
            "refusing to overwrite existing unit or symlink: {}",
            path.display()
        ))),
    }
}

fn swap_paths() -> io::Result<Vec<String>> {
    let file = File::open("/proc/swaps")?;
    let mut data = String::new();
    file.take(MAX_INPUT + 1).read_to_string(&mut data)?;
    if data.len() as u64 > MAX_INPUT {
        return Err(io::Error::other("swap list exceeds limit"));
    }
    let mut paths = Vec::new();
    for line in data.lines().skip(1) {
        let name = line
            .split_whitespace()
            .next()
            .ok_or_else(|| io::Error::other("invalid swap entry"))?;
        if name.contains('\\') || !name.starts_with('/') || name.chars().any(char::is_control) {
            return Err(io::Error::other(
                "unsupported escaped or non-absolute active swap path",
            ));
        }
        paths.push(name.to_owned());
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn escaped_swap(path: &str) -> io::Result<String> {
    let unit = bounded_command(
        "/usr/bin/systemd-escape",
        &["--path", "--suffix=swap", "--", path],
    )?
    .trim()
    .to_owned();
    if !valid_unit(&unit) || !unit.ends_with(".swap") {
        return Err(io::Error::other("invalid generated swap unit"));
    }
    Ok(unit)
}

fn fstab_units(fstab: &Option<FileEvidence>) -> io::Result<Vec<String>> {
    let mut units = Vec::new();
    if let Some(file) = fstab {
        let text = std::str::from_utf8(&file.contents).map_err(io::Error::other)?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 3 || fields[2] != "swap" {
                continue;
            }
            if fields[0].contains('\\') {
                return Err(io::Error::other(
                    "escaped fstab swap source requires separate review",
                ));
            }
            let source = if let Some(id) = fields[0].strip_prefix("UUID=") {
                format!("/dev/disk/by-uuid/{id}")
            } else if let Some(id) = fields[0].strip_prefix("LABEL=") {
                format!("/dev/disk/by-label/{id}")
            } else if let Some(id) = fields[0].strip_prefix("PARTUUID=") {
                format!("/dev/disk/by-partuuid/{id}")
            } else if let Some(id) = fields[0].strip_prefix("PARTLABEL=") {
                format!("/dev/disk/by-partlabel/{id}")
            } else {
                fields[0].to_owned()
            };
            if !source.starts_with('/') || source.contains("..") {
                return Err(io::Error::other("unsupported fstab swap source"));
            }
            units.push(escaped_swap(&source)?);
        }
    }
    Ok(units)
}

fn valid_source(value: &str) -> bool {
    let path = Path::new(value);
    (path.starts_with("/usr/lib/systemd/system")
        || path.starts_with("/etc/systemd/system")
        || path.starts_with("/run/systemd/system")
        || path.starts_with("/run/systemd/generator")
        || path.starts_with("/run/systemd/generator.early")
        || path.starts_with("/run/systemd/generator.late"))
        && path.components().all(|part| {
            !matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

fn unit_sources(units: &BTreeSet<String>) -> io::Result<Vec<UnitSource>> {
    let mut paths = BTreeSet::new();
    for unit in units {
        let text = bounded_command(
            "/usr/bin/systemctl",
            &[
                "show",
                unit,
                "--property=FragmentPath",
                "--property=DropInPaths",
            ],
        )?;
        for line in text.lines() {
            let (_, values) = line
                .split_once('=')
                .ok_or_else(|| io::Error::other("invalid systemd unit source"))?;
            for path in values.split_whitespace() {
                if path == "/dev/null" {
                    continue;
                }
                if !valid_source(path) {
                    return Err(io::Error::other(format!("unsupported unit source: {path}")));
                }
                paths.insert(path.to_owned());
            }
        }
    }
    if paths.len() > 256 {
        return Err(io::Error::other("too many unit sources"));
    }
    paths
        .into_iter()
        .map(|path| {
            let file = snapshot(Path::new(&path))?
                .ok_or_else(|| io::Error::other("systemd unit source disappeared"))?;
            Ok(UnitSource { path, file })
        })
        .collect()
}

fn sources_unchanged(sources: &[UnitSource]) -> io::Result<bool> {
    for source in sources {
        if !valid_source(&source.path) {
            return Ok(false);
        }
        let Some(now) = snapshot(Path::new(&source.path))? else {
            return Ok(false);
        };
        if now.uid != source.file.uid
            || now.gid != source.file.gid
            || now.mode != source.file.mode
            || now.contents != source.file.contents
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn observe(commissioning: bool) -> io::Result<Evidence> {
    host::checked_service()?;
    for path in [
        "/etc/systemd/zram-generator.conf",
        "/usr/lib/systemd/zram-generator.conf",
        "/run/systemd/zram-generator.conf",
        "/etc/systemd/zram-generator.conf.d",
        "/usr/lib/systemd/zram-generator.conf.d",
        "/run/systemd/zram-generator.conf.d",
        "/etc/default/zramswap",
        "/etc/conf.d/zram",
    ] {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "unsupported zram swap configuration: {path}"
                )));
            }
        }
    }
    let fstab = snapshot(Path::new("/etc/fstab"))?;
    let crypttab = snapshot(Path::new("/etc/crypttab"))?;
    if let Some(file) = &crypttab {
        let text = std::str::from_utf8(&file.contents).map_err(io::Error::other)?;
        if text.lines().any(|line| {
            line.split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .skip(3)
                .any(|options| options.split(',').any(|option| option == "swap"))
        }) {
            return Err(io::Error::other(
                "crypttab swap configuration is not supported",
            ));
        }
    }
    let swaps = swap_paths()?;
    let mut units = BTreeSet::new();
    for command in [
        &[
            "list-unit-files",
            "--type=swap",
            "--no-legend",
            "--no-pager",
        ][..],
        &[
            "list-units",
            "--all",
            "--type=swap",
            "--no-legend",
            "--no-pager",
            "--plain",
        ][..],
    ] {
        for line in bounded_command("/usr/bin/systemctl", command)?.lines() {
            let unit = line
                .split_whitespace()
                .next()
                .ok_or_else(|| io::Error::other("invalid systemd swap list"))?;
            if !valid_unit(unit) || !unit.ends_with(".swap") {
                return Err(io::Error::other("unsupported systemd swap unit"));
            }
            units.insert(unit.to_owned());
        }
    }
    units.extend(fstab_units(&fstab)?);
    for swap in &swaps {
        let escaped = escaped_swap(swap)?;
        if !units.contains(&escaped) {
            let mut accounted = false;
            for unit in &units {
                let what = bounded_command(
                    "/usr/bin/systemctl",
                    &["show", unit, "--property=What", "--value"],
                )?;
                if let (Ok(a), Ok(b)) = (fs::canonicalize(what.trim()), fs::canonicalize(swap))
                    && a == b
                {
                    accounted = true;
                    break;
                }
            }
            if !accounted {
                return Err(io::Error::other(format!(
                    "active swap has no discovered systemd swap unit: {swap}"
                )));
            }
        }
    }
    let sources = unit_sources(&units)?;
    units.extend(SLEEP.into_iter().map(str::to_owned));
    units.insert("swap.target".into());
    if units.len() > 128 || swaps.len() > 128 {
        return Err(io::Error::other("too many swap units or active swaps"));
    }
    let units: Vec<_> = units.into_iter().collect();
    let masks = units
        .iter()
        .map(|unit| masked(unit))
        .collect::<io::Result<_>>()?;
    let policy = snapshot(Path::new(POLICY)).map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(error.kind(), format!("cannot review {POLICY}: {error}; ensure your login has pico2-kes-agent group membership and sign in again"))
        } else { error }
    })?;
    let agent_limits = bounded_command(
        "/usr/bin/systemctl",
        &[
            "show",
            "pico2-kes-agentd.service",
            "--property=LimitCORE",
            "--property=MemorySwapMax",
        ],
    )?;
    if !agent_limits.lines().any(|l| l == "LimitCORE=0")
        || !agent_limits.lines().any(|l| l == "MemorySwapMax=0")
    {
        return Err(io::Error::other(
            "authenticated agent unit must report LimitCORE=0 and MemorySwapMax=0",
        ));
    }
    let node_limits = if commissioning {
        String::new()
    } else {
        bounded_command(
            "/usr/bin/systemctl",
            &[
                "show",
                "cardano-node.service",
                "--property=LoadState",
                "--property=LimitCORE",
                "--property=MemorySwapMax",
            ],
        )?
    };
    if !commissioning && !node_limits.lines().any(|line| line == "LoadState=loaded") {
        return Err(io::Error::other(
            "Normal operation requires a real, loaded cardano-node.service; no dummy unit or drop-in will be created for an absent node",
        ));
    }
    let (_, group) = setup::service_identity()?;
    if policy.as_ref().is_some_and(|f| f.gid != group) {
        return Err(io::Error::other(
            "existing host policy has a different group; refusing to change its ownership",
        ));
    }
    let node_policy = if commissioning {
        None
    } else {
        producer::inspect("cardano-node.service")?
    };
    if node_policy.as_ref().is_some_and(|f| {
        f.owner != 0
            || f.group != 0
            || f.mode != 0o644
            || f.contents.as_slice()
                != include_bytes!("../../deploy/cardano-node-memory-hardening.conf")
    }) {
        return Err(io::Error::other(
            "existing producer hardening drop-in differs; refusing to overwrite it",
        ));
    }
    let node_state = if commissioning {
        String::new()
    } else {
        node_state()?
    };
    let node_invocation = if commissioning {
        String::new()
    } else {
        bounded_command(
            "/usr/bin/systemctl",
            &[
                "show",
                "cardano-node.service",
                "--property=InvocationID",
                "--value",
            ],
        )?
        .trim()
        .to_owned()
    };
    if node_state == "active" && !valid_invocation(&node_invocation) {
        return Err(io::Error::other(
            "active producer InvocationID is unavailable",
        ));
    }
    Ok(Evidence {
        fstab,
        crypttab,
        swaps,
        units,
        masks,
        sources,
        policy,
        group,
        node_policy,
        node_state,
        node_invocation,
        agent_limits,
        node_limits,
    })
}

pub(super) fn require_ready(commissioning: bool) -> io::Result<()> {
    let review = review(commissioning)?;
    if !review.ready {
        return Err(io::Error::other(format!(
            "Host security prerequisites changed or remain incomplete; return to setup before starting the service:\n{}",
            review.lines.join("\n")
        )));
    }
    Ok(())
}

pub fn review(commissioning: bool) -> io::Result<Review> {
    let evidence = observe(commissioning)?;
    let request = Request {
        commissioning,
        snapshot_policy_acknowledged: false,
        backup_private_off_primary: false,
        node_memory_acknowledged: false,
        evidence,
    };
    let preflight = check(commissioning);
    let ready = request.evidence.swaps.is_empty()
        && request.evidence.masks.iter().all(|m| *m)
        && request
            .evidence
            .policy
            .as_ref()
            .is_some_and(|f| f.uid == 0 && f.gid == request.evidence.group && f.mode == 0o640)
        && (commissioning
            || request.evidence.node_policy.as_ref().is_some_and(|f| {
                f.owner == 0
                    && f.group == 0
                    && f.mode == 0o644
                    && f.contents.as_slice()
                        == include_bytes!("../../deploy/cardano-node-memory-hardening.conf")
            }))
        && preflight.is_ok();
    let mut lines = request.lines();
    if let Err(error) = preflight {
        lines.push(format!("Current installed preflight: {error}"));
    }
    Ok(Review {
        ready,
        lines,
        request,
    })
}
fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value.bytes().all(|c| c.is_ascii_hexdigit())
        && value.bytes().any(|c| c != b'0')
}

fn restarted_after(baseline: Option<&str>, current: &str) -> bool {
    baseline.is_some_and(|baseline| valid_invocation(baseline) && baseline != current)
        && valid_invocation(current)
}

fn limits_disabled(limits: &str) -> bool {
    limits.lines().any(|line| line == "LimitCORE=0")
        && limits.lines().any(|line| line == "MemorySwapMax=0")
}

fn policy_bytes(original: Option<&FileEvidence>, commissioning: bool) -> io::Result<Vec<u8>> {
    let original = original.map(|f| f.contents.as_slice()).unwrap_or_default();
    let text = std::str::from_utf8(original).map_err(io::Error::other)?;
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let key = line.trim_start().split('=').next().unwrap_or("").trim();
        if matches!(key, "SNAPSHOT_POLICY" | "BACKUP_PRIVATE_POLICY")
            || (!commissioning && key == "NODE_MEMORY_POLICY")
        {
            continue;
        }
        out.push_str(line);
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(
        "SNAPSHOT_POLICY=disabled-or-encrypted-off-host\nBACKUP_PRIVATE_POLICY=off-primary\n",
    );
    if !commissioning {
        out.push_str("NODE_MEMORY_POLICY=core-and-swap-disabled\n");
    }
    if out.len() as u64 > MAX_INPUT {
        return Err(io::Error::other("updated policy exceeds limit"));
    }
    Ok(out.into_bytes())
}

fn note(
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    name: &str,
    evidence: String,
) -> io::Result<()> {
    record.checkpoints.push(host::checkpoint(name, evidence));
    store.update(record)
}

fn done(record: &MaintenanceRecord, name: &str, evidence: &str) -> bool {
    record
        .checkpoints
        .iter()
        .any(|c| c.name == name && c.evidence == evidence)
}

fn complete_policy_stage(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut partial = Vec::new();
    (&mut *file).take(MAX_INPUT + 1).read_to_end(&mut partial)?;
    if !bytes.starts_with(&partial) {
        return Err(io::Error::other("staged policy contains unexpected bytes"));
    }
    file.write_all(&bytes[partial.len()..])?;
    file.sync_all()
}

fn publish_policy(
    request: &Request,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<()> {
    let path = Path::new(POLICY);
    let dir = path.parent().unwrap();
    host::trusted_ancestry(path)?;
    let bytes = policy_bytes(request.evidence.policy.as_ref(), request.commissioning)?;
    let temp = dir.join(format!(".host-security-{}.tmp", record.operation_id));
    let staged = record
        .checkpoints
        .iter()
        .find(|c| c.name == "host-security-policy-staged")
        .map(|c| serde_json::from_str::<FileEvidence>(&c.evidence).map_err(io::Error::other))
        .transpose()?;
    let staged = match staged {
        Some(staged) => staged,
        None => {
            if snapshot(path)? != request.evidence.policy {
                return Err(io::Error::other("host policy changed since review"));
            }
            let resuming = done(
                record,
                "host-security-policy-stage-starting",
                &temp.display().to_string(),
            );
            note(
                store,
                record,
                "host-security-policy-stage-starting",
                temp.display().to_string(),
            )?;
            *effects = true;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
            let mut file = match options.create_new(true).open(&temp) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && resuming => {
                    let existing = snapshot(&temp)?
                        .ok_or_else(|| io::Error::other("staged policy disappeared"))?;
                    if !matches!(existing.mode, 0o600 | 0o640)
                        || (existing.gid != 0 && existing.gid != request.evidence.group)
                        || !bytes.starts_with(&existing.contents)
                    {
                        return Err(io::Error::other("unexpected partial policy stage"));
                    }
                    let file = options.create_new(false).open(&temp)?;
                    let metadata = file.metadata()?;
                    if metadata.dev() != existing.device || metadata.ino() != existing.inode {
                        return Err(io::Error::other(
                            "partial policy stage changed while opening",
                        ));
                    }
                    file
                }
                Err(error) => return Err(error),
            };
            if unsafe { libc::fchown(file.as_raw_fd(), 0, request.evidence.group) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), 0o640) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            complete_policy_stage(&mut file, &bytes)?;
            File::open(dir)?.sync_all()?;
            let staged =
                snapshot(&temp)?.ok_or_else(|| io::Error::other("staged policy disappeared"))?;
            note(
                store,
                record,
                "host-security-policy-staged",
                serde_json::to_string(&staged).map_err(io::Error::other)?,
            )?;
            staged
        }
    };
    if staged.uid != 0
        || staged.gid != request.evidence.group
        || staged.mode != 0o640
        || staged.contents != bytes
    {
        return Err(io::Error::other("staged host policy evidence is invalid"));
    }
    let current = snapshot(path)?;
    if current.as_ref() == Some(&staged) {
        match snapshot(&temp)? {
            Some(old) if request.evidence.policy.as_ref() == Some(&old) => {
                fs::remove_file(&temp)?;
            }
            None => {}
            _ => return Err(io::Error::other("unexpected file beside published policy")),
        }
        // A prior process may have died after rename but before persisting the directory.
        File::open(dir)?.sync_all()?;
        return Ok(());
    }
    if current != request.evidence.policy || snapshot(&temp)?.as_ref() != Some(&staged) {
        return Err(io::Error::other(
            "host policy or staged file changed since review",
        ));
    }
    note(
        store,
        record,
        "host-security-policy-publish-starting",
        path.display().to_string(),
    )?;
    let a = CString::new(temp.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let b = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let flags = if current.is_some() {
        libc::RENAME_EXCHANGE
    } else {
        libc::RENAME_NOREPLACE
    };
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if current.is_some() {
        if snapshot(&temp)? != current {
            let rollback = unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    a.as_ptr(),
                    libc::AT_FDCWD,
                    b.as_ptr(),
                    libc::RENAME_EXCHANGE,
                )
            };
            File::open(dir)?.sync_all()?;
            return Err(io::Error::other(format!(
                "policy destination raced; rollback status {rollback}; staged file retained"
            )));
        }
        fs::remove_file(&temp)?;
    }
    File::open(dir)?.sync_all()?;
    note(
        store,
        record,
        "host-security-policy-published",
        path.display().to_string(),
    )
}

fn compatible(original: &Evidence, current: &Evidence, record: &MaintenanceRecord) -> bool {
    if original.fstab != current.fstab
        || original.crypttab != current.crypttab
        || original.group != current.group
        || original.agent_limits != current.agent_limits
        || current
            .units
            .iter()
            .any(|unit| !original.units.contains(unit))
        || current
            .swaps
            .iter()
            .any(|swap| !original.swaps.contains(swap))
    {
        return false;
    }
    for (unit, was_masked) in original.units.iter().zip(&original.masks) {
        let Some(index) = current.units.iter().position(|candidate| candidate == unit) else {
            return false;
        };
        let now = current.masks[index];
        if (*was_masked && !now)
            || (!*was_masked && now && !done(record, "host-security-mask-starting", unit))
        {
            return false;
        }
    }
    for swap in &original.swaps {
        if !current.swaps.contains(swap) && !done(record, "host-security-swapoff-starting", swap) {
            return false;
        }
    }
    true
}

fn advance(
    request: &Request,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
    recovery: bool,
) -> io::Result<String> {
    if !request.validate() || !rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid approval or root required",
        ));
    }
    let current = observe(request.commissioning)?;
    if !sources_unchanged(&request.evidence.sources)? {
        return Err(io::Error::other("reviewed swap unit source changed"));
    }
    if (!recovery && current != request.evidence)
        || (recovery && !compatible(&request.evidence, &current, record))
    {
        return Err(io::Error::other(
            "host security evidence changed since approval; review again",
        ));
    }
    let staged = record
        .checkpoints
        .iter()
        .find(|c| c.name == "host-security-policy-staged")
        .map(|c| serde_json::from_str::<FileEvidence>(&c.evidence).map_err(io::Error::other))
        .transpose()?;
    if current.policy != request.evidence.policy
        && !staged
            .as_ref()
            .is_some_and(|staged| current.policy.as_ref() == Some(staged))
    {
        return Err(io::Error::other("host policy changed since approval"));
    }
    if !request.commissioning
        && !record
            .checkpoints
            .iter()
            .any(|c| c.name == "producer-file-starting")
        && (current.node_policy != request.evidence.node_policy
            || current.node_state != request.evidence.node_state
            || current.node_limits != request.evidence.node_limits
            || current.node_invocation != request.evidence.node_invocation)
    {
        return Err(io::Error::other("producer evidence changed since approval"));
    }
    if !recovery && current.policy != request.evidence.policy {
        return Err(io::Error::other("host policy changed since approval"));
    }
    for (unit, was_masked) in request.evidence.units.iter().zip(&request.evidence.masks) {
        if *was_masked {
            if !masked(unit)? {
                return Err(io::Error::other(format!(
                    "reviewed mask disappeared: {unit}"
                )));
            }
            continue;
        }
        if masked(unit)? {
            if !done(record, "host-security-mask-starting", unit) {
                return Err(io::Error::other(format!(
                    "unreviewed mask appeared: {unit}"
                )));
            }
            File::open("/etc/systemd/system")?.sync_all()?;
            if !done(record, "host-security-mask", unit) {
                note(store, record, "host-security-mask", unit.clone())?;
            }
            continue;
        }
        note(store, record, "host-security-mask-starting", unit.clone())?;
        *effects = true;
        let path = Path::new("/etc/systemd/system").join(unit);
        std::os::unix::fs::symlink("/dev/null", &path)?;
        File::open("/etc/systemd/system")?.sync_all()?;
        if !masked(unit)? {
            return Err(io::Error::other("persistent mask not retained"));
        }
        note(store, record, "host-security-mask", unit.clone())?;
    }
    note(
        store,
        record,
        "host-security-reload-starting",
        "daemon-reload".into(),
    )?;
    *effects = true;
    bounded_command("/usr/bin/systemctl", &["daemon-reload"])?;
    note(
        store,
        record,
        "host-security-reload",
        "daemon-reload".into(),
    )?;
    for swap in &request.evidence.swaps {
        let active = swap_paths()?;
        if active
            .iter()
            .any(|path| !request.evidence.swaps.contains(path))
        {
            return Err(io::Error::other("unreviewed swap became active"));
        }
        if !active.contains(swap) {
            if !done(record, "host-security-swapoff-starting", swap) {
                return Err(io::Error::other("swap changed since review"));
            }
            continue;
        }
        note(
            store,
            record,
            "host-security-swapoff-starting",
            swap.clone(),
        )?;
        *effects = true;
        bounded_command("/usr/sbin/swapoff", &["--", swap])?;
        if swap_paths()?.contains(swap) {
            return Err(io::Error::other("swap remains active"));
        }
        note(store, record, "host-security-swapoff", swap.clone())?;
    }
    if !request.commissioning {
        let prior_started = record
            .checkpoints
            .iter()
            .any(|c| c.name == "producer-file-starting");
        let restart_started = record
            .checkpoints
            .iter()
            .any(|c| c.name == "producer-restart-starting");
        let producer_finished = record
            .checkpoints
            .iter()
            .any(|c| c.name == "host-security-producer-completed");
        let installed = producer::inspect("cardano-node.service")?;
        let approved = installed.as_ref().is_some_and(|f| {
            f.owner == 0
                && f.group == 0
                && f.mode == 0o644
                && f.contents.as_slice()
                    == include_bytes!("../../deploy/cardano-node-memory-hardening.conf")
        });
        if restart_started && !producer_finished {
            let baseline = record
                .checkpoints
                .iter()
                .rev()
                .find(|c| c.name == "host-security-producer-restart-baseline")
                .map(|c| c.evidence.as_str());
            if !approved
                || current.node_state != "active"
                || !restarted_after(baseline, &current.node_invocation)
                || !limits_disabled(&current.node_limits)
            {
                return Err(io::Error::other(
                    "producer restart outcome is uncertain; invocation and limits do not prove completion, so it will not be repeated",
                ));
            }
            note(
                store,
                record,
                "host-security-producer-completed",
                "cardano-node.service".into(),
            )?;
        }
        if !record
            .checkpoints
            .iter()
            .any(|c| c.name == "host-security-producer-completed")
        {
            if node_state()? != request.evidence.node_state {
                return Err(io::Error::other("producer state changed since approval"));
            }
            let invocation = bounded_command(
                "/usr/bin/systemctl",
                &[
                    "show",
                    "cardano-node.service",
                    "--property=InvocationID",
                    "--value",
                ],
            )?;
            if invocation.trim() != request.evidence.node_invocation {
                return Err(io::Error::other(
                    "producer invocation changed since approval",
                ));
            }
            if prior_started && approved {
                note(
                    store,
                    record,
                    "host-security-producer-reload-starting",
                    "daemon-reload".into(),
                )?;
                bounded_command("/usr/bin/systemctl", &["daemon-reload"])?;
            } else {
                if installed != request.evidence.node_policy {
                    return Err(io::Error::other("producer drop-in changed since approval"));
                }
                let producer_request = producer::Request {
                    policy_sha256: producer::policy_sha256(),
                    targets: vec![producer::Target {
                        unit: "cardano-node.service".into(),
                        existing: request.evidence.node_policy.clone(),
                        restart: false,
                    }],
                };
                *effects = true;
                producer::apply(&producer_request, store, record)?;
            }
            if request.evidence.node_state == "active" {
                if node_state()? != "active" {
                    return Err(io::Error::other("producer stopped before approved restart"));
                }
                let baseline = bounded_command(
                    "/usr/bin/systemctl",
                    &[
                        "show",
                        "cardano-node.service",
                        "--property=InvocationID",
                        "--value",
                    ],
                )?;
                if !valid_invocation(baseline.trim()) {
                    return Err(io::Error::other("producer restart baseline is unavailable"));
                }
                note(
                    store,
                    record,
                    "host-security-producer-restart-baseline",
                    baseline.trim().into(),
                )?;
                note(
                    store,
                    record,
                    "producer-restart-starting",
                    "cardano-node.service".into(),
                )?;
                bounded_command(
                    "/usr/bin/systemctl",
                    &["try-restart", "--", "cardano-node.service"],
                )?;
            }
            note(
                store,
                record,
                "host-security-producer-completed",
                "cardano-node.service".into(),
            )?;
        }
    }
    publish_policy(request, store, record, effects)?;
    let final_state = observe(request.commissioning)?;
    if !sources_unchanged(&request.evidence.sources)? {
        return Err(io::Error::other(
            "reviewed swap unit source changed during application",
        ));
    }
    if !compatible(&request.evidence, &final_state, record)
        || !final_state.swaps.is_empty()
        || (!request.commissioning
            && !final_state.node_policy.as_ref().is_some_and(|f| {
                f.owner == 0
                    && f.group == 0
                    && f.mode == 0o644
                    && f.contents.as_slice()
                        == include_bytes!("../../deploy/cardano-node-memory-hardening.conf")
            }))
        || !final_state.masks.iter().all(|m| *m)
        || final_state.policy
            != record
                .checkpoints
                .iter()
                .find(|c| c.name == "host-security-policy-staged")
                .map(|c| {
                    serde_json::from_str::<FileEvidence>(&c.evidence).map_err(io::Error::other)
                })
                .transpose()?
    {
        return Err(io::Error::other(
            "host security final state changed or is incomplete",
        ));
    }
    check(request.commissioning)?;
    note(
        store,
        record,
        "host-security-verified",
        "installed preflight and retained state passed".into(),
    )?;
    Ok("persistent discovered swap and sleep masks, active swap removal, policy and installed preflight verified".into())
}

pub(super) fn apply(
    request: &Request,
    store: &RecordStore,
    record: &mut MaintenanceRecord,
    effects: &mut bool,
) -> io::Result<String> {
    advance(request, store, record, effects, false)
}

pub(super) fn recover(id: &str, digest: &str, store: &RecordStore) -> io::Result<()> {
    let id = kes_core::identity::OperationId::parse_hex(id)
        .map_err(|_| io::Error::other("invalid original operation"))?;
    let mut record = store.load(&id)?.supported()?;
    if record.action != "host-security"
        || record.plan_digest.to_string() != digest
        || host::maintenance_outcome_allows_new_action(&record.outcome)
        || record.approved_scope.len() != 1
    {
        return Err(io::Error::other(
            "host security recovery does not match a pending original operation",
        ));
    }
    let action: host::HostAction =
        serde_json::from_str(&record.approved_scope[0]).map_err(io::Error::other)?;
    let host::HostAction::HostSecurity { request } = action else {
        return Err(io::Error::other("invalid original host security approval"));
    };
    let mut effects = true;
    match advance(&request, store, &mut record, &mut effects, true) {
        Ok(result) => {
            record.post_observations.push(result);
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

/// Authenticate and run the installed, selected preflight without changing the host.
pub fn check(commissioning: bool) -> io::Result<()> {
    host::checked_service()?;
    let registry = host::installation_registry()?;
    let deployment = registry
        .current
        .as_ref()
        .and_then(|selection| {
            selection
                .components
                .iter()
                .find(|item| item.component == "deployment")
        })
        .ok_or_else(|| io::Error::other("selected deployment unavailable"))?;
    let installed = Path::new("/usr/libexec/pico2-kes-agent-host-check");
    let source = Path::new("/usr/lib/pico2-kes-agent/components/deployment")
        .join(deployment.digest.to_string())
        .join("pico2-kes-agent-host-check");
    let find = |path: &Path| {
        registry
            .files
            .iter()
            .find(|entry| entry.path == path && entry.component == "deployment")
    };
    let target = find(installed)
        .ok_or_else(|| io::Error::other("installed host preflight is not registered"))?;
    let selected = find(&source)
        .ok_or_else(|| io::Error::other("selected host preflight is not registered"))?;
    if target.owner != 0
        || target.mode & 0o022 != 0
        || selected.owner != 0
        || selected.mode & 0o022 != 0
        || target.digest != selected.digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "installed host preflight differs from selected deployment",
        ));
    }
    host::trusted_ancestry(installed)?;
    host::trusted_ancestry(&source)?;
    host::check_owned_file(installed, Some(target))?;
    host::check_owned_file(&source, Some(selected))?;
    for program in ["/usr/bin/timeout", "/usr/bin/systemctl", "/usr/bin/grep"] {
        trusted_program(Path::new(program))?;
    }
    let mut command = Command::new("/usr/bin/timeout");
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args([
            "--kill-after=2s",
            "15s",
            "/usr/libexec/pico2-kes-agent-host-check",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if commissioning {
        command.arg("--commission");
    }
    let mut child = command.spawn()?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("host preflight stderr unavailable"))?;
    // Closing the pipe at the cap also prevents an unbounded producer from blocking the caller.
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = (&mut stderr).take(4097).read_to_end(&mut bytes);
        result.map(|_| bytes)
    });
    let status = child.wait()?;
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("host preflight diagnostic reader failed"))??;
    if status.success() {
        return Ok(());
    }
    let text = diagnostic(&bytes[..bytes.len().min(4096)]);
    Err(io::Error::other(if text.is_empty() {
        format!(
            "installed host preflight failed ({status}); inspect host policy, swap, sleep masks and service limits"
        )
    } else {
        format!("installed host preflight failed ({status}): {text}")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_identifiers_are_accounted_for_in_swap_masks() {
        let file = FileEvidence {
            device: 1,
            inode: 1,
            uid: 0,
            gid: 0,
            mode: 0o644,
            contents: b"PARTUUID=12345678-02 none swap sw 0 0\nPARTLABEL=swap none swap sw 0 0\n"
                .to_vec(),
        };
        assert_eq!(
            fstab_units(&Some(file)).unwrap(),
            vec![
                r"dev-disk-by\x2dpartuuid-12345678\x2d02.swap",
                r"dev-disk-by\x2dpartlabel-swap.swap"
            ]
        );
    }

    #[test]
    fn restart_recovery_uses_the_post_reload_baseline() {
        let reviewed = "11111111111111111111111111111111";
        let before_restart = "22222222222222222222222222222222";
        let after_restart = "33333333333333333333333333333333";
        assert!(restarted_after(Some(reviewed), before_restart));
        assert!(!restarted_after(Some(before_restart), before_restart));
        assert!(!restarted_after(None, after_restart));
        assert!(restarted_after(Some(before_restart), after_restart));
    }

    fn evidence() -> Evidence {
        Evidence {
            fstab: None,
            crypttab: None,
            swaps: vec!["/swap.img".into()],
            units: vec!["swap.img.swap".into(), "sleep.target".into()],
            masks: vec![false, false],
            sources: vec![],
            policy: None,
            group: 77,
            node_policy: None,
            node_state: String::new(),
            node_invocation: String::new(),
            agent_limits: "LimitCORE=0\nMemorySwapMax=0\n".into(),
            node_limits: String::new(),
        }
    }

    fn record() -> MaintenanceRecord {
        serde_json::from_value(serde_json::json!({
            "schema_version":1,"operation_id":"00000000000000000000000000000000",
            "action":"host-security","plan_digest":"0000000000000000000000000000000000000000000000000000000000000000",
            "selected":null,"approved_scope":[],"previous_service_state":null,"pre_observations":[],
            "checkpoints":[],"post_observations":[],"outcome":"planned","bundle_digest":null,
            "image_digest":null,"physical_selection":null
        })).unwrap()
    }

    #[test]
    fn assertions_are_required_before_any_action() {
        let mut request = Request {
            commissioning: true,
            snapshot_policy_acknowledged: false,
            backup_private_off_primary: false,
            node_memory_acknowledged: false,
            evidence: evidence(),
        };
        assert!(!request.validate());
        request.snapshot_policy_acknowledged = true;
        request.backup_private_off_primary = true;
        assert!(request.validate());
        request.commissioning = false;
        assert!(!request.validate());
        request.node_memory_acknowledged = true;
        assert!(request.validate());
    }

    #[test]
    fn policy_preserves_unrelated_lines_and_commissioning_node_policy() {
        let file = FileEvidence {
            device: 1,
            inode: 2,
            uid: 0,
            gid: 7,
            mode: 0o640,
            contents: b"# keep\nOTHER=value\nNODE_MEMORY_POLICY=old\nSNAPSHOT_POLICY=old\n"
                .to_vec(),
        };
        let commission = String::from_utf8(policy_bytes(Some(&file), true).unwrap()).unwrap();
        assert!(commission.contains("# keep\nOTHER=value\nNODE_MEMORY_POLICY=old\n"));
        assert!(!commission.contains("SNAPSHOT_POLICY=old"));
        let normal = String::from_utf8(policy_bytes(Some(&file), false).unwrap()).unwrap();
        assert!(normal.contains("# keep\nOTHER=value\n"));
        assert!(!normal.contains("NODE_MEMORY_POLICY=old"));
        assert!(normal.contains("NODE_MEMORY_POLICY=core-and-swap-disabled\n"));
    }

    #[test]
    fn interrupted_policy_stage_completes_without_overwriting_conflicts() {
        let path = std::env::temp_dir().join(format!("p2kes-policy-stage-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let expected = b"SNAPSHOT_POLICY=disabled-or-encrypted-off-host\n";
        file.write_all(&expected[..17]).unwrap();
        complete_policy_stage(&mut file, expected).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
        complete_policy_stage(&mut file, expected).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"external").unwrap();
        let conflicting = fs::read(&path).unwrap();
        assert!(complete_policy_stage(&mut file, expected).is_err());
        assert_eq!(fs::read(&path).unwrap(), conflicting);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_accepts_only_checkpointed_progress() {
        let original = evidence();
        let mut current = original.clone();
        let mut record = record();
        current.masks[0] = true;
        assert!(!compatible(&original, &current, &record));
        record.checkpoints.push(host::checkpoint(
            "host-security-mask-starting",
            "swap.img.swap".into(),
        ));
        assert!(compatible(&original, &current, &record));
        current.swaps.clear();
        assert!(!compatible(&original, &current, &record));
        record.checkpoints.push(host::checkpoint(
            "host-security-swapoff-starting",
            "/swap.img".into(),
        ));
        assert!(compatible(&original, &current, &record));
        current.units.push("unexpected.swap".into());
        current.masks.push(false);
        assert!(!compatible(&original, &current, &record));
    }

    #[test]
    fn masks_refuse_files_and_unrelated_symlinks() {
        let dir = std::env::temp_dir().join(format!("p2kes-mask-fixture-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("example.swap");
        std::fs::write(&path, b"existing").unwrap();
        assert!(mask_path(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/tmp/unrelated", &path).unwrap();
        assert!(mask_path(&path).is_err());
        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            Path::new("/tmp/unrelated")
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn rejects_untrusted_sources_and_unprovable_invocations() {
        assert!(!valid_source("/etc/systemd/system/../../shadow"));
        assert!(!valid_source("/tmp/example.swap"));
        assert!(!valid_invocation("00000000000000000000000000000000"));
        assert!(valid_invocation("1234567890abcdef1234567890abcdef"));
        assert!(!limits_disabled("LimitCORE=0\nMemorySwapMax=infinity\n"));
    }

    #[test]
    fn diagnostics_do_not_emit_terminal_control_bytes() {
        assert_eq!(diagnostic(b"\x1b[31mproblem\r\n"), "[31mproblem");
    }
}
