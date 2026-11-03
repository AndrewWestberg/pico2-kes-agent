//! Authenticated distribution bundle admission.
use super::model::{
    MAX_ARTIFACT_BYTES, MAX_ARTIFACT_PATH_BYTES, MAX_ARTIFACTS, MAX_MANIFEST_BYTES,
    MAX_RELEASE_BYTES, Qualification, ReleaseSelection, SelectedComponent,
};
use kes_core::identity::Digest32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Component as PathComponent, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

const PRIMARY: &str = "9FF957E79B5D853544805F4725491F18087931B6";
const SIGNER: &str = "78C0F32094CD02A4BAFA444C684E37A210480F82";
const PURPOSE: &str = "pico2-kes-agent-distribution-v1";
const AUTHORITY_PURPOSE: &str = "pico2-kes-agent-distribution-authority-v1";
const PROJECT: &str = "https://github.com/AndrewWestberg/pico2-kes-agent";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DistributionAuthority {
    schema_version: u64,
    purpose: String,
    project: String,
    algorithm: String,
    public_key_pem: String,
}

fn parse_authority(bytes: &[u8]) -> io::Result<DistributionAuthority> {
    let authority: DistributionAuthority =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid distribution authority"))?;
    if authority.schema_version != 1 || authority.purpose != AUTHORITY_PURPOSE
        || authority.project != PROJECT || authority.algorithm != "secp256k1"
    {
        return Err(invalid("invalid distribution authority scope"));
    }
    Ok(authority)
}
#[derive(Clone, Copy, Debug)]
pub enum Admission {
    Qualified,
    AttendedCandidate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u64,
    pub purpose: String,
    pub release: Release,
    pub platform: Platform,
    pub components: Vec<Component>,
    pub artifacts: Vec<Artifact>,
    pub compatibility: Compatibility,
    pub qualification: Qualification,
    #[serde(deserialize_with = "required_option")]
    pub promotion: Option<Promotion>,
    pub prerequisites: Vec<Prerequisite>,
    pub preservation: Preservation,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Promotion {
    pub candidate_sha256: String,
    pub approval_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub source_commit: String,
    pub build_id: String,
    pub channel: String,
    pub published_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub target: String,
    pub glibc_min: String,
    pub os: Vec<Os>,
    pub systemd: bool,
    pub udev: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Os {
    pub id: String,
    pub version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProvenance {
    schema_version: u64,
    os: Os,
    libraries: Vec<RuntimeLibrary>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLibrary {
    path: String,
    package: String,
    package_version: String,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub build_id: String,
    pub artifact: String,
    pub digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub class: String,
    pub mode: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    #[serde(deserialize_with = "unique_tuples")]
    pub tuples: Vec<BTreeMap<String, String>>,
    pub readable_schemas: Schemas,
    pub management_actions: Vec<String>,
    pub usb_profiles: Vec<String>,
    pub storage_versions: Vec<u64>,
    pub security_profiles: Vec<String>,
    pub hardware: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schemas {
    pub config: Vec<u64>,
    pub journal: Vec<u64>,
    pub receipt: Vec<u64>,
    pub installation: Vec<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prerequisite {
    pub operation: String,
    pub tool: String,
    pub version: String,
    pub packages: Vec<Packages>,
    #[serde(deserialize_with = "required_option")]
    pub artifact: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    pub id: String,
    pub version: String,
    pub names: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preservation {
    pub firmware_start: u64,
    pub firmware_end: u64,
    pub state_start: u64,
    pub state_end: u64,
    pub migration: String,
    pub retained: Vec<String>,
}

fn unique_tuples<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<BTreeMap<String, String>>, D::Error> {
    struct Unique(BTreeMap<String, String>);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a component digest map without duplicate keys")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> Result<Unique, M::Error> {
                    let mut result = BTreeMap::new();
                    while let Some((k, v)) = map.next_entry::<String, String>()? {
                        if result.insert(k, v).is_some() {
                            return Err(serde::de::Error::custom("duplicate tuple component"));
                        }
                    }
                    Ok(Unique(result))
                }
            }
            d.deserialize_map(Visitor)
        }
    }
    Ok(Vec::<Unique>::deserialize(d)?
        .into_iter()
        .map(|u| u.0)
        .collect())
}

pub struct VerifiedBundle {
    snapshot: Temp,
    manifest: Manifest,
    selection: ReleaseSelection,
}
impl VerifiedBundle {
    pub fn root(&self) -> &Path {
        &self.snapshot.0
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn selection(&self) -> &ReleaseSelection {
        &self.selection
    }
}

pub fn component_for_artifact(path: &str) -> Option<&'static str> {
    match path {
        "bin/p2kesup" => Some("manager"),
        "bin/pico2-kes-agentd" => Some("daemon"),
        "bin/pico2-kes-agent-cli" => Some("cli"),
        "install.sh" => Some("deployment"),
        p if p.starts_with("firmware/") => Some("firmware"),
        p if p.starts_with("tools/") || p.starts_with("runtime/") || p.starts_with("licenses/") => {
            Some("tool")
        }
        p if p.starts_with("deploy/") => Some("deployment"),
        _ => None,
    }
}

pub fn component_digest(name: &str, artifacts: &[Artifact]) -> io::Result<String> {
    let mut entries: Vec<_> = artifacts
        .iter()
        .filter(|a| component_for_artifact(&a.path) == Some(name))
        .collect();
    if entries.is_empty() {
        return Err(invalid("component inventory is empty"));
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hash = Sha256::new();
    let mut previous: Option<&str> = None;
    for a in entries {
        if previous == Some(a.path.as_str())
            || !confined(&a.path)
            || !hash_text(&a.sha256)
            || ![0o644, 0o755].contains(&a.mode)
        {
            return Err(invalid("invalid component inventory"));
        }
        previous = Some(&a.path);
        hash.update(a.path.as_bytes());
        hash.update([0]);
        hash.update(a.size_bytes.to_string().as_bytes());
        hash.update([0]);
        hash.update(a.sha256.as_bytes());
        hash.update([0]);
        hash.update(a.mode.to_string().as_bytes());
        hash.update(b"\n");
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Choices identify the authenticated source manifest for each component.
pub fn select_components(
    authorizing: &VerifiedBundle,
    sources: &[&VerifiedBundle],
    choices: &BTreeMap<String, String>,
) -> io::Result<ReleaseSelection> {
    const NAMES: [&str; 6] = ["manager", "daemon", "cli", "firmware", "tool", "deployment"];
    if choices.len() != NAMES.len()
        || !NAMES
            .iter()
            .all(|name| choices.get(*name).is_some_and(|d| hash_text(d)))
    {
        return Err(invalid("invalid component provenance"));
    }
    let mut selection = authorizing.selection.clone();
    selection.components.clear();
    let mut tuple = BTreeMap::new();
    for name in NAMES {
        let mut selected: Option<&SelectedComponent> = None;
        for source in sources {
            if source.selection.manifest_digest.to_string() != choices[name] {
                continue;
            }
            for candidate in &source.selection.components {
                if candidate.component == name
                    && candidate.manifest_digest == source.selection.manifest_digest
                {
                    if selected.is_some() {
                        return Err(invalid("ambiguous component provenance"));
                    }
                    selected = Some(candidate);
                }
            }
        }
        let candidate = selected.ok_or_else(|| invalid("component source missing"))?;
        tuple.insert(name.to_owned(), candidate.digest.to_string());
        selection.components.push(candidate.clone());
    }
    if !authorizing.manifest.compatibility.tuples.contains(&tuple) {
        return Err(invalid("unauthorized component tuple"));
    }
    Ok(selection)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn clean(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s.bytes().all(|b| (32..127).contains(&b))
}
fn hash_text(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return false;
    }
    if [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
        .iter()
        .any(|&i| !b[i].is_ascii_digit())
    {
        return false;
    }
    let n = |i: usize| u32::from(b[i] - b'0') * 10 + u32::from(b[i + 1] - b'0');
    let year = n(0) * 100 + n(2);
    let month = n(5);
    let day = n(8);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    year > 0 && day > 0 && day <= days && n(11) < 24 && n(14) < 60 && n(17) < 60
}
fn confined(s: &str) -> bool {
    s.len() <= MAX_ARTIFACT_PATH_BYTES
        && clean(s)
        && !s.contains('\\')
        && Path::new(s)
            .components()
            .all(|c| matches!(c, PathComponent::Normal(_)))
        && !s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
}
fn read_file(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() > limit {
        return Err(invalid("unsafe or oversized bundle file"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != m.len() {
        return Err(invalid("bundle file changed"));
    }
    Ok(bytes)
}
fn walk(
    root: &Path,
    dir: &Path,
    found: &mut BTreeSet<String>,
    directories: &mut usize,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| invalid("invalid bundle path"))?
            .to_str()
            .ok_or_else(|| invalid("invalid UTF-8 path"))?;
        if !confined(relative) {
            return Err(invalid("invalid bundle path"));
        }
        if meta.is_dir() {
            *directories += 1;
            if *directories > MAX_ARTIFACTS * 4 {
                return Err(invalid("too many bundle directories"));
            }
            let before = found.len();
            walk(root, &path, found, directories)?;
            if found.len() == before {
                return Err(invalid("empty bundle directory"));
            }
        } else if meta.is_file() && meta.nlink() == 1 {
            if !found.insert(relative.to_owned()) || found.len() > MAX_ARTIFACTS + 2 {
                return Err(invalid("too many bundle files"));
            }
        } else {
            return Err(invalid("link or special file in bundle"));
        }
    }
    Ok(())
}
static TEMP_ID: AtomicU64 = AtomicU64::new(0);
static INHERIT_WORKER_GROUP: AtomicBool = AtomicBool::new(false);

pub(super) fn inherit_worker_process_group() {
    INHERIT_WORKER_GROUP.store(true, Ordering::Relaxed);
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn bounded_command(command: &mut Command, timeout: Duration) -> io::Result<Vec<u8>> {
    let inherit_group = INHERIT_WORKER_GROUP.load(Ordering::Relaxed);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if !inherit_group {
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing subprocess output"))?;
    let result = (|| {
        let fd = stdout.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + timeout;
        let mut captured = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut eof = false;
        let mut status = None;
        loop {
            while !eof {
                match stdout.read(&mut buffer) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        if captured.len() + n > 65536 {
                            return Err(invalid("verifier output exceeds limit"));
                        }
                        captured.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if eof && let Some(status) = status {
                return if status.success() {
                    Ok(captured)
                } else {
                    Err(invalid("verifier subprocess failed"))
                };
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "verifier subprocess timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        if !inherit_group {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
pub(super) fn verify_signature(root: &Path, name: &str) -> io::Result<()> {
    let purpose = match name {
        "distribution.json" => PURPOSE,
        "install.sh" => "pico2-kes-agent-bootstrap-v1",
        _ => return Err(invalid("invalid distribution signature purpose")),
    };
    let statement = read_file(&root.join("distribution-authority.json"), MAX_MANIFEST_BYTES)?;
    let signature = read_file(&root.join("distribution-authority.json.asc"), MAX_MANIFEST_BYTES)?;
    let certificate = read_file(&root.join("firmware/release-authority.asc"), MAX_MANIFEST_BYTES)?;
    let data = read_file(&root.join(name), MAX_ARTIFACT_BYTES)?;
    let detached = read_file(&root.join(format!("{name}.sig")), MAX_MANIFEST_BYTES)?;
    let dir = PathBuf::from(format!(
        "/tmp/p2kesup-gpg-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::os::unix::fs::DirBuilderExt::mode(fs::DirBuilder::new().recursive(false), 0o700)
        .create(&dir)?;
    let dir = Temp(dir);
    fs::write(dir.0.join("statement"), &statement)?;
    fs::write(dir.0.join("statement.asc"), &signature)?;
    fs::write(dir.0.join("certificate.asc"), &certificate)?;
    let keyring = dir.0.join("authority.gpg");
    bounded_command(
        Command::new("/usr/bin/gpg")
            .env_clear()
            .env("HOME", &dir.0)
            .env("GNUPGHOME", &dir.0)
            .args(["--batch", "--no-options", "--dearmor", "--output"])
            .arg(&keyring)
            .arg(dir.0.join("certificate.asc")),
        Duration::from_secs(30),
    )?;
    let output = bounded_command(
        Command::new("/usr/bin/gpgv")
            .env_clear()
            .env("HOME", &dir.0)
            .env("GNUPGHOME", &dir.0)
            .args(["--homedir"])
            .arg(&dir.0)
            .arg("--keyring")
            .arg(&keyring)
            .args(["--status-fd", "1"])
            .arg(dir.0.join("statement.asc"))
            .arg(dir.0.join("statement")),
        Duration::from_secs(30),
    )?;
    let text = std::str::from_utf8(&output).map_err(|_| invalid("invalid signature status"))?;
    let sigs: Vec<Vec<&str>> = text
        .lines()
        .filter(|l| l.starts_with("[GNUPG:] VALIDSIG "))
        .map(|l| l.split_whitespace().collect())
        .collect();
    if sigs.len() != 1
        || sigs[0].len() != 12
        || sigs[0][2] != SIGNER
        || sigs[0][11] != PRIMARY
        || ["REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG"]
            .iter()
            .any(|bad| text.contains(&format!("[GNUPG:] {bad}")))
    {
        return Err(invalid("distribution authority mismatch"));
    }
    let authority = parse_authority(&statement)?;
    let key = dir.0.join("public.pem");
    fs::write(&key, authority.public_key_pem.as_bytes())?;
    bounded_command(
        Command::new("/usr/bin/openssl").env_clear()
            .args(["pkey", "-pubin", "-pubcheck", "-noout", "-in"]).arg(&key),
        Duration::from_secs(30),
    )?;
    let der = bounded_command(
        Command::new("/usr/bin/openssl").env_clear()
            .args(["pkey", "-pubin", "-outform", "DER", "-in"]).arg(&key),
        Duration::from_secs(30),
    )?;
    const PREFIX: &[u8] = b"\x30\x56\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x42\x00\x04";
    if der.len() != PREFIX.len() + 64 || !der.starts_with(PREFIX) {
        return Err(invalid("authority is not uncompressed secp256k1"));
    }
    verify_der_signature(&dir.0, &key, purpose, &data, &detached)
}

fn verify_der_signature(dir: &Path, key: &Path, purpose: &str, data: &[u8], detached: &[u8]) -> io::Result<()> {
    if ![PURPOSE, "pico2-kes-agent-bootstrap-v1"].contains(&purpose) {
        return Err(invalid("invalid distribution signature purpose"));
    }
    let input = dir.join("input");
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&input)?;
    writeln!(file, "{purpose}")?;
    file.write_all(data)?;
    fs::write(dir.join("signature"), detached)?;
    bounded_command(
        Command::new("/usr/bin/openssl").env_clear()
            .args(["dgst", "-sha256", "-verify"]).arg(key)
            .arg("-signature").arg(dir.join("signature")).arg(&input),
        Duration::from_secs(30),
    )?;
    Ok(())
}
fn digest_bytes(s: &str) -> io::Result<Digest32> {
    if !hash_text(s) {
        return Err(invalid("invalid digest"));
    }
    let mut out = [0; 32];
    for (i, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hex = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = hex(pair[0]) * 16 + hex(pair[1]);
    }
    Ok(Digest32::from_bytes(out))
}

/// Authenticate a private snapshot before using any bundled executable.
pub fn verify_bundle(root: &Path, admission: Admission) -> io::Result<VerifiedBundle> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(invalid("bundle root is not a directory"));
    }
    let original = fs::canonicalize(root)?;
    let mut files = BTreeSet::new();
    walk(&original, &original, &mut files, &mut 0)?;
    let dir = PathBuf::from(format!(
        "/tmp/p2kesup-snapshot-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::os::unix::fs::DirBuilderExt::mode(fs::DirBuilder::new().recursive(false), 0o700)
        .create(&dir)?;
    let dir = Temp(dir);
    let mut total = 0u64;
    let mut hashes = BTreeMap::new();
    for name in files {
        let source = original.join(&name);
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(source)?;
        let meta = input.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_ARTIFACT_BYTES {
            return Err(invalid("unsafe snapshot file"));
        }
        total = total
            .checked_add(meta.len())
            .ok_or_else(|| invalid("snapshot size overflow"))?;
        if total > MAX_RELEASE_BYTES {
            return Err(invalid("snapshot too large"));
        }
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c"/tmp".as_ptr(), &mut space) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let available = (space.f_bavail as u64).saturating_mul(space.f_frsize as u64);
        if available < meta.len().saturating_add(1024 * 1024) {
            return Err(invalid("insufficient staging space"));
        }
        let target = dir.0.join(&name);
        fs::create_dir_all(
            target
                .parent()
                .ok_or_else(|| invalid("invalid snapshot path"))?,
        )?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(target)?;
        let mut hash = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            if copied > meta.len() {
                return Err(invalid("snapshot source changed"));
            }
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        if copied != meta.len() {
            return Err(invalid("snapshot source changed"));
        }
        hashes.insert(name, (copied, format!("{:x}", hash.finalize())));
    }
    let (manifest, selection) = verify_snapshot(&dir.0, admission, &hashes)?;
    Ok(VerifiedBundle {
        snapshot: dir,
        manifest,
        selection,
    })
}
fn validate_runtime_provenance(
    path: &Path,
    hashes: &BTreeMap<String, (u64, String)>,
) -> io::Result<()> {
    let data = read_file(path, MAX_MANIFEST_BYTES)?;
    let provenance: RuntimeProvenance =
        serde_json::from_slice(&data).map_err(|_| invalid("invalid runtime provenance"))?;
    let packages = [
        ("runtime/libusb-1.0.so.0", "libusb-1.0-0"),
        ("runtime/libudev.so.1", "libudev1"),
        ("runtime/libstdc++.so.6", "libstdc++6"),
        ("runtime/libgcc_s.so.1", "libgcc-s1"),
    ];
    if provenance.schema_version != 1
        || provenance.os.id != "debian"
        || provenance.os.version != "12"
        || provenance.libraries.len() != packages.len()
    {
        return Err(invalid("invalid runtime provenance"));
    }
    let mut seen = BTreeSet::new();
    for library in &provenance.libraries {
        let valid_package = packages
            .iter()
            .any(|(path, package)| library.path == *path && library.package == *package);
        if !valid_package
            || !seen.insert(library.path.as_str())
            || !hash_text(&library.sha256)
            || library.package_version.is_empty()
            || library.package_version.len() > 255
            || !library
                .package_version
                .bytes()
                .all(|b| b.is_ascii_graphic())
            || !matches!(hashes.get(&library.path), Some((_, hash)) if *hash == library.sha256)
        {
            return Err(invalid(
                "runtime provenance does not match signed artifacts",
            ));
        }
    }
    Ok(())
}
fn verify_snapshot(
    root: &Path,
    admission: Admission,
    hashes: &BTreeMap<String, (u64, String)>,
) -> io::Result<(Manifest, ReleaseSelection)> {
    let root = root.to_path_buf();
    let bytes = read_file(&root.join("distribution.json"), MAX_MANIFEST_BYTES)?;
    read_file(&root.join("distribution.json.sig"), MAX_MANIFEST_BYTES)?;
    read_file(
        &root.join("firmware/release-authority.asc"),
        MAX_MANIFEST_BYTES,
    )?;
    verify_signature(&root, "distribution.json")?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid distribution manifest"))?;
    if manifest.schema_version != 1
        || manifest.purpose != PURPOSE
        || (manifest.qualification == Qualification::Candidate
            && !matches!(admission, Admission::AttendedCandidate))
    {
        return Err(invalid("unsupported distribution or qualification"));
    }
    match (manifest.qualification, &manifest.promotion) {
        (Qualification::Candidate, None) => {}
        (Qualification::Qualified, Some(p))
            if hash_text(&p.candidate_sha256) && hash_text(&p.approval_sha256) => {}
        _ => return Err(invalid("invalid promotion linkage")),
    }
    let r = &manifest.release;
    if ![&r.tag, &r.version, &r.build_id, &r.published_at]
        .iter()
        .all(|s| clean(s))
        || !timestamp(&r.published_at)
        || !(r.source_commit.len() == 40 || r.source_commit.len() == 64)
        || !r
            .source_commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !["stable", "prerelease"].contains(&r.channel.as_str())
    {
        return Err(invalid("invalid release identity"));
    }
    let p = &manifest.platform;
    if p.target != "x86_64-unknown-linux-gnu"
        || p.glibc_min != "2.36"
        || !p.systemd
        || !p.udev
        || p.os.len() != 2
        || !p.os.iter().any(|o| o.id == "debian" && o.version == "12")
        || !p
            .os
            .iter()
            .any(|o| o.id == "ubuntu" && o.version == "24.04")
    {
        return Err(invalid("unsupported platform declaration"));
    }
    let preservation = &manifest.preservation;
    if (
        preservation.firmware_start,
        preservation.firmware_end,
        preservation.state_start,
        preservation.state_end,
    ) != (0x10000000, 0x10100000, 0x10100000, 0x10308000)
        || preservation.migration != "none"
        || !["config", "state", "identity", "receipt"]
            .iter()
            .all(|s| preservation.retained.iter().any(|x| x == s))
    {
        return Err(invalid("unsafe preservation policy"));
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_ARTIFACTS {
        return Err(invalid("artifact count"));
    }
    let mut expected = BTreeSet::from([
        "distribution.json".to_owned(),
        "distribution.json.sig".to_owned(),
    ]);
    let mut total = 0u64;
    for a in &manifest.artifacts {
        let class = match a.path.split('/').next().unwrap_or("") {
            "bin" => "bin",
            "firmware" => "firmware",
            "tools" => "tool",
            "deploy" => "deployment",
            "licenses" => "license",
            "runtime" => "runtime",
            _ => "bootstrap",
        };
        if !confined(&a.path)
            || !hash_text(&a.sha256)
            || a.size_bytes > MAX_ARTIFACT_BYTES
            || a.class != class
            || ![0o644, 0o755].contains(&a.mode)
            || (["distribution-authority.json", "distribution-authority.json.asc", "install.sh.sig", "firmware/release-authority.asc"].contains(&a.path.as_str()) && a.mode != 0o644)
            || !expected.insert(a.path.clone())
        {
            return Err(invalid("invalid artifact entry"));
        }
        total = total
            .checked_add(a.size_bytes)
            .ok_or_else(|| invalid("artifact size overflow"))?;
        if total > MAX_RELEASE_BYTES {
            return Err(invalid("bundle too large"));
        }
    }
    let mut found = BTreeSet::new();
    walk(&root, &root, &mut found, &mut 0)?;
    if found != expected {
        return Err(invalid("unexpected or missing bundle files"));
    }
    for a in &manifest.artifacts {
        if !matches!(hashes.get(&a.path), Some((size, hash)) if *size == a.size_bytes && *hash == a.sha256)
        {
            return Err(invalid("artifact digest or size mismatch"));
        }
    }
    for required in [
        "distribution-authority.json",
        "distribution-authority.json.asc",
        "firmware/release-authority.asc",
        "firmware/firmware.py",
        "tools/firmware.py",
        "tools/picotool",
        "install.sh",
        "install.sh.sig",
        "licenses/picotool.txt",
        "deploy/uninstall.sh",
        "deploy/pico2-kes-agentd.service",
        "deploy/70-pico2-kes-agent.rules",
        "deploy/pico2-kes-agent-host-check",
        "deploy/cardano-node-memory-hardening.conf",
    ] {
        if !expected.contains(required) {
            return Err(invalid("missing required artifact"));
        }
    }
    for required in [
        "runtime/libusb-1.0.so.0",
        "runtime/libudev.so.1",
        "runtime/libstdc++.so.6",
        "runtime/libgcc_s.so.1",
        "runtime/provenance.json",
        "licenses/mbedtls.txt",
        "licenses/libusb-1.0-0.txt",
        "licenses/libudev1.txt",
        "licenses/libstdc++6.txt",
        "licenses/libgcc-s1.txt",
    ] {
        if !expected.contains(required) {
            return Err(invalid("missing tool runtime or license"));
        }
    }
    validate_runtime_provenance(&root.join("runtime/provenance.json"), hashes)?;
    if hashes.get("firmware/firmware.py") != hashes.get("tools/firmware.py") {
        return Err(invalid("firmware verifier mismatch"));
    }
    verify_signature(&root, "install.sh")?;
    let mut components = Vec::new();
    let mut tuple = BTreeMap::new();
    let manifest_digest = Digest32::from_bytes(Sha256::digest(&bytes).into());
    for c in &manifest.components {
        let expected_path = match c.name.as_str() {
            "manager" => "bin/p2kesup",
            "daemon" => "bin/pico2-kes-agentd",
            "cli" => "bin/pico2-kes-agent-cli",
            "firmware" => "firmware/pico2-kes-firmware.signed.uf2",
            "tool" => "tools/picotool",
            "deployment" => "deploy/install.sh",
            _ => return Err(invalid("unknown component")),
        };
        if !clean(&c.name)
            || !clean(&c.version)
            || !clean(&c.build_id)
            || c.artifact != expected_path
        {
            return Err(invalid("invalid component identity"));
        }
        let a = manifest
            .artifacts
            .iter()
            .find(|a| a.path == c.artifact)
            .ok_or_else(|| invalid("component artifact missing"))?;
        if matches!(c.name.as_str(), "manager" | "daemon" | "cli" | "tool") && a.mode != 0o755 {
            return Err(invalid("non-executable component"));
        }
        let inventory = component_digest(&c.name, &manifest.artifacts)?;
        if inventory != c.digest {
            return Err(invalid("component inventory digest mismatch"));
        }
        if tuple.insert(c.name.clone(), inventory).is_some() {
            return Err(invalid("duplicate component"));
        }
        components.push(SelectedComponent {
            component: c.name.clone(),
            version: c.version.clone(),
            build_id: c.build_id.clone(),
            digest: digest_bytes(&c.digest)?,
            entrypoint_digest: digest_bytes(&a.sha256)?,
            source_commit: r.source_commit.clone(),
            manifest_digest,
        });
    }
    let names = ["manager", "daemon", "cli", "firmware", "tool", "deployment"];
    let mut unique = BTreeSet::new();
    if manifest.compatibility.tuples.is_empty()
        || manifest.compatibility.tuples.len() > 256
        || manifest.compatibility.tuples.iter().any(|t| {
            t.len() != names.len()
                || !names
                    .iter()
                    .all(|n| t.get(*n).is_some_and(|v| hash_text(v)))
                || !unique.insert(t.clone())
        })
    {
        return Err(invalid("invalid compatibility tuple declarations"));
    }
    if !["manager", "daemon", "cli", "firmware", "tool", "deployment"]
        .iter()
        .all(|s| tuple.contains_key(*s))
        || !manifest.compatibility.tuples.contains(&tuple)
    {
        return Err(invalid("unauthorized component tuple"));
    }
    let c = &manifest.compatibility;
    if !c.readable_schemas.config.contains(&1)
        || !c.readable_schemas.journal.contains(&1)
        || !c.readable_schemas.receipt.contains(&1)
        || !c.readable_schemas.installation.contains(&1)
        || !c.storage_versions.contains(&2)
        || !c.usb_profiles.iter().any(|p| p == "usb-protocol-1")
        || c.management_actions.is_empty()
        || c.security_profiles.is_empty()
        || c.hardware.is_empty()
        || manifest.prerequisites.is_empty()
    {
        return Err(invalid("incomplete compatibility evidence"));
    }
    for prerequisite in &manifest.prerequisites {
        if !clean(&prerequisite.operation)
            || !clean(&prerequisite.tool)
            || !clean(&prerequisite.version)
            || prerequisite.packages.is_empty()
            || prerequisite
                .artifact
                .as_ref()
                .is_some_and(|path| !expected.contains(path))
            || prerequisite.packages.iter().any(|p| {
                !clean(&p.id)
                    || !clean(&p.version)
                    || p.names.is_empty()
                    || p.names.iter().any(|name| !clean(name))
            })
        {
            return Err(invalid("invalid prerequisite"));
        }
    }
    let verifier_home = PathBuf::from(format!(
        "/tmp/p2kesup-firmware-gpg-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::os::unix::fs::DirBuilderExt::mode(fs::DirBuilder::new().recursive(false), 0o700)
        .create(&verifier_home)?;
    let verifier_home = Temp(verifier_home);
    bounded_command(
        Command::new("/usr/bin/python3")
            .arg("-I")
            .arg(root.join("tools/firmware.py"))
            .args(["verify", "--bundle"])
            .arg(root.join("firmware"))
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("tools").display()),
            )
            .env("LD_LIBRARY_PATH", root.join("runtime"))
            .env("HOME", &verifier_home.0)
            .env("GNUPGHOME", &verifier_home.0)
            .env("TMPDIR", &verifier_home.0),
        Duration::from_secs(180),
    )?;
    let inner: serde_json::Value = serde_json::from_slice(&read_file(
        &root.join("firmware/release.json"),
        MAX_MANIFEST_BYTES,
    )?)
    .map_err(|_| invalid("invalid inner firmware manifest"))?;
    if inner.get("tag").and_then(|v| v.as_str()) != Some(r.tag.as_str())
        || inner.get("commit").and_then(|v| v.as_str()) != Some(r.source_commit.as_str())
    {
        return Err(invalid("inner firmware source identity mismatch"));
    }
    let selection = ReleaseSelection {
        tag: r.tag.clone(),
        version: r.version.clone(),
        source_commit: r.source_commit.clone(),
        channel: r.channel.clone(),
        qualification: manifest.qualification,
        platform: p.target.clone(),
        components,
        manifest_digest,
    };
    Ok((manifest, selection))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distribution_authority_scope_is_strict() {
        let valid = r#"{"schema_version":1,"purpose":"pico2-kes-agent-distribution-authority-v1","project":"https://github.com/AndrewWestberg/pico2-kes-agent","algorithm":"secp256k1","public_key_pem":"key"}"#;
        assert!(parse_authority(valid.as_bytes()).is_ok());
        for bad in [
            valid.replace("distribution-authority-v1", "firmware-boot-authority-v1"),
            valid.replace("\"schema_version\":1", "\"schema_version\":true"),
            valid.replace("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1"),
            valid.replace("\"algorithm\":\"secp256k1\"", "\"algorithm\":\"secp256k1\",\"extra\":0"),
            valid.replace("secp256k1", "prime256v1"),
        ] {
            assert!(parse_authority(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn distribution_signatures_are_bound_to_context_and_bytes() {
        let path = PathBuf::from(format!("/tmp/p2kesup-test-{}-{}", std::process::id(), TEMP_ID.fetch_add(1, Ordering::Relaxed)));
        std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700).create(&path).unwrap();
        let dir = Temp(path);
        let private = dir.0.join("private.pem");
        let public = dir.0.join("public.pem");
        bounded_command(Command::new("/usr/bin/openssl").args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1", "-out"]).arg(&private), Duration::from_secs(30)).unwrap();
        bounded_command(Command::new("/usr/bin/openssl").args(["pkey", "-in"]).arg(&private).args(["-pubout", "-out"]).arg(&public), Duration::from_secs(30)).unwrap();
        let message = dir.0.join("message");
        let signature = dir.0.join("signed");
        fs::write(&message, format!("{PURPOSE}\nbody")).unwrap();
        bounded_command(Command::new("/usr/bin/openssl").args(["dgst", "-sha256", "-sign"]).arg(&private).arg("-out").arg(&signature).arg(&message), Duration::from_secs(30)).unwrap();
        let sig = fs::read(signature).unwrap();
        assert!(verify_der_signature(&dir.0, &public, PURPOSE, b"body", &sig).is_ok());
        assert!(verify_der_signature(&dir.0, &public, PURPOSE, b"changed", &sig).is_err());
        assert!(verify_der_signature(&dir.0, &public, "pico2-kes-agent-bootstrap-v1", b"body", &sig).is_err());
        assert!(verify_der_signature(&dir.0, &public, "other", b"body", &sig).is_err());
    }
    #[test]
    fn selection_requires_authorized_tuple_and_exact_source() {
        let names = ["manager", "daemon", "cli", "firmware", "tool", "deployment"];
        let digest = Digest32::from_bytes([1; 32]);
        let source = Digest32::from_bytes([2; 32]);
        let other = Digest32::from_bytes([3; 32]);
        let tuple: BTreeMap<String, String> = names
            .iter()
            .map(|n| (n.to_string(), digest.to_string()))
            .collect();
        let selected: Vec<_> = names
            .iter()
            .map(|n| SelectedComponent {
                component: n.to_string(),
                version: "v".into(),
                build_id: "b".into(),
                digest,
                entrypoint_digest: digest,
                source_commit: "a".repeat(40),
                manifest_digest: source,
            })
            .collect();
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "schema_version":1,"purpose":"test",
            "release":{"tag":"t","version":"v","source_commit":"a","build_id":"b","channel":"stable","published_at":"x"},
            "platform":{"target":"x","glibc_min":"x","os":[],"systemd":true,"udev":true},
            "components":[],"artifacts":[],
            "compatibility":{"tuples":[tuple.clone()],"readable_schemas":{"config":[],"journal":[],"receipt":[],"installation":[]},"management_actions":[],"usb_profiles":[],"storage_versions":[],"security_profiles":[],"hardware":[]},
            "qualification":"qualified","promotion":null,"prerequisites":[],
            "preservation":{"firmware_start":0,"firmware_end":0,"state_start":0,"state_end":0,"migration":"none","retained":[]}
        })).unwrap();
        let selection = ReleaseSelection {
            tag: "t".into(),
            version: "v".into(),
            source_commit: "a".into(),
            channel: "stable".into(),
            qualification: Qualification::Qualified,
            platform: "x".into(),
            components: selected,
            manifest_digest: source,
        };
        let mut bundle = VerifiedBundle {
            snapshot: Temp(PathBuf::new()),
            manifest,
            selection,
        };
        let choices: BTreeMap<String, String> = names
            .iter()
            .map(|n| (n.to_string(), source.to_string()))
            .collect();
        assert!(select_components(&bundle, &[&bundle], &choices).is_ok());
        let mut wrong = choices.clone();
        wrong.insert("tool".into(), other.to_string());
        assert!(select_components(&bundle, &[&bundle], &wrong).is_err());
        assert!(select_components(&bundle, &[], &choices).is_err());
        let mut unauthorized = choices.clone();
        unauthorized.remove("firmware");
        assert!(select_components(&bundle, &[&bundle], &unauthorized).is_err());
        bundle.manifest.compatibility.tuples.clear();
        assert!(select_components(&bundle, &[&bundle], &choices).is_err());
    }
    #[test]
    fn component_inventory_binds_all_files_and_modes() {
        let artifact = |path: &str, mode| Artifact {
            path: path.into(),
            size_bytes: 4,
            sha256: "a".repeat(64),
            class: "runtime".into(),
            mode,
        };
        let mut entries = vec![
            artifact("tools/picotool", 0o755),
            artifact("runtime/libusb-1.0.so.0", 0o644),
        ];
        let original = component_digest("tool", &entries).unwrap();
        entries[1].mode = 0o755;
        assert_ne!(original, component_digest("tool", &entries).unwrap());
        entries[1].mode = 0o644;
        entries[1].sha256 = "b".repeat(64);
        assert_ne!(original, component_digest("tool", &entries).unwrap());
        entries.push(entries[0].clone());
        assert!(component_digest("tool", &entries).is_err());
        assert_eq!(component_for_artifact("install.sh"), Some("deployment"));
        assert_eq!(component_for_artifact("install.sh.sig"), None);
        assert_eq!(component_for_artifact("distribution-authority.json"), None);
        assert_eq!(component_for_artifact("distribution-authority.json.asc"), None);
    }
    #[test]
    fn paths_and_duplicate_tuple_keys_fail_closed() {
        assert!(confined("firmware/release.json"));
        for path in [
            "", "/tmp/a", "../a", "a/../b", "a//b", "a/./b", "a\\b", "a/\n",
        ] {
            assert!(!confined(path), "{path:?}");
        }
        let duplicate = r#"{"tuples":[{"manager":"a","manager":"b"}],"readable_schemas":{"config":[1],"journal":[1],"receipt":[1],"installation":[1]},"management_actions":[],"usb_profiles":[],"storage_versions":[],"security_profiles":[],"hardware":[]}"#;
        assert!(serde_json::from_str::<Compatibility>(duplicate).is_err());
        let duplicate_provenance = r#"{"schema_version":1,"schema_version":1,"os":{"id":"debian","version":"12"},"libraries":[]}"#;
        assert!(serde_json::from_str::<RuntimeProvenance>(duplicate_provenance).is_err());
        assert!(timestamp("2024-02-29T00:00:00Z"));
        assert!(!timestamp("2023-02-29T00:00:00Z"));
    }
    #[test]
    fn verifier_process_is_bounded() {
        assert_eq!(
            bounded_command(
                Command::new("/usr/bin/printf").arg("ok"),
                Duration::from_secs(1)
            )
            .unwrap(),
            b"ok"
        );
        assert!(
            bounded_command(&mut Command::new("/usr/bin/yes"), Duration::from_secs(1)).is_err()
        );
        let error = bounded_command(
            Command::new("/usr/bin/sleep").arg("1"),
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
