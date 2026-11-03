//! Independent, authenticated release discovery and private offline cache.
use super::{
    model::{
        MAX_ARTIFACT_BYTES, MAX_ARTIFACT_PATH_BYTES, MAX_ARTIFACTS, MAX_MANIFEST_BYTES,
        MAX_RELEASE_BYTES, Qualification, ReleaseSelection,
    },
    release::{self, Admission, Manifest},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const API: &str =
    "https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases?per_page=100";
const TAG_API: &str = "https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases/tags/";
const LATEST_API: &str = "https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases/latest";
const PROJECT: &str = "https://github.com/AndrewWestberg/pico2-kes-agent/releases/download/";
const ARCHIVE_LIMIT: u64 = MAX_RELEASE_BYTES + 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub bundle: PathBuf,
    pub manifest: Manifest,
    pub selection: ReleaseSelection,
    /// Unix time when this cache entry was fetched; local cache metadata is not signed.
    pub fetched_at: u64,
    pub source: String,
}
impl Offer {
    pub const PROVENANCE: &'static str = "Signature and bundle reverified against available authority evidence; offline cache cannot establish current global revocation or latest release status";
    pub fn age(&self) -> Duration {
        Duration::from_secs(now().saturating_sub(self.fetched_at))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub offers: Vec<Offer>,
    pub notice: Option<String>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct Worker {
    cancel: std::sync::Arc<AtomicBool>,
    receiver: Receiver<io::Result<Discovery>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    pub fn poll(&mut self) -> Option<io::Result<Discovery>> {
        match self.receiver.try_recv() {
            Ok(v) => Some(v),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err(io::Error::other("release worker stopped")))
            }
        }
    }
    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start(cache: PathBuf, include_prerelease: bool, online: bool) -> io::Result<Worker> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("release-discovery-worker")
        .arg(&cache)
        .arg(if include_prerelease { "1" } else { "0" })
        .arg(if online { "1" } else { "0" })
        .env("P2KES_DISCOVERY_WORKER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let (tx, receiver) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let stdout = child.stdout.take().unwrap();
        let (out_tx, out_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut data = Vec::new();
            let result = stdout
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut data)
                .map(|_| data);
            let _ = out_tx.send(result);
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = loop {
            if flag.load(Ordering::Acquire) || Instant::now() >= deadline {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "release discovery stopped or timed out",
                ));
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        break Err(io::Error::other("release discovery failed"));
                    }
                    break match out_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(Ok(bytes)) if bytes.len() <= 8 * 1024 * 1024 => {
                            serde_json::from_slice(&bytes)
                                .map_err(|_| invalid("invalid release worker response"))
                        }
                        _ => Err(invalid("invalid release worker response")),
                    };
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => break Err(e),
            }
        };
        cleanup_stages(&cache, child.id());
        cleanup_stages(Path::new("/tmp"), child.id());
        let _ = tx.send(result);
    });
    Ok(Worker {
        cancel,
        receiver,
        thread: Some(thread),
    })
}

pub fn default_cache() -> io::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
        _ => PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME is unavailable"))?,
        )
        .join(".cache"),
    };
    fs::create_dir_all(&base)?;
    let parent = base.join("p2kesup");
    cache_dir(&parent)?;
    let cache = parent.join("releases");
    cache_dir(&cache)?;
    Ok(cache)
}

/// Remove only complete entries in the manager's own cache, never the cache root.
pub fn clear_cache() -> io::Result<usize> {
    let cache = default_cache()?;
    let mut removed = 0;
    for entry in fs::read_dir(&cache)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && id(name)
        {
            remove(&cache, name)?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn cache_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(invalid("release cache must be a private owned directory"));
    }
    Ok(())
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Only a named, complete cache entry can be removed; arbitrary paths are never accepted.
pub fn remove(cache: &Path, entry: &str) -> io::Result<()> {
    cache_dir(cache)?;
    if fs::canonicalize(cache)? != fs::canonicalize(default_cache()?)? {
        return Err(invalid("removal is restricted to the release cache"));
    }
    if !id(entry) {
        return Err(invalid("invalid cache entry"));
    }
    let path = cache.join(entry);
    let m = fs::symlink_metadata(&path)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != unsafe { libc::geteuid() } {
        return Err(invalid("unsafe cache entry"));
    }
    fs::remove_dir_all(path)
}
fn cleanup_stages(root: &Path, pid: u32) {
    let prefixes = [
        format!(".stage-{pid}-"),
        format!("p2kesup-snapshot-{pid}-"),
        format!("p2kesup-gpg-{pid}-"),
        format!("p2kesup-firmware-gpg-{pid}-"),
    ];
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = prefixes.iter().find_map(|prefix| name.strip_prefix(prefix)) else {
                continue;
            };
            if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(meta) = fs::symlink_metadata(entry.path())
                && meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == unsafe { libc::geteuid() }
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temporary(root: &Path) -> io::Result<Temp> {
    for _ in 0..32 {
        let p = root.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(Temp(p)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("cannot create release staging directory"))
}
fn available(path: &Path, bytes: u64) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid("invalid staging path"))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(p.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64)
        < bytes.saturating_add(1024 * 1024)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "insufficient release staging space",
        ));
    }
    Ok(())
}
fn size_tree(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    for e in fs::read_dir(path)? {
        let e = e?;
        let m = fs::symlink_metadata(e.path())?;
        if m.file_type().is_symlink() {
            return Err(invalid("unsafe cache contents"));
        }
        let size = if m.is_dir() {
            size_tree(&e.path())?
        } else if m.is_file() && m.nlink() == 1 {
            m.len()
        } else {
            return Err(invalid("unsafe cache contents"));
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid("cache size overflow"))?;
        if total > MAX_RELEASE_BYTES {
            return Err(invalid("release cache exceeds limit"));
        }
    }
    Ok(total)
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ARTIFACT_PATH_BYTES
        && s.bytes().all(|b| (32..127).contains(&b) && b != b'\\')
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}
fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() > limit {
        return Err(invalid("unsafe or oversized file"));
    }
    let mut v = Vec::new();
    f.take(limit + 1).read_to_end(&mut v)?;
    if v.len() as u64 != m.len() {
        return Err(invalid("file changed"));
    }
    Ok(v)
}
fn private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::PermissionsExt;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}
fn url_allowed(url: &str, initial: bool) -> bool {
    if initial {
        return url.starts_with(PROJECT)
            && !url[PROJECT.len()..].contains(['?', '#', '\\', '@'])
            && url.bytes().all(|b| (33..127).contains(&b));
    }
    (url.starts_with(PROJECT)
        || [
            "https://objects.githubusercontent.com/",
            "https://release-assets.githubusercontent.com/",
        ]
        .iter()
        .any(|p| url.starts_with(p)))
        && url.bytes().all(|b| (33..127).contains(&b))
        && !url.contains('\\')
}
fn fetch(url: &str, target: &Path, limit: u64, api: bool) -> io::Result<()> {
    if (!api && !url_allowed(url, true)) || (api && url != API && url != LATEST_API && !url.strip_prefix(TAG_API).is_some_and(valid_tag)) {
        return Err(invalid("unapproved release URL"));
    }
    private_file(target)?;
    let mut url = url.to_owned();
    for _ in 0..5 {
        let headers = target.with_extension("headers");
        private_file(&headers)?;
        let status = Command::new("/usr/bin/curl")
            .env_clear()
            .args([
                "--disable",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--max-time",
                "10",
                "--max-filesize",
                &limit.to_string(),
                "--user-agent",
                "p2kesup",
                "--dump-header",
            ])
            .arg(&headers)
            .arg("--output")
            .arg(target)
            .arg("--")
            .arg(&url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("release download failed"));
        }
        let h = read_bounded(&headers, 65536)?;
        let _ = fs::remove_file(&headers);
        let h = std::str::from_utf8(&h).map_err(|_| invalid("invalid HTTP headers"))?;
        let code = h
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");
        if code == "200" {
            read_bounded_size(target, limit)?;
            return Ok(());
        }
        if !matches!(code, "301" | "302" | "303" | "307" | "308") {
            return Err(io::Error::other("release HTTP request failed"));
        }
        let locations: Vec<_> = h
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.trim())
            .collect();
        if locations.len() != 1 || !url_allowed(locations[0], false) {
            return Err(invalid("unapproved release redirect"));
        }
        url = locations[0].to_owned();
    }
    Err(invalid("too many release redirects"))
}
fn read_bounded_size(path: &Path, limit: u64) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 || m.len() > limit {
        return Err(invalid("oversized download"));
    }
    Ok(())
}
fn octal(field: &[u8]) -> io::Result<u64> {
    let s = std::str::from_utf8(field)
        .map_err(|_| invalid("invalid tar number"))?
        .trim_matches(|c| c == '\0' || c == ' ');
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| invalid("invalid tar number"))
}
fn tar_text(field: &[u8]) -> io::Result<&str> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    if field[end..].iter().any(|&b| b != 0) {
        return Err(invalid("invalid tar string"));
    }
    std::str::from_utf8(&field[..end]).map_err(|_| invalid("invalid tar string"))
}
fn valid_header(header: &[u8; 512]) -> io::Result<()> {
    let expected = octal(&header[148..156])?;
    let sum: u64 = header
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            if (148..156).contains(&i) {
                32
            } else {
                v as u64
            }
        })
        .sum();
    if sum != expected || !matches!(header[156], 0 | b'0') || &header[257..263] != b"ustar\0" {
        return Err(invalid("unsafe tar member"));
    }
    Ok(())
}
fn extract(archive: &Path, output: &Path, manifest: &Manifest) -> io::Result<()> {
    if manifest.artifacts.len() > MAX_ARTIFACTS {
        return Err(invalid("too many artifacts"));
    }
    let mut declared = BTreeMap::new();
    let mut total = 0u64;
    for a in &manifest.artifacts {
        if !safe_path(&a.path)
            || a.size_bytes > MAX_ARTIFACT_BYTES
            || !matches!(a.mode, 0o644 | 0o755)
            || declared.insert(a.path.clone(), a).is_some()
        {
            return Err(invalid("invalid artifact declaration"));
        }
        total = total
            .checked_add(a.size_bytes)
            .ok_or_else(|| invalid("artifact size overflow"))?;
    }
    if total > MAX_RELEASE_BYTES {
        return Err(invalid("archive expansion exceeds limit"));
    }
    available(output, total)?;
    let mut input = File::open(archive)?;
    let mut seen = BTreeSet::new();
    let mut header = [0u8; 512];
    loop {
        input.read_exact(&mut header)?;
        if header.iter().all(|b| *b == 0) {
            input.read_exact(&mut header)?;
            if header.iter().any(|b| *b != 0) {
                return Err(invalid("invalid tar end"));
            }
            break;
        }
        valid_header(&header)?;
        let name = tar_text(&header[..100])?;
        let prefix = tar_text(&header[345..500])?;
        let name = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let a = declared
            .get(&name)
            .ok_or_else(|| invalid("undeclared archive member"))?;
        if !seen.insert(name.clone())
            || octal(&header[124..136])? != a.size_bytes
            || octal(&header[100..108])? != a.mode as u64
        {
            return Err(invalid("invalid archive member"));
        }
        let target = output.join(&name);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(target.parent().ok_or_else(|| invalid("invalid path"))?)?;
        let mut out = private_file(&target)?;
        let mut hash = Sha256::new();
        let mut remaining = a.size_bytes;
        let mut buf = [0u8; 65536];
        while remaining != 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            input.read_exact(&mut buf[..n])?;
            out.write_all(&buf[..n])?;
            hash.update(&buf[..n]);
            remaining -= n as u64;
        }
        if format!("{:x}", hash.finalize()) != a.sha256 {
            return Err(invalid("archive hash mismatch"));
        }
        let padding = (512 - a.size_bytes % 512) % 512;
        input.read_exact(&mut buf[..padding as usize])?;
    }
    if seen.len() != declared.len() {
        return Err(invalid("incomplete archive"));
    }
    let mut rest = [0u8; 8192];
    loop {
        let n = input.read(&mut rest)?;
        if n == 0 {
            break;
        }
        if rest[..n].iter().any(|b| *b != 0) {
            return Err(invalid("trailing tar data"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct GithubRelease {
    draft: bool,
    tag_name: String,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}
#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}
fn publication_matches(published: &str, signed: &str, qualification: Qualification) -> bool {
    published == signed
        || (qualification == Qualification::Qualified
            && published.strip_prefix("qualified-") == Some(signed))
}

fn obtain(cache: &Path, item: &GithubRelease, admission: Admission, stable_only: bool) -> io::Result<PathBuf> {
    if item.draft || item.assets.len() > 128 {
        return Err(invalid("invalid release assets"));
    }
    let asset = |name: &str| -> io::Result<&str> {
        let v: Vec<_> = item.assets.iter().filter(|a| a.name == name).collect();
        if v.len() != 1 {
            return Err(invalid("missing or duplicate release asset"));
        }
        Ok(&v[0].browser_download_url)
    };
    let stage = temporary(cache)?;
    let bundle = stage.0.join("bundle");
    fs::DirBuilder::new().mode(0o700).create(&bundle)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(bundle.join("firmware"))?;
    fetch(
        asset("distribution.json")?,
        &bundle.join("distribution.json"),
        MAX_MANIFEST_BYTES,
        false,
    )?;
    fetch(
        asset("distribution.json.sig")?,
        &bundle.join("distribution.json.sig"),
        MAX_MANIFEST_BYTES,
        false,
    )?;
    fetch(
        asset("release-authority.asc")?,
        &bundle.join("firmware/release-authority.asc"),
        MAX_MANIFEST_BYTES,
        false,
    )?;
    for name in ["distribution-authority.json", "distribution-authority.json.asc"] {
        fetch(asset(name)?, &bundle.join(name), MAX_MANIFEST_BYTES, false)?;
    }
    let delegation = read_bounded(&bundle.join("distribution-authority.json"), MAX_MANIFEST_BYTES)?;
    let delegation_signature = read_bounded(&bundle.join("distribution-authority.json.asc"), MAX_MANIFEST_BYTES)?;
    let authority = read_bounded(
        &bundle.join("firmware/release-authority.asc"),
        MAX_MANIFEST_BYTES,
    )?;
    release::verify_signature(&bundle, "distribution.json")?;
    let bytes = read_bounded(&bundle.join("distribution.json"), MAX_MANIFEST_BYTES)?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid signed manifest"))?;
    if (stable_only && (item.prerelease || manifest.release.channel != "stable"))
        || (matches!(admission, Admission::Qualified) && manifest.qualification != Qualification::Qualified)
        || !publication_matches(&item.tag_name, &manifest.release.tag, manifest.qualification)
    {
        return Err(invalid("release tag, channel or qualification differs from authenticated manifest"));
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if cache.join(&digest).exists() {
        let path = cache.join(&digest).join("bundle");
        let verified = release::verify_bundle(&path, admission)?;
        if verified.selection().manifest_digest.to_string() != digest {
            return Err(invalid("cached manifest digest mismatch"));
        }
        return Ok(path);
    }
    let total = manifest
        .artifacts
        .iter()
        .try_fold(0u64, |n, a| n.checked_add(a.size_bytes))
        .ok_or_else(|| invalid("artifact size overflow"))?;
    if total > MAX_RELEASE_BYTES
        || size_tree(cache)?
            .saturating_add(total)
            .saturating_add(2 * MAX_MANIFEST_BYTES)
            > MAX_RELEASE_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "release cache capacity exceeded",
        ));
    }
    available(cache, total)?;
    let archive_stage = temporary(Path::new("/tmp"))?;
    available(&archive_stage.0, total.saturating_add(1024 * 1024))?;
    let archive = archive_stage.0.join("distribution.tar");
    fetch(
        asset("distribution.tar")?,
        &archive,
        ARCHIVE_LIMIT.min(total.saturating_add(1024 * 1024)),
        false,
    )?;
    // The certificate is used for metadata authentication, then must be reproduced by the signed archive.
    fs::remove_file(bundle.join("firmware/release-authority.asc"))?;
    fs::remove_file(bundle.join("distribution-authority.json"))?;
    fs::remove_file(bundle.join("distribution-authority.json.asc"))?;
    extract(&archive, &bundle, &manifest)?;
    if read_bounded(
        &bundle.join("firmware/release-authority.asc"),
        MAX_MANIFEST_BYTES,
    )? != authority
        || read_bounded(&bundle.join("distribution-authority.json"), MAX_MANIFEST_BYTES)? != delegation
        || read_bounded(&bundle.join("distribution-authority.json.asc"), MAX_MANIFEST_BYTES)? != delegation_signature
    {
        return Err(invalid("archive authority mismatch"));
    }
    let verified = release::verify_bundle(&bundle, admission)?;
    drop(verified);
    fs::remove_file(archive)?;
    private_file(&stage.0.join("fetched"))?.write_all(now().to_string().as_bytes())?;
    fs::rename(&stage.0, cache.join(&digest))?;
    Ok(cache.join(digest).join("bundle"))
}
fn offers(cache: &Path, prerelease: bool) -> io::Result<Vec<Offer>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(cache)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !id(name) {
            continue;
        }
        let m = fs::symlink_metadata(entry.path())?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != unsafe { libc::geteuid() } {
            continue;
        }
        let bundle = entry.path().join("bundle");
        let verified = match release::verify_bundle(&bundle, Admission::Qualified) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let manifest = verified.manifest().clone();
        if !prerelease && manifest.release.channel != "stable" {
            continue;
        }
        if format!(
            "{:x}",
            Sha256::digest(read_bounded(
                &bundle.join("distribution.json"),
                MAX_MANIFEST_BYTES
            )?)
        ) != name
        {
            continue;
        }
        let fetched_at = read_bounded(&entry.path().join("fetched"), 32)
            .ok()
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        result.push(Offer {
            bundle,
            manifest,
            selection: verified.selection().clone(),
            fetched_at,
            source: "authenticated cache".to_owned(),
        });
    }
    Ok(result)
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty() && tag != "." && tag != ".." && !tag.starts_with('-') && tag.len() <= 128
        && tag.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Fetch the newest qualified stable release, or one explicitly named release.
pub fn fetch_release(tag: Option<&str>) -> io::Result<PathBuf> {
    if tag.is_some_and(|tag| !valid_tag(tag)) {
        return Err(invalid("invalid release tag"));
    }
    let cache = default_cache()?;
    let stage = temporary(&cache)?;
    let api = stage.0.join("releases.json");
    if let Some(tag) = tag {
        fetch(&format!("{TAG_API}{tag}"), &api, MAX_MANIFEST_BYTES, true)?;
        let item: GithubRelease = serde_json::from_slice(&read_bounded(&api, MAX_MANIFEST_BYTES)?)
            .map_err(|_| invalid("invalid release discovery response"))?;
        if item.tag_name != tag {
            return Err(invalid("release response tag differs from requested tag"));
        }
        return obtain(&cache, &item, Admission::AttendedCandidate, false);
    }
    fetch(LATEST_API, &api, MAX_MANIFEST_BYTES, true)?;
    let item: GithubRelease = serde_json::from_slice(&read_bounded(&api, MAX_MANIFEST_BYTES)?)
        .map_err(|_| invalid("invalid latest release response"))?;
    obtain(&cache, &item, Admission::Qualified, true)
}
/// Hidden subprocess entry point; never execute a downloaded program as discovery authority.
pub fn run_worker(cache: &Path, include_prerelease: bool, online: bool) -> io::Result<()> {
    release::inherit_worker_process_group();
    cache_dir(cache)?;
    let mut notice = None;
    if online {
        let stage = temporary(cache)?;
        let api = stage.0.join("releases.json");
        fetch(API, &api, MAX_MANIFEST_BYTES, true)?;
        let bytes = read_bounded(&api, MAX_MANIFEST_BYTES)?;
        let releases: Vec<GithubRelease> = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid release discovery response"))?;
        for item in releases.iter().take(100) {
            match obtain(cache, item, Admission::Qualified, false) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
                Err(error) if error.kind() == io::ErrorKind::StorageFull => {
                    notice = Some("Cache capacity reached; stopped additional downloads and reverified available cached releases".into());
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }
    let result = Discovery {
        offers: offers(cache, include_prerelease)?,
        notice,
    };
    serde_json::to_writer(io::stdout(), &result).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualified_publication_mapping_does_not_promote_candidates() {
        assert!(publication_matches("qualified-v1.2.3", "v1.2.3", Qualification::Qualified));
        assert!(!publication_matches("qualified-v1.2.3", "v1.2.3", Qualification::Candidate));
        assert!(!publication_matches("qualified-v1.2.4", "v1.2.3", Qualification::Qualified));
        assert!(publication_matches("v1.2.3-rc1", "v1.2.3-rc1", Qualification::Candidate));
        assert!(valid_tag("v1.2.3-rc1"));
        assert!(!valid_tag("../v1"));
        assert!(!valid_tag(".."));
    }
    #[test]
    fn paths_and_origins_are_confined() {
        assert!(safe_path("firmware/release.json"));
        for path in ["../x", "/x", "a/../b", "a//b", "a/./b", "a\\b", "a\nb"] {
            assert!(!safe_path(path));
        }
        assert!(url_allowed(
            "https://github.com/AndrewWestberg/pico2-kes-agent/releases/download/v1/distribution.tar",
            true
        ));
        assert!(!url_allowed(
            "https://github.com.evil/AndrewWestberg/pico2-kes-agent/releases/download/x",
            true
        ));
        assert!(!url_allowed(
            "https://release-assets.githubusercontent.com.evil/x",
            false
        ));
    }
    #[test]
    fn tar_numbers_are_bounded() {
        assert_eq!(octal(b"000777\0 ").unwrap(), 0o777);
        assert!(octal(b"999").is_err());
        assert!(octal(b"77777777777777777777777777").is_err());
    }
    #[test]
    fn rejects_link_and_corrupt_headers() {
        let mut header = [0u8; 512];
        header[257..263].copy_from_slice(b"ustar\0");
        header[156] = b'2';
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    v as u64
                }
            })
            .sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(valid_header(&header).is_err());
        header[156] = b'0';
        assert!(valid_header(&header).is_err());
    }
    #[test]
    fn cancellation_removes_owned_verifier_snapshots_not_other_paths() {
        let root = temporary(Path::new("/tmp")).unwrap();
        let pid = 4242;
        let names = [
            ".stage-4242-1",
            "p2kesup-snapshot-4242-2",
            "p2kesup-gpg-4242-3",
            "p2kesup-firmware-gpg-4242-4",
        ];
        for name in names {
            fs::create_dir(root.0.join(name)).unwrap();
            fs::write(root.0.join(name).join("payload"), b"public payload").unwrap();
        }
        let unrelated = root.0.join("p2kesup-snapshot-4243-1");
        fs::create_dir(&unrelated).unwrap();
        let malformed = root.0.join("p2kesup-snapshot-4242-not-an-id");
        fs::create_dir(&malformed).unwrap();
        let link = root.0.join("p2kesup-snapshot-4242-9");
        std::os::unix::fs::symlink(&unrelated, &link).unwrap();
        cleanup_stages(&root.0, pid);
        for name in names {
            assert!(!root.0.join(name).exists(), "abandoned {name}");
        }
        assert!(unrelated.is_dir());
        assert!(malformed.is_dir());
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    }
}
