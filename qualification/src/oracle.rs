//! Direct, bounded access to the independently built native oracle.
//! Secrets travel only through anonymous inherited memory-backed files. Diagnostic
//! output is never included in errors or evidence.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

const LIMIT: usize = 1024 * 1024;
const OUTPUT_LIMIT: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_HASH: &str = "37b9729cb30590a0a520058b1d33f4ee1853b7503bbb46d3513be57d88369797";
const CRYPTO_HASH: &str = "43afbdfbb6ee992d34adb1d1b3ac1070da5395ffa2ddd8411c2cc4ad1818cc36";
type Result<T, E = &'static str> = std::result::Result<T, E>;

/// Paths must identify the actual Cabal plans and binaries, not installed tools.
pub struct Configuration {
    pub node_source: PathBuf,
    pub consensus_source: PathBuf,
    pub cli_source: PathBuf,
    pub agent_archive: PathBuf,
    pub crypto_archive: PathBuf,
    pub oracle_source: PathBuf,
    pub oracle_plan: PathBuf,
    pub oracle_executable: PathBuf,
    pub cli_plan: PathBuf,
    pub cli_executable: PathBuf,
    pub ghc: PathBuf,
    pub cabal: PathBuf,
}

pub struct Oracle {
    executable: PathBuf,
}

fn drain<R: Read + Send + 'static>(
    mut stream: R,
    index: usize,
    exceeded: Arc<AtomicBool>,
    tx: mpsc::Sender<(usize, Result<Vec<u8>>)>,
) {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buf = [0; 1024];
        let result = loop {
            match stream.read(&mut buf) {
                Ok(0) => break Ok(bytes),
                Ok(n) if bytes.len() + n <= OUTPUT_LIMIT => bytes.extend_from_slice(&buf[..n]),
                Ok(_) => {
                    exceeded.store(true, Ordering::Relaxed);
                    break Err("process output limit exceeded");
                }
                Err(_) => break Err("process output read failed"),
            }
        };
        let _ = tx.send((index, result));
    });
}

// The child has its own process group so descendants cannot retain pipe or secret
// descriptors after a timeout. RLIMIT_FSIZE also bounds protected output growth.
fn execute(command: &mut Command, fds: Option<(i32, i32)>) -> Result<(Vec<u8>, Vec<u8>)> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some((input, output)) = fds {
                if libc::dup2(input, 3) < 0 || libc::dup2(output, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let limit = libc::rlimit {
                    rlim_cur: LIMIT as libc::rlim_t,
                    rlim_max: LIMIT as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| "cannot start process")?;
    let pid = child.id() as i32;
    let exceeded = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    drain(
        child.stdout.take().ok_or("missing stdout")?,
        0,
        exceeded.clone(),
        tx.clone(),
    );
    drain(
        child.stderr.take().ok_or("missing stderr")?,
        1,
        exceeded.clone(),
        tx,
    );
    let start = Instant::now();
    let status = loop {
        if exceeded.load(Ordering::Relaxed) || start.elapsed() >= TIMEOUT {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err("process timed out or exceeded output limit");
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err("process wait failed");
            }
        }
    };
    // A child that exited must not leave descendants holding protected handles.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    // Both streams are bounded and kept separate.
    let (ai, a) = rx
        .recv_timeout(TIMEOUT.saturating_sub(start.elapsed()))
        .map_err(|_| "process pipes did not close")?;
    let (bi, b) = rx
        .recv_timeout(TIMEOUT.saturating_sub(start.elapsed()))
        .map_err(|_| "process pipes did not close")?;
    if !status.success() || exceeded.load(Ordering::Relaxed) {
        return Err("process failed");
    }
    let (a, b) = (a?, b?);
    if ai == bi {
        return Err("invalid process streams");
    }
    if ai == 0 { Ok((a, b)) } else { Ok((b, a)) }
}

fn check_version(executable: &Path, args: &[&str], expected: &str) -> Result<()> {
    if !executable.is_absolute() {
        return Err("tool path must be absolute");
    }
    let (a, b) = execute(Command::new(executable).args(args), None)?;
    if !b.is_empty() {
        return Err("unexpected version diagnostic");
    }
    let text = [a, b].concat();
    let text = std::str::from_utf8(&text).map_err(|_| "invalid version output")?;
    if !text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .any(|word| word == expected)
    {
        return Err("tool version pin mismatch");
    }
    Ok(())
}
fn check_git(path: &Path, revision: &str) -> Result<()> {
    let (a, b) = execute(
        Command::new("git")
            .args(["-C"])
            .arg(path)
            .args(["rev-parse", "HEAD"]),
        None,
    )?;
    let combined = [a, b].concat();
    if std::str::from_utf8(&combined)
        .map_err(|_| "invalid source revision")?
        .trim()
        != revision
    {
        return Err("source revision pin mismatch");
    }
    let (a, b) = execute(
        Command::new("git").args(["-C"]).arg(path).args([
            "status",
            "--porcelain=v1",
            "-z",
            "-uall",
        ]),
        None,
    )?;
    if !a.is_empty() || !b.is_empty() {
        return Err("source checkout is dirty");
    }
    Ok(())
}
fn archive(path: &Path, expected: &str) -> Result<()> {
    let mut file = File::open(path).map_err(|_| "archive unavailable")?;
    let mut hash = Sha256::new();
    let mut buf = [0; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|_| "archive read failed")?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err("archive digest pin mismatch");
    }
    Ok(())
}
fn plan(
    path: &Path,
    executable: &Path,
    source: &Path,
    package: &str,
    version: &str,
    pins: bool,
) -> Result<()> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "plan unavailable")?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "plan read failed")?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("plan too large");
    }
    let plan: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "invalid plan")?;
    if plan.get("compiler-id").and_then(|x| x.as_str()) != Some("ghc-9.12.4") {
        return Err("plan compiler pin mismatch");
    }
    let entries = plan
        .get("install-plan")
        .and_then(|x| x.as_array())
        .ok_or("invalid plan")?;
    let mut selected = None;
    let mut agent = false;
    let mut crypto = false;
    for entry in entries {
        let name = entry.get("pkg-name").and_then(|x| x.as_str());
        let v = entry.get("pkg-version").and_then(|x| x.as_str());
        if name == Some(package) {
            if v != Some(version) {
                return Err("plan package version mismatch");
            }
            if let Some(bin) = entry.get("bin-file").and_then(|x| x.as_str()) {
                let local = entry
                    .get("pkg-src")
                    .and_then(|s| {
                        if s.get("type").and_then(|x| x.as_str()) != Some("local") {
                            return None;
                        }
                        s.get("path").and_then(|x| x.as_str())
                    })
                    .and_then(|p| std::fs::canonicalize(p).ok());
                let root = std::fs::canonicalize(source).map_err(|_| "source unavailable")?;
                if std::fs::canonicalize(bin).ok() == std::fs::canonicalize(executable).ok()
                    && executable.is_file()
                    && local.as_ref().is_some_and(|p| p.starts_with(&root))
                {
                    if selected.is_some() {
                        return Err("ambiguous plan executable");
                    }
                    selected = entry.get("id").and_then(|x| x.as_str());
                }
            }
        }
        if pins && name == Some("cardano-api") && v != Some("11.6.0.0") {
            return Err("plan cardano-api version mismatch");
        }
        let expected = match name {
            Some("kes-agent") if pins => {
                agent = true;
                Some(("1.3.0.0", AGENT_HASH))
            }
            Some("kes-agent-crypto") if pins => {
                crypto = true;
                Some(("1.1.0.0", CRYPTO_HASH))
            }
            _ => None,
        };
        if let Some((version, digest)) = expected
            && (v != Some(version)
                || entry.get("pkg-src-sha256").and_then(|x| x.as_str()) != Some(digest))
        {
            return Err("plan dependency pin mismatch");
        }
    }
    let root = selected.ok_or("plan executable not selected")?;
    if pins {
        if !agent || !crypto {
            return Err("plan dependencies not selected");
        }
        let mut seen = std::collections::HashSet::new();
        let mut pending = vec![root];
        let mut reached_agent = false;
        let mut reached_crypto = false;
        let mut reached_api = false;
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let entry = entries
                .iter()
                .find(|e| e.get("id").and_then(|x| x.as_str()) == Some(id))
                .ok_or("missing plan dependency")?;
            match entry.get("pkg-name").and_then(|x| x.as_str()) {
                Some("kes-agent") => reached_agent = true,
                Some("kes-agent-crypto") => reached_crypto = true,
                Some("cardano-api") => reached_api = true,
                _ => {}
            }
            for field in ["depends", "exe-depends"] {
                if let Some(deps) = entry.get(field) {
                    for dep in deps.as_array().ok_or("invalid plan dependency list")? {
                        pending.push(dep.as_str().ok_or("invalid plan dependency")?);
                    }
                }
            }
        }
        if !reached_agent || !reached_crypto || !reached_api {
            return Err("oracle does not depend on pinned packages");
        }
    }
    Ok(())
}
impl Oracle {
    pub fn new(c: &Configuration) -> Result<Self> {
        check_git(&c.node_source, "746f1b3cbdaada2c3ed2f702b0946643248dd30b")?;
        check_git(
            &c.consensus_source,
            "6673fce255f12addb602b0ae2d0a20f51a2cd519",
        )?;
        check_git(&c.cli_source, "25f4d7a6b243d80ed7d716cc91b9c51d9265ace6")?;
        archive(&c.agent_archive, AGENT_HASH)?;
        archive(&c.crypto_archive, CRYPTO_HASH)?;
        check_version(&c.ghc, &["--numeric-version"], "9.12.4")?;
        check_version(&c.cabal, &["--numeric-version"], "3.16.1.0")?;
        plan(
            &c.oracle_plan,
            &c.oracle_executable,
            &c.oracle_source,
            "native-oracle",
            "0.1.0.0",
            true,
        )?;
        plan(
            &c.cli_plan,
            &c.cli_executable,
            &c.cli_source,
            "cardano-cli",
            "11.4.0.0",
            false,
        )?;
        check_version(&c.cli_executable, &["--version"], "11.4.0.0")?;
        Ok(Self {
            executable: c.oracle_executable.clone(),
        })
    }
}

// Unlinked memory-backed files never enter a filesystem or pathname namespace.
struct SecretFile(File);
impl SecretFile {
    fn new() -> Result<Self> {
        let fd = unsafe { libc::memfd_create(c"oracle-secret".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err("cannot create protected memory file");
        }
        let file = unsafe { File::from_raw_fd(fd) };
        // Keep source descriptors away from 3 and 4, even when the parent has
        // closed standard descriptors, so dup2 cannot overwrite the other input.
        let dup = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if dup < 0 {
            return Err("cannot duplicate protected descriptor");
        }
        Ok(Self(unsafe { File::from_raw_fd(dup) }))
    }
}
impl Drop for SecretFile {
    fn drop(&mut self) {
        if let Ok(len) = self.0.metadata().map(|m| m.len())
            && self.0.seek(SeekFrom::Start(0)).is_ok()
        {
            let zeros = [0u8; 4096];
            let mut left = len;
            while left != 0 {
                let n = left.min(zeros.len() as u64) as usize;
                if self.0.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
        }
        let _ = self.0.set_len(0);
    }
}

#[derive(Serialize)]
pub struct KesRequest<'a> {
    pub seed: &'a str,
    pub period: u64,
    pub message: &'a str,
    pub expected_state: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KesResponse {
    vkey: String,
    state: String,
    signature: String,
    verified: bool,
    state_matches: bool,
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}
impl Drop for KesResponse {
    fn drop(&mut self) {
        unsafe {
            wipe(self.state.as_mut_vec());
            wipe(self.signature.as_mut_vec());
        }
    }
}
struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub struct KesResult {
    pub vkey: String,
    pub signature_sha256: String,
    pub signature_len: usize,
    pub state_sha256: String,
    pub state_len: usize,
    pub verified: bool,
    pub state_matches: bool,
}
fn hex(value: &str, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Call only after `hex` validates the input. Hash decoded bytes, not their
// textual encoding, without allocating another copy of secret material.
fn hex_sha256(value: &str) -> String {
    let mut hash = Sha256::new();
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        hash.update([(nibble(pair[0]) << 4) | nibble(pair[1])]);
    }
    format!("{:x}", hash.finalize())
}

#[derive(Serialize)]
struct OpCertRequest<'a> {
    cbor: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpCertResult {
    pub hot_vkey: String,
    pub cold_vkey: String,
    pub counter: u64,
    pub start_period: u64,
    pub verified: bool,
}

#[derive(Serialize)]
pub struct ServiceRequest<'a> {
    pub state: &'a str,
    pub period: u64,
    pub cbor: &'a str,
    pub timestamp: u64,
    pub confirmation: &'a str,
    pub expected_wire: &'a str,
}

#[derive(Clone, Copy, Deserialize)]
pub enum Confirmation {
    RecvOK,
    RecvErrorKeyOutdated,
    RecvErrorInvalidOpCert,
    RecvErrorNoKey,
    RecvErrorUnsupportedOperation,
    RecvErrorUnknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceResponse {
    wire: String,
    wire_matches: bool,
    confirmation: Confirmation,
}
impl Drop for ServiceResponse {
    fn drop(&mut self) {
        unsafe {
            wipe(self.wire.as_mut_vec());
        }
    }
}

pub struct ServiceResult {
    pub wire_sha256: String,
    pub wire_len: usize,
    pub wire_matches: bool,
    pub confirmation: Confirmation,
}

#[derive(Serialize)]
pub struct EnvelopeRequest<'a> {
    pub envelope: &'a str,
    pub expected_state: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeResponse {
    state: String,
    vkey: String,
    state_matches: bool,
}
impl Drop for EnvelopeResponse {
    fn drop(&mut self) {
        unsafe {
            wipe(self.state.as_mut_vec());
        }
    }
}
pub struct EnvelopeResult {
    pub vkey: String,
    pub state_sha256: String,
    pub state_len: usize,
    pub state_matches: bool,
}

#[derive(Serialize)]
pub struct VerifyRequest<'a> {
    pub message: &'a str,
    pub period: u64,
    pub signature: &'a str,
    pub vkey: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyResponse {
    verified: bool,
}
impl Oracle {
    pub fn verify(&self, request: &VerifyRequest<'_>) -> Result<bool> {
        if request.period > 63
            || request.message.len() > 8192
            || request.signature.len() > 16000
            || request.vkey.len() != 64
            || !hex(request.message, true)
            || !hex(request.signature, false)
            || !hex(request.vkey, false)
        {
            return Err("invalid verification request");
        }
        let bytes = self.invoke("verify", request)?;
        let response: VerifyResponse =
            serde_json::from_slice(&bytes.0).map_err(|_| "invalid oracle response")?;
        Ok(response.verified)
    }
    pub fn envelope(&self, request: &EnvelopeRequest<'_>) -> Result<EnvelopeResult> {
        if request.expected_state.len() != 1216
            || request.envelope.len() > 16000
            || !hex(request.expected_state, false)
            || !hex(request.envelope, false)
        {
            return Err("invalid envelope request");
        }
        let bytes = self.invoke("envelope", request)?;
        let response: EnvelopeResponse =
            serde_json::from_slice(&bytes.0).map_err(|_| "invalid oracle response")?;
        if response.state.len() != 1216
            || response.vkey.len() != 64
            || !hex(&response.state, false)
            || !hex(&response.vkey, false)
        {
            return Err("invalid oracle response fields");
        }
        let matches = response.state == request.expected_state;
        if matches != response.state_matches {
            return Err("inconsistent oracle state comparison");
        }
        Ok(EnvelopeResult {
            vkey: response.vkey.clone(),
            state_sha256: hex_sha256(&response.state),
            state_len: response.state.len() / 2,
            state_matches: matches,
        })
    }
    pub fn service(&self, request: &ServiceRequest<'_>) -> Result<ServiceResult> {
        if request.state.len() != 1216
            || request.period > 63
            || request.confirmation.len() != 8
            || request.expected_wire.len() > 8192
            || request.cbor.len() > 16000
            || !hex(request.state, false)
            || !hex(request.cbor, false)
            || !hex(request.confirmation, false)
            || !hex(request.expected_wire, true)
        {
            return Err("invalid service request");
        }
        let bytes = self.invoke("service", request)?;
        let response: ServiceResponse =
            serde_json::from_slice(&bytes.0).map_err(|_| "invalid oracle response")?;
        if !hex(&response.wire, false) {
            return Err("invalid oracle response fields");
        }
        let matches = response.wire == request.expected_wire;
        if matches != response.wire_matches {
            return Err("inconsistent oracle wire comparison");
        }
        Ok(ServiceResult {
            wire_sha256: hex_sha256(&response.wire),
            wire_len: response.wire.len() / 2,
            wire_matches: matches,
            confirmation: response.confirmation,
        })
    }
    pub fn opcert(&self, cbor: &str) -> Result<OpCertResult> {
        if cbor.len() > 16000 || !hex(cbor, false) {
            return Err("invalid opcert request");
        }
        let bytes = self.invoke("opcert", &OpCertRequest { cbor })?;
        let response: OpCertResult =
            serde_json::from_slice(&bytes.0).map_err(|_| "invalid oracle response")?;
        if response.hot_vkey.len() != 64
            || response.cold_vkey.len() != 64
            || !hex(&response.hot_vkey, false)
            || !hex(&response.cold_vkey, false)
        {
            return Err("invalid oracle response fields");
        }
        Ok(response)
    }
    /// The protected state is compared locally and is not exposed in evidence.
    pub fn kes(&self, request: &KesRequest<'_>) -> Result<KesResult> {
        if request.seed.len() != 64
            || request.expected_state.len() != 1216
            || request.message.len() > 8192
            || request.period > 63
            || !hex(request.seed, false)
            || !hex(request.message, true)
            || !hex(request.expected_state, false)
        {
            return Err("invalid KES request");
        }
        let bytes = self.invoke("kes", request)?;
        let response: KesResponse =
            serde_json::from_slice(&bytes.0).map_err(|_| "invalid oracle response")?;
        if response.vkey.len() != 64
            || !hex(&response.vkey, false)
            || !hex(&response.state, false)
            || !hex(&response.signature, false)
            || response.state.len() != 1216
        {
            return Err("invalid oracle response fields");
        }
        let matches = response.state == request.expected_state;
        if matches != response.state_matches {
            return Err("inconsistent oracle state comparison");
        }
        Ok(KesResult {
            vkey: response.vkey.clone(),
            signature_sha256: hex_sha256(&response.signature),
            signature_len: response.signature.len() / 2,
            state_sha256: hex_sha256(&response.state),
            state_len: response.state.len() / 2,
            verified: response.verified,
            state_matches: matches,
        })
    }

    fn invoke<T: Serialize>(&self, operation: &str, request: &T) -> Result<SecretBytes> {
        let mut input = SecretFile::new()?;
        let mut output = SecretFile::new()?;
        serde_json::to_writer(&mut input.0, request)
            .map_err(|_| "cannot write protected request")?;
        if input
            .0
            .metadata()
            .map_err(|_| "cannot inspect protected request")?
            .len()
            > 16384
        {
            return Err("protected request too large");
        }
        input
            .0
            .seek(SeekFrom::Start(0))
            .map_err(|_| "cannot rewind protected request")?;
        let (stdout, stderr) = execute(
            Command::new(&self.executable).args(["protected", operation, "3", "4"]),
            Some((input.0.as_raw_fd(), output.0.as_raw_fd())),
        )?;
        let stdout = SecretBytes(stdout);
        let stderr = SecretBytes(stderr);
        if !stdout.0.is_empty() || !stderr.0.is_empty() {
            return Err("unexpected oracle output");
        }
        if output
            .0
            .metadata()
            .map_err(|_| "cannot inspect protected response")?
            .len()
            > LIMIT as u64
        {
            return Err("protected response too large");
        }
        output
            .0
            .seek(SeekFrom::Start(0))
            .map_err(|_| "cannot rewind protected response")?;
        let mut bytes = SecretBytes(Vec::new());
        (&mut output.0)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes.0)
            .map_err(|_| "cannot read protected response")?;
        if bytes.0.len() > LIMIT {
            return Err("protected response too large");
        }
        Ok(bytes)
    }
}
