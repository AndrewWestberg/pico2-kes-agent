//! Public-only foundation evidence. Check descriptions must be static, public
//! labels, never captured process output, fixture contents, or credentials.
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const DEFINITION: &str = "specs/001-pico2-kes-agent/contracts/quality-gates.md";
pub(crate) const APPROVED_DIGEST: &str =
    "f6d0e7962bad19bb142afb22251c63a0aba41ba2dda7cc63a9db71f2f26493ce";
const APPROVED_STORAGE_DIGEST: &str =
    "9b0616cbd3e3ef3e5ee5e82f276e61e83df38faa6653a1c1fd45fea96ba6862b";
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct Check {
    pub name: &'static str,
    pub expected: &'static str,
    pub observed: &'static str,
    pub executions: u64,
    pub passed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass-for-foundation-scope",
            Self::Fail => "failed",
            Self::Inconclusive => "inconclusive",
        }
    }
}

// Never retain stderr or print raw command output. Drain stdout concurrently so
// the child cannot deadlock on a full pipe; enforce both byte and time limits.
pub(crate) fn command(program: &str, args: &[&str], timeout: Duration) -> Option<(bool, Vec<u8>)> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(ROOT)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn().ok()?;
    let pid = child.id() as i32;
    let Some(stdout) = child.stdout.take() else {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= OUTPUT_LIMIT).then_some(bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                break Some(status);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let bytes = reader.join().ok().flatten()?;
    status.map(|s| (s.success(), bytes))
}

fn metadata_command(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    let (success, bytes) = command(program, args, TIMEOUT)?;
    success.then_some(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn public_label(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" .,:;_-/()+=<>".contains(&b))
    {
        return false;
    }
    // This is a defense in depth check, not a substitute for the static,
    // explicitly public labels required by the API.
    let lower = value.to_ascii_lowercase();
    ![
        "secret",
        "password",
        "passwd",
        "credential",
        "private",
        "token",
        "passphrase",
        "seed",
        "mnemonic",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn version(program: &str) -> Option<String> {
    let bytes = metadata_command(program, &["--version"])?;
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    public_label(text).then(|| text.to_owned())
}

pub(crate) fn candidate() -> Option<(String, String)> {
    let revision = metadata_command("git", &["rev-parse", "--verify", "HEAD"])?;
    let revision = std::str::from_utf8(&revision).ok()?.trim();
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let staged = metadata_command(
        "git",
        &[
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "--",
        ],
    )?;
    let unstaged = metadata_command(
        "git",
        &["diff", "--binary", "--no-ext-diff", "--no-textconv", "--"],
    )?;
    let untracked = metadata_command("git", &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut hash = Sha256::new();
    hash.update(b"qualification-dirty-v1\0");
    for diff in [&staged, &unstaged] {
        hash.update((diff.len() as u64).to_be_bytes());
        hash.update(diff);
    }
    for name in untracked.split(|b| *b == 0).filter(|name| !name.is_empty()) {
        // Git paths are untrusted. Refuse symlinks, non-UTF-8, and paths that
        // escape the checkout instead of reading an arbitrary external file.
        let name = std::str::from_utf8(name).ok()?;
        // Reports are generated artifacts, not candidate source.
        if name.starts_with("evidence/") {
            continue;
        }
        let path = Path::new(name);
        if path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return None;
        }
        let full = Path::new(ROOT).join(path);
        let mut current = PathBuf::from(ROOT);
        for part in path.components() {
            current.push(part.as_os_str());
            if fs::symlink_metadata(&current)
                .ok()?
                .file_type()
                .is_symlink()
            {
                return None;
            }
        }
        let meta = fs::metadata(&full).ok()?;
        if !meta.is_file() || meta.len() > OUTPUT_LIMIT as u64 {
            return None;
        }
        let mut file = File::open(full).ok()?;
        let mut content = Vec::new();
        Read::by_ref(&mut file)
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut content)
            .ok()?;
        if content.len() > OUTPUT_LIMIT {
            return None;
        }
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((content.len() as u64).to_be_bytes());
        hash.update(&content);
    }
    Some((revision.to_owned(), hex(&hash.finalize())))
}

pub(crate) fn approved_definition() -> bool {
    let Ok(bytes) = fs::read(Path::new(ROOT).join(DEFINITION)) else {
        return false;
    };
    let marker = b"## Approval record";
    let Some(end) = bytes.windows(marker.len()).position(|w| w == marker) else {
        return false;
    };
    let Ok(storage) =
        fs::read(Path::new(ROOT).join("specs/001-pico2-kes-agent/contracts/device-storage.md"))
    else {
        return false;
    };
    let Ok(record) = std::str::from_utf8(&bytes[end..]) else {
        return false;
    };
    let current = record;
    hex(&Sha256::digest(&bytes[..end])) == APPROVED_DIGEST
        && current.contains("**Status:** Approved.")
        && current.contains("**Approver:** Project maintainer")
        && current.contains("**Date:** 2026-10-28.")
        && current.contains(APPROVED_DIGEST)
        && current.contains(APPROVED_STORAGE_DIGEST)
        && hex(&Sha256::digest(&storage)) == APPROVED_STORAGE_DIGEST
}

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn field(out: &mut String, key: &str, value: &str) {
    json_string(out, key);
    out.push(':');
    json_string(out, value);
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing report directory"))?;
    fs::create_dir_all(parent)?;
    let mut temp = None;
    for _ in 0..100 {
        let name = format!(
            ".report.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let candidate = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let (temp_path, mut file) = temp.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate report temporary file",
        )
    })?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

fn check_verdict(checks: &[Check], metadata_available: bool) -> Verdict {
    let valid = !checks.is_empty()
        && checks.iter().all(|c| {
            c.executions > 0
                && c.observed != "unavailable"
                && public_label(c.name)
                && public_label(c.expected)
                && public_label(c.observed)
        })
        && checks
            .iter()
            .enumerate()
            .all(|(i, c)| !checks[..i].iter().any(|prior| prior.name == c.name));
    if !metadata_available || !valid {
        Verdict::Inconclusive
    } else if checks.iter().any(|c| !c.passed) {
        Verdict::Fail
    } else {
        Verdict::Pass
    }
}

/// Write a sanitized foundation report. Only predefined public labels may be
/// supplied in checks; raw errors, process output and input bytes are forbidden.
/// Metadata collection failure is recorded as inconclusive, never as a pass.
pub fn run(checks: &[Check]) -> io::Result<(Verdict, PathBuf)> {
    let identity = candidate();
    let rustc = version("rustc");
    let cargo = version("cargo");
    let approved = approved_definition();
    let verdict = check_verdict(
        checks,
        identity.is_some() && rustc.is_some() && cargo.is_some() && approved,
    );
    let (revision, dirty) = identity
        .as_ref()
        .map(|(r, d)| (r.as_str(), d.as_str()))
        .unwrap_or(("unavailable", "unavailable"));
    let dir = if identity.is_some() {
        format!("{}-{}", revision, dirty)
    } else {
        "unavailable".to_owned()
    };
    let path = Path::new(ROOT)
        .join("evidence")
        .join(dir)
        .join("foundation/report.json");
    let mut report = String::from("{\"schema_version\":1,\"candidate\":{");
    field(&mut report, "revision", revision);
    report.push(',');
    field(&mut report, "dirty_sha256", dirty);
    report.push_str("},\"gate\":{");
    field(
        &mut report,
        "approval",
        if approved { "approved" } else { "unavailable" },
    );
    report.push(',');
    field(
        &mut report,
        "definition_sha256",
        if approved {
            APPROVED_DIGEST
        } else {
            "unavailable"
        },
    );
    report.push(',');
    field(
        &mut report,
        "approver",
        if approved {
            "Project maintainer"
        } else {
            "unavailable"
        },
    );
    report.push(',');
    field(
        &mut report,
        "approval_date",
        if approved {
            "2026-10-28"
        } else {
            "unavailable"
        },
    );
    report.push_str("},\"environment\":{");
    field(&mut report, "os", std::env::consts::OS);
    report.push(',');
    field(&mut report, "arch", std::env::consts::ARCH);
    report.push(',');
    field(
        &mut report,
        "rustc",
        rustc.as_deref().unwrap_or("unavailable"),
    );
    report.push(',');
    field(
        &mut report,
        "cargo",
        cargo.as_deref().unwrap_or("unavailable"),
    );
    report.push_str(
        "},\"command\":\"cargo run --locked -p qualification -- foundation\",\"checks\":[",
    );
    for (i, check) in checks.iter().enumerate() {
        if i != 0 {
            report.push(',');
        }
        report.push('{');
        // Invalid labels are never copied into a report, even on failure.
        field(
            &mut report,
            "name",
            if public_label(check.name) {
                check.name
            } else {
                "invalid"
            },
        );
        report.push(',');
        field(
            &mut report,
            "expected",
            if public_label(check.expected) {
                check.expected
            } else {
                "invalid"
            },
        );
        report.push(',');
        field(
            &mut report,
            "observed",
            if public_label(check.observed) {
                check.observed
            } else {
                "invalid"
            },
        );
        report.push_str(&format!(
            ",\"executions\":{},\"passed\":{}}}",
            check.executions, check.passed
        ));
    }
    report.push_str("],");
    field(&mut report, "verdict", verdict.label());
    report.push_str("}\n");
    atomic_write(&path, report.as_bytes())?;
    Ok((verdict, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descendant_is_stopped(timeout_case: bool) {
        let path = std::env::temp_dir().join(format!(
            "qualification-child-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let path_arg = path.to_str().unwrap();
        let script = if timeout_case {
            "sleep 30 & echo $! > \"$1\"; wait"
        } else {
            "sleep 30 & echo $! > \"$1\"; exit 0"
        };
        let started = Instant::now();
        let result = command(
            "sh",
            &["-c", script, "sh", path_arg],
            Duration::from_millis(500),
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(result.is_some(), !timeout_case);
        let pid: u32 = fs::read_to_string(&path).unwrap().trim().parse().unwrap();
        fs::remove_file(path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = fs::read_to_string(format!("/proc/{pid}/status"));
            if match status {
                Ok(s) => s.lines().any(|line| line.starts_with("State:\tZ")),
                Err(_) => true,
            } {
                break;
            }
            assert!(Instant::now() < deadline, "descendant still running");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn leader_exit_closes_descendant_stdout() {
        descendant_is_stopped(false);
    }

    #[test]
    fn timeout_terminates_descendant() {
        descendant_is_stopped(true);
    }
    #[test]
    fn verdict_rejects_missing_execution_metadata_and_unavailable() {
        let pass = Check {
            name: "codec",
            expected: "rejected",
            observed: "rejected",
            executions: 1,
            passed: true,
        };
        let failed = Check {
            name: "codec",
            expected: "rejected",
            observed: "accepted",
            executions: 1,
            passed: false,
        };
        let unavailable = Check {
            name: "codec",
            expected: "rejected",
            observed: "unavailable",
            executions: 1,
            passed: false,
        };
        let missing = Check {
            name: "codec",
            expected: "rejected",
            observed: "rejected",
            executions: 0,
            passed: true,
        };
        assert_eq!(check_verdict(&[], true), Verdict::Inconclusive);
        assert_eq!(check_verdict(&[pass], false), Verdict::Inconclusive);
        assert_eq!(check_verdict(&[failed], true), Verdict::Fail);
        assert_eq!(check_verdict(&[unavailable], true), Verdict::Inconclusive);
        assert_eq!(check_verdict(&[missing], true), Verdict::Inconclusive);
        let pass = Check {
            name: "codec",
            expected: "rejected",
            observed: "rejected",
            executions: 1,
            passed: true,
        };
        assert_eq!(check_verdict(&[pass], true), Verdict::Pass);
        assert_eq!(Verdict::Pass.label(), "pass-for-foundation-scope");
        assert_eq!(Verdict::Fail.label(), "failed");
        assert_eq!(Verdict::Inconclusive.label(), "inconclusive");
    }
    #[test]
    fn public_labels_reject_unbounded_or_control_data() {
        assert!(public_label("malformed USB: rejected"));
        assert!(!public_label(""));
        assert!(!public_label("secret\nbytes"));
        assert!(!public_label("Password=abc"));
        assert!(!public_label("PRIVATE key"));
        assert!(!public_label("credential"));
        assert!(!public_label("token-value"));
        assert!(!public_label("seed bytes"));
        assert!(!public_label(&"x".repeat(257)));
    }
    #[test]
    fn json_escapes_controls_and_quotes() {
        let mut out = String::new();
        json_string(&mut out, "a\"\\\n\u{1}");
        assert_eq!(out, "\"a\\\"\\\\\\n\\u0001\"");
    }
    #[test]
    fn atomic_replace_preserves_complete_contents() {
        let dir = std::env::temp_dir().join(format!(
            "qualification-evidence-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let path = dir.join("report.json");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
