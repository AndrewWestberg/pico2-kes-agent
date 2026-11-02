//! Existing CLI lifecycle receipt orchestration.

use crate::{cli, files};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const OUTPUT_LIMIT: usize = 64 * 1024;
const REFERENCE_LIMIT: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthority {
    pub socket: PathBuf,
    pub pid: u32,
    pub uid: u32,
    pub identity: AuthorityIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AuthorityIdentity {
    Normal {
        device_id: String,
        identity_public_key: String,
    },
    Commissioning {
        serial: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    version: u8,
    caller_uid: u32,
    created: u64,
    authority: PeerAuthority,
}

const ADMISSION_DIR: &str = "/run/p2kesup/lifecycle";

fn now() -> io::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}
fn admission_id(id: &str) -> io::Result<()> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid admission ID",
        ));
    }
    Ok(())
}
fn root_directory(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe lifecycle authority directory",
        ));
    }
    Ok(())
}
fn valid_authority(a: &PeerAuthority) -> io::Result<()> {
    let hex = |s: &str, n| s.len() == n && s.bytes().all(|c| c.is_ascii_hexdigit());
    let identity_valid = match &a.identity {
        AuthorityIdentity::Normal {
            device_id,
            identity_public_key,
        } => hex(device_id, 32) && hex(identity_public_key, 64),
        AuthorityIdentity::Commissioning { serial } => {
            serial.len() == 16
                && serial
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
    };
    if !a.socket.is_absolute() || a.pid == 0 || !identity_valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid authenticated daemon authority",
        ));
    }
    Ok(())
}

/// Root-only finite admission; the caller UID is authenticated by the host entrypoint.
pub fn admit(id: &str, caller_uid: u32, commissioning_serial: Option<&str>) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root required",
        ));
    }
    admission_id(id)?;
    let authority = match commissioning_serial {
        Some(serial) => super::host::commissioning_authority(serial)?,
        None => super::host::lifecycle_authority()?,
    };
    if !authority_matches(&authority, commissioning_serial) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon authority mode or serial differs from admission",
        ));
    }
    valid_authority(&authority)?;
    root_directory(Path::new("/run"))?;
    for path in [Path::new("/run/p2kesup"), Path::new(ADMISSION_DIR)] {
        match std::fs::DirBuilder::new().mode(0o755).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        root_directory(path)?;
    }
    let current = now()?;
    let mut entries = 0usize;
    for entry in std::fs::read_dir(ADMISSION_DIR)? {
        let entry = entry?;
        entries += 1;
        if entries > 4096 {
            return Err(io::Error::other(
                "lifecycle admission directory capacity exceeded",
            ));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        if admission_id(name).is_err() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mtime() >= 0
            && current.saturating_sub(metadata.mtime() as u64) > 300
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    let record = Admission {
        version: 2,
        caller_uid,
        created: now()?,
        authority,
    };
    files::publish_no_clobber(
        &Path::new(ADMISSION_DIR).join(format!("{id}.json")),
        &serde_json::to_vec(&record).map_err(io::Error::other)?,
        0o644,
    )
}

pub(crate) fn admitted(id: &str) -> io::Result<PeerAuthority> {
    use std::os::unix::fs::OpenOptionsExt;
    admission_id(id)?;
    for path in ["/run", "/run/p2kesup", ADMISSION_DIR] {
        root_directory(Path::new(path))?;
    }
    let path = Path::new(ADMISSION_DIR).join(format!("{id}.json"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > 16384 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe lifecycle admission record",
        ));
    }
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized lifecycle admission record",
        ));
    }
    let record: Admission = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let current = now()?;
    if record.version != 2
        || record.caller_uid != rustix::process::geteuid().as_raw()
        || record.created > current
        || current - record.created > 120
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "expired or wrong-user lifecycle admission",
        ));
    }
    valid_authority(&record.authority)?;
    Ok(record.authority)
}

pub(crate) fn authority_matches(authority: &PeerAuthority, serial: Option<&str>) -> bool {
    match (&authority.identity, serial) {
        (AuthorityIdentity::Normal { .. }, None) => true,
        (AuthorityIdentity::Commissioning { serial: actual }, Some(expected)) => actual == expected,
        _ => false,
    }
}

pub(crate) fn receipt_commissioning_serial(
    receipt: &cli::receipt::PublicReceipt,
) -> io::Result<Option<&str>> {
    if receipt.request["action"] != "device.commission" {
        return Ok(None);
    }
    let serial = receipt.request["arguments"]["usb_serial"]
        .as_str()
        .filter(|s| {
            s.len() == 16
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid commissioning receipt serial",
            )
        })?;
    Ok(Some(serial))
}

/// Only the authenticated host/distribution authority may supply this path.
/// This does not grant privilege or authenticate an executable by itself.
#[derive(Clone)]
pub struct TrustedCli(PathBuf, Option<(u32, u32)>);

impl TrustedCli {
    pub(crate) fn from_authenticated_host(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CLI path must be absolute",
            ));
        }
        Ok(Self(path, None))
    }

    pub(crate) fn command(&self) -> Command {
        Command::new(&self.0)
    }

    pub(crate) fn bind_peer(mut self, authority: &PeerAuthority) -> Self {
        self.1 = Some((authority.pid, authority.uid));
        self
    }

    fn socket_args(&self, socket: &str) -> Vec<String> {
        let mut args = vec!["--socket".into(), socket.into(), "--json".into()];
        if let Some((pid, uid)) = self.1 {
            args.extend([
                "--expected-peer-pid".into(),
                pid.to_string(),
                "--expected-peer-uid".into(),
                uid.to_string(),
            ]);
        }
        args
    }
}

/// Public mutation inputs only; private backup operations cannot be captured here.
pub enum Mutation {
    Commission {
        usb_serial: String,
        out: String,
    },
    Enroll {
        cold_vkey: String,
        network: String,
    },
    Delete {
        pool: String,
        incarnation: String,
    },
    Generate {
        pool: String,
        incarnation: String,
    },
    Discard {
        pool: String,
        incarnation: String,
        generation: String,
    },
    InstallCertificate {
        pool: String,
        incarnation: String,
        generation: String,
        certificate: String,
    },
    SetRecipient {
        public_key: String,
    },
}

impl Mutation {
    fn arguments(self) -> Vec<String> {
        let strings = |values: &[&str]| values.iter().map(|s| (*s).to_owned()).collect();
        match self {
            Self::Commission { usb_serial, out } => strings(&[
                "device",
                "commission",
                "--usb-serial",
                &usb_serial,
                "--out",
                &out,
            ]),
            Self::Enroll { cold_vkey, network } => strings(&[
                "pool",
                "enroll",
                "--cold-vkey",
                &cold_vkey,
                "--network",
                &network,
            ]),
            Self::Delete { pool, incarnation } => strings(&[
                "pool",
                "delete",
                "--pool",
                &pool,
                "--incarnation",
                &incarnation,
                "--yes",
            ]),
            Self::Generate { pool, incarnation } => strings(&[
                "key",
                "generate",
                "--pool",
                &pool,
                "--incarnation",
                &incarnation,
            ]),
            Self::Discard {
                pool,
                incarnation,
                generation,
            } => strings(&[
                "key",
                "discard",
                "--pool",
                &pool,
                "--incarnation",
                &incarnation,
                "--generation",
                &generation,
                "--yes",
            ]),
            Self::InstallCertificate {
                pool,
                incarnation,
                generation,
                certificate,
            } => strings(&[
                "certificate",
                "install",
                "--pool",
                &pool,
                "--incarnation",
                &incarnation,
                "--generation",
                &generation,
                "--certificate",
                &certificate,
            ]),
            Self::SetRecipient { public_key } => {
                strings(&["recipient", "set", "--public-key", &public_key])
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitClass {
    Success,
    Invocation,
    Permission,
    Unavailable,
    Rejected,
    Uncertain,
    Failure,
}

impl ExitClass {
    fn from_code(code: Option<i32>) -> Self {
        match code {
            Some(cli::EXIT_SUCCESS) => Self::Success,
            Some(cli::EXIT_INVOCATION) => Self::Invocation,
            Some(cli::EXIT_PERMISSION) => Self::Permission,
            Some(cli::EXIT_UNAVAILABLE) => Self::Unavailable,
            Some(cli::EXIT_REJECTED) => Self::Rejected,
            Some(cli::EXIT_UNCERTAIN) => Self::Uncertain,
            _ => Self::Failure,
        }
    }
}

pub struct Outcome {
    pub class: ExitClass,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
    /// None means no receipt was found; an unreadable receipt is an error.
    pub receipt: Option<cli::receipt::PublicReceipt>,
    /// A child interruption or missing final evidence must not be treated as success.
    pub uncertain: bool,
    /// Durable reconciliation evidence, separate from the original receipt.
    pub reconciliation_evidence: Option<PathBuf>,
    pub reconciliation_evidence_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    version: u8,
    receipt: PathBuf,
}

fn absolute_utf8(path: &Path) -> io::Result<&str> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        ));
    }
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path must be UTF-8"))
}

/// Durably record the exact future receipt path before starting the CLI.
pub fn retain_reference(reference: &Path, receipt: &Path) -> io::Result<()> {
    absolute_utf8(reference)?;
    absolute_utf8(receipt)?;
    if reference == receipt {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reference and receipt paths must differ",
        ));
    }
    match std::fs::symlink_metadata(receipt) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "receipt path already exists",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let bytes = serde_json::to_vec(&Reference {
        version: 1,
        receipt: receipt.to_owned(),
    })
    .map_err(io::Error::other)?;
    if bytes.len() as u64 > REFERENCE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "receipt reference too large",
        ));
    }
    files::publish_no_clobber(reference, &bytes, 0o600)
}

pub fn load_reference(reference: &Path) -> io::Result<PathBuf> {
    let file = files::open_owner_controlled_file(reference)?;
    let meta = file.metadata()?;
    if meta.mode() & 0o077 != 0 || meta.len() > REFERENCE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe or oversized receipt reference",
        ));
    }
    let mut bytes = Vec::new();
    file.take(REFERENCE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > REFERENCE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt reference too large",
        ));
    }
    let reference: Reference = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if reference.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown receipt reference schema",
        ));
    }
    absolute_utf8(&reference.receipt)?;
    Ok(reference.receipt)
}

pub fn load_public_receipt(path: &Path) -> io::Result<cli::receipt::PublicReceipt> {
    let receipt = cli::receipt::load(path)?;
    if receipt.version != 1
        || !matches!(
            receipt
                .request
                .get("action")
                .and_then(serde_json::Value::as_str),
            Some(
                "device.commission"
                    | "pool.enroll"
                    | "pool.delete"
                    | "generation.create"
                    | "generation.discard"
                    | "generation.certificate"
                    | "recipient.set"
            )
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported public receipt",
        ));
    }
    Ok(receipt)
}

fn reconcile_arguments(receipt: &Path, out: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "operation".into(),
        "reconcile".into(),
        "--receipt".into(),
        receipt.to_str().expect("validated receipt path").into(),
    ];
    if let Some(out) = out {
        args.extend(["--out".into(), out.into()]);
    }
    args
}

/// Submit exactly once. If this returns an error, reopen the reference; never
/// repeat submission under a new identity.
pub fn submit(
    cli: &TrustedCli,
    socket: &Path,
    reference: &Path,
    receipt: &Path,
    revision: u64,
    mutation: Mutation,
) -> io::Result<Outcome> {
    let socket = absolute_utf8(socket)?;
    let receipt_arg = absolute_utf8(receipt)?;
    let mut args = mutation.arguments();
    args.extend([
        "--expected-revision".into(),
        revision.to_string(),
        "--receipt".into(),
        receipt_arg.into(),
    ]);
    retain_reference(reference, receipt)?;
    run(cli, socket, args, receipt)
}

/// Reconciliation always uses the saved CLI receipt, including its original ID.
/// `out` is needed only for a commissioned public enrollment record.
pub fn reconcile(
    cli: &TrustedCli,
    socket: &Path,
    reference: &Path,
    out: Option<&str>,
) -> io::Result<Outcome> {
    let receipt = load_reference(reference)?;
    let saved = load_public_receipt(&receipt)?;
    if out.is_some()
        && saved
            .request
            .get("action")
            .and_then(serde_json::Value::as_str)
            != Some("device.commission")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output is only valid for commissioning",
        ));
    }
    run(
        cli,
        absolute_utf8(socket)?,
        reconcile_arguments(&receipt, out),
        &receipt,
    )
}

/// The exact reference and request presented to the operator.
pub struct ReviewedReceipt {
    reference: PathBuf,
    receipt_path: PathBuf,
    pub receipt: cli::receipt::PublicReceipt,
}

pub fn review_receipt(reference: &Path) -> io::Result<ReviewedReceipt> {
    let receipt_path = load_reference(reference)?;
    let receipt = load_public_receipt(&receipt_path)?;
    Ok(ReviewedReceipt {
        reference: reference.to_owned(),
        receipt_path,
        receipt,
    })
}

fn random_hex() -> io::Result<String> {
    use std::fmt::Write;
    let mut random = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut text = String::with_capacity(32);
    for byte in random {
        write!(&mut text, "{byte:02x}").expect("string formatting");
    }
    Ok(text)
}

pub(crate) fn new_admission_id() -> io::Result<String> {
    random_hex()
}

/// Reconcile only the reviewed request, using a private snapshot so a path swap
/// cannot substitute a different operation while the child opens the receipt.
pub fn reconcile_reviewed(
    cli: &TrustedCli,
    socket: &Path,
    reviewed: ReviewedReceipt,
    out: Option<&str>,
) -> io::Result<Outcome> {
    use std::os::unix::fs::DirBuilderExt;
    if load_reference(&reviewed.reference)? != reviewed.receipt_path
        || load_public_receipt(&reviewed.receipt_path)? != reviewed.receipt
    {
        return Err(io::Error::other(
            "reference or receipt changed; confirmation expired",
        ));
    }
    if out.is_some() && reviewed.receipt.request["action"] != "device.commission" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output is only valid for commissioning",
        ));
    }
    let directory = std::env::temp_dir().join(format!("p2kesup-reconcile-{}", random_hex()?));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("receipt.json"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let temporary = Temporary(directory);
    let copy = temporary.0.join("receipt.json");
    files::publish_no_clobber(
        &copy,
        &serde_json::to_vec(&reviewed.receipt).map_err(io::Error::other)?,
        0o600,
    )?;
    let mut outcome = run(
        cli,
        absolute_utf8(socket)?,
        reconcile_arguments(&copy, out),
        &copy,
    )?;
    if !outcome.stdout.is_empty() && !outcome.output_truncated {
        let response: serde_json::Value =
            serde_json::from_slice(&outcome.stdout).map_err(|_| {
                io::Error::other("invalid reconciliation result; retain original receipt")
            })?;
        let evidence = serde_json::json!({"version":1,"reference":reviewed.reference,"receipt_path":reviewed.receipt_path,
            "request":reviewed.receipt.request,"response":response,"exit_class":format!("{:?}",outcome.class)});
        let path = PathBuf::from(format!(
            "{}.reconcile-{}.json",
            reviewed.reference.display(),
            random_hex()?
        ));
        match files::publish_no_clobber(
            &path,
            &serde_json::to_vec_pretty(&evidence).map_err(io::Error::other)?,
            0o600,
        ) {
            Ok(()) => outcome.reconciliation_evidence = Some(path),
            Err(error) => {
                outcome.reconciliation_evidence_error = Some(format!("{}: {error}", path.display()))
            }
        }
        outcome.uncertain = outcome.class == ExitClass::Uncertain
            || !matches!(response["outcome"].as_str(), Some("success" | "rejected"));
    }
    Ok(outcome)
}

fn fixed_hex<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::other("invalid public binding"));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| io::Error::other("invalid public binding"))?;
    }
    Ok(out)
}

/// Authenticate the artifact against the enrolled device pin and target.
pub fn artifact_recipient(
    cli: &TrustedCli,
    authority: &PeerAuthority,
    pool: &str,
    incarnation: &str,
    generation: &str,
    artifact: &[u8],
) -> io::Result<[u8; 32]> {
    let AuthorityIdentity::Normal {
        device_id,
        identity_public_key,
    } = &authority.identity
    else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "normal daemon authority required",
        ));
    };
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!("p2kesup-vkey-{}", random_hex()?));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("vkey"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let temp = Temporary(directory);
    let output = temp.0.join("vkey");
    let args = vec![
        "key".into(),
        "verification-key".into(),
        "--pool".into(),
        pool.into(),
        "--incarnation".into(),
        incarnation.into(),
        "--generation".into(),
        generation.into(),
        "--out".into(),
        absolute_utf8(&output)?.into(),
    ];
    let (class, result) = public_command(cli, &authority.socket, &args)?;
    if class != ExitClass::Success {
        return Err(io::Error::other(
            "verification key unavailable for artifact authentication",
        ));
    }
    let verification_key = result["result"]["verification_key"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing public verification key"))?;
    let expected = crate::backup::recover::Expectations {
        device: fixed_hex(device_id)?,
        pool: fixed_hex(pool)?,
        incarnation: fixed_hex(incarnation)?,
        generation: fixed_hex(generation)?,
        verification_key: fixed_hex(verification_key)?,
        identity_public_key: fixed_hex(identity_public_key)?,
    };
    crate::backup::recover::artifact_recipient(artifact, expected)
        .map_err(|_| io::Error::other("artifact signature or public binding rejected"))
}

fn capture(mut input: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let keep = n.min(OUTPUT_LIMIT.saturating_sub(captured.len()));
        captured.extend_from_slice(&buffer[..keep]);
        truncated |= keep != n;
    }
    Ok((captured, truncated))
}

fn run(
    cli: &TrustedCli,
    socket: &str,
    args: Vec<String>,
    receipt_path: &Path,
) -> io::Result<Outcome> {
    let mut child = cli
        .command()
        .args(cli.socket_args(socket))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out_thread = std::thread::spawn(move || capture(stdout));
    let err_thread = std::thread::spawn(move || capture(stderr));
    let status = child.wait();
    let out = out_thread
        .join()
        .map_err(|_| io::Error::other("stdout reader failed"))?;
    let err = err_thread
        .join()
        .map_err(|_| io::Error::other("stderr reader failed"))?;
    let status = status?;
    let (stdout, out_truncated) = out?;
    let (stderr, err_truncated) = err?;
    let receipt = match load_public_receipt(receipt_path) {
        Ok(receipt) => Some(receipt),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let class = ExitClass::from_code(status.code());
    let uncertain = status.code().is_none()
        || class == ExitClass::Uncertain
        || receipt.as_ref().is_some_and(|r| r.response.is_none())
        || receipt
            .as_ref()
            .and_then(|r| r.response.as_ref())
            .is_some_and(|r| matches!(r["outcome"].as_str(), Some("pending" | "uncertain")))
        || (class == ExitClass::Success && receipt.is_none());
    Ok(Outcome {
        class,
        stdout,
        stderr,
        output_truncated: out_truncated || err_truncated,
        receipt,
        uncertain,
        reconciliation_evidence: None,
        reconciliation_evidence_error: None,
    })
}

/// Read an existing CLI observation or export; no mutation identity is minted.
pub fn public_command(
    cli: &TrustedCli,
    socket: &Path,
    args: &[String],
) -> io::Result<(ExitClass, serde_json::Value)> {
    let mut child = cli
        .command()
        .args(cli.socket_args(absolute_utf8(socket)?))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out = std::thread::spawn(move || capture(stdout));
    let err = std::thread::spawn(move || capture(stderr));
    let status = child.wait()?;
    let (bytes, truncated) = out
        .join()
        .map_err(|_| io::Error::other("stdout reader failed"))??;
    let (_, err_truncated) = err
        .join()
        .map_err(|_| io::Error::other("stderr reader failed"))??;
    if truncated || err_truncated {
        return Err(io::Error::other("CLI output exceeded public limit"));
    }
    let class = ExitClass::from_code(status.code());
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|_| io::Error::other("invalid structured CLI result"))?
    };
    Ok((class, value))
}

/// Read complete device membership and the consistent paginated host binding view.
pub fn observations(
    cli: &TrustedCli,
    socket: &Path,
    target: Option<(&str, &str)>,
    cancelled: &std::sync::atomic::AtomicBool,
) -> io::Result<serde_json::Value> {
    let call = |args: &[&str]| -> io::Result<serde_json::Value> {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "observation cancelled before submission",
            ));
        }
        let args = args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let (class, response) = public_command(cli, socket, &args)?;
        if class != ExitClass::Success || response["outcome"] != "success" {
            return Err(io::Error::other(format!(
                "observation unavailable: {class:?}"
            )));
        }
        Ok(response["result"].clone())
    };
    let info = call(&["device", "info"])?;
    let status = call(&["status"])?;
    let inventory = call(&["device", "inventory"])?;
    let members = inventory["pools"]
        .as_array()
        .ok_or_else(|| io::Error::other("incomplete device inventory"))?;
    if members.len() > 64
        || info["device_id"].as_str().is_none()
        || inventory["device_id"] != info["device_id"]
        || status["device_id"] != info["device_id"]
        || status["revision"].as_u64().is_none()
        || inventory["revision"].as_u64().is_none()
    {
        return Err(io::Error::other("invalid or mismatched device inventory"));
    }
    let mut seen = std::collections::HashSet::new();
    for member in members {
        let pool = member["pool_id"]
            .as_str()
            .ok_or_else(|| io::Error::other("missing inventory pool"))?;
        let incarnation = member["incarnation_id"]
            .as_str()
            .ok_or_else(|| io::Error::other("missing inventory incarnation"))?;
        if member["revision"].as_u64().is_none() || !seen.insert((pool, incarnation)) {
            return Err(io::Error::other("duplicate or invalid inventory target"));
        }
    }
    let mut bindings = Vec::new();
    let mut cursor = None::<String>;
    let mut snapshot = None::<String>;
    let mut total = None::<u64>;
    loop {
        let mut args = vec!["host", "observe", "--page-size", "16"];
        if let Some(id) = &snapshot {
            args.extend(["--snapshot-id", id]);
        }
        if let Some(next) = &cursor {
            args.extend(["--cursor", next]);
        }
        let page = call(&args)?;
        let id = page["snapshot_id"]
            .as_str()
            .ok_or_else(|| io::Error::other("missing host snapshot"))?;
        let count = page["total"]
            .as_u64()
            .filter(|n| *n <= 128)
            .ok_or_else(|| io::Error::other("invalid host binding total"))?;
        if snapshot.as_deref().is_some_and(|old| old != id) || total.is_some_and(|old| old != count)
        {
            return Err(io::Error::other("host binding snapshot changed"));
        }
        snapshot = Some(id.to_owned());
        total = Some(count);
        let entries = page["bindings"]
            .as_array()
            .ok_or_else(|| io::Error::other("missing host bindings"))?;
        if entries.len() > 16 || bindings.len() + entries.len() > count as usize {
            return Err(io::Error::other("invalid host page"));
        }
        bindings.extend(entries.iter().cloned());
        match &page["next_cursor"] {
            serde_json::Value::Null if bindings.len() == count as usize => break,
            serde_json::Value::String(next)
                if !next.is_empty() && cursor.as_ref() != Some(next) && !entries.is_empty() =>
            {
                cursor = Some(next.clone())
            }
            _ => return Err(io::Error::other("incomplete host bindings")),
        }
    }
    let pool = match target {
        Some((pool, incarnation)) => {
            let member = members
                .iter()
                .find(|m| m["pool_id"] == pool && m["incarnation_id"] == incarnation)
                .ok_or_else(|| {
                    io::Error::other("exact pool incarnation is absent from device inventory")
                })?;
            let p = call(&[
                "pool",
                "observe",
                "--pool",
                pool,
                "--incarnation",
                incarnation,
            ])?;
            if p["pool_id"] != pool
                || p["incarnation_id"] != incarnation
                || p["device_id"] != info["device_id"]
                || p["revision"] != member["revision"]
                || !p["failure"].is_null()
            {
                return Err(io::Error::other(
                    "pool observation does not match exact target",
                ));
            }
            Some(p)
        }
        None => None,
    };
    if call(&["device", "inventory"])? != inventory {
        return Err(io::Error::other(
            "device inventory changed during observation",
        ));
    }
    let host_check = call(&[
        "host",
        "observe",
        "--page-size",
        "1",
        "--snapshot-id",
        snapshot.as_deref().expect("host page"),
    ])?;
    if host_check["snapshot_id"].as_str() != snapshot.as_deref()
        || call(&["status"])?["revision"] != status["revision"]
    {
        return Err(io::Error::other(
            "host or device revision changed during observation",
        ));
    }
    Ok(
        serde_json::json!({"device":info,"status":status,"inventory":inventory,"host_snapshot":snapshot,"bindings":bindings,"pool":pool}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn authority_mode_and_original_receipt_serial_are_bound() {
        let mut authority = PeerAuthority {
            socket: "/run/pico2-kes-agent/management.sock".into(),
            pid: 1,
            uid: 2,
            identity: AuthorityIdentity::Commissioning {
                serial: "0123456789abcdef".into(),
            },
        };
        assert!(valid_authority(&authority).is_ok());
        assert!(authority_matches(&authority, Some("0123456789abcdef")));
        assert!(!authority_matches(&authority, Some("fedcba9876543210")));
        assert!(!authority_matches(&authority, None));
        let mut receipt = cli::receipt::PublicReceipt {
            version: 1,
            request: json!({"action":"device.commission","arguments":{"usb_serial":"0123456789abcdef"}}),
            response: None,
        };
        assert_eq!(
            receipt_commissioning_serial(&receipt).unwrap(),
            Some("0123456789abcdef")
        );
        receipt.request["arguments"]["usb_serial"] = "wrong".into();
        assert!(receipt_commissioning_serial(&receipt).is_err());
        receipt.request["action"] = "generation.create".into();
        assert_eq!(receipt_commissioning_serial(&receipt).unwrap(), None);
        authority.identity = AuthorityIdentity::Normal {
            device_id: "11".repeat(16),
            identity_public_key: "22".repeat(32),
        };
        assert!(valid_authority(&authority).is_ok());
        assert!(authority_matches(&authority, None));
        assert!(!authority_matches(&authority, Some("0123456789abcdef")));
    }

    #[test]
    fn interrupted_submission_reopens_original_receipt() {
        let dir = std::env::temp_dir().join(format!(
            "p2kes-lifecycle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reference = dir.join("reference.json");
        let receipt = dir.join("receipt.json");
        retain_reference(&reference, &receipt).unwrap();
        let socket = dir.join("management.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let read_request = |stream: &mut std::os::unix::net::UnixStream| {
                let mut header = [0; 4];
                stream.read_exact(&mut header).unwrap();
                let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
                stream.read_exact(&mut bytes).unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            };
            let (mut first, _) = listener.accept().unwrap();
            let original = read_request(&mut first);
            drop(first);
            let (mut second, _) = listener.accept().unwrap();
            let retried = read_request(&mut second);
            assert_eq!(retried, original);
            let response = serde_json::to_vec(&json!({
                "version": 1, "request_id": original["request_id"], "outcome": "success",
                "result": { "kind": "applied", "revision": 18 }, "error": null
            }))
            .unwrap();
            second
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            second.write_all(&response).unwrap();
            original
        });
        let mut args = vec![
            "--socket".to_owned(),
            socket.to_str().unwrap().into(),
            "--json".into(),
        ];
        args.extend(
            Mutation::Generate {
                pool: "11".repeat(28),
                incarnation: "22".repeat(16),
            }
            .arguments(),
        );
        args.extend([
            "--expected-revision".into(),
            "17".into(),
            "--receipt".into(),
            receipt.to_str().unwrap().into(),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            cli::run(&args, &mut stdout, &mut stderr),
            cli::EXIT_UNCERTAIN
        );
        let reopened = load_reference(&reference).unwrap();
        assert_eq!(reopened, receipt);
        let original = load_public_receipt(&reopened).unwrap();
        assert!(original.response.is_none());
        let mut reconcile = vec![
            "--socket".to_owned(),
            socket.to_str().unwrap().into(),
            "--json".into(),
        ];
        reconcile.extend(reconcile_arguments(&reopened, None));
        assert_eq!(
            cli::run(&reconcile, &mut stdout, &mut stderr),
            cli::EXIT_SUCCESS
        );
        assert_eq!(server.join().unwrap(), original.request);
        assert_eq!(
            load_public_receipt(&receipt).unwrap().request,
            original.request
        );
        assert!(retain_reference(&reference, &dir.join("replacement.json")).is_err());
        assert_eq!(load_reference(&reference).unwrap(), receipt);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconciliation_rejects_a_replaced_reviewed_receipt_before_spawning() {
        let dir = std::env::temp_dir().join(format!(
            "p2kes-reviewed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reference = dir.join("reference");
        let receipt = dir.join("receipt");
        retain_reference(&reference, &receipt).unwrap();
        cli::receipt::create(
            &receipt,
            json!({"action":"generation.create", "operation_id":"11".repeat(16)}),
        )
        .unwrap();
        let reviewed = review_receipt(&reference).unwrap();
        let mut changed = cli::receipt::load(&receipt).unwrap();
        changed.request["operation_id"] = "22".repeat(16).into();
        std::fs::write(&receipt, serde_json::to_vec(&changed).unwrap()).unwrap();
        let cli = TrustedCli::from_authenticated_host("/nonexistent/cli".into()).unwrap();
        let error = reconcile_reviewed(&cli, &dir.join("socket"), reviewed, None)
            .err()
            .unwrap();
        assert!(error.to_string().contains("confirmation expired"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn digest_reconciliation_retains_the_actual_result_without_replacing_receipt() {
        let dir = std::env::temp_dir().join(format!(
            "p2kes-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reference = dir.join("reference");
        let receipt = dir.join("receipt");
        retain_reference(&reference, &receipt).unwrap();
        cli::receipt::create(
            &receipt,
            json!({"action":"generation.create","operation_id":"11".repeat(16)}),
        )
        .unwrap();
        cli::receipt::update(
            &receipt,
            json!({"outcome":"uncertain","error":{"request_digest":"22".repeat(32)}}),
        )
        .unwrap();
        let original = cli::receipt::load(&receipt).unwrap();
        let script = dir.join("cli");
        std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' '{\"outcome\":\"success\",\"result\":{\"kind\":\"generated\"}}'\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let trusted = TrustedCli::from_authenticated_host(script).unwrap();
        let outcome = reconcile_reviewed(
            &trusted,
            &dir.join("socket"),
            review_receipt(&reference).unwrap(),
            None,
        )
        .unwrap();
        assert!(!outcome.uncertain);
        let evidence: serde_json::Value = serde_json::from_slice(
            &std::fs::read(outcome.reconciliation_evidence.unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(evidence["request"], original.request);
        assert_eq!(evidence["response"]["result"]["kind"], "generated");
        assert_eq!(cli::receipt::load(&receipt).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
