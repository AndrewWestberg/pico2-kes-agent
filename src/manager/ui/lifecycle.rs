use super::{
    review,
    widgets::{ConfirmMode, FieldSpec, pick_file, review_mode},
};
use crate::manager::{
    discovery::files::FileKind,
    host,
    lifecycle::{self, Mutation},
    observe::{Snapshot, Worker},
    terminal::TerminalOwner,
    workspace::{self, WorkspaceKind},
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Enroll,
    Delete,
    Generate,
    Discard,
    VerificationKey,
    Artifact,
    Certificate,
    Recipient,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (Action::Delete, "Delete pool"),
    (Action::Discard, "Discard staged key"),
    (Action::Artifact, "Export backup again"),
    (Action::Recipient, "Change backup encryption key"),
];

impl Action {
    fn stem(self) -> &'static str {
        match self {
            Self::Enroll => "pool-enroll",
            Self::Delete => "pool-delete",
            Self::Generate => "key-generate",
            Self::Discard => "key-discard",
            Self::VerificationKey => "export-vkey",
            Self::Artifact => "export-backup",
            Self::Certificate => "cert-install",
            Self::Recipient => "recipient-set",
        }
    }
}

fn progress<T: Send + 'static>(
    terminal: &mut TerminalOwner,
    label: &str,
    cancellable: bool,
    work: impl FnOnce(Arc<AtomicBool>) -> io::Result<T> + Send + 'static,
) -> io::Result<Option<T>> {
    let (tx, rx) = mpsc::sync_channel(1);
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    std::thread::spawn(move || {
        let _ = tx.send(work(worker_stop));
    });
    let mut cancelled = false;
    let mut terminal_error = None;
    loop {
        if terminal_error.is_none() {
            let draw = terminal.terminal().and_then(|terminal| {
                terminal
                    .draw(|frame| {
                        let message = if cancelled {
                            "Cancellation requested; waiting for the current read to finish. No mutation will be submitted."
                        } else if cancellable {
                            "Working; Esc cancels after the current read finishes, before submission."
                        } else {
                            "Working; if submitted, this operation cannot be cancelled. Waiting for its original result."
                        };
                        frame.render_widget(
                            Paragraph::new(message)
                                .wrap(Wrap { trim: false })
                                .block(Block::default().borders(Borders::ALL).title(label)),
                            frame.area(),
                        );
                    })
                    .map(|_| ())
            });
            if let Err(error) = draw {
                terminal_error = Some(error);
            }
        }
        match rx.try_recv() {
            Ok(result) => {
                if let Some(error) = terminal_error {
                    return Err(error);
                }
                return if cancelled {
                    Ok(None)
                } else {
                    result.map(Some)
                };
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::other("lifecycle worker stopped unexpectedly"));
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if terminal_error.is_some() {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key))
                    if cancellable
                        && key.kind != KeyEventKind::Release
                        && matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) =>
                {
                    cancelled = true;
                    stop.store(true, Ordering::Relaxed);
                }
                Ok(_) => {}
                Err(error) => terminal_error = Some(error),
            },
            Ok(false) => {}
            Err(error) => terminal_error = Some(error),
        }
    }
}

pub(super) fn admission(
    terminal: &mut TerminalOwner,
    socket: &Path,
    serial: Option<&str>,
) -> io::Result<lifecycle::PeerAuthority> {
    let id = lifecycle::new_admission_id()?;
    let executable = host::trusted_manager()?;
    let mut command = if rustix::process::geteuid().is_root() {
        Command::new(executable)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("--").arg(executable);
        command
    };
    command.args(["host-lifecycle-admit", "--id", &id]);
    if let Some(serial) = serial {
        command.args(["--commissioning-serial", serial]);
    }
    if !terminal.foreground(&mut command, false)?.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host lifecycle admission failed",
        ));
    }
    let authority = lifecycle::admitted(&id)?;
    if authority.socket != socket || !lifecycle::authority_matches(&authority, serial) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "selected socket or daemon mode differs from approved authority",
        ));
    }
    Ok(authority)
}

pub(crate) fn observe(
    terminal: &mut TerminalOwner,
    cli: &lifecycle::TrustedCli,
    authority: &lifecycle::PeerAuthority,
    target: Option<(&str, &str)>,
) -> io::Result<Option<Value>> {
    let cli = cli.clone();
    let authority = authority.clone();
    let target = target.map(|(a, b)| (a.to_owned(), b.to_owned()));
    progress(
        terminal,
        "Reading authoritative lifecycle state",
        true,
        move |stop| {
            let value = lifecycle::observations(
                &cli,
                &authority.socket,
                target.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
                &stop,
            )?;
            if !matches!(&authority.identity, lifecycle::AuthorityIdentity::Normal { device_id, .. } if value["device"]["device_id"] == *device_id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "device does not match approved identity pin",
                ));
            }
            Ok(value)
        },
    )
}

fn lines(value: &Value) -> io::Result<Vec<String>> {
    Ok(serde_json::to_string_pretty(value)
        .map_err(io::Error::other)?
        .lines()
        .map(str::to_owned)
        .collect())
}

struct PublicInput {
    directory: PathBuf,
    path: String,
    digest: String,
}
impl PublicInput {
    fn copy(source: &str) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut bytes = Vec::new();
        crate::files::open_owner_controlled_file(Path::new(source))?
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(io::Error::other("public input exceeds 64 KiB"));
        }
        let directory = loop {
            let candidate = std::env::temp_dir().join(format!(
                "p2kesup-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => break candidate,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        };
        let path = directory.join("input");
        if let Err(error) = crate::files::publish_no_clobber(&path, &bytes, 0o600) {
            let _ = std::fs::remove_dir(&directory);
            return Err(error);
        }
        let path = path
            .to_str()
            .ok_or_else(|| io::Error::other("temporary path is not UTF-8"))?
            .to_owned();
        Ok(Self {
            directory,
            path,
            digest: format!("{:x}", Sha256::digest(&bytes)),
        })
    }
}
impl Drop for PublicInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn absolute(path: &str) -> io::Result<()> {
    if !Path::new(path).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        ));
    }
    Ok(())
}

fn enrolled_target_from_outcome(result: &lifecycle::Outcome) -> Option<(String, String)> {
    let from_val = |v: &Value| -> Option<(String, String)> {
        let res = v.get("result")?;
        if res.get("kind").and_then(Value::as_str) != Some("enrolled") {
            return None;
        }
        Some((
            res.get("pool_id")?.as_str()?.to_owned(),
            res.get("incarnation_id")?.as_str()?.to_owned(),
        ))
    };
    if let Some(receipt) = &result.receipt
        && let Some(resp) = &receipt.response
        && let Some(pair) = from_val(resp)
    {
        return Some(pair);
    }
    if !result.stdout.is_empty()
        && !result.output_truncated
        && let Ok(resp) = serde_json::from_slice::<Value>(&result.stdout)
    {
        return from_val(&resp);
    }
    None
}
#[derive(Debug)]
pub(super) struct MissingRecipient;

impl std::fmt::Display for MissingRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Device rejected generation because no backup recipient is configured")
    }
}

impl std::error::Error for MissingRecipient {}

fn missing_recipient_rejection(result: &lifecycle::Outcome) -> bool {
    if result.class != lifecycle::ExitClass::Rejected || result.uncertain {
        return false;
    }
    let Some(receipt) = &result.receipt else {
        return false;
    };
    let Some(response) = &receipt.response else {
        return false;
    };
    let request = &receipt.request;
    request["action"] == "generation.create"
        && request["request_id"].as_str().is_some()
        && request["operation_id"].as_str().is_some()
        && response["request_id"] == request["request_id"]
        && response["outcome"] == "rejected"
        && response["error"]["code"] == "recipient_mismatch"
        && response["error"]["operation_id"] == request["operation_id"]
}

fn outcome(
    terminal: &mut TerminalOwner,
    result: lifecycle::Outcome,
    reference: &Path,
) -> io::Result<(bool, Option<(String, String)>)> {
    let enrolled = if result.class == lifecycle::ExitClass::Success && !result.uncertain {
        enrolled_target_from_outcome(&result)
    } else {
        None
    };
    let mut text = vec![
        format!(
            "CLI exit class: {:?}; uncertain: {}",
            result.class, result.uncertain
        ),
        format!("Retained reference: {}", reference.display()),
        "Never submit a replacement operation for an uncertain or interrupted result. Reopen the original receipt in Activity (6)."
            .into(),
    ];
    if let Some(path) = &result.reconciliation_evidence {
        text.push(format!(
            "Reconciliation evidence retained at {}",
            path.display()
        ));
    }
    if let Some(error) = &result.reconciliation_evidence_error {
        text.push(format!(
            "Reconciliation evidence could not be retained: {error}; record the actual response shown below."
        ));
    }
    if !result.stdout.is_empty()
        && !result.output_truncated
        && let Ok(response) = serde_json::from_slice::<Value>(&result.stdout)
    {
        text.push(String::new());
        text.push("CLI response:".into());
        text.extend(lines(&response)?);
    }
    if let Some(receipt) = result.receipt {
        text.push(String::new());
        text.push("Durable receipt:".into());
        text.extend(lines(
            &serde_json::to_value(receipt).map_err(io::Error::other)?,
        )?);
    } else {
        text.push(
            "No readable receipt was found; inspect the retained reference before any further action."
                .into(),
        );
    }
    let continue_wizard = review_mode(
        terminal,
        "Lifecycle result",
        text,
        ConfirmMode::Enter("continue"),
    )?;
    Ok((continue_wizard, enrolled))
}

fn revisions_match(before: &Value, after: &Value) -> bool {
    let comparable_pool = |value: &Value| {
        let mut pool = value["pool"].clone();
        if let Some(context) = pool.get_mut("context").and_then(Value::as_object_mut) {
            context.remove("age_us");
        }
        pool
    };
    before["device"]["device_id"] == after["device"]["device_id"]
        && before["inventory"] == after["inventory"]
        && before["status"]["revision"] == after["status"]["revision"]
        && before["host_snapshot"] == after["host_snapshot"]
        && comparable_pool(before) == comparable_pool(after)
}

pub(super) fn reconcile_reference(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    reference_path: &Path,
) -> io::Result<()> {
    let observing = worker.is_some();
    if let Some(active) = worker.take() {
        active.shutdown();
    }
    let res = reconcile_reference_stopped(terminal, socket, reference_path);
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    res
}

fn reconcile_reference_stopped(
    terminal: &mut TerminalOwner,
    socket: &Path,
    reference_path: &Path,
) -> io::Result<()> {
    let cli = host::trusted_cli()?;
    let saved = lifecycle::review_receipt(reference_path)?;
    let serial = lifecycle::receipt_commissioning_serial(&saved.receipt)?;
    let out_opt = serial
        .map(|ser| workspace::next_path(WorkspaceKind::Exports, ser, "device.json"))
        .transpose()?
        .map(|p| p.to_string_lossy().into_owned());

    let authority = admission(terminal, socket, serial)?;
    let mut text = vec![
        format!("Original reference: {}", reference_path.display()),
        "Reconciles the saved request identity forward-only; never creates a new operation ID."
            .into(),
        String::new(),
    ];
    text.extend(lines(
        &serde_json::to_value(&saved.receipt).map_err(io::Error::other)?,
    )?);
    if !review_mode(
        terminal,
        "Reconcile original receipt",
        text,
        ConfirmMode::Enter("reconcile original operation ID"),
    )? {
        return Ok(());
    }
    let current = admission(terminal, socket, serial)?;
    if current != authority {
        return Err(io::Error::other(
            "daemon authority changed; confirmation expired",
        ));
    }
    let cli = cli.bind_peer(&authority);
    let socket_owned = socket.to_owned();
    let result = progress(
        terminal,
        "Reconciling original operation",
        false,
        move |_| lifecycle::reconcile_reviewed(&cli, &socket_owned, saved, out_opt.as_deref()),
    )?
    .expect("noncancellable");
    let _ = outcome(terminal, result, reference_path)?;
    Ok(())
}

pub(super) fn run(
    action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    selected: Option<(&str, &str)>,
    snapshot: Option<&Snapshot>,
) -> io::Result<()> {
    let action = ACTIONS
        .get(action)
        .ok_or_else(|| io::Error::other("unknown lifecycle action"))?
        .0;
    let input = if action == Action::Recipient {
        let Some(path) = pick_file(
            terminal,
            "Choose public backup recipient",
            &[FileKind::Recipient],
        )?
        else {
            return Ok(());
        };
        Some(path.to_string_lossy().into_owned())
    } else {
        None
    };
    let observing = worker.is_some();
    if let Some(active) = worker.take() {
        progress(
            terminal,
            "Stopping queued observation refresh",
            false,
            move |_| {
                active.shutdown();
                Ok(())
            },
        )?;
    }
    let result = run_stopped(
        action,
        terminal,
        socket,
        selected,
        snapshot,
        Inputs {
            file: input.as_deref(),
            network: None,
            generation_id: None,
            destination: None,
        },
    );
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    result.map(|_| ())
}

fn known_pool_generations(
    snapshot: Option<&Snapshot>,
    target: Option<(&str, &str)>,
) -> (Option<String>, Option<String>) {
    let (Some(s), Some((p_id, inc_id))) = (snapshot, target) else {
        return (None, None);
    };
    let Some(pool) = s
        .pools
        .iter()
        .find(|p| p.pool_id == p_id && p.incarnation_id == inc_id)
    else {
        return (None, None);
    };
    let Some(obs) = &pool.observation.value else {
        return (None, None);
    };
    let staged = obs
        .pointer("/staged/generation_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let active = obs
        .pointer("/active/generation_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (staged, active)
}

pub(crate) struct Inputs<'a> {
    pub file: Option<&'a str>,
    pub network: Option<&'a str>,
    pub generation_id: Option<&'a str>,
    pub destination: Option<&'a str>,
}

pub(crate) fn run_stopped(
    action: Action,
    terminal: &mut TerminalOwner,
    socket: &Path,
    selected: Option<(&str, &str)>,
    snapshot: Option<&Snapshot>,
    inputs: Inputs<'_>,
) -> io::Result<Option<(String, String, String)>> {
    let Inputs {
        file: input,
        network,
        generation_id,
        destination,
    } = inputs;
    let cli = host::trusted_cli()?;

    let authority = admission(terminal, socket, None)?;
    let cli = cli.bind_peer(&authority);
    let targeted = matches!(
        action,
        Action::Delete
            | Action::Generate
            | Action::Discard
            | Action::VerificationKey
            | Action::Artifact
            | Action::Certificate
    );
    let generation = matches!(
        action,
        Action::Discard | Action::VerificationKey | Action::Artifact | Action::Certificate
    );
    let mutation = matches!(
        action,
        Action::Enroll
            | Action::Delete
            | Action::Generate
            | Action::Discard
            | Action::Certificate
            | Action::Recipient
    );

    let (staged_gen, active_gen) = known_pool_generations(snapshot, selected);
    let gen_default = generation_id
        .map(str::to_owned)
        .or_else(|| staged_gen.clone())
        .or_else(|| {
            if action == Action::Discard {
                None
            } else {
                active_gen.clone()
            }
        })
        .unwrap_or_default();

    let (sel_pool, sel_inc) = selected.unwrap_or(("", ""));
    let export_stem = if !sel_pool.is_empty() && !gen_default.is_empty() {
        format!(
            "pool-{}-gen-{}",
            workspace::short_id(sel_pool),
            workspace::short_id(&gen_default)
        )
    } else if !sel_pool.is_empty() {
        format!("pool-{}", workspace::short_id(sel_pool))
    } else {
        action.stem().to_owned()
    };
    let export_default = if let Some(path) = destination {
        path.to_owned()
    } else if matches!(action, Action::VerificationKey | Action::Artifact) {
        workspace::next_path(
            WorkspaceKind::Exports,
            &export_stem,
            if action == Action::Artifact {
                "kes-backup"
            } else {
                "vkey"
            },
        )?
        .to_string_lossy()
        .into_owned()
    } else {
        String::new()
    };
    let receipt_stem = if !sel_pool.is_empty() {
        format!("{}-{}", action.stem(), workspace::short_id(sel_pool))
    } else {
        action.stem().to_owned()
    };
    let receipt_default = if mutation {
        workspace::next_path(WorkspaceKind::Receipts, &receipt_stem, "receipt.json")?
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    let auto_reference = if mutation {
        Some(workspace::next_path(
            WorkspaceKind::References,
            &receipt_stem,
            "ref.json",
        )?)
    } else {
        None
    };

    let mut specs = Vec::new();
    if targeted {
        if sel_pool.is_empty() || sel_inc.is_empty() {
            return Err(io::Error::other("Select an observed pool first"));
        }
        specs.push(FieldSpec::readonly("Target pool ID", sel_pool));
        specs.push(FieldSpec::readonly("Target incarnation ID", sel_inc));
    }
    if generation {
        if gen_default.is_empty() {
            return Err(io::Error::other(
                "No observed generation is available for this operation",
            ));
        }
        specs.push(FieldSpec::readonly("Generation", &gen_default));
    }
    match action {
        Action::Enroll => {
            let path =
                input.ok_or_else(|| io::Error::other("Cold verification key not selected"))?;
            absolute(path)?;
            let net = network.ok_or_else(|| io::Error::other("Network not selected"))?;
            specs.push(FieldSpec::readonly("Cold verification key", path));
            specs.push(FieldSpec::readonly("Network", net));
        }
        Action::Certificate | Action::Recipient => {
            let path = input.ok_or_else(|| io::Error::other("Public input not selected"))?;
            absolute(path)?;
            specs.push(FieldSpec::readonly("Public input", path));
        }
        Action::VerificationKey | Action::Artifact => {
            absolute(&export_default)?;
            specs.push(FieldSpec::readonly("Export destination", &export_default));
        }
        _ => {}
    }
    if mutation {
        specs.push(FieldSpec::readonly("Durable receipt", &receipt_default));
    }
    let offset = usize::from(targeted) * 2 + usize::from(generation);
    let values: Vec<String> = specs.iter().map(|s| s.initial.to_owned()).collect();

    let target = targeted.then(|| (values[0].as_str(), values[1].as_str()));
    let Some(before) = observe(terminal, &cli, &authority, target)? else {
        return Ok(None);
    };
    if generation {
        let staged = before
            .pointer("/pool/staged/generation_id")
            .and_then(Value::as_str);
        let active = before
            .pointer("/pool/active/generation_id")
            .and_then(Value::as_str);
        let chosen = values[2].as_str();
        if staged != Some(chosen) && (action == Action::Discard || active != Some(chosen)) {
            return Err(io::Error::other(
                "Selected generation no longer matches authoritative pool state",
            ));
        }
    }
    if action == Action::Generate && before["pool"].get("staged") != Some(&Value::Null) {
        return Err(io::Error::other(
            "A staged generation already exists or its state is unknown",
        ));
    }

    let input = match action {
        Action::Enroll | Action::Certificate | Action::Recipient => Some(values[offset].as_str()),
        _ => None,
    };
    let copy = if let Some(path) = input {
        absolute(path)?;
        Some(PublicInput::copy(path)?)
    } else {
        None
    };

    let mut text = vec![format!(
        "Device ID : {}",
        before["device"]["device_id"].as_str().unwrap_or("unknown")
    )];
    for (spec, value) in specs.iter().zip(&values) {
        text.push(format!("{:<28}: {value}", spec.label));
    }
    if let (Some(path), Some(c)) = (input, &copy) {
        text.push(format!("Input SHA-256 ({path}): {}", c.digest));
    }
    if let Some(ref_path) = &auto_reference {
        text.push(format!(
            "Managed reference           : {}",
            ref_path.display()
        ));
    }
    text.push(String::new());
    match action {
        Action::Delete => {
            text.push("DESTRUCTIVE: Permanently erases this pool incarnation's KES keys and artifacts from the Pico 2. Fence all producers first.".into());
        }
        Action::Discard => {
            text.push("DESTRUCTIVE: Permanently erases the staged generation from the Pico 2; its encrypted backup can no longer be exported from the device.".into());
        }
        Action::Enroll => {
            text.push(
                "Creates a new pool incarnation on the Pico 2 (capacity <= 64 pools).".into(),
            );
        }
        Action::Generate => {
            text.push("Generates a fresh KES keypair in the staged slot on the Pico 2.".into());
        }
        Action::Certificate => {
            text.push("Installs the cold-signed OpCert onto the target generation; automatic activation rules apply when valid.".into());
        }
        Action::Recipient => {
            text.push("Updates the HPKE public recipient for future generations (existing backups still use their original recipient key).".into());
        }
        Action::VerificationKey | Action::Artifact => {
            text.push("Exports public/HPKE-encrypted material to a new 0600 file without modifying activation state.".into());
        }
    }
    text.push(String::new());
    text.push("Authoritative pre-mutation observation:".into());
    text.extend(lines(&before)?);

    let confirm_mode = ConfirmMode::YesNo {
        danger: matches!(action, Action::Delete | Action::Discard),
    };
    if !(destination.is_some() && matches!(action, Action::VerificationKey | Action::Artifact))
        && !review_mode(terminal, "Review lifecycle operation", text, confirm_mode)?
    {
        return Ok(None);
    }

    let current = admission(terminal, socket, None)?;
    if current != authority {
        return Err(io::Error::other(
            "daemon authority changed; confirmation expired",
        ));
    }
    let Some(after) = observe(terminal, &cli, &authority, target)? else {
        return Ok(None);
    };
    if !revisions_match(&before, &after) {
        return Err(io::Error::other(
            "target, revision or host binding changed; confirmation expired, review again",
        ));
    }
    if mutation && after["status"]["receipt_pending"] != false {
        return Err(io::Error::other(
            "device operation pending or unknown; reconcile the original receipt before another mutation",
        ));
    }

    if matches!(action, Action::VerificationKey | Action::Artifact) {
        absolute(&values[offset])?;
        let args = vec![
            "key".into(),
            if action == Action::Artifact {
                "export".into()
            } else {
                "verification-key".into()
            },
            "--pool".into(),
            values[0].clone(),
            "--incarnation".into(),
            values[1].clone(),
            "--generation".into(),
            values[2].clone(),
            "--out".into(),
            values[offset].clone(),
        ];
        let export_cli = cli.clone();
        let export_socket = socket.to_owned();
        let (class, mut response) = progress(terminal, "Exporting material", false, move |_| {
            lifecycle::public_command(&export_cli, &export_socket, &args)
        })?
        .expect("noncancellable");
        let mut result = vec![
            format!("CLI result  : {class:?}"),
            format!("Destination : {}", values[offset]),
        ];
        if class == lifecycle::ExitClass::Success {
            let mut output = Vec::new();
            crate::files::open_owner_controlled_file(Path::new(&values[offset]))?
                .take(65537)
                .read_to_end(&mut output)?;
            if output.len() > 65536 {
                return Err(io::Error::other("export exceeds metadata digest limit"));
            }
            if let Some(object) = response["result"].as_object_mut() {
                object.remove("artifact");
            }
            let recipient = if action == Action::Artifact {
                let cli = cli.clone();
                let authority = authority.clone();
                let pool = values[0].clone();
                let incarnation = values[1].clone();
                let generation = values[2].clone();
                let artifact = output.clone();
                let public = match progress(
                    terminal,
                    "Authenticating artifact recipient",
                    false,
                    move |_| {
                        lifecycle::artifact_recipient(
                            &cli,
                            &authority,
                            &pool,
                            &incarnation,
                            &generation,
                            &artifact,
                        )
                    },
                ) {
                    Ok(Some(public)) => public,
                    Ok(None) => {
                        return Err(io::Error::other(
                            "artifact validation interrupted after export",
                        ));
                    }
                    Err(error) => {
                        review(terminal, "Artifact validation failed", vec![
                            format!(
                                "Exported file {} exists but its identity or signature could not be verified: {error}",
                                values[offset]
                            ),
                            "No authenticated recipient metadata was retained. Preserve the file and investigate."
                                .into(),
                        ])?;
                        return Ok(None);
                    }
                };
                Some(serde_json::json!({
                    "public_key": public.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "recipient_id": format!("{:x}", Sha256::digest(public)),
                }))
            } else {
                None
            };
            let metadata = serde_json::json!({
                "device_id": after["device"]["device_id"],
                "pool_id": values[0],
                "incarnation_id": values[1],
                "generation_id": values[2],
                "recipient_binding": recipient,
                "output_path": values[offset],
                "output_sha256": format!("{:x}", Sha256::digest(&output)),
                "response": response,
            });
            let metadata_path = format!("{}.metadata.json", values[offset]);
            match crate::files::publish_no_clobber(
                Path::new(&metadata_path),
                &serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?,
                0o600,
            ) {
                Ok(()) => result.push(format!("Metadata    : {metadata_path}")),
                Err(error) => result.push(format!(
                    "Metadata publication failed at {metadata_path}: {error}"
                )),
            }
            result.push(String::new());
            result.extend(lines(&metadata)?);
        } else {
            result.extend(lines(&response)?);
        }
        let proceed = review_mode(
            terminal,
            "Export result",
            result,
            ConfirmMode::Enter("continue"),
        )?;
        return Ok((proceed && class == lifecycle::ExitClass::Success)
            .then(|| (String::new(), String::new(), String::new())));
    }

    let reference = auto_reference.expect("mutation reference");
    let receipt = &values[values.len() - 1];
    absolute(receipt)?;
    let revision = if targeted {
        after["pool"]["revision"].as_u64()
    } else {
        after["status"]["revision"].as_u64()
    }
    .ok_or_else(|| io::Error::other("authoritative revision unavailable"))?;

    let enrolled_net = (action == Action::Enroll).then(|| values[offset + 1].clone());
    let m = match action {
        Action::Enroll => Mutation::Enroll {
            cold_vkey: copy.as_ref().expect("public input").path.clone(),
            network: values[offset + 1].clone(),
        },
        Action::Delete => Mutation::Delete {
            pool: values[0].clone(),
            incarnation: values[1].clone(),
        },
        Action::Generate => Mutation::Generate {
            pool: values[0].clone(),
            incarnation: values[1].clone(),
        },
        Action::Discard => Mutation::Discard {
            pool: values[0].clone(),
            incarnation: values[1].clone(),
            generation: values[2].clone(),
        },
        Action::Certificate => Mutation::InstallCertificate {
            pool: values[0].clone(),
            incarnation: values[1].clone(),
            generation: values[2].clone(),
            certificate: copy.as_ref().expect("public input").path.clone(),
        },
        Action::Recipient => Mutation::SetRecipient {
            public_key: copy.as_ref().expect("public input").path.clone(),
        },
        _ => return Err(io::Error::other("unsupported lifecycle action")),
    };
    let submit_cli = cli.clone();
    let submit_socket = socket.to_owned();
    let submit_reference = reference.clone();
    let submit_receipt = receipt.clone();
    match progress(
        terminal,
        "Submitting original operation",
        false,
        move |_| {
            lifecycle::submit(
                &submit_cli,
                &submit_socket,
                &submit_reference,
                Path::new(&submit_receipt),
                revision,
                m,
            )
        },
    )
    .and_then(|value| value.ok_or_else(|| io::Error::other("operation outcome unavailable")))
    {
        Ok(result) => {
            let success = result.class == lifecycle::ExitClass::Success && !result.uncertain;
            let missing_recipient =
                action == Action::Generate && missing_recipient_rejection(&result);
            let (proceed, enrolled) = outcome(terminal, result, &reference)?;
            if !proceed {
                Ok(None)
            } else if missing_recipient {
                Err(io::Error::other(MissingRecipient))
            } else if action == Action::Enroll {
                Ok(enrolled.zip(enrolled_net).map(|((p, i), n)| (p, i, n)))
            } else {
                Ok(success.then(|| (String::new(), String::new(), String::new())))
            }
        }
        Err(error) => {
            review(
                terminal,
                "Submission interrupted or unavailable",
                vec![
                    format!("{error}"),
                    format!(
                        "Inspect retained reference {} in Activity (6); do not create a replacement operation if a receipt exists.",
                        reference.display()
                    ),
                ],
            )?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{missing_recipient_rejection, revisions_match};
    use crate::{
        cli::receipt::PublicReceipt,
        manager::lifecycle::{ExitClass, Outcome},
    };
    use serde_json::json;

    #[test]
    fn only_certain_device_recipient_rejection_allows_fallback() {
        let mut result = Outcome {
            class: ExitClass::Rejected,
            stdout: vec![],
            stderr: vec![],
            output_truncated: false,
            receipt: Some(PublicReceipt {
                version: 1,
                request: json!({"action":"generation.create", "request_id":"request", "operation_id":"operation"}),
                response: Some(json!({"request_id":"request", "outcome":"rejected",
                    "error":{"code":"recipient_mismatch", "operation_id":"operation"}})),
            }),
            uncertain: false,
            reconciliation_evidence: None,
            reconciliation_evidence_error: None,
        };
        assert!(missing_recipient_rejection(&result));
        result.uncertain = true;
        assert!(!missing_recipient_rejection(&result));
        result.uncertain = false;
        let response = result.receipt.as_mut().unwrap().response.as_mut().unwrap();
        response["error"]["code"] = json!("staged_occupied");
        assert!(!missing_recipient_rejection(&result));
        let response = result.receipt.as_mut().unwrap().response.as_mut().unwrap();
        response["error"]["code"] = json!("recipient_mismatch");
        response["error"]["operation_id"] = json!("other");
        assert!(!missing_recipient_rejection(&result));
        result.receipt = None;
        assert!(!missing_recipient_rejection(&result));
    }

    #[test]
    fn confirmation_expires_on_target_revision_or_context_change() {
        let original = json!({"device":{"device_id":"a"},"inventory":{"revision":1},
            "status":{"revision":2},"host_snapshot":"h",
            "pool":{"pool_id":"p","incarnation_id":"i","revision":3,
                    "context":{"valid":true,"age_us":1}}});
        let mut after = original.clone();
        after["pool"]["context"]["age_us"] = 2.into();
        assert!(revisions_match(&original, &after));
        for (path, value) in [
            ("/pool/incarnation_id", json!("other")),
            ("/pool/revision", json!(4)),
            ("/pool/context/valid", json!(false)),
            ("/inventory/revision", json!(2)),
            ("/host_snapshot", json!("other")),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(!revisions_match(&original, &changed));
        }
    }
}
