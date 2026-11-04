use super::{
    review, setup,
    widgets::{ConfirmMode, FieldSpec, form_validated, review_mode},
};
use crate::manager::{
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
    List,
    Detail,
    Enroll,
    Delete,
    Generate,
    Discard,
    VerificationKey,
    Artifact,
    Certificate,
    Recipient,
    Receipts,
    Reconcile,
}
pub(super) const ACTIONS: &[(Action, &str)] = &[
    (
        Action::List,
        "Inspect complete device inventory & host bindings",
    ),
    (Action::Detail, "Inspect exact pool & generation JSON"),
    (Action::Enroll, "Enroll new pool from cold verification key"),
    (
        Action::Delete,
        "Delete pool incarnation from device (destructive)",
    ),
    (Action::Generate, "Create next staged KES generation"),
    (Action::Discard, "Discard staged generation (destructive)"),
    (
        Action::VerificationKey,
        "Export KES verification key (.vkey)",
    ),
    (
        Action::Artifact,
        "Export encrypted HPKE backup (.kes-backup)",
    ),
    (
        Action::Certificate,
        "Install cold-signed operational certificate",
    ),
    (Action::Recipient, "Install or rotate HPKE backup recipient"),
    (
        Action::Receipts,
        "Browse retained lifecycle operation receipts",
    ),
    (Action::Reconcile, "Reconcile an interrupted CLI receipt"),
];

impl Action {
    fn stem(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Detail => "detail",
            Self::Enroll => "pool-enroll",
            Self::Delete => "pool-delete",
            Self::Generate => "key-generate",
            Self::Discard => "key-discard",
            Self::VerificationKey => "export-vkey",
            Self::Artifact => "export-backup",
            Self::Certificate => "cert-install",
            Self::Recipient => "recipient-set",
            Self::Receipts => "receipts",
            Self::Reconcile => "reconcile",
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

fn observe(
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

fn outcome(
    terminal: &mut TerminalOwner,
    result: lifecycle::Outcome,
    reference: &Path,
) -> io::Result<Option<(String, String)>> {
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
    review(terminal, "Lifecycle result", text, None)?;
    Ok(enrolled)
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
    let res = reconcile_reference_stopped(terminal, socket, reference_path, None);
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    res
}

fn reconcile_reference_stopped(
    terminal: &mut TerminalOwner,
    socket: &Path,
    reference_path: &Path,
    explicit_output: Option<&str>,
) -> io::Result<()> {
    let cli = host::trusted_cli()?;
    let saved = lifecycle::review_receipt(reference_path)?;
    let serial = lifecycle::receipt_commissioning_serial(&saved.receipt)?;
    let out_opt = match (explicit_output, serial) {
        (Some(out), _) if !out.is_empty() => {
            if serial.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "output path is only valid for commissioning receipts",
                ));
            }
            Some(out.to_owned())
        }
        (_, Some(ser)) => {
            let suggested = workspace::next_path(WorkspaceKind::Exports, ser, "device.json")?
                .to_string_lossy()
                .into_owned();
            let specs = [FieldSpec::text_hint(
                "Commissioning device.json output path (optional)",
                &suggested,
                "Leave empty if device.json was already written",
            )];
            let Some(chosen) = form_validated(
                terminal,
                "Commissioning reconciliation output",
                &specs,
                |v| {
                    let s = v[0].trim();
                    if !s.is_empty() && !Path::new(s).is_absolute() {
                        return Err((Some(0), "Output path must be absolute or empty".into()));
                    }
                    Ok((!s.is_empty()).then(|| s.to_owned()))
                },
            )?
            else {
                return Ok(());
            };
            chosen
        }
        _ => None,
    };

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
    let result = run_stopped(action, terminal, socket, selected, snapshot);
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    if let Ok(Some((pool_id, incarnation_id, enrolled_net))) = result {
        if review_mode(
            terminal,
            "Bind enrolled pool in host configuration?",
            vec![
                format!("Enrolled pool ID       : {pool_id}"),
                format!("Enrolled incarnation ID: {incarnation_id}"),
                format!("Enrolled network       : {enrolled_net}"),
                String::new(),
                "Pool enrollment is recorded in the daemon journal, but KES socket serving and UTC context polling start only after the pool is listed in /etc/pico2-kes-agent/config.json and pico2-kes-agentd is restarted."
                    .into(),
                "Press Enter to bind this pool and optionally restart pico2-kes-agentd now (or Esc to defer; you can press 'b' on Pools later)."
                    .into(),
            ],
            ConfirmMode::Enter("bind pool in config.json now"),
        )? {
            setup::bind_pool_workflow(
                terminal,
                worker,
                socket,
                &pool_id,
                &incarnation_id,
                Some(&enrolled_net),
            )?;
        }
        return Ok(());
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

fn configured_net_hints(snapshot: Option<&Snapshot>) -> Vec<String> {
    snapshot
        .and_then(|s| s.local.value.as_ref())
        .and_then(|l| l.config_summary.value.as_ref())
        .map(|c| c.networks.clone())
        .unwrap_or_default()
}

fn run_stopped(
    action: Action,
    terminal: &mut TerminalOwner,
    socket: &Path,
    selected: Option<(&str, &str)>,
    snapshot: Option<&Snapshot>,
) -> io::Result<Option<(String, String, String)>> {
    let cli = host::trusted_cli()?;
    if action == Action::Receipts {
        let default_dir = workspace::dir(WorkspaceKind::References)?
            .to_string_lossy()
            .into_owned();
        let specs = [FieldSpec::text(
            "Owner-controlled reference directory",
            &default_dir,
        )];
        let Some(dir_path) = form_validated(
            terminal,
            "Browse lifecycle operation references",
            &specs,
            |v| {
                let p = v[0].trim();
                absolute(p).map_err(|e| (Some(0), e.to_string()))?;
                Ok(p.to_owned())
            },
        )?
        else {
            return Ok(None);
        };
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir_path)? {
            let path = entry?.path();
            if let Ok(receipt) = lifecycle::load_reference(&path) {
                let detail = match lifecycle::load_public_receipt(&receipt) {
                    Ok(r) => serde_json::to_string(&r).map_err(io::Error::other)?,
                    Err(e) => format!("receipt unavailable: {e}"),
                };
                entries.push(format!(
                    "Reference {} -> {}: {detail}",
                    path.display(),
                    receipt.display()
                ));
                if entries.len() > 1024 {
                    return Err(io::Error::other("too many receipt references to display"));
                }
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".reconcile-") && n.ends_with(".json"))
            {
                if let Ok(file) = crate::files::open_owner_controlled_file(&path) {
                    let mut bytes = Vec::new();
                    file.take(65537).read_to_end(&mut bytes)?;
                    if bytes.len() <= 65536
                        && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                        && value["version"] == 1
                        && value["request"].is_object()
                        && value["response"].is_object()
                    {
                        entries.push(format!(
                            "Reconciliation evidence {}: {}",
                            path.display(),
                            value
                        ));
                    }
                }
                if entries.len() > 1024 {
                    return Err(io::Error::other("too many operation records to display"));
                }
            }
        }
        entries.sort();
        entries.reverse();
        if entries.is_empty() {
            entries.push("No readable references found in this directory.".into());
        }
        review(terminal, "Retained lifecycle operations", entries, None)?;
        return Ok(None);
    }
    if action == Action::Reconcile {
        let latest_ref = workspace::list_files(WorkspaceKind::References)?
            .into_iter()
            .next()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let specs = [
            FieldSpec::text("Absolute original reference file", &latest_ref),
            FieldSpec::text_hint(
                "Commissioning output path (only for commissioning receipts)",
                "",
                "Leave empty for pool/key/recipient operations",
            ),
        ];
        let Some((ref_str, out_str)) =
            form_validated(terminal, "Reopen original CLI operation", &specs, |v| {
                let r = v[0].trim();
                absolute(r).map_err(|e| (Some(0), e.to_string()))?;
                let o = v[1].trim();
                if !o.is_empty() {
                    absolute(o).map_err(|e| (Some(1), e.to_string()))?;
                }
                Ok((r.to_owned(), o.to_owned()))
            })?
        else {
            return Ok(None);
        };
        reconcile_reference_stopped(
            terminal,
            socket,
            Path::new(&ref_str),
            (!out_str.is_empty()).then_some(out_str.as_str()),
        )?;
        return Ok(None);
    }

    let authority = admission(terminal, socket, None)?;
    let cli = cli.bind_peer(&authority);
    let targeted = matches!(
        action,
        Action::Detail
            | Action::Delete
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
    let gen_default = match action {
        Action::Discard => staged_gen.clone().unwrap_or_default(),
        _ => staged_gen
            .clone()
            .or_else(|| active_gen.clone())
            .unwrap_or_default(),
    };
    let dual_gen_opts: Vec<(&str, &str)> = match (&staged_gen, &active_gen, action) {
        (Some(s), Some(a), Action::VerificationKey | Action::Artifact | Action::Certificate) => {
            vec![
                (s.as_str(), "Staged generation"),
                (a.as_str(), "Active generation"),
            ]
        }
        _ => Vec::new(),
    };

    let net_hints = configured_net_hints(snapshot);
    let net_default = net_hints.first().map(String::as_str).unwrap_or("mainnet");
    let net_opts: Vec<(&str, &str)> = net_hints
        .iter()
        .map(|n| (n.as_str(), "configured network"))
        .collect();

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
    let export_default = match action {
        Action::VerificationKey => {
            workspace::next_path(WorkspaceKind::Exports, &export_stem, "vkey")?
                .to_string_lossy()
                .into_owned()
        }
        Action::Artifact => {
            workspace::next_path(WorkspaceKind::Exports, &export_stem, "kes-backup")?
                .to_string_lossy()
                .into_owned()
        }
        _ => String::new(),
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
        if !sel_pool.is_empty() && !sel_inc.is_empty() {
            specs.push(FieldSpec::readonly("Target pool ID", sel_pool));
            specs.push(FieldSpec::readonly("Target incarnation ID", sel_inc));
        } else {
            specs.push(FieldSpec::text("Exact pool ID (56 hex)", sel_pool));
            specs.push(FieldSpec::text("Exact incarnation ID (32 hex)", sel_inc));
        }
    }
    if generation {
        if !dual_gen_opts.is_empty() {
            specs.push(FieldSpec::select(
                "Target generation slot",
                &gen_default,
                &dual_gen_opts,
            ));
        } else {
            specs.push(FieldSpec::text_hint(
                "Exact generation ID (32 hex)",
                &gen_default,
                if action == Action::Discard {
                    "Only the staged generation can be discarded"
                } else {
                    "Pre-filled from observed generation when available"
                },
            ));
        }
    }
    match action {
        Action::Enroll => {
            specs.push(FieldSpec::text(
                "Absolute cold verification key file (cold.vkey)",
                "",
            ));
            if net_opts.len() > 1 {
                specs.push(FieldSpec::select(
                    "Configured network name",
                    net_default,
                    &net_opts,
                ));
            } else {
                specs.push(FieldSpec::text("Configured network name", net_default));
            }
        }
        Action::Certificate => {
            specs.push(FieldSpec::text(
                "Absolute cold-signed operational certificate (node.cert)",
                "",
            ));
        }
        Action::Recipient => {
            specs.push(FieldSpec::text(
                "Absolute HPKE recipient public record file",
                "",
            ));
        }
        Action::VerificationKey | Action::Artifact => {
            specs.push(FieldSpec::text(
                "Protected export destination (0600, no overwrite)",
                &export_default,
            ));
        }
        _ => {}
    }
    if mutation {
        specs.push(FieldSpec::text(
            "Durable CLI receipt file (0600, no overwrite)",
            &receipt_default,
        ));
    }

    let offset = usize::from(targeted) * 2 + usize::from(generation);
    let values = if specs.iter().all(|s| {
        !matches!(
            s.kind,
            super::widgets::FieldKind::Text | super::widgets::FieldKind::Select(_)
        )
    }) {
        specs.iter().map(|s| s.initial.to_owned()).collect()
    } else {
        let Some(vals) = form_validated(
            terminal,
            ACTIONS
                .iter()
                .find(|(a, _)| *a == action)
                .map_or("Lifecycle input", |(_, l)| *l),
            &specs,
            |v| {
                let trimmed: Vec<String> = v.iter().map(|s| s.trim().to_owned()).collect();
                if targeted && (trimmed[0].is_empty() || trimmed[1].is_empty()) {
                    return Err((Some(0), "Pool ID and Incarnation ID are required".into()));
                }
                if generation && trimmed[2].is_empty() {
                    return Err((Some(2), "Generation ID is required".into()));
                }
                if matches!(
                    action,
                    Action::Enroll
                        | Action::Certificate
                        | Action::Recipient
                        | Action::VerificationKey
                        | Action::Artifact
                ) {
                    absolute(&trimmed[offset]).map_err(|e| (Some(offset), e.to_string()))?;
                }
                if action == Action::Enroll && trimmed[offset + 1].is_empty() {
                    return Err((
                        Some(offset + 1),
                        "Configured network name is required".into(),
                    ));
                }
                if mutation {
                    let rec_idx = trimmed.len() - 1;
                    absolute(&trimmed[rec_idx]).map_err(|e| (Some(rec_idx), e.to_string()))?;
                }
                Ok(trimmed)
            },
        )?
        else {
            return Ok(None);
        };
        vals
    };

    let target = targeted.then(|| (values[0].as_str(), values[1].as_str()));
    let Some(before) = observe(terminal, &cli, &authority, target)? else {
        return Ok(None);
    };
    if action == Action::List || action == Action::Detail {
        review(
            terminal,
            "Authoritative lifecycle observations",
            lines(&before)?,
            None,
        )?;
        return Ok(None);
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
        _ => {}
    }
    text.push(String::new());
    text.push("Authoritative pre-mutation observation:".into());
    text.extend(lines(&before)?);

    let confirm_phrase = match action {
        Action::Delete => Some(format!("DELETE {}", workspace::short_id(&values[0]))),
        Action::Discard => Some(format!("DISCARD {}", workspace::short_id(&values[2]))),
        _ => None,
    };
    let confirm_mode = match &confirm_phrase {
        Some(phrase) => ConfirmMode::Phrase(phrase),
        None => ConfirmMode::Enter("submit reviewed lifecycle operation"),
    };
    if !review_mode(terminal, "Review lifecycle operation", text, confirm_mode)? {
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
                        review(
                            terminal,
                            "Artifact validation failed",
                            vec![
                                format!(
                                    "Exported file {} exists but its identity or signature could not be verified: {error}",
                                    values[offset]
                                ),
                                "No authenticated recipient metadata was retained. Preserve the file and investigate."
                                    .into(),
                            ],
                            None,
                        )?;
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
        review(terminal, "Export result", result, None)?;
        return Ok(None);
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
            let enrolled = outcome(terminal, result, &reference)?;
            Ok(enrolled.zip(enrolled_net).map(|((p, i), n)| (p, i, n)))
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
                None,
            )?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::revisions_match;
    use serde_json::json;

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
