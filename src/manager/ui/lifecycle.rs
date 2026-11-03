use super::{public_fields, review};
use crate::manager::{
    host,
    lifecycle::{self, Mutation},
    observe::Worker,
    terminal::TerminalOwner,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
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
        "List complete device inventory and host bindings",
    ),
    (Action::Detail, "Inspect exact pool and generation details"),
    (
        Action::Enroll,
        "Enroll supplied public cold verification key",
    ),
    (
        Action::Delete,
        "Delete exact pool incarnation (irreversible)",
    ),
    (Action::Generate, "Create staged generation"),
    (Action::Discard, "Discard exact staged generation"),
    (Action::VerificationKey, "Export public verification key"),
    (Action::Artifact, "Export encrypted artifact"),
    (Action::Certificate, "Install matching public certificate"),
    (Action::Recipient, "Install / rotate public recipient"),
    (
        Action::Receipts,
        "Discover and inspect original operation receipts",
    ),
    (Action::Reconcile, "Reconcile an original receipt"),
];

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
            let draw = terminal.terminal().and_then(|terminal| terminal.draw(|frame| {
                let message = if cancelled { "Cancellation requested; waiting for the current read to finish. No mutation will be submitted." }
                    else if cancellable { "Working; Esc cancels after the current read finishes, before submission." }
                    else { "Working; if submitted, this operation cannot be cancelled. Waiting for its original result." };
                frame.render_widget(Paragraph::new(message).wrap(Wrap { trim: false }).block(Block::default().borders(Borders::ALL).title(label)), frame.area());
            }).map(|_| ()));
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
) -> io::Result<Option<serde_json::Value>> {
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

fn lines(value: &serde_json::Value) -> io::Result<Vec<String>> {
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
fn outcome(
    terminal: &mut TerminalOwner,
    result: lifecycle::Outcome,
    reference: &str,
) -> io::Result<()> {
    let mut text = vec![format!("CLI exit class: {:?}; uncertain: {}", result.class, result.uncertain), format!("Original reference: {reference}"), "Never submit a replacement operation for an uncertain or interrupted result. Reopen this original receipt and reconcile it.".into()];
    if let Some(path) = &result.reconciliation_evidence {
        text.push(format!(
            "Reconciliation evidence retained at {}",
            path.display()
        ));
    }
    if let Some(error) = &result.reconciliation_evidence_error {
        text.push(format!("Reconciliation evidence could not be retained: {error}; record the actual response shown below."));
    }
    if !result.stdout.is_empty()
        && !result.output_truncated
        && let Ok(response) = serde_json::from_slice::<serde_json::Value>(&result.stdout)
    {
        text.push("Actual CLI response:".into());
        text.extend(lines(&response)?);
    }
    if let Some(receipt) = result.receipt {
        text.extend(lines(
            &serde_json::to_value(receipt).map_err(io::Error::other)?,
        )?);
    } else {
        text.push("No readable receipt was found; inspect the original reference before any further action.".into());
    }
    review(terminal, "Lifecycle result", text, None)?;
    Ok(())
}
fn revisions_match(before: &serde_json::Value, after: &serde_json::Value) -> bool {
    let comparable_pool = |value: &serde_json::Value| {
        let mut pool = value["pool"].clone();
        if let Some(context) = pool
            .get_mut("context")
            .and_then(serde_json::Value::as_object_mut)
        {
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

pub(super) fn run(
    action: usize,
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    _selected: Option<&PathBuf>,
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
    let result = run_stopped(action, terminal, socket);
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    result
}

fn run_stopped(action: Action, terminal: &mut TerminalOwner, socket: &Path) -> io::Result<()> {
    let cli = host::trusted_cli()?;
    if action == Action::Receipts {
        let Some(v) = public_fields(
            terminal,
            "Original receipt discovery",
            &[("Absolute owner-controlled reference directory", "")],
        )?
        else {
            return Ok(());
        };
        absolute(&v[0])?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&v[0])? {
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
                        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
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
        if entries.is_empty() {
            entries.push("No readable references found; inaccessible references are not proof of no operation.".into());
        }
        review(terminal, "Original operations", entries, None)?;
        return Ok(());
    }
    if action == Action::Reconcile {
        let Some(v) = public_fields(
            terminal,
            "Reopen original operation",
            &[
                ("Absolute original reference file", ""),
                ("Commissioning output path only, otherwise empty", ""),
            ],
        )?
        else {
            return Ok(());
        };
        absolute(&v[0])?;
        let saved = lifecycle::review_receipt(Path::new(&v[0]))?;
        let serial = lifecycle::receipt_commissioning_serial(&saved.receipt)?;
        if !v[1].is_empty() && serial.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output is only valid for commissioning",
            ));
        }
        let authority = admission(terminal, socket, serial)?;
        let mut text = vec![
            format!("Original reference {}", v[0]),
            "This resends/reconciles the saved request identity, never creates a new operation ID."
                .into(),
        ];
        text.extend(lines(
            &serde_json::to_value(&saved.receipt).map_err(io::Error::other)?,
        )?);
        if !review(
            terminal,
            "Reconcile original receipt",
            text,
            Some("RECONCILE"),
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
        let socket = socket.to_owned();
        let output = v[1].clone();
        let result = progress(
            terminal,
            "Reconciling original operation",
            false,
            move |_| {
                lifecycle::reconcile_reviewed(
                    &cli,
                    &socket,
                    saved,
                    if output.is_empty() {
                        None
                    } else {
                        Some(&output)
                    },
                )
            },
        )?
        .expect("noncancellable");
        return outcome(terminal, result, &v[0]);
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
    let mut fields = Vec::new();
    if targeted {
        fields.extend([("Exact pool ID", ""), ("Exact incarnation ID", "")]);
    }
    if generation {
        fields.push(("Exact generation ID", ""));
    }
    match action {
        Action::Enroll => fields.extend([
            ("Absolute public cold verification key", ""),
            ("Configured network name", ""),
        ]),
        Action::Certificate => fields.push(("Absolute public certificate", "")),
        Action::Recipient => fields.push(("Absolute recipient public record", "")),
        Action::VerificationKey | Action::Artifact => {
            fields.push(("New absolute output file (no overwrite)", ""))
        }
        _ => {}
    }
    let mutation = matches!(
        action,
        Action::Enroll
            | Action::Delete
            | Action::Generate
            | Action::Discard
            | Action::Certificate
            | Action::Recipient
    );
    if mutation {
        fields.extend([
            ("New absolute reference file", ""),
            ("New absolute CLI receipt file", ""),
        ]);
    }
    let values = if fields.is_empty() {
        Vec::new()
    } else {
        match public_fields(terminal, "Lifecycle public inputs", &fields)? {
            Some(v) => v,
            None => return Ok(()),
        }
    };
    let target = targeted.then(|| (values[0].as_str(), values[1].as_str()));
    let Some(before) = observe(terminal, &cli, &authority, target)? else {
        return Ok(());
    };
    let mut text = lines(&before)?;
    if action == Action::List || action == Action::Detail {
        review(terminal, "Authoritative lifecycle observations", text, None)?;
        return Ok(());
    }
    let offset = usize::from(targeted) * 2 + usize::from(generation);
    let input = match action {
        Action::Enroll | Action::Certificate | Action::Recipient => Some(values[offset].as_str()),
        _ => None,
    };
    let copy = if let Some(path) = input {
        absolute(path)?;
        let copy = PublicInput::copy(path)?;
        text.push(format!("Public input {path}; SHA-256 {}", copy.digest));
        Some(copy)
    } else {
        None
    };
    for (label, value) in fields.iter().zip(&values) {
        text.push(format!("{}: {}", label.0, value));
    }
    text.extend([
        "Only public inputs and encrypted artifacts belong on the primary; cold signing and private recipient keys remain off-primary.".into(),
        "A new enrollment creates a new incarnation; review its returned binding. Capacity is limited to 64; no pool is evicted.".into(),
        "Deletion removes device keys and artifacts irreversibly; fence all producers and account for external copies. Discard removes only the staged generation and ends its artifact retrieval.".into(),
        "Occupied stage, expired certificate or invalid/missing context may block progress. Active generation is not replaced by discard; activation races are rejected.".into(),
        "Certificate signing is off-primary; the existing matching and automatic activation rules apply. Export retains the existing activation intent; no archive approval gate is added.".into(),
        "Recipient changes affect future artifacts only. Old artifacts still require their original private recipient keys.".into(),
    ]);
    let confirm = match action {
        Action::Delete => format!("DELETE {} {}", values[0], values[1]),
        Action::Discard => format!("DISCARD {} {} {}", values[0], values[1], values[2]),
        _ => "APPLY".into(),
    };
    if !review(
        terminal,
        "Review exact lifecycle action",
        text,
        Some(&confirm),
    )? {
        return Ok(());
    }
    let current = admission(terminal, socket, None)?;
    if current != authority {
        return Err(io::Error::other(
            "daemon authority changed; confirmation expired",
        ));
    }
    let Some(after) = observe(terminal, &cli, &authority, target)? else {
        return Ok(());
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
        let (class, mut response) =
            progress(terminal, "Exporting public material", false, move |_| {
                lifecycle::public_command(&export_cli, &export_socket, &args)
            })?
            .expect("noncancellable");
        let mut result = vec![format!("CLI result: {class:?}; destination: {}", values[offset]), "Output is no-clobber. Export preserves the existing activation intent; it is not a new generation.".into()];
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
                        review(terminal, "Artifact validation failed", vec![format!("Exported file {} exists but its identity or signature could not be verified: {error}", values[offset]), "No authenticated recipient metadata was retained. Preserve the file and investigate; it will not be overwritten.".into()], None)?;
                        return Ok(());
                    }
                };
                Some(
                    serde_json::json!({"public_key": public.iter().map(|b| format!("{b:02x}")).collect::<String>(), "recipient_id": format!("{:x}", Sha256::digest(public))}),
                )
            } else {
                None
            };
            let metadata = serde_json::json!({
                "device_id": after["device"]["device_id"], "pool_id": values[0],
                "incarnation_id": values[1], "generation_id": values[2],
                "recipient_binding": recipient,
                "output_path": values[offset], "output_sha256": format!("{:x}", Sha256::digest(&output)),
                "response": response,
            });
            let metadata_path = format!("{}.metadata.json", values[offset]);
            match crate::files::publish_no_clobber(Path::new(&metadata_path), &serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?, 0o600) {
                Ok(()) => result.push(format!("Public export metadata retained at {metadata_path}")),
                Err(error) => result.push(format!("Export succeeded but metadata publication failed at {metadata_path}: {error}; retain the displayed public evidence")),
            }
            result.extend(lines(&metadata)?);
        } else {
            result.extend(lines(&response)?);
        }
        result.push("Recipient identity above is authenticated from this artifact, not inferred from the current recipient policy; verification-key-only exports have no recipient binding.".into());
        review(terminal, "Export result", result, None)?;
        return Ok(());
    }
    let reference = &values[values.len() - 2];
    let receipt = &values[values.len() - 1];
    absolute(reference)?;
    absolute(receipt)?;
    let revision = if targeted {
        after["pool"]["revision"].as_u64()
    } else {
        after["status"]["revision"].as_u64()
    }
    .ok_or_else(|| io::Error::other("authoritative revision unavailable"))?;
    let m = match action {
        Action::Enroll => Mutation::Enroll {
            cold_vkey: copy.as_ref().expect("public input").path.clone(),
            network: values[1].clone(),
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
                Path::new(&submit_reference),
                Path::new(&submit_receipt),
                revision,
                m,
            )
        },
    )
    .and_then(|value| value.ok_or_else(|| io::Error::other("operation outcome unavailable")))
    {
        Ok(result) => outcome(terminal, result, reference),
        Err(error) => {
            review(
                terminal,
                "Submission interrupted or unavailable",
                vec![
                    format!("{error}"),
                    format!(
                        "Inspect original reference {reference}; do not create a replacement operation if a receipt exists."
                    ),
                    "A missing final response is not proof of cancellation.".into(),
                ],
                None,
            )?;
            Ok(())
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
