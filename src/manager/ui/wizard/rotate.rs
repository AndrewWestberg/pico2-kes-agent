use super::super::{
    lifecycle::{self, Action},
    review,
    widgets::{ConfirmMode, pick_file, progress_steps, review_mode},
};
use crate::{
    config::{Config, RunMode},
    manager::{
        discovery::files::FileKind,
        host, kes_clock,
        observe::Worker,
        terminal::TerminalOwner,
        workspace::{self, WorkspaceKind},
    },
};
use serde_json::Value;
use std::{
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) fn stopped<T>(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    f: impl FnOnce(&mut TerminalOwner) -> io::Result<T>,
) -> io::Result<T> {
    let observing = worker.is_some();
    if let Some(active) = worker.take() {
        active.shutdown();
    }
    let result = f(terminal);
    if observing && terminal.terminal().is_ok() {
        *worker = Some(Worker::start(socket.to_owned(), None));
    }
    result
}

fn observation(
    terminal: &mut TerminalOwner,
    socket: &Path,
    pool: &str,
    incarnation: &str,
) -> io::Result<Option<Value>> {
    let authority = lifecycle::admission(terminal, socket, None)?;
    let cli = host::trusted_cli()?.bind_peer(&authority);
    lifecycle::observe(terminal, &cli, &authority, Some((pool, incarnation)))
}

fn private_dir(path: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Export directory must be private and owned by the operator",
        ));
    }
    Ok(())
}

fn export_path(dir: &Path, stem: &str, extension: &str) -> io::Result<PathBuf> {
    for n in 0..10000 {
        let name = if n == 0 {
            format!("{stem}.{extension}")
        } else {
            format!("{stem}-{n}.{extension}")
        };
        let path = dir.join(name);
        if !path.try_exists()? {
            return Ok(path);
        }
    }
    Err(io::Error::other("No available export filename"))
}

fn stage(pool: &Value) -> io::Result<Option<&str>> {
    match pool.get("staged") {
        Some(Value::Null) => Ok(None),
        Some(value) => value
            .get("generation_id")
            .and_then(Value::as_str)
            .map(Some)
            .ok_or_else(|| io::Error::other("Staged generation identity unavailable")),
        None => Err(io::Error::other("Staged generation state unavailable")),
    }
}

pub(crate) fn run(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
    pool_id: &str,
    incarnation_id: &str,
) -> io::Result<()> {
    let Some(mut state) = stopped(terminal, worker, socket, |t| {
        observation(t, socket, pool_id, incarnation_id)
    })?
    else {
        return Ok(());
    };
    if stage(&state["pool"])?.is_none() {
        let generate = |t: &mut TerminalOwner| {
            lifecycle::run_stopped(
                Action::Generate,
                t,
                socket,
                Some((pool_id, incarnation_id)),
                None,
                lifecycle::Inputs {
                    file: None,
                    network: None,
                    generation_id: None,
                    destination: None,
                },
            )
        };
        match stopped(terminal, worker, socket, generate) {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(error)
                if error
                    .get_ref()
                    .is_some_and(|e| e.is::<lifecycle::MissingRecipient>()) =>
            {
                if !review_mode(terminal, "Backup recipient required", vec![
                    "The device rejected generation because it has no backup encryption recipient. Select the public JSON transferred from your backup host; keep the private key off this host.".into(),
                ], ConfirmMode::Enter("choose recipient"))? { return Ok(()); }
                let Some(path) = pick_file(
                    terminal,
                    "Choose public backup recipient",
                    &[FileKind::Recipient],
                )?
                else {
                    return Ok(());
                };
                let path = path
                    .to_str()
                    .ok_or_else(|| io::Error::other("Recipient path is not UTF-8"))?;
                if stopped(terminal, worker, socket, |t| {
                    lifecycle::run_stopped(
                        Action::Recipient,
                        t,
                        socket,
                        None,
                        None,
                        lifecycle::Inputs {
                            file: Some(path),
                            network: None,
                            generation_id: None,
                            destination: None,
                        },
                    )
                })?
                .is_none()
                {
                    return Ok(());
                }
                if stopped(terminal, worker, socket, generate)?.is_none() {
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
        let Some(refreshed) = stopped(terminal, worker, socket, |t| {
            observation(t, socket, pool_id, incarnation_id)
        })?
        else {
            return Ok(());
        };
        state = refreshed;
    }
    let generation = stage(&state["pool"])?
        .ok_or_else(|| {
            io::Error::other("Generated key is not visible in authoritative staged state")
        })?
        .to_owned();
    let root = workspace::dir(WorkspaceKind::Exports)?;
    let pool_dir = root.join(format!("pool-{}", workspace::short_id(pool_id)));
    private_dir(&pool_dir)?;
    let dir = pool_dir.join(format!("gen-{}", workspace::short_id(&generation)));
    private_dir(&dir)?;
    let vkey = export_path(&dir, "kes", "vkey")?;
    let backup = export_path(&dir, "kes", "kes-backup")?;
    for (action, path) in [
        (Action::VerificationKey, &vkey),
        (Action::Artifact, &backup),
    ] {
        let dest = path
            .to_str()
            .ok_or_else(|| io::Error::other("Export path is not UTF-8"))?;
        let result = stopped(terminal, worker, socket, |t| {
            lifecycle::run_stopped(
                action,
                t,
                socket,
                Some((pool_id, incarnation_id)),
                None,
                lifecycle::Inputs {
                    file: None,
                    network: None,
                    generation_id: Some(&generation),
                    destination: Some(dest),
                },
            )
        })?;
        if result.is_none() {
            return Ok(());
        }
    }
    let (_, bytes) = crate::manager::setup::current_config_review()?
        .ok_or_else(|| io::Error::other("Normal configuration unavailable"))?;
    let config = Config::inspect_bytes(&bytes, RunMode::Normal).map_err(io::Error::other)?;
    let binding = config
        .pools
        .iter()
        .find(|p| p.pool.to_string() == pool_id && p.incarnation.to_string() == incarnation_id)
        .ok_or_else(|| io::Error::other("Selected pool has no configured binding"))?;
    let network = config
        .networks
        .get(&binding.network)
        .ok_or_else(|| io::Error::other("Configured pool network unavailable"))?;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_micros(),
    )
    .map_err(io::Error::other)?;
    let clock = kes_clock::current_kes_period(network, now)
        .map_err(|e| io::Error::other(format!("KES clock: {e:?}")))?;
    let minutes = clock.next_period_at_us.saturating_sub(now) / 60_000_000;
    let name = vkey
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("Export filename is not UTF-8"))?;
    let mut instructions = progress_steps(
        &[
            "Generate key",
            "Export key and backup",
            "Cold machine",
            "Install certificate",
        ],
        2,
    );
    instructions.extend([
        format!("Current KES period: {} (slot {}; next period in {}h {}m)", clock.period, clock.slot, minutes / 60, minutes % 60),
        format!("Copy {} to the cold machine and run there:", vkey.display()),
        format!("cardano-cli conway node issue-op-cert --kes-verification-key-file {name} --cold-signing-key-file cold.skey --operational-certificate-issue-counter-file cold.counter --kes-period {} --out-file node.cert", clock.period),
        "Keep cold.skey and cold.counter on the cold machine. Copy the resulting node.cert back to this host.".into(),
        format!("Copy the encrypted backup {} to your backup host.", backup.display()),
        "p2kesup never runs this cold-machine command.".into(),
    ]);
    if !review_mode(
        terminal,
        "Cold machine instructions",
        instructions,
        ConfirmMode::Enter("continue when node.cert is available"),
    )? {
        return Ok(());
    }
    let Some(cert) = pick_file(
        terminal,
        "Choose cold-signed operational certificate",
        &[FileKind::OpCert],
    )?
    else {
        return Ok(());
    };
    let path = cert
        .to_str()
        .ok_or_else(|| io::Error::other("Certificate path is not UTF-8"))?;
    if state["pool"]["staged"]["certificate_present"] != true {
        let result = stopped(terminal, worker, socket, |t| lifecycle::run_stopped(Action::Certificate, t, socket, Some((pool_id, incarnation_id)), None, lifecycle::Inputs { file: Some(path), network: None, generation_id: Some(&generation), destination: None }))?;
        if result.is_none() { return Ok(()); }
    } else if !review_mode(terminal, "Previously installed certificate", vec![
        "The staged generation already has a certificate, but its identity is not exposed here.".into(),
        format!("Confirm that {} is the same certificate installed for this generation before using it on the node.", cert.display()),
    ], ConfirmMode::YesNo { danger: false })? {
        return Ok(());
    }
    review(
        terminal,
        "KES rotation complete",
        vec![
            format!(
                "--shelley-kes-agent-socket '{}'",
                binding
                    .socket_path
                    .display()
                    .to_string()
                    .replace('\'', "'\\''")
            ),
            format!(
                "--shelley-operational-certificate '{}'",
                path.replace('\'', "'\\''")
            ),
            "Use the certificate path on the node host.".into(),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{export_path, stage};
    use serde_json::json;
    #[test]
    fn staged_state_must_be_authoritative() {
        assert_eq!(stage(&json!({"staged":null})).unwrap(), None);
        assert_eq!(
            stage(&json!({"staged":{"generation_id":"abc"}})).unwrap(),
            Some("abc")
        );
        assert!(stage(&json!({})).is_err());
        assert!(stage(&json!({"staged":{}})).is_err());
    }
    #[test]
    fn resumed_exports_keep_existing_backup() {
        let dir = std::env::temp_dir().join(format!(
            "p2kesup-export-test-{}",
            crate::manager::lifecycle::new_admission_id().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let first = export_path(&dir, "kes", "kes-backup").unwrap();
        std::fs::write(&first, b"existing backup").unwrap();
        let next = export_path(&dir, "kes", "kes-backup").unwrap();
        assert_ne!(first, next);
        assert_eq!(std::fs::read(&first).unwrap(), b"existing backup");
        std::fs::remove_file(first).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
