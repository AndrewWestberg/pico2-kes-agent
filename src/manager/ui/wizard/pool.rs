use super::{
    super::{
        lifecycle::{self, Action},
        setup,
        widgets::{ConfirmMode, FieldSpec, form_validated, pick_file, progress_steps, review_mode},
    },
    rotate,
};
use crate::manager::{
    config_builder,
    discovery::files::FileKind,
    host::{self, HostAction, ServiceAction},
    observe::Worker,
    terminal::TerminalOwner,
};
use std::{io, path::Path};

fn select_network(terminal: &mut TerminalOwner, networks: &[String]) -> io::Result<Option<String>> {
    match networks {
        [] => Err(io::Error::other("No configured network is available")),
        [only] => Ok(Some(only.clone())),
        _ => {
            let options: Vec<_> = networks
                .iter()
                .map(|n| (n.as_str(), "configured network"))
                .collect();
            form_validated(
                terminal,
                "Choose pool network",
                &[FieldSpec::select("Network", &networks[0], &options)],
                |v| Ok(v[0].clone()),
            )
        }
    }
}

pub(crate) fn run(
    terminal: &mut TerminalOwner,
    worker: &mut Option<Worker>,
    socket: &Path,
) -> io::Result<()> {
    if !review_mode(
        terminal,
        "Add a pool",
        progress_steps(&["Enroll pool", "Bind and restart", "Rotate KES"], 0),
        ConfirmMode::Enter("continue"),
    )? {
        return Ok(());
    }
    let (_, current) = crate::manager::setup::current_config_review()?
        .ok_or_else(|| io::Error::other("Normal configuration is unavailable"))?;
    let networks = config_builder::configured_networks(&current);
    let Some(network) = select_network(terminal, &networks)? else {
        return Ok(());
    };
    let Some(cold) = pick_file(
        terminal,
        "Choose cold verification key",
        &[FileKind::ColdVkey],
    )?
    else {
        return Ok(());
    };
    let cold = cold
        .to_str()
        .ok_or_else(|| io::Error::other("Cold key path is not UTF-8"))?;
    let Some((pool, incarnation, _)) = rotate::stopped(terminal, worker, socket, |t| {
        lifecycle::run_stopped(
            Action::Enroll,
            t,
            socket,
            None,
            None,
            lifecycle::Inputs {
                file: Some(cold),
                network: Some(&network),
                generation_id: None,
                destination: None,
            },
        )
    })?
    else {
        return Ok(());
    };
    let (_, current) = crate::manager::setup::current_config_review()?
        .ok_or_else(|| io::Error::other("Normal configuration is unavailable"))?;
    let pool_socket = config_builder::default_pool_socket_path(&current, &pool);
    let updated =
        config_builder::bind_pool_bytes(&current, &pool, &incarnation, &network, &pool_socket)?;
    let candidate = config_builder::publish_candidate("bind-pool", &updated)?;
    setup::configuration(terminal, worker, socket, false, candidate)?;
    let (_, actual) = crate::manager::setup::current_config_review()?
        .ok_or_else(|| io::Error::other("Pool binding was not installed"))?;
    if actual != updated {
        return Err(io::Error::other(
            "Pool binding was not installed; use the binding repair action before rotation",
        ));
    }
    if !review_mode(
        terminal,
        "Restart agent",
        vec![format!(
            "The pool is bound to {}. Restart the agent to apply the configuration before rotating.",
            pool_socket.display()
        )],
        ConfirmMode::YesNo { danger: false },
    )? {
        return Ok(());
    }
    let expected_state = host::observed_service_state(false)?;
    setup::apply(
        terminal,
        worker,
        socket,
        HostAction::Service {
            operation: ServiceAction::Restart,
            expected_state,
        },
        None,
    )?;
    rotate::run(terminal, worker, socket, &pool, &incarnation)
}
