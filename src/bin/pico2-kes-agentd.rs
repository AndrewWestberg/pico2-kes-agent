use pico2_kes_agent::{
    config::{Config, RunMode},
    daemon::runtime,
};
use std::path::PathBuf;

fn main() {
    match execute(std::env::args().skip(1)) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn execute(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut config_path = None;
    let mut mode = RunMode::Normal;
    let mut check = false;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" => {
                if config_path.is_some() || mode != RunMode::Normal || check {
                    return Err("--version must be used alone or with --json".to_owned());
                }
                let json = match (arguments.next(), arguments.next()) {
                    (None, None) => false,
                    (Some(arg), None) if arg == "--json" => true,
                    _ => return Err("--version must be used alone or with --json".to_owned()),
                };
                return pico2_kes_agent::build_info::write_version(
                    std::io::stdout().lock(),
                    "pico2-kes-agentd",
                    json,
                )
                .map_err(|error| format!("failed to write command output: {error}"));
            }
            "--config" => {
                if config_path.is_some() {
                    return Err("--config specified more than once".to_owned());
                }
                config_path = Some(PathBuf::from(
                    arguments.next().ok_or("--config requires FILE")?,
                ));
            }
            "--commission" => {
                if mode == RunMode::Commissioning {
                    return Err("--commission specified more than once".to_owned());
                }
                mode = RunMode::Commissioning;
            }
            "--check-config" => {
                if check {
                    return Err("--check-config specified more than once".to_owned());
                }
                check = true;
            }
            "--help" => {
                if arguments.any(|argument| argument == "--version") {
                    return Err("--version must be used alone or with --json".to_owned());
                }
                println!(
                    "usage: pico2-kes-agentd --config FILE [--check-config] [--commission]\n\
                     --commission is attended blank-device initialization only; install the emitted identity pin in normal configuration before enrolling pools"
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let path = config_path.ok_or("missing --config FILE")?;
    let config = Config::load(&path, mode).map_err(|error| error.to_string())?;
    if check {
        println!(
            "configuration valid ({})",
            match mode {
                RunMode::Normal => "normal",
                RunMode::Commissioning => "commissioning",
            }
        );
        return Ok(());
    }
    if mode == RunMode::Commissioning {
        eprintln!(
            "commissioning mode: only status, commission, and reconciliation are exposed; after commissioning, stop this process and install the emitted device identity pin in normal configuration"
        );
    }
    runtime::serve(config).map_err(|error| error.to_string())
}
