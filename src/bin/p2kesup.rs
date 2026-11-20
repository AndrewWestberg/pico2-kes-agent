use pico2_kes_agent::updater;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!(
            "p2kesup - Pico 2 KES Agent Software Updater\n\n\
             USAGE:\n  p2kesup <install|update|uninstall|status> [--bundle DIR] [--prefix DIR] [--version [--json]]"
        );
        return;
    }
    if args[0] == "--version" {
        let json = args.iter().any(|a| a == "--json");
        let _ = pico2_kes_agent::build_info::write_version(std::io::stdout(), "p2kesup", json);
        return;
    }

    let prefix = args
        .windows(2)
        .find(|w| w[0] == "--prefix")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(|| PathBuf::from(updater::DEFAULT_PREFIX));
    let bundle = args
        .windows(2)
        .find(|w| w[0] == "--bundle")
        .map(|w| PathBuf::from(&w[1]));

    let res: Result<(), String> = match args[0].as_str() {
        "install" => {
            let b = bundle.unwrap_or_else(|| PathBuf::from("."));
            updater::install_or_update(&b, &prefix, false)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        "update" => {
            let b = bundle.unwrap_or_else(|| PathBuf::from("."));
            updater::install_or_update(&b, &prefix, true)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        "uninstall" => updater::uninstall(&prefix).map_err(|e| e.to_string()),
        "status" => match updater::load_state(&prefix) {
            Ok(Some(st)) => {
                println!("{}", serde_json::to_string_pretty(&st).unwrap());
                Ok(())
            }
            Ok(None) => {
                println!("not installed");
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        },
        other => Err(format!("unknown subcommand: {other}")),
    };
    if let Err(err) = res {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
