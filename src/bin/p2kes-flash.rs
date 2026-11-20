use pico2_kes_agent::flash;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!(
            "p2kes-flash - Pico 2 Firmware Flasher\n\n\
             USAGE:\n  p2kes-flash <verify|flash|wipe|otp> [ARGS] [--version [--json]]"
        );
        return;
    }
    if args[0] == "--version" {
        let json = args.iter().any(|a| a == "--json");
        let _ = pico2_kes_agent::build_info::write_version(std::io::stdout(), "p2kes-flash", json);
        return;
    }

    let res: Result<(), String> = match args[0].as_str() {
        "verify" => {
            let uf2 = args.get(1).map(PathBuf::from);
            flash::cmd_verify(&PathBuf::from("."), uf2.as_deref())
        }
        "flash" => {
            let uf2 = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/local/share/pico2-kes-agent/firmware.uf2"));
            flash::cmd_flash(&uf2)
        }
        "wipe" => flash::picotool::wipe_device(&flash::default_picotool()),
        "otp" => {
            let stage = args.get(1).map(String::as_str).unwrap_or("");
            let json = args.get(2).map(PathBuf::from).unwrap_or_default();
            flash::picotool::otp_stage(&flash::default_picotool(), stage, &json)
        }
        other => Err(format!("unknown subcommand: {other}")),
    };
    if let Err(err) = res {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
