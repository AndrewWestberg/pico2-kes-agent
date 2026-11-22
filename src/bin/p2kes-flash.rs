use pico2_kes_agent::flash;
use std::path::{Path, PathBuf};

fn parse_firmware_args(args: &[String]) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
    let mut firmware_dir = None;
    let mut uf2_path = None;
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--firmware-dir" | "--bundle" => {
                if firmware_dir.is_some() {
                    return Err("duplicate --firmware-dir option".into());
                }
                let dir = args
                    .get(idx + 1)
                    .ok_or_else(|| format!("{} requires a directory path", args[idx]))?;
                firmware_dir = Some(PathBuf::from(dir));
                idx += 2;
            }
            opt if opt.starts_with('-') => {
                return Err(format!("unknown option: {opt}"));
            }
            positional => {
                if uf2_path.is_some() {
                    return Err(format!("unexpected extra argument: {positional}"));
                }
                uf2_path = Some(PathBuf::from(positional));
                idx += 1;
            }
        }
    }
    Ok((firmware_dir, uf2_path))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        println!(
            "p2kes-flash - Pico 2 Firmware Flasher\n\n\
             USAGE:\n  \
             p2kes-flash verify [--firmware-dir DIR] [UF2]\n  \
             p2kes-flash flash [--firmware-dir DIR] [UF2]\n  \
             p2kes-flash <wipe|otp> [ARGS]\n  \
             p2kes-flash --version [--json]"
        );
        return;
    }
    if args[0] == "--version" {
        let json = args.iter().any(|a| a == "--json");
        let _ = pico2_kes_agent::build_info::write_version(std::io::stdout(), "p2kes-flash", json);
        return;
    }

    let res: Result<(), String> = match args[0].as_str() {
        "verify" => match parse_firmware_args(&args[1..]) {
            Ok((Some(dir), uf2)) => flash::cmd_verify(&dir, uf2.as_deref()),
            Ok((None, None)) => flash::cmd_verify(Path::new(flash::DEFAULT_FIRMWARE_DIR), None),
            Ok((None, Some(path))) => {
                if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                    flash::cmd_verify(&path, None)
                } else {
                    let dir = flash::manifest_dir_for_uf2(&path);
                    flash::cmd_verify(&dir, Some(&path))
                }
            }
            Err(e) => Err(e),
        },
        "flash" => match parse_firmware_args(&args[1..]) {
            Ok((Some(dir), uf2)) => flash::cmd_flash_from_dir(&dir, uf2.as_deref()),
            Ok((None, None)) => {
                let staged_uf2 = flash::default_staged_uf2();
                flash::cmd_flash_from_dir(Path::new(flash::DEFAULT_FIRMWARE_DIR), Some(&staged_uf2))
            }
            Ok((None, Some(uf2))) => flash::cmd_flash(&uf2),
            Err(e) => Err(e),
        },
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
