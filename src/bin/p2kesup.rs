use std::{ffi::OsString, io, path::PathBuf};

use pico2_kes_agent::{
    build_info, cli,
    manager::{model::InstallationRole, ui},
};

const USAGE: &str = "Usage: p2kesup [--role primary|backup] [--socket PATH] [--bundle DIRECTORY]\n       p2kesup install --bundle DIRECTORY --role primary|backup\n       p2kesup upgrade [--version TAG | --bundle DIRECTORY | --resume PLAN]\n       p2kesup --help | --version [--json]";

fn main() {
    std::process::exit(run(std::env::args_os().skip(1).collect()));
}

fn run(args: Vec<OsString>) -> i32 {
    if args == ["--help"] {
        println!("{USAGE}");
        return cli::EXIT_SUCCESS;
    }
    if args == ["--version"] || args == ["--version", "--json"] {
        return match build_info::write_version(io::stdout().lock(), "p2kesup", args.len() == 2) {
            Ok(()) => cli::EXIT_SUCCESS,
            Err(error) => {
                eprintln!("failed to write command output: {error}");
                cli::EXIT_FAILURE
            }
        };
    }
    if args
        .first()
        .is_some_and(|arg| arg == "release-discovery-worker")
    {
        if args.len() != 4
            || args[1].is_empty()
            || !matches!(args[2].to_str(), Some("0" | "1"))
            || !matches!(args[3].to_str(), Some("0" | "1"))
        {
            return invalid();
        }
        return match pico2_kes_agent::manager::release_discovery::run_worker(
            &PathBuf::from(&args[1]),
            args[2] == "1",
            args[3] == "1",
        ) {
            Ok(()) => cli::EXIT_SUCCESS,
            Err(error) => {
                eprintln!(
                    "release discovery failed: {}",
                    error.to_string().escape_default()
                );
                cli::EXIT_FAILURE
            }
        };
    }
    if args
        .first()
        .is_some_and(|arg| arg == "host-firmware-preview")
    {
        if !matches!(args.len(), 3 | 5)
            || args[1] != "--id"
            || args[2].to_str().is_none()
            || (args.len() == 5 && (args[3] != "--temporary-state" || args[4].to_str().is_none()))
        {
            return invalid();
        }
        return host_result(
            pico2_kes_agent::manager::host::firmware_preview_to(
                args[2].to_str().unwrap(),
                args.get(4).and_then(|value| value.to_str()),
            )
            .map(|path| println!("Protected public firmware review: {}", path.display())),
        );
    }
    if args.first().is_some_and(|arg| arg == "host-backup-admit") {
        if args.len() != 3 || args[1] != "--socket" || args[2].is_empty() {
            return invalid();
        }
        return host_result(pico2_kes_agent::manager::backup::admit(&PathBuf::from(
            &args[2],
        )));
    }
    if args
        .first()
        .is_some_and(|arg| arg == "host-lifecycle-admit")
    {
        if !matches!(args.len(), 3 | 5)
            || args[1] != "--id"
            || args[2].to_str().is_none()
            || (args.len() == 5
                && (args[3] != "--commissioning-serial"
                    || args[4].to_str().is_none_or(str::is_empty)))
        {
            return invalid();
        }
        let caller = match caller_identity(std::env::var("SUDO_UID"), rustix::process::getuid().as_raw()) {
            Ok(uid) => uid,
            Err(error) => return host_result(Err(error)),
        };
        return host_result(pico2_kes_agent::manager::lifecycle::admit(
            args[2].to_str().unwrap(),
            caller,
            args.get(4).and_then(|value| value.to_str()),
        ));
    }
    if args
        .first()
        .is_some_and(|arg| arg == "host-apply" || arg == "host-inspect" || arg == "host-admit")
    {
        if args.len() != 3 || args[1] != "--plan" || args[2].is_empty() {
            return invalid();
        }
        let path = PathBuf::from(&args[2]);
        let result = if args[0] == "host-inspect" {
            pico2_kes_agent::manager::host::inspect_plan(&path)
        } else if args[0] == "host-admit" {
            pico2_kes_agent::manager::host::admit_plan(&path)
        } else {
            pico2_kes_agent::manager::host::apply_plan(&path)
        };
        return host_result(result);
    }
    if args.first().is_some_and(|arg| arg == "install") {
        let mut role = None;
        let mut bundle = None;
        let mut args = args.into_iter().skip(1);
        while let Some(arg) = args.next() {
            let Some(value) = args.next().filter(|value| !value.is_empty()) else {
                return invalid();
            };
            if arg == "--role" && role.is_none() {
                role = if value == "primary" {
                    Some(InstallationRole::Primary)
                } else if value == "backup" {
                    Some(InstallationRole::Backup)
                } else {
                    return invalid();
                };
            } else if arg == "--bundle" && bundle.is_none() {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return invalid();
                }
                bundle = Some(path);
            } else {
                return invalid();
            }
        }
        return match (bundle, role) {
            (Some(bundle), Some(role)) => host_result(ui::install(bundle, role)),
            _ => invalid(),
        };
    }
    if args.first().is_some_and(|arg| arg == "upgrade") {
        let mut version = None;
        let mut bundle = None;
        let mut resume = None;
        let mut args = args.into_iter().skip(1);
        while let Some(arg) = args.next() {
            let Some(value) = args.next().filter(|value| !value.is_empty()) else {
                return invalid();
            };
            if arg == "--version" && version.is_none() && bundle.is_none() && resume.is_none() {
                let Some(tag) = value.to_str() else { return invalid() };
                if tag.len() > 128 || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) || tag.starts_with('-') {
                    return invalid();
                }
                version = Some(tag.to_owned());
            } else if arg == "--bundle" && bundle.is_none() && version.is_none() && resume.is_none() {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return invalid();
                }
                bundle = Some(path);
            } else if arg == "--resume" && resume.is_none() && version.is_none() && bundle.is_none() {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return invalid();
                }
                resume = Some(path);
            } else {
                return invalid();
            }
        }
        return host_result(match resume {
            Some(path) => ui::resume_upgrade(path),
            None => ui::upgrade(version.as_deref(), bundle),
        });
    }
    let mut role = InstallationRole::Primary;
    let mut socket = PathBuf::from("/run/pico2-kes-agent/management.sock");
    let mut bundle = None;
    let mut role_seen = false;
    let mut socket_seen = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let value = match args.next() {
            Some(value) if !value.is_empty() => value,
            _ => return invalid(),
        };
        if arg == "--role" && !role_seen {
            role_seen = true;
            role = if value == "primary" {
                InstallationRole::Primary
            } else if value == "backup" {
                InstallationRole::Backup
            } else {
                return invalid();
            };
        } else if arg == "--socket" && !socket_seen && !value.to_string_lossy().starts_with('-') {
            socket_seen = true;
            socket = value.into();
        } else if arg == "--bundle" && bundle.is_none() && !value.to_string_lossy().starts_with('-')
        {
            bundle = Some(PathBuf::from(value));
        } else {
            return invalid();
        }
    }
    ui::run(role, socket, bundle)
}

fn caller_identity(value: Result<String, std::env::VarError>, direct_uid: u32) -> io::Result<u32> {
    match value {
        Ok(value) => value.parse().map_err(|_| io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid privilege caller identity",
        )),
        Err(std::env::VarError::NotPresent) => Ok(direct_uid),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid privilege caller identity",
        )),
    }
}

fn invalid() -> i32 {
    eprintln!("{USAGE}");
    cli::EXIT_INVOCATION
}

fn host_result(result: io::Result<()>) -> i32 {
    match result {
        Ok(()) => cli::EXIT_SUCCESS,
        Err(error) => {
            eprintln!(
                "host maintenance failed: {}",
                error.to_string().escape_default()
            );
            if error.kind() == io::ErrorKind::PermissionDenied {
                cli::EXIT_PERMISSION
            } else {
                cli::EXIT_FAILURE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::caller_identity;
    use std::{env::VarError, ffi::OsString, io, os::unix::ffi::OsStringExt};

    #[test]
    fn lifecycle_caller_identity_uses_sudo_uid_and_rejects_invalid_values() {
        assert_eq!(caller_identity(Ok("1234".into()), 0).unwrap(), 1234);
        assert_eq!(caller_identity(Err(VarError::NotPresent), 0).unwrap(), 0);
        for value in [
            Ok("invalid".into()),
            Ok("4294967296".into()),
            Err(VarError::NotUnicode(OsString::from_vec(vec![0xff]))),
        ] {
            assert_eq!(caller_identity(value, 0).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }
}
