use std::io;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let version = match arguments.as_slice() {
        [version] if version == "--version" => Some(false),
        [version, json] if version == "--version" && json == "--json" => Some(true),
        _ => None,
    };
    if let Some(json) = version {
        let exit = match pico2_kes_agent::build_info::write_version(
            io::stdout().lock(),
            "pico2-kes-agent-cli",
            json,
        ) {
            Ok(()) => pico2_kes_agent::cli::EXIT_SUCCESS,
            Err(error) => {
                eprintln!("failed to write command output: {error}");
                pico2_kes_agent::cli::EXIT_FAILURE
            }
        };
        std::process::exit(exit);
    }
    let exit = pico2_kes_agent::cli::run(&arguments, &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit);
}
