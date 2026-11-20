fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        let json = args.iter().any(|a| a == "--json");
        let _ = pico2_kes_agent::build_info::write_version(std::io::stdout(), "p2kes", json);
        return;
    }
    if let Err(err) = pico2_kes_agent::cli::run(args) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
