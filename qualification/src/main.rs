mod benchmarks;
mod evidence;
mod fixture;
mod foundation;
mod gates;
mod hardware;
mod load;
mod native_regression;
pub mod oracle;
mod physical;
mod security;
mod tools;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let code = match args.as_slice() {
        [command] if command == "tools" => match tools::check() {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(error) => {
                eprintln!("tool inventory error: {error}");
                1
            }
        },
        [command] if command == "foundation" => foundation::run(),
        [command, flag, revision] if command == "benchmarks" && flag == "--baseline" => {
            benchmarks::run(revision)
        }
        [command] if command == "load" => load::run(),
        [command, rest @ ..] if command == "hardware" => hardware::run(rest),
        [command] if command == "native-regression" => native_regression::run(),
        [command, rest @ ..] if command == "physical-context" => physical::run(rest),
        [command, rest @ ..] if command == "security" => security::run(rest),
        [command, rest @ ..] if command == "gates" => gates::run(rest),
        [command] if command == "__foundation-memory-child" => foundation::memory_child(),
        _ => {
            eprintln!(
                "usage: qualification tools|foundation|hardware|load|native-regression|physical-context --input INPUT.json|security --input INPUT.json|benchmarks --baseline REV|gates run SCOPE|gates validate REPORT --require SCOPE"
            );
            1
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}
