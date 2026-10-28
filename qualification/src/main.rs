mod attended;
mod benchmarks;
mod evidence;
mod fixture;
mod foundation;
mod gates;
mod hardware;
mod native_regression;
pub mod oracle;
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
        [command, rest @ ..] if command == "attended-cuts" => attended::run(rest),
        [command, rest @ ..] if command == "hardware" => hardware::run(rest),
        [command, flag, path] if command == "native-regression" && flag == "--fixture" => {
            native_regression::run(std::path::Path::new(path))
        }
        [command, rest @ ..] if command == "gates" => gates::run(rest),
        [command] if command == "__foundation-memory-child" => foundation::memory_child(),
        _ => {
            eprintln!(
                "usage: qualification tools|foundation|hardware [--input PHYSICAL_INPUT.json|--write-template PATH]|attended-cuts --fixture FIXTURE --cuts 10|benchmarks --baseline REV|gates run SCOPE|gates validate REPORT --require SCOPE|native-regression --fixture PATH"
            );
            1
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}
