use std::io;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let exit = pico2_kes_agent::cli::run(&arguments, &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit);
}
