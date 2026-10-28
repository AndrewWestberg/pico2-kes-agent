//! Native regression is deliberately separate from fixture parsing and from
//! the future receiver/finalizer cases. An empty registry is not a pass.
use crate::fixture::{self, Fixture};
use std::fs::File;
use std::io::Read;
use std::path::Path;

struct NativeCase {
    name: &'static str,
    run: fn(&Fixture) -> Result<(), &'static str>,
}

// T047/T055 must register actual native receiver/finalizer cases here. Do not
// add synthetic checks: executing no native cases is explicitly inconclusive.
const CASES: &[NativeCase] = &[];

pub fn run(path: &Path) -> i32 {
    let fixture = match load(path) {
        Ok(fixture) => fixture,
        Err(error) => {
            eprintln!("native-regression: {error}");
            return 1;
        }
    };
    if let Err(error) = fixture.validate_prerequisites() {
        eprintln!("native-regression: prerequisite validation failed: {error}");
        return 1;
    }
    if CASES.is_empty() {
        eprintln!(
            "native-regression: inconclusive: zero registered native cases; receiver/finalizer cases pending"
        );
        return 1;
    }
    let mut failed = false;
    for case in CASES {
        if (case.run)(&fixture).is_err() {
            eprintln!("native-regression: case failed: {}", case.name);
            failed = true;
        }
    }
    if failed { 1 } else { 0 }
}

fn load(path: &Path) -> Result<Fixture, String> {
    let file = File::open(path).map_err(|_| "cannot open fixture".to_owned())?;
    let mut bytes = Vec::new();
    file.take((fixture::MAX_FIXTURE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read fixture".to_owned())?;
    fixture::parse_fixture(&bytes).map_err(|error| format!("invalid fixture: {error}"))
}
