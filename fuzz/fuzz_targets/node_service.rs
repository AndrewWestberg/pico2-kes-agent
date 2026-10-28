#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    panic!("node-service parser is not implemented; this fuzz scope is pending");
});
