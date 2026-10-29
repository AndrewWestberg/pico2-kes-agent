#![no_main]

use kes_core::certificate::{MAX_ENCODED_CERTIFICATE_LEN, OperationalCertificate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = OperationalCertificate::decode(data);
    if data.len() > MAX_ENCODED_CERTIFICATE_LEN {
        assert!(result.is_err());
    }
});
