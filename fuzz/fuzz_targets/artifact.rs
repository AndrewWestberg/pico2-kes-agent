#![no_main]

use kes_core::public_object::MAX_ARTIFACT_LEN;
use kes_protocol::usb::{ArtifactResult, decode_artifact_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(response) = decode_artifact_response(data)
        && let ArtifactResult::Retained { artifact, .. } = response.result
    {
        assert!(artifact.len() <= MAX_ARTIFACT_LEN);
    }
});
