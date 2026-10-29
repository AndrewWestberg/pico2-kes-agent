#![no_main]

use kes_protocol::node_service::{
    decode_choice, decode_confirmation, decode_initialization, decode_offer, decode_publication,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_offer(data);
    let _ = decode_choice(data);
    let _ = decode_initialization(data);
    let _ = decode_publication(data);
    let _ = decode_confirmation(data);
});
