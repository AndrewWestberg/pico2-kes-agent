#![no_main]

use kes_protocol::management::{self, FrameDecoder, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > management::MAX_FRAME * 2 + 8 {
        return;
    }

    if data.len() <= management::MAX_FRAME {
        let _ = Message::decode(data);
    }

    let width = data
        .first()
        .copied()
        .map_or(1, |byte| usize::from(byte % 31) + 1);
    let mut decoder = FrameDecoder::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + width).min(data.len());
        match decoder.feed(&data[offset..end]) {
            Ok(used) => {
                assert!(used <= end - offset);
                if let Some(frame) = decoder.frame() {
                    assert!(frame.len() <= management::MAX_FRAME);
                    let _ = Message::decode(frame);
                    break;
                }
                if used == 0 {
                    break;
                }
                offset += used;
            }
            Err(_) => break,
        }
    }
});
