#![no_main]

use kes_protocol::usb::{self, Decoder, Error, Kind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > usb::MAX_FRAME * 2 {
        return;
    }

    if data.len() <= usb::MAX_PAYLOAD {
        for kind in [
            Kind::Hello,
            Kind::Status,
            Kind::Context,
            Kind::Mutate,
            Kind::Reconcile,
            Kind::ReceiptAck,
            Kind::Current,
            Kind::Artifact,
            Kind::PublicKey,
            Kind::Commission,
        ] {
            let _ = usb::decode_request(kind, data);
            let _ = usb::decode_response(kind, data);
        }
    }

    let width = data
        .first()
        .copied()
        .map_or(1, |byte| usize::from(byte % 31) + 1);
    let mut decoder = Decoder::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + width).min(data.len());
        match decoder.feed(&data[offset..end]) {
            Ok((used, frame)) => {
                assert!(used <= end - offset);
                if let Some(frame) = frame {
                    assert!(frame.payload.len() <= usb::MAX_PAYLOAD);
                    let _ = usb::decode_request(frame.kind, frame.payload);
                    let _ = usb::decode_response(frame.kind, frame.payload);
                }
                assert!(decoder.buffered_len() <= usb::MAX_FRAME);
                if used == 0 {
                    break;
                }
                offset += used;
            }
            Err(_) => {
                assert!(matches!(decoder.feed(&[]), Err(Error::Poisoned)));
                break;
            }
        }
    }
});
