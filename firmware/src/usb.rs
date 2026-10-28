//! Vendor-specific bulk transport. Framing errors poison the connection until
//! USB disconnect; the device never scans attacker-controlled bytes for magic.
use embassy_usb::{
    Builder,
    driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointOut},
};
use kes_protocol::usb::{self as wire, Decoder, Kind, MAX_FRAME, MAX_PAYLOAD};
use zeroize::Zeroize;

pub const MAX_PACKET_SIZE: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    Protocol,
    State,
}

/// One request is dispatched at a time. Implementations must return a complete
/// canonical-CBOR payload; no secret-bearing response is retained by transport.
pub trait Dispatcher {
    fn reconnect(&mut self);

    fn dispatch(
        &mut self,
        kind: Kind,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<(Kind, usize), DispatchError>;
}

pub struct VendorBulk<'d, D: Driver<'d>> {
    read: D::EndpointOut,
    write: D::EndpointIn,
}

impl<'d, D: Driver<'d>> VendorBulk<'d, D> {
    pub fn new(builder: &mut Builder<'d, D>) -> Self {
        let mut function = builder.function(0xff, 0x50, 0x01);
        let mut interface = function.interface();
        let mut alternate = interface.alt_setting(0xff, 0x50, 0x01, None);
        let read = alternate.endpoint_bulk_out(None, MAX_PACKET_SIZE);
        let write = alternate.endpoint_bulk_in(None, MAX_PACKET_SIZE);
        drop(function);
        Self { read, write }
    }

    pub async fn run<H: Dispatcher>(&mut self, handler: &mut H) -> ! {
        let mut decoder = Decoder::new();
        let mut packet = [0; MAX_PACKET_SIZE as usize];
        let mut response_payload = [0; MAX_PAYLOAD];
        let mut response_frame = [0; MAX_FRAME];
        loop {
            self.read.wait_enabled().await;
            decoder.reconnect();
            handler.reconnect();
            let mut poisoned = false;
            loop {
                let count = match self.read.read(&mut packet).await {
                    Ok(count) => count,
                    Err(EndpointError::Disabled) => break,
                    Err(EndpointError::BufferOverflow) => {
                        poisoned = true;
                        continue;
                    }
                };
                if poisoned {
                    packet[..count].zeroize();
                    continue;
                }
                let mut consumed = 0;
                while consumed < count {
                    let result = decoder.feed(&packet[consumed..count]);
                    let (used, frame) = match result {
                        Ok(value) => value,
                        Err(_) => {
                            poisoned = true;
                            break;
                        }
                    };
                    consumed += used;
                    let Some(frame) = frame else {
                        continue;
                    };
                    let (response_kind, payload_len) =
                        match handler.dispatch(frame.kind, frame.payload, &mut response_payload) {
                            Ok(value) => value,
                            Err(_) => {
                                poisoned = true;
                                break;
                            }
                        };
                    let frame_len = match wire::encode(
                        response_kind,
                        frame.request_number,
                        &response_payload[..payload_len],
                        &mut response_frame,
                    ) {
                        Ok(value) => value,
                        Err(_) => {
                            poisoned = true;
                            break;
                        }
                    };
                    if self.write_all(&response_frame[..frame_len]).await.is_err() {
                        break;
                    }
                    response_payload[..payload_len].zeroize();
                    response_frame[..frame_len].zeroize();
                }
                packet[..count].zeroize();
            }
            packet.zeroize();
            response_payload.zeroize();
            response_frame.zeroize();
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), EndpointError> {
        for chunk in bytes.chunks(MAX_PACKET_SIZE as usize) {
            self.write.write(chunk).await?;
        }
        if bytes.len().is_multiple_of(MAX_PACKET_SIZE as usize) {
            self.write.write(&[]).await?;
        }
        Ok(())
    }
}
