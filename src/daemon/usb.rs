//! Sole-owner nusb transport with nonce-bound identity verification.

use kes_core::{device::EnrollmentRecord, identity::DeviceId};
use kes_protocol::usb::{
    self as wire, Decoder, HelloIdentity, HelloState, Kind, MAX_FRAME, MAX_PAYLOAD, Request,
    Response,
};
use nusb::{
    MaybeFuture,
    io::{EndpointRead, EndpointWrite},
    transfer::Bulk,
};
use std::{
    fs::File,
    io::{self, Read, Write},
    time::Duration,
};
use zeroize::Zeroize;

pub const USB_VENDOR_ID: u16 = 0x1209;
pub const USB_PRODUCT_ID: u16 = 0x4b45;
const INTERFACE: u8 = 0;
const ENDPOINT_OUT: u8 = 0x01;
const ENDPOINT_IN: u8 = 0x81;
const PACKET_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbSelection([u8; 16]);

impl UsbSelection {
    pub fn new(serial: &[u8]) -> Result<Self, Error> {
        serial.try_into().map(Self).map_err(|_| Error::WrongSerial)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityPin {
    pub device: DeviceId,
    pub public_key: [u8; 32],
    pub serial: UsbSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Commissioning { selected_serial: UsbSelection },
    Normal { pin: IdentityPin },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectedIdentity {
    Blank,
    Committed(IdentityPin),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Outstanding {
    sequence: u64,
    digest: kes_core::identity::Digest32,
}

#[derive(Debug)]
pub enum Error {
    Usb(nusb::Error),
    Io(io::Error),
    NotFound,
    AmbiguousSelection,
    WrongSerial,
    Interface,
    Protocol,
    IdentityMismatch,
    Signature,
    Busy,
    PreAdmission,
    Uncertain {
        sequence: u64,
        digest: kes_core::identity::Digest32,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usb(error) => write!(formatter, "USB: {error}"),
            Self::Io(error) => write!(formatter, "USB I/O: {error}"),
            Self::NotFound => formatter.write_str("selected KES device is not connected"),
            Self::AmbiguousSelection => {
                formatter.write_str("more than one device matches the selected serial")
            }
            Self::WrongSerial => formatter.write_str("USB serial does not match selection"),
            Self::Interface => formatter.write_str("KES vendor bulk interface is unavailable"),
            Self::Protocol => formatter.write_str("invalid KES USB response"),
            Self::IdentityMismatch => {
                formatter.write_str("device identity does not match the installed pin")
            }
            Self::Signature => {
                formatter.write_str("nonce-bound device identity signature is invalid")
            }
            Self::Busy => formatter.write_str("an outstanding mutation must be reconciled first"),
            Self::PreAdmission => formatter.write_str("request failed before USB admission"),
            Self::Uncertain { .. } => {
                formatter.write_str("mutation disposition is uncertain; reconcile it")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<nusb::Error> for Error {
    fn from(value: nusb::Error) -> Self {
        Self::Usb(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Bounded response bytes. Secret-bearing current-key payloads are wiped on
/// every drop and are never included in diagnostic formatting.
pub struct Reply {
    pub kind: Kind,
    payload: Vec<u8>,
}

impl Reply {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn decode(&self) -> Result<Response<'_>, Error> {
        wire::decode_response(self.kind, &self.payload).map_err(|_| Error::Protocol)
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

impl Reply {
    #[doc(hidden)]
    pub fn from_parts(kind: Kind, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }
}

pub trait DeviceTransport {
    fn request(&mut self, request: &Request) -> Result<Reply, Error>;

    fn clear_outstanding(
        &mut self,
        sequence: u64,
        digest: kes_core::identity::Digest32,
    ) -> Result<(), Error>;
}

pub struct Transport {
    writer: EndpointWrite<Bulk>,
    reader: EndpointRead<Bulk>,
    decoder: Decoder,
    request_number: u64,
    mode: Mode,
    identity: ConnectedIdentity,
    outstanding: Option<Outstanding>,
}

impl Transport {
    pub fn connect(mode: Mode, timeout: Duration) -> Result<Self, Error> {
        let selected_serial = match mode {
            Mode::Commissioning { selected_serial } => selected_serial,
            Mode::Normal { pin } => pin.serial,
        };
        let mut matches = nusb::list_devices().wait()?.filter(|device| {
            device.vendor_id() == USB_VENDOR_ID
                && device.product_id() == USB_PRODUCT_ID
                && device
                    .serial_number()
                    .is_some_and(|serial| serial.as_bytes() == selected_serial.as_bytes())
        });
        let info = matches.next().ok_or(Error::NotFound)?;
        if matches.next().is_some() {
            return Err(Error::AmbiguousSelection);
        }
        if info.serial_number().map(str::as_bytes) != Some(selected_serial.as_bytes()) {
            return Err(Error::WrongSerial);
        }
        let device = info.open().wait()?;
        let interface = device
            .claim_interface(INTERFACE)
            .wait()
            .map_err(|_| Error::Interface)?;
        let writer = interface
            .endpoint::<Bulk, nusb::transfer::Out>(ENDPOINT_OUT)
            .map_err(|_| Error::Interface)?
            .writer(PACKET_BYTES)
            .with_num_transfers(1)
            .with_write_timeout(timeout);
        let reader = interface
            .endpoint::<Bulk, nusb::transfer::In>(ENDPOINT_IN)
            .map_err(|_| Error::Interface)?
            .reader(PACKET_BYTES)
            .with_num_transfers(1)
            .with_read_timeout(timeout);
        let mut transport = Self {
            writer,
            reader,
            decoder: Decoder::new(),
            request_number: 1,
            mode,
            identity: ConnectedIdentity::Blank,
            outstanding: None,
        };
        transport.identity = transport.verify_identity()?;
        Ok(transport)
    }

    pub const fn identity(&self) -> ConnectedIdentity {
        self.identity
    }

    pub fn set_outstanding(&mut self, sequence: u64, digest: kes_core::identity::Digest32) {
        self.outstanding = Some(Outstanding { sequence, digest });
    }

    pub fn clear_outstanding(
        &mut self,
        sequence: u64,
        digest: kes_core::identity::Digest32,
    ) -> Result<(), Error> {
        if self.outstanding == Some(Outstanding { sequence, digest }) {
            self.outstanding = None;
            Ok(())
        } else {
            Err(Error::Busy)
        }
    }

    /// Exactly one request is in flight. Once mutation bytes may have reached
    /// the endpoint, all transport failures are uncertain rather than rejected.
    pub fn request(&mut self, request: &Request) -> Result<Reply, Error> {
        let mutation = request_mutation(request);
        if let Some(outstanding) = self.outstanding {
            match request {
                Request::Reconcile {
                    sequence, digest, ..
                } if *sequence == outstanding.sequence && *digest == outstanding.digest => {}
                Request::ReceiptAck {
                    sequence,
                    result_digest: _,
                } if *sequence == outstanding.sequence => {}
                _ => return Err(Error::Busy),
            }
        }

        let mut payload = [0; MAX_PAYLOAD];
        let (kind, payload_len) =
            wire::encode_request(request, &mut payload).map_err(|_| Error::Protocol)?;
        let request_number = self.request_number;
        self.request_number = self.request_number.checked_add(1).ok_or(Error::Protocol)?;
        let mut frame = [0; MAX_FRAME];
        let frame_len = wire::encode(kind, request_number, &payload[..payload_len], &mut frame)
            .map_err(|_| Error::Protocol)?;
        payload[..payload_len].zeroize();

        let admitted = mutation.is_some();
        let result = (|| {
            self.writer.write_all(&frame[..frame_len])?;
            self.writer.flush()?;
            frame[..frame_len].zeroize();
            self.read_reply(request_number)
        })();
        frame.zeroize();
        match result {
            Ok(reply) => {
                if let Some(outstanding) = mutation {
                    self.outstanding = Some(outstanding);
                }
                Ok(reply)
            }
            Err(Error::Io(_)) | Err(Error::Usb(_)) if admitted => {
                let outstanding = mutation.expect("admitted mutation");
                self.outstanding = Some(outstanding);
                Err(Error::Uncertain {
                    sequence: outstanding.sequence,
                    digest: outstanding.digest,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn read_reply(&mut self, request_number: u64) -> Result<Reply, Error> {
        let mut packet = [0; PACKET_BYTES];
        loop {
            let count = self.reader.read(&mut packet)?;
            if count == 0 {
                return Err(Error::Protocol);
            }
            let mut consumed = 0;
            while consumed < count {
                let (used, decoded) = self
                    .decoder
                    .feed(&packet[consumed..count])
                    .map_err(|_| Error::Protocol)?;
                if used == 0 {
                    return Err(Error::Protocol);
                }
                consumed += used;
                if let Some(decoded) = decoded {
                    if decoded.request_number != request_number {
                        return Err(Error::Protocol);
                    }
                    let reply = Reply {
                        kind: decoded.kind,
                        payload: decoded.payload.to_vec(),
                    };
                    packet[..count].zeroize();
                    return Ok(reply);
                }
            }
            packet[..count].zeroize();
        }
    }

    fn verify_identity(&mut self) -> Result<ConnectedIdentity, Error> {
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let reply = self.request(&Request::Hello { nonce })?;
        if reply.kind != Kind::Hello {
            return Err(Error::Protocol);
        }
        let Response::Hello(response) = reply.decode()? else {
            return Err(Error::Protocol);
        };
        if response.nonce != nonce {
            return Err(Error::Protocol);
        }
        nonce.zeroize();
        match response.state {
            HelloState::Uncommissioned => match self.mode {
                Mode::Commissioning { .. } => Ok(ConnectedIdentity::Blank),
                Mode::Normal { .. } => Err(Error::IdentityMismatch),
            },
            HelloState::Committed(identity) => {
                verify_hello(&response, identity)?;
                let observed = IdentityPin {
                    device: identity.device,
                    public_key: identity.public_key,
                    serial: UsbSelection::new(identity.serial.as_slice())?,
                };
                match self.mode {
                    Mode::Commissioning { selected_serial }
                        if observed.serial == selected_serial =>
                    {
                        Ok(ConnectedIdentity::Committed(observed))
                    }
                    Mode::Normal { pin } if pin == observed => {
                        Ok(ConnectedIdentity::Committed(observed))
                    }
                    _ => Err(Error::IdentityMismatch),
                }
            }
        }
    }
}

impl DeviceTransport for Transport {
    fn request(&mut self, request: &Request) -> Result<Reply, Error> {
        Self::request(self, request)
    }

    fn clear_outstanding(
        &mut self,
        sequence: u64,
        digest: kes_core::identity::Digest32,
    ) -> Result<(), Error> {
        Self::clear_outstanding(self, sequence, digest)
    }
}

fn verify_hello(response: &wire::HelloResponse, identity: HelloIdentity) -> Result<(), Error> {
    let mut signing = [0; MAX_PAYLOAD];
    let len = wire::encode_hello_signing(response, &mut signing).map_err(|_| Error::Protocol)?;
    let valid = EnrollmentRecord::verify_identity_message(
        &identity.public_key,
        &signing[..len],
        &identity.signature,
    );
    signing[..len].zeroize();
    if valid { Ok(()) } else { Err(Error::Signature) }
}

fn request_mutation(request: &Request) -> Option<Outstanding> {
    let mutation = match request {
        Request::Mutate(mutation) | Request::Commission(mutation) => mutation,
        _ => return None,
    };
    Some(Outstanding {
        sequence: mutation.sequence(),
        digest: mutation.usb_digest(),
    })
}
