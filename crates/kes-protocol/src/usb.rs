//! USB v1 framing and restricted canonical CBOR primitives.
//!
//! The decoder is connection-scoped. An error poisons it until `reconnect`;
//! callers must not search the stream for another magic word. Neither frames
//! nor their decoder implement `Debug`: current responses can contain secrets.

pub const HEADER_LEN: usize = 20;
pub const MAX_PAYLOAD: usize = 4096;
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PAYLOAD + 4;
pub const MAJOR: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Magic,
    Major,
    Kind,
    Length,
    Crc,
    Cbor,
    Schema,
    OutputTooSmall,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Kind {
    Hello = 1,
    Status,
    Context,
    Mutate,
    Reconcile,
    ReceiptAck,
    Current,
    Artifact,
    PublicKey,
    Commission,
    SecurityStatus,
}
impl TryFrom<u16> for Kind {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::Status,
            3 => Self::Context,
            4 => Self::Mutate,
            5 => Self::Reconcile,
            6 => Self::ReceiptAck,
            7 => Self::Current,
            8 => Self::Artifact,
            9 => Self::PublicKey,
            10 => Self::Commission,
            11 => Self::SecurityStatus,
            _ => return Err(Error::Kind),
        })
    }
}

/// A borrowed frame; the request number is transport-local, not an operation ID.
pub struct Frame<'a> {
    pub kind: Kind,
    pub request_number: u64,
    pub payload: &'a [u8],
}

/// Decoder stores no more than one frame, with a fixed maximum footprint.
pub struct Decoder {
    bytes: [u8; MAX_FRAME],
    len: usize,
    total: usize,
    poisoned: bool,
    complete: bool,
}
impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
impl Decoder {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_FRAME],
            len: 0,
            total: 0,
            poisoned: false,
            complete: false,
        }
    }
    /// Discard both partial frames and errors on a new connection.
    pub fn reconnect(&mut self) {
        self.bytes[..self.len].fill(0);
        self.len = 0;
        self.total = 0;
        self.poisoned = false;
        self.complete = false;
    }
    pub const fn buffered_len(&self) -> usize {
        self.len
    }
    /// Consume at most one frame. `used` allows the caller to retain surplus
    /// input. A returned frame borrows this decoder until the next call.
    pub fn feed<'a>(&'a mut self, input: &[u8]) -> Result<(usize, Option<Frame<'a>>), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.complete {
            self.bytes[..self.len].fill(0);
            self.len = 0;
            self.total = 0;
            self.complete = false;
        }
        let mut used = 0;
        if self.len < HEADER_LEN {
            let n = core::cmp::min(HEADER_LEN - self.len, input.len());
            self.bytes[self.len..self.len + n].copy_from_slice(&input[..n]);
            self.len += n;
            used += n;
            if self.len < HEADER_LEN {
                return Ok((used, None));
            }
            let checked = self.check_header();
            if let Err(e) = checked {
                self.poisoned = true;
                return Err(e);
            }
        }
        let n = core::cmp::min(self.total - self.len, input.len() - used);
        self.bytes[self.len..self.len + n].copy_from_slice(&input[used..used + n]);
        self.len += n;
        used += n;
        if self.len < self.total {
            return Ok((used, None));
        }
        let payload_end = self.total - 4;
        let actual = u32::from_be_bytes(self.bytes[payload_end..self.total].try_into().unwrap());
        if crc32c(&self.bytes[..payload_end]) != actual {
            self.poisoned = true;
            return Err(Error::Crc);
        }
        if validate_cbor(&self.bytes[HEADER_LEN..payload_end]).is_err() {
            self.poisoned = true;
            return Err(Error::Cbor);
        }
        self.complete = true;
        Ok((
            used,
            Some(Frame {
                kind: Kind::try_from(u16::from_be_bytes([self.bytes[6], self.bytes[7]]))?,
                request_number: u64::from_be_bytes(self.bytes[8..16].try_into().unwrap()),
                payload: &self.bytes[HEADER_LEN..payload_end],
            }),
        ))
    }
    fn check_header(&mut self) -> Result<(), Error> {
        if &self.bytes[..4] != b"PKA1" {
            return Err(Error::Magic);
        }
        if u16::from_be_bytes([self.bytes[4], self.bytes[5]]) != MAJOR {
            return Err(Error::Major);
        }
        Kind::try_from(u16::from_be_bytes([self.bytes[6], self.bytes[7]]))?;
        let n = u32::from_be_bytes(self.bytes[16..20].try_into().unwrap()) as usize;
        if n > MAX_PAYLOAD {
            return Err(Error::Length);
        }
        self.total = HEADER_LEN + n + 4;
        Ok(())
    }
}
impl Drop for Decoder {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Encode one frame into caller-owned storage.
pub fn encode(
    kind: Kind,
    request_number: u64,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(payload)?;
    let size = HEADER_LEN + payload.len() + 4;
    if out.len() < size {
        return Err(Error::OutputTooSmall);
    }
    out[..4].copy_from_slice(b"PKA1");
    out[4..6].copy_from_slice(&MAJOR.to_be_bytes());
    out[6..8].copy_from_slice(&(kind as u16).to_be_bytes());
    out[8..16].copy_from_slice(&request_number.to_be_bytes());
    out[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[20..20 + payload.len()].copy_from_slice(payload);
    let crc = crc32c(&out[..size - 4]);
    out[size - 4..size].copy_from_slice(&crc.to_be_bytes());
    Ok(size)
}

pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// Definite, shortest-form CBOR only. Maps have unsigned integer field keys
/// in increasing order. Strings must be UTF-8; tags, floats and negative
/// integers are deliberately outside this protocol's data model.
pub fn validate_cbor(bytes: &[u8]) -> Result<(), Error> {
    let mut c = Cursor { bytes, pos: 0 };
    c.item(0)?;
    if c.pos != bytes.len() {
        return Err(Error::Cbor);
    }
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Cbor)?;
        let result = self.bytes.get(self.pos..end).ok_or(Error::Cbor)?;
        self.pos = end;
        Ok(result)
    }
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let b = self.take(1)?[0];
        let major = b >> 5;
        let ai = b & 31;
        let (n, min) = match ai {
            0..=23 => (u64::from(ai), 0),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                256,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                65536,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            _ => return Err(Error::Cbor),
        };
        if n < min {
            return Err(Error::Cbor);
        }
        Ok((major, n))
    }
    fn item(&mut self, depth: usize) -> Result<(), Error> {
        if depth > 16 {
            return Err(Error::Cbor);
        }
        let (major, n) = self.head()?;
        match major {
            0 => Ok(()),
            2 | 3 => {
                let n = usize::try_from(n).map_err(|_| Error::Cbor)?;
                let bytes = self.take(n)?;
                if major == 3 {
                    core::str::from_utf8(bytes).map_err(|_| Error::Cbor)?;
                }
                Ok(())
            }
            4 => {
                if n > MAX_PAYLOAD as u64 {
                    return Err(Error::Cbor);
                }
                for _ in 0..n {
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                if n > MAX_PAYLOAD as u64 {
                    return Err(Error::Cbor);
                }
                let mut previous = None;
                for _ in 0..n {
                    let (m, key) = self.head()?;
                    if m != 0 || previous.is_some_and(|p| key <= p) {
                        return Err(Error::Cbor);
                    }
                    previous = Some(key);
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            7 if matches!(n, 20..=22) => Ok(()),
            _ => Err(Error::Cbor),
        }
    }
}

use kes_core::identity::{
    BoundedBytes, DeviceId, Digest32, GenerationId, IncarnationId, NetworkBinding, OperationId,
    PoolId,
};
use kes_core::operation::{Action, GenerationTarget, Mutation, PoolTarget, UsbSerial};

/// The typed host-to-device messages. Integer map keys are specified by the
/// decoder below and are always emitted in increasing order on the wire.
pub enum Request {
    SecurityStatus,
    Hello {
        nonce: [u8; 32],
    },
    Status {
        pool: Option<PoolId>,
    },
    Context {
        target: PoolTarget,
        network: NetworkBinding,
        period: u64,
        session: u64,
        sequence: u64,
        lease_seconds: u8,
        publication_time_us: u64,
    },
    Mutate(Mutation),
    Reconcile {
        sequence: u64,
        operation_id: OperationId,
        digest: Digest32,
        binding: ReconcileBinding,
    },
    ReceiptAck {
        sequence: u64,
        result_digest: Digest32,
    },
    Current {
        target: PoolTarget,
    },
    Artifact {
        target: GenerationTarget,
    },
    PublicKey {
        target: GenerationTarget,
    },
    Commission(Mutation),
}
// The bounded serial is retained inline so firmware decoding never allocates.
#[allow(clippy::large_enum_variant)]
pub enum ReconcileBinding {
    Serial(UsbSerial),
    Device(DeviceId),
}

impl<'a> Cursor<'a> {
    fn uint(&mut self) -> Result<u64, Error> {
        let (major, n) = self.head()?;
        if major != 0 {
            return Err(Error::Schema);
        }
        Ok(n)
    }
    fn map(&mut self, expected: u64) -> Result<(), Error> {
        if self.head()? != (5, expected) {
            return Err(Error::Schema);
        }
        Ok(())
    }
    fn key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? != expected {
            return Err(Error::Schema);
        }
        Ok(())
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let (major, len) = self.head()?;
        if major != 2 {
            return Err(Error::Schema);
        }
        let len = usize::try_from(len).map_err(|_| Error::Schema)?;
        self.take(len).map_err(|_| Error::Schema)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes()?.try_into().map_err(|_| Error::Schema)
    }
    fn optional_uint(&mut self) -> Result<Option<u64>, Error> {
        if self.bytes.get(self.pos) == Some(&0xf6) {
            self.pos += 1;
            Ok(None)
        } else {
            self.uint().map(Some)
        }
    }
    fn optional_pool(&mut self) -> Result<Option<PoolId>, Error> {
        if self.bytes.get(self.pos) == Some(&0xf6) {
            self.pos += 1;
            Ok(None)
        } else {
            Ok(Some(PoolId::from_bytes(self.fixed()?)))
        }
    }
    fn target(&mut self) -> Result<PoolTarget, Error> {
        self.map(2)?;
        self.key(1)?;
        let pool = PoolId::from_bytes(self.fixed()?);
        self.key(2)?;
        let incarnation = IncarnationId::from_bytes(self.fixed()?);
        Ok(PoolTarget { pool, incarnation })
    }
    fn generation(&mut self) -> Result<GenerationTarget, Error> {
        self.map(2)?;
        self.key(1)?;
        let pool = self.target()?;
        self.key(2)?;
        let generation = GenerationId::from_bytes(self.fixed()?);
        Ok(GenerationTarget { pool, generation })
    }
    fn network(&mut self) -> Result<NetworkBinding, Error> {
        self.map(4)?;
        self.key(1)?;
        let genesis = Digest32::from_bytes(self.fixed()?);
        self.key(2)?;
        let magic = u32::try_from(self.uint()?).map_err(|_| Error::Schema)?;
        self.key(3)?;
        let slots = self.uint()?;
        self.key(4)?;
        let lifetime = u8::try_from(self.uint()?).map_err(|_| Error::Schema)?;
        NetworkBinding::new(genesis, magic, slots, lifetime).map_err(|_| Error::Schema)
    }
    fn action(&mut self) -> Result<Action, Error> {
        let (major, count) = self.head()?;
        if major != 5 {
            return Err(Error::Schema);
        }
        self.key(1)?;
        let tag = self.uint()?;
        match (tag, count) {
            (1, 4) => {
                self.key(2)?;
                let cold_key = self.fixed()?;
                self.key(3)?;
                let network = self.network()?;
                self.key(4)?;
                let publication_floor_us = self.uint()?;
                Ok(Action::Enroll {
                    cold_key,
                    network,
                    publication_floor_us,
                })
            }
            (2, 2) => {
                self.key(2)?;
                Ok(Action::Generate {
                    target: self.target()?,
                })
            }
            (3, 3) => {
                self.key(2)?;
                let target = self.generation()?;
                self.key(3)?;
                let certificate = BoundedBytes::new(self.bytes()?).map_err(|_| Error::Schema)?;
                Ok(Action::InstallCertificate {
                    target,
                    certificate,
                })
            }
            (4, 2) => {
                self.key(2)?;
                Ok(Action::Discard {
                    target: self.generation()?,
                })
            }
            (5, 2) => {
                self.key(2)?;
                Ok(Action::SetRecipient {
                    public_key: self.fixed()?,
                })
            }
            (6, 3) => {
                self.key(2)?;
                let target = self.target()?;
                self.key(3)?;
                let publication_time_us = self.optional_uint()?;
                Ok(Action::Delete {
                    target,
                    publication_time_us,
                })
            }
            _ => Err(Error::Schema),
        }
    }
}

/// Decode a canonical request and verify the operation digest using the
/// domain-separated core operation implementation, never a transport hash.
pub fn decode_request(kind: Kind, bytes: &[u8]) -> Result<Request, Error> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(bytes)?;
    let mut c = Cursor { bytes, pos: 0 };
    let request = match kind {
        Kind::SecurityStatus => {
            c.map(0)?;
            Request::SecurityStatus
        }
        Kind::Hello => {
            c.map(1)?;
            c.key(1)?;
            Request::Hello { nonce: c.fixed()? }
        }
        Kind::Status => {
            c.map(1)?;
            c.key(1)?;
            Request::Status {
                pool: c.optional_pool()?,
            }
        }
        Kind::Context => {
            c.map(7)?;
            c.key(1)?;
            let target = c.target()?;
            c.key(2)?;
            let network = c.network()?;
            c.key(3)?;
            let period = c.uint()?;
            c.key(4)?;
            let session = c.uint()?;
            c.key(5)?;
            let sequence = c.uint()?;
            c.key(6)?;
            let lease_seconds = u8::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            if !(1..=30).contains(&lease_seconds) {
                return Err(Error::Schema);
            }
            c.key(7)?;
            let publication_time_us = c.uint()?;
            Request::Context {
                target,
                network,
                period,
                session,
                sequence,
                lease_seconds,
                publication_time_us,
            }
        }
        Kind::Mutate => {
            c.map(6)?;
            c.key(1)?;
            let sequence = c.uint()?;
            c.key(2)?;
            let op = OperationId::from_bytes(c.fixed()?);
            c.key(3)?;
            let revision = c.uint()?;
            c.key(4)?;
            let device = DeviceId::from_bytes(c.fixed()?);
            c.key(5)?;
            let digest = Digest32::from_bytes(c.fixed()?);
            c.key(6)?;
            let action = c.action()?;
            let mutation = Mutation::managed(device, sequence, op, revision, action)
                .map_err(|_| Error::Schema)?;
            if mutation.usb_digest() != digest {
                return Err(Error::Schema);
            }
            Request::Mutate(mutation)
        }
        Kind::Reconcile => {
            c.map(4)?;
            c.key(1)?;
            let sequence = c.uint()?;
            c.key(2)?;
            let operation_id = OperationId::from_bytes(c.fixed()?);
            c.key(3)?;
            let digest = Digest32::from_bytes(c.fixed()?);
            c.key(4)?;
            let binding = if sequence == 0 {
                let serial = UsbSerial::new(c.bytes()?).map_err(|_| Error::Schema)?;
                if serial.as_slice().is_empty() {
                    return Err(Error::Schema);
                }
                ReconcileBinding::Serial(serial)
            } else {
                ReconcileBinding::Device(DeviceId::from_bytes(c.fixed()?))
            };
            Request::Reconcile {
                sequence,
                operation_id,
                digest,
                binding,
            }
        }
        Kind::ReceiptAck => {
            c.map(2)?;
            c.key(1)?;
            let sequence = c.uint()?;
            c.key(2)?;
            Request::ReceiptAck {
                sequence,
                result_digest: Digest32::from_bytes(c.fixed()?),
            }
        }
        Kind::Current => {
            c.map(1)?;
            c.key(1)?;
            Request::Current {
                target: c.target()?,
            }
        }
        Kind::Artifact => {
            c.map(1)?;
            c.key(1)?;
            Request::Artifact {
                target: c.generation()?,
            }
        }
        Kind::PublicKey => {
            c.map(1)?;
            c.key(1)?;
            Request::PublicKey {
                target: c.generation()?,
            }
        }
        Kind::Commission => {
            c.map(5)?;
            c.key(1)?;
            let sequence = c.uint()?;
            c.key(2)?;
            let op = OperationId::from_bytes(c.fixed()?);
            c.key(3)?;
            let revision = c.uint()?;
            c.key(4)?;
            let serial = UsbSerial::new(c.bytes()?).map_err(|_| Error::Schema)?;
            c.key(5)?;
            let digest = Digest32::from_bytes(c.fixed()?);
            if sequence != 0 {
                return Err(Error::Schema);
            }
            let mutation = Mutation::commission(serial, op, revision).map_err(|_| Error::Schema)?;
            if mutation.usb_digest() != digest {
                return Err(Error::Schema);
            }
            Request::Commission(mutation)
        }
    };
    if c.pos != bytes.len() {
        return Err(Error::Schema);
    }
    Ok(request)
}

struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}
impl Writer<'_> {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(bytes.len()).ok_or(Error::Length)?;
        if end > MAX_PAYLOAD {
            return Err(Error::Length);
        }
        self.out
            .get_mut(self.pos..end)
            .ok_or(Error::OutputTooSmall)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
    fn head(&mut self, major: u8, n: u64) -> Result<(), Error> {
        if n < 24 {
            self.raw(&[(major << 5) | n as u8])
        } else if n <= u8::MAX as u64 {
            self.raw(&[(major << 5) | 24, n as u8])
        } else if n <= u16::MAX as u64 {
            self.raw(&[(major << 5) | 25])?;
            self.raw(&(n as u16).to_be_bytes())
        } else if n <= u32::MAX as u64 {
            self.raw(&[(major << 5) | 26])?;
            self.raw(&(n as u32).to_be_bytes())
        } else {
            self.raw(&[(major << 5) | 27])?;
            self.raw(&n.to_be_bytes())
        }
    }
    fn uint(&mut self, n: u64) -> Result<(), Error> {
        self.head(0, n)
    }
    fn map(&mut self, n: u64) -> Result<(), Error> {
        self.head(5, n)
    }
    fn bytes(&mut self, b: &[u8]) -> Result<(), Error> {
        self.head(2, b.len() as u64)?;
        self.raw(b)
    }
    fn optional_uint(&mut self, value: Option<u64>) -> Result<(), Error> {
        match value {
            Some(v) => self.uint(v),
            None => self.raw(&[0xf6]),
        }
    }
    fn target(&mut self, target: PoolTarget) -> Result<(), Error> {
        self.map(2)?;
        self.uint(1)?;
        self.bytes(target.pool.as_bytes())?;
        self.uint(2)?;
        self.bytes(target.incarnation.as_bytes())
    }
    fn generation(&mut self, target: GenerationTarget) -> Result<(), Error> {
        self.map(2)?;
        self.uint(1)?;
        self.target(target.pool)?;
        self.uint(2)?;
        self.bytes(target.generation.as_bytes())
    }
    fn network(&mut self, network: NetworkBinding) -> Result<(), Error> {
        self.map(4)?;
        self.uint(1)?;
        self.bytes(network.genesis().as_bytes())?;
        self.uint(2)?;
        self.uint(network.magic().into())?;
        self.uint(3)?;
        self.uint(network.slots_per_period())?;
        self.uint(4)?;
        self.uint(network.lifetime().into())
    }
    fn action(&mut self, action: &Action) -> Result<(), Error> {
        match action {
            Action::Enroll {
                cold_key,
                network,
                publication_floor_us,
            } => {
                self.map(4)?;
                self.uint(1)?;
                self.uint(1)?;
                self.uint(2)?;
                self.bytes(cold_key)?;
                self.uint(3)?;
                self.network(*network)?;
                self.uint(4)?;
                self.uint(*publication_floor_us)
            }
            Action::Generate { target } => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(2)?;
                self.uint(2)?;
                self.target(*target)
            }
            Action::InstallCertificate {
                target,
                certificate,
            } => {
                self.map(3)?;
                self.uint(1)?;
                self.uint(3)?;
                self.uint(2)?;
                self.generation(*target)?;
                self.uint(3)?;
                self.bytes(certificate.as_slice())
            }
            Action::Discard { target } => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(4)?;
                self.uint(2)?;
                self.generation(*target)
            }
            Action::SetRecipient { public_key } => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(5)?;
                self.uint(2)?;
                self.bytes(public_key)
            }
            Action::Delete {
                target,
                publication_time_us,
            } => {
                self.map(3)?;
                self.uint(1)?;
                self.uint(6)?;
                self.uint(2)?;
                self.target(*target)?;
                self.uint(3)?;
                self.optional_uint(*publication_time_us)
            }
        }
    }
}

/// Encode a request as bounded canonical CBOR into caller-owned storage.
pub fn encode_request(request: &Request, out: &mut [u8]) -> Result<(Kind, usize), Error> {
    use kes_core::operation::Binding;
    let mut w = Writer { out, pos: 0 };
    let kind = match request {
        Request::SecurityStatus => {
            w.map(0)?;
            Kind::SecurityStatus
        }
        Request::Hello { nonce } => {
            w.map(1)?;
            w.uint(1)?;
            w.bytes(nonce)?;
            Kind::Hello
        }
        Request::Status { pool } => {
            w.map(1)?;
            w.uint(1)?;
            match pool {
                Some(pool) => w.bytes(pool.as_bytes())?,
                None => w.raw(&[0xf6])?,
            }
            Kind::Status
        }
        Request::Context {
            target,
            network,
            period,
            session,
            sequence,
            lease_seconds,
            publication_time_us,
        } => {
            if !(1..=30).contains(lease_seconds) {
                return Err(Error::Schema);
            }
            w.map(7)?;
            w.uint(1)?;
            w.target(*target)?;
            w.uint(2)?;
            w.network(*network)?;
            w.uint(3)?;
            w.uint(*period)?;
            w.uint(4)?;
            w.uint(*session)?;
            w.uint(5)?;
            w.uint(*sequence)?;
            w.uint(6)?;
            w.uint((*lease_seconds).into())?;
            w.uint(7)?;
            w.uint(*publication_time_us)?;
            Kind::Context
        }
        Request::Mutate(m) => {
            let Binding::Managed { device, action } = m.binding() else {
                return Err(Error::Schema);
            };
            w.map(6)?;
            w.uint(1)?;
            w.uint(m.sequence())?;
            w.uint(2)?;
            w.bytes(m.operation_id().as_bytes())?;
            w.uint(3)?;
            w.uint(m.expected_revision())?;
            w.uint(4)?;
            w.bytes(device.as_bytes())?;
            w.uint(5)?;
            w.bytes(m.usb_digest().as_bytes())?;
            w.uint(6)?;
            w.action(action)?;
            Kind::Mutate
        }
        Request::Reconcile {
            sequence,
            operation_id,
            digest,
            binding,
        } => {
            w.map(4)?;
            w.uint(1)?;
            w.uint(*sequence)?;
            w.uint(2)?;
            w.bytes(operation_id.as_bytes())?;
            w.uint(3)?;
            w.bytes(digest.as_bytes())?;
            w.uint(4)?;
            match binding {
                ReconcileBinding::Serial(serial)
                    if *sequence == 0 && !serial.as_slice().is_empty() =>
                {
                    w.bytes(serial.as_slice())?
                }
                ReconcileBinding::Device(device) if *sequence != 0 => w.bytes(device.as_bytes())?,
                _ => return Err(Error::Schema),
            }
            Kind::Reconcile
        }
        Request::ReceiptAck {
            sequence,
            result_digest,
        } => {
            w.map(2)?;
            w.uint(1)?;
            w.uint(*sequence)?;
            w.uint(2)?;
            w.bytes(result_digest.as_bytes())?;
            Kind::ReceiptAck
        }
        Request::Current { target } => {
            w.map(1)?;
            w.uint(1)?;
            w.target(*target)?;
            Kind::Current
        }
        Request::Artifact { target } => {
            w.map(1)?;
            w.uint(1)?;
            w.generation(*target)?;
            Kind::Artifact
        }
        Request::PublicKey { target } => {
            w.map(1)?;
            w.uint(1)?;
            w.generation(*target)?;
            Kind::PublicKey
        }
        Request::Commission(m) => {
            let Binding::Commission { serial } = m.binding() else {
                return Err(Error::Schema);
            };
            w.map(5)?;
            w.uint(1)?;
            w.uint(m.sequence())?;
            w.uint(2)?;
            w.bytes(m.operation_id().as_bytes())?;
            w.uint(3)?;
            w.uint(m.expected_revision())?;
            w.uint(4)?;
            w.bytes(serial.as_slice())?;
            w.uint(5)?;
            w.bytes(m.usb_digest().as_bytes())?;
            Kind::Commission
        }
    };
    Ok((kind, w.pos))
}

/// A committed publication descriptor. `timestamp_us` is the stored value,
/// not a host-generated replacement on redelivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Publication {
    pub revision: u64,
    pub timestamp_us: u64,
    pub high_water_us: u64,
    pub kind: PublicationKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationKind {
    None,
    Key {
        generation: GenerationId,
        period: u64,
        certificate_digest: Digest32,
    },
    Drop,
}

/// Current responses borrow their state bytes. They intentionally have no
/// `Debug` or `Display` implementation.
pub struct CurrentResponse<'a> {
    pub target: PoolTarget,
    pub snapshot_revision: u64,
    pub publication: Publication,
    pub result: CurrentResult<'a>,
}
pub enum CurrentResult<'a> {
    Unavailable {
        code: u16,
    },
    Drop,
    Key {
        generation: GenerationId,
        period: u64,
        state: &'a [u8; 608],
        certificate: &'a [u8],
    },
}

impl Cursor<'_> {
    fn publication(&mut self) -> Result<Publication, Error> {
        let (major, len) = self.head()?;
        if major != 5 {
            return Err(Error::Schema);
        }
        self.key(1)?;
        let tag = self.uint()?;
        self.key(2)?;
        let revision = self.uint()?;
        self.key(3)?;
        let timestamp_us = self.uint()?;
        self.key(4)?;
        let high_water_us = self.uint()?;
        if timestamp_us > high_water_us {
            return Err(Error::Schema);
        }
        let kind = match (tag, len) {
            (0, 4) => PublicationKind::None,
            (1, 7) => {
                self.key(5)?;
                let generation = GenerationId::from_bytes(self.fixed()?);
                self.key(6)?;
                let period = self.uint()?;
                self.key(7)?;
                let certificate_digest = Digest32::from_bytes(self.fixed()?);
                PublicationKind::Key {
                    generation,
                    period,
                    certificate_digest,
                }
            }
            (2, 4) => PublicationKind::Drop,
            _ => return Err(Error::Schema),
        };
        Ok(Publication {
            revision,
            timestamp_us,
            high_water_us,
            kind,
        })
    }
}
impl Writer<'_> {
    fn publication(&mut self, publication: Publication) -> Result<(), Error> {
        if publication.timestamp_us > publication.high_water_us {
            return Err(Error::Schema);
        }
        self.map(if matches!(publication.kind, PublicationKind::Key { .. }) {
            7
        } else {
            4
        })?;
        self.uint(1)?;
        self.uint(match publication.kind {
            PublicationKind::None => 0,
            PublicationKind::Key { .. } => 1,
            PublicationKind::Drop => 2,
        })?;
        self.uint(2)?;
        self.uint(publication.revision)?;
        self.uint(3)?;
        self.uint(publication.timestamp_us)?;
        self.uint(4)?;
        self.uint(publication.high_water_us)?;
        if let PublicationKind::Key {
            generation,
            period,
            certificate_digest,
        } = publication.kind
        {
            self.uint(5)?;
            self.bytes(generation.as_bytes())?;
            self.uint(6)?;
            self.uint(period)?;
            self.uint(7)?;
            self.bytes(certificate_digest.as_bytes())?;
        }
        Ok(())
    }
}

pub fn decode_current_response(bytes: &[u8]) -> Result<CurrentResponse<'_>, Error> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(bytes)?;
    let mut c = Cursor { bytes, pos: 0 };
    c.map(4)?;
    c.key(1)?;
    let target = c.target()?;
    c.key(2)?;
    let snapshot_revision = c.uint()?;
    c.key(3)?;
    let publication = c.publication()?;
    if publication.revision > snapshot_revision {
        return Err(Error::Schema);
    }
    c.key(4)?;
    let (major, len) = c.head()?;
    if major != 5 {
        return Err(Error::Schema);
    }
    c.key(1)?;
    let tag = c.uint()?;
    let result = match (tag, len) {
        (0, 2) => {
            c.key(2)?;
            CurrentResult::Unavailable {
                code: u16::try_from(c.uint()?).map_err(|_| Error::Schema)?,
            }
        }
        (1, 1) if publication.kind == PublicationKind::Drop => CurrentResult::Drop,
        (2, 5) => {
            c.key(2)?;
            let generation = GenerationId::from_bytes(c.fixed()?);
            c.key(3)?;
            let period = c.uint()?;
            c.key(4)?;
            let state = c.bytes()?.try_into().map_err(|_| Error::Schema)?;
            c.key(5)?;
            let certificate = c.bytes()?;
            match publication.kind {
                PublicationKind::Key {
                    generation: g,
                    period: p,
                    ..
                } if g == generation && p == period => {}
                _ => return Err(Error::Schema),
            }
            CurrentResult::Key {
                generation,
                period,
                state,
                certificate,
            }
        }
        _ => return Err(Error::Schema),
    };
    if c.pos != bytes.len() {
        return Err(Error::Schema);
    }
    Ok(CurrentResponse {
        target,
        snapshot_revision,
        publication,
        result,
    })
}

pub fn encode_current_response(
    response: &CurrentResponse<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if response.publication.revision > response.snapshot_revision {
        return Err(Error::Schema);
    }
    let mut w = Writer { out, pos: 0 };
    w.map(4)?;
    w.uint(1)?;
    w.target(response.target)?;
    w.uint(2)?;
    w.uint(response.snapshot_revision)?;
    w.uint(3)?;
    w.publication(response.publication)?;
    w.uint(4)?;
    match &response.result {
        CurrentResult::Unavailable { code } => {
            w.map(2)?;
            w.uint(1)?;
            w.uint(0)?;
            w.uint(2)?;
            w.uint((*code).into())?;
        }
        CurrentResult::Drop if response.publication.kind == PublicationKind::Drop => {
            w.map(1)?;
            w.uint(1)?;
            w.uint(1)?;
        }
        CurrentResult::Key {
            generation,
            period,
            state,
            certificate,
        } => {
            match response.publication.kind {
                PublicationKind::Key {
                    generation: g,
                    period: p,
                    ..
                } if g == *generation && p == *period => {}
                _ => return Err(Error::Schema),
            }
            w.map(5)?;
            w.uint(1)?;
            w.uint(2)?;
            w.uint(2)?;
            w.bytes(generation.as_bytes())?;
            w.uint(3)?;
            w.uint(*period)?;
            w.uint(4)?;
            w.bytes(*state)?;
            w.uint(5)?;
            w.bytes(certificate)?;
        }
        _ => return Err(Error::Schema),
    }
    Ok(w.pos)
}

/// Deletion's terminal public receipt keeps the old incarnation and timestamp
/// high-water even after its storage slot is reused.
pub fn encode_deletion_publication(
    value: &kes_core::operation::DeletionPublication,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut w = Writer { out, pos: 0 };
    w.map(4)?;
    w.uint(1)?;
    w.target(value.target())?;
    w.uint(2)?;
    w.uint(value.revision())?;
    w.uint(3)?;
    w.optional_uint(value.drop_timestamp_us())?;
    w.uint(4)?;
    w.uint(value.high_water_us())?;
    Ok(w.pos)
}

pub fn decode_deletion_publication(
    bytes: &[u8],
) -> Result<kes_core::operation::DeletionPublication, Error> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(bytes)?;
    let mut c = Cursor { bytes, pos: 0 };
    c.map(4)?;
    c.key(1)?;
    let target = c.target()?;
    c.key(2)?;
    let revision = c.uint()?;
    c.key(3)?;
    let timestamp = c.optional_uint()?;
    c.key(4)?;
    let high_water = c.uint()?;
    if c.pos != bytes.len() {
        return Err(Error::Schema);
    }
    kes_core::operation::DeletionPublication::new(target, revision, timestamp, high_water)
        .map_err(|_| Error::Schema)
}

pub enum ArtifactResult<'a> {
    Retained {
        artifact: &'a [u8],
        digest: Digest32,
        retention_policy: u8,
    },
    Retired,
    Unavailable {
        code: u16,
    },
}
pub struct ArtifactResponse<'a> {
    pub target: GenerationTarget,
    pub result: ArtifactResult<'a>,
}

pub fn encode_artifact_response(
    value: &ArtifactResponse<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut w = Writer { out, pos: 0 };
    w.map(2)?;
    w.uint(1)?;
    w.generation(value.target)?;
    w.uint(2)?;
    match &value.result {
        ArtifactResult::Retained {
            artifact,
            digest,
            retention_policy,
        } => {
            if artifact.len() > 2048 {
                return Err(Error::Length);
            }
            w.map(4)?;
            w.uint(1)?;
            w.uint(0)?;
            w.uint(2)?;
            w.bytes(artifact)?;
            w.uint(3)?;
            w.bytes(digest.as_bytes())?;
            w.uint(4)?;
            w.uint((*retention_policy).into())?;
        }
        ArtifactResult::Retired => {
            w.map(1)?;
            w.uint(1)?;
            w.uint(1)?;
        }
        ArtifactResult::Unavailable { code } => {
            w.map(2)?;
            w.uint(1)?;
            w.uint(2)?;
            w.uint(2)?;
            w.uint((*code).into())?;
        }
    }
    Ok(w.pos)
}
pub fn decode_artifact_response(bytes: &[u8]) -> Result<ArtifactResponse<'_>, Error> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(bytes)?;
    let mut c = Cursor { bytes, pos: 0 };
    c.map(2)?;
    c.key(1)?;
    let target = c.generation()?;
    c.key(2)?;
    let (major, len) = c.head()?;
    if major != 5 {
        return Err(Error::Schema);
    }
    c.key(1)?;
    let tag = c.uint()?;
    let result = match (tag, len) {
        (0, 4) => {
            c.key(2)?;
            let artifact = c.bytes()?;
            if artifact.len() > 2048 {
                return Err(Error::Length);
            }
            c.key(3)?;
            let digest = Digest32::from_bytes(c.fixed()?);
            c.key(4)?;
            let retention_policy = u8::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            ArtifactResult::Retained {
                artifact,
                digest,
                retention_policy,
            }
        }
        (1, 1) => ArtifactResult::Retired,
        (2, 2) => {
            c.key(2)?;
            ArtifactResult::Unavailable {
                code: u16::try_from(c.uint()?).map_err(|_| Error::Schema)?,
            }
        }
        _ => return Err(Error::Schema),
    };
    if c.pos != bytes.len() {
        return Err(Error::Schema);
    }
    Ok(ArtifactResponse { target, result })
}

pub enum PublicKeyResult {
    Available {
        verification_key: [u8; 32],
        revision: u64,
        artifact_digest: Digest32,
    },
    Unavailable {
        code: u16,
    },
}
pub struct PublicKeyResponse {
    pub target: GenerationTarget,
    pub result: PublicKeyResult,
}

pub fn encode_public_key_response(
    value: &PublicKeyResponse,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut w = Writer { out, pos: 0 };
    w.map(2)?;
    w.uint(1)?;
    w.generation(value.target)?;
    w.uint(2)?;
    match &value.result {
        PublicKeyResult::Available {
            verification_key,
            revision,
            artifact_digest,
        } => {
            w.map(4)?;
            w.uint(1)?;
            w.uint(0)?;
            w.uint(2)?;
            w.bytes(verification_key)?;
            w.uint(3)?;
            w.uint(*revision)?;
            w.uint(4)?;
            w.bytes(artifact_digest.as_bytes())?;
        }
        PublicKeyResult::Unavailable { code } => {
            w.map(2)?;
            w.uint(1)?;
            w.uint(1)?;
            w.uint(2)?;
            w.uint((*code).into())?;
        }
    }
    Ok(w.pos)
}
pub fn decode_public_key_response(bytes: &[u8]) -> Result<PublicKeyResponse, Error> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(bytes)?;
    let mut c = Cursor { bytes, pos: 0 };
    c.map(2)?;
    c.key(1)?;
    let target = c.generation()?;
    c.key(2)?;
    let (major, len) = c.head()?;
    if major != 5 {
        return Err(Error::Schema);
    }
    c.key(1)?;
    let tag = c.uint()?;
    let result = match (tag, len) {
        (0, 4) => {
            c.key(2)?;
            let verification_key = c.fixed()?;
            c.key(3)?;
            let revision = c.uint()?;
            c.key(4)?;
            let artifact_digest = Digest32::from_bytes(c.fixed()?);
            PublicKeyResult::Available {
                verification_key,
                revision,
                artifact_digest,
            }
        }
        (1, 2) => {
            c.key(2)?;
            PublicKeyResult::Unavailable {
                code: u16::try_from(c.uint()?).map_err(|_| Error::Schema)?,
            }
        }
        _ => return Err(Error::Schema),
    };
    if c.pos != bytes.len() {
        return Err(Error::Schema);
    }
    Ok(PublicKeyResponse { target, result })
}

use kes_core::operation::{CommissioningRecord, CommittedResult, DeletionPublication, LiveTarget};

/// Public, nonce-bound commissioning identity. Signature verification and pin
/// validation are transport-session responsibilities, not CBOR parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloIdentity {
    pub device: DeviceId,
    pub public_key: [u8; 32],
    pub serial: UsbSerial,
    pub protocol_version: u16,
    pub storage_version: u16,
    pub capacity: u8,
    pub commissioning_state: u8,
    pub signature: [u8; 64],
}
// Hello remains allocation-free and copyable across the no_std transport.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloState {
    Uncommissioned,
    Committed(HelloIdentity),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloResponse {
    pub nonce: [u8; 32],
    pub state: HelloState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationStatus {
    pub generation: GenerationId,
    pub revision: u64,
    pub role: u8,
    pub period: u64,
    pub health: u8,
    pub artifact_digest: Digest32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolStatus {
    pub target: PoolTarget,
    pub revision: u64,
    pub health: u8,
    pub active: Option<GenerationStatus>,
    pub staged: Option<GenerationStatus>,
    pub publication: Publication,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusResponse {
    pub device: DeviceId,
    pub revision: u64,
    pub health: u8,
    pub commissioning_state: u8,
    pub receipt_pending: bool,
    pub pool: Option<PoolStatus>,
    pub next_pool: Option<PoolId>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextResponse {
    pub target: PoolTarget,
    pub session: u64,
    pub sequence: u64,
    pub floor: u64,
    pub result: Result<(), u16>,
}
// Receipt reconciliation keeps the bounded serial inline without allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptBinding {
    Serial(UsbSerial),
    Device(DeviceId),
}
// Durable results stay inline for allocation-free response encoding.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicOutcome {
    Pending,
    Unknown,
    Stale,
    Committed {
        result: CommittedResult,
        result_digest: Digest32,
    },
    Rejected {
        code: u16,
        result_digest: Digest32,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicReceipt {
    pub sequence: u64,
    pub operation_id: OperationId,
    pub request_digest: Digest32,
    pub binding: ReceiptBinding,
    pub target: Option<LiveTarget>,
    pub outcome: PublicOutcome,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptAckResponse {
    pub sequence: u64,
    pub result_digest: Digest32,
    pub result: Result<(), u16>,
}

/// Secret-bearing variants do not expose diagnostic formatting.
pub enum Response<'a> {
    SecurityStatus(crate::security::SecurityStatus),
    Hello(HelloResponse),
    Status(StatusResponse),
    Context(ContextResponse),
    Mutate(PublicReceipt),
    Reconcile(PublicReceipt),
    ReceiptAck(ReceiptAckResponse),
    Current(CurrentResponse<'a>),
    Artifact(ArtifactResponse<'a>),
    PublicKey(PublicKeyResponse),
    Commission(PublicReceipt),
}

impl Writer<'_> {
    fn boolean(&mut self, b: bool) -> Result<(), Error> {
        self.raw(&[if b { 0xf5 } else { 0xf4 }])
    }
    fn option_pool(&mut self, p: Option<PoolId>) -> Result<(), Error> {
        match p {
            Some(p) => self.bytes(p.as_bytes()),
            None => self.raw(&[0xf6]),
        }
    }
    fn generation_status(&mut self, value: Option<GenerationStatus>) -> Result<(), Error> {
        let Some(v) = value else {
            return self.raw(&[0xf6]);
        };
        self.map(6)?;
        self.uint(1)?;
        self.bytes(v.generation.as_bytes())?;
        self.uint(2)?;
        self.uint(v.revision)?;
        self.uint(3)?;
        self.uint(v.role.into())?;
        self.uint(4)?;
        self.uint(v.period)?;
        self.uint(5)?;
        self.uint(v.health.into())?;
        self.uint(6)?;
        self.bytes(v.artifact_digest.as_bytes())
    }
    fn pool_status(&mut self, value: Option<PoolStatus>) -> Result<(), Error> {
        let Some(v) = value else {
            return self.raw(&[0xf6]);
        };
        if v.publication.revision > v.revision {
            return Err(Error::Schema);
        }
        self.map(6)?;
        self.uint(1)?;
        self.target(v.target)?;
        self.uint(2)?;
        self.uint(v.revision)?;
        self.uint(3)?;
        self.uint(v.health.into())?;
        self.uint(4)?;
        self.generation_status(v.active)?;
        self.uint(5)?;
        self.generation_status(v.staged)?;
        self.uint(6)?;
        self.publication(v.publication)
    }
    fn result(&mut self, result: Result<(), u16>) -> Result<(), Error> {
        match result {
            Ok(()) => self.raw(&[0xf6]),
            Err(code) => self.uint(code.into()),
        }
    }
    fn live_target(&mut self, target: Option<LiveTarget>) -> Result<(), Error> {
        match target {
            None => self.raw(&[0xf6]),
            Some(LiveTarget::Pool(p)) => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(0)?;
                self.uint(2)?;
                self.target(p)
            }
            Some(LiveTarget::Generation(g)) => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(1)?;
                self.uint(2)?;
                self.generation(g)
            }
        }
    }
    fn commissioning_record(&mut self, r: &CommissioningRecord) -> Result<(), Error> {
        if r.serial().as_slice().is_empty() {
            return Err(Error::Schema);
        }
        self.map(9)?;
        self.uint(1)?;
        self.bytes(r.device().as_bytes())?;
        self.uint(2)?;
        self.bytes(r.identity_public_key())?;
        self.uint(3)?;
        self.bytes(r.identity_fingerprint().as_bytes())?;
        self.uint(4)?;
        self.bytes(r.serial().as_slice())?;
        self.uint(5)?;
        self.uint(r.protocol_version().into())?;
        self.uint(6)?;
        self.uint(r.storage_version().into())?;
        self.uint(7)?;
        self.uint(r.device_revision())?;
        self.uint(8)?;
        self.bytes(r.operation_id().as_bytes())?;
        self.uint(9)?;
        self.bytes(r.request_digest().as_bytes())
    }
    fn deletion(&mut self, d: DeletionPublication) -> Result<(), Error> {
        self.map(4)?;
        self.uint(1)?;
        self.target(d.target())?;
        self.uint(2)?;
        self.uint(d.revision())?;
        self.uint(3)?;
        self.optional_uint(d.drop_timestamp_us())?;
        self.uint(4)?;
        self.uint(d.high_water_us())
    }
    fn committed(&mut self, result: CommittedResult) -> Result<(), Error> {
        match result {
            CommittedResult::Commissioned(r) => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(0)?;
                self.uint(2)?;
                self.commissioning_record(&r)
            }
            CommittedResult::Deleted(d) => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(1)?;
                self.uint(2)?;
                self.deletion(d)
            }
            CommittedResult::Enrolled { target, revision } => {
                self.map(3)?;
                self.uint(1)?;
                self.uint(2)?;
                self.uint(2)?;
                self.target(target)?;
                self.uint(3)?;
                self.uint(revision)
            }
            CommittedResult::Generated {
                generation,
                revision,
                artifact_digest,
            } => {
                self.map(4)?;
                self.uint(1)?;
                self.uint(3)?;
                self.uint(2)?;
                self.bytes(generation.as_bytes())?;
                self.uint(3)?;
                self.uint(revision)?;
                self.uint(4)?;
                self.bytes(artifact_digest.as_bytes())
            }
            CommittedResult::Applied { revision } => {
                self.map(2)?;
                self.uint(1)?;
                self.uint(4)?;
                self.uint(2)?;
                self.uint(revision)
            }
        }
    }
    fn receipt(&mut self, r: &PublicReceipt) -> Result<(), Error> {
        validate_receipt(r)?;
        self.map(6)?;
        self.uint(1)?;
        self.uint(r.sequence)?;
        self.uint(2)?;
        self.bytes(r.operation_id.as_bytes())?;
        self.uint(3)?;
        self.bytes(r.request_digest.as_bytes())?;
        self.uint(4)?;
        match r.binding {
            ReceiptBinding::Serial(s) => self.bytes(s.as_slice())?,
            ReceiptBinding::Device(d) => self.bytes(d.as_bytes())?,
        }
        self.uint(5)?;
        self.live_target(r.target)?;
        self.uint(6)?;
        match r.outcome {
            PublicOutcome::Pending => {
                self.map(1)?;
                self.uint(1)?;
                self.uint(0)
            }
            PublicOutcome::Unknown => {
                self.map(1)?;
                self.uint(1)?;
                self.uint(1)
            }
            PublicOutcome::Stale => {
                self.map(1)?;
                self.uint(1)?;
                self.uint(2)
            }
            PublicOutcome::Committed {
                result,
                result_digest,
            } => {
                self.map(3)?;
                self.uint(1)?;
                self.uint(3)?;
                self.uint(2)?;
                self.committed(result)?;
                self.uint(3)?;
                self.bytes(result_digest.as_bytes())
            }
            PublicOutcome::Rejected {
                code,
                result_digest,
            } => {
                self.map(3)?;
                self.uint(1)?;
                self.uint(4)?;
                self.uint(2)?;
                self.uint(code.into())?;
                self.uint(3)?;
                self.bytes(result_digest.as_bytes())
            }
        }
    }
}

impl<'a> Cursor<'a> {
    fn null(&mut self) -> bool {
        if self.bytes.get(self.pos) == Some(&0xf6) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.take(1)?[0] {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(Error::Schema),
        }
    }
    fn small(&mut self) -> Result<u8, Error> {
        u8::try_from(self.uint()?).map_err(|_| Error::Schema)
    }
    fn code(&mut self) -> Result<u16, Error> {
        u16::try_from(self.uint()?).map_err(|_| Error::Schema)
    }
    fn result(&mut self) -> Result<Result<(), u16>, Error> {
        if self.null() {
            Ok(Ok(()))
        } else {
            Ok(Err(self.code()?))
        }
    }
    fn serial(&mut self) -> Result<UsbSerial, Error> {
        let s = UsbSerial::new(self.bytes()?).map_err(|_| Error::Schema)?;
        if s.as_slice().is_empty() {
            return Err(Error::Schema);
        }
        Ok(s)
    }
    fn generation_status(&mut self) -> Result<Option<GenerationStatus>, Error> {
        if self.null() {
            return Ok(None);
        }
        self.map(6)?;
        self.key(1)?;
        let generation = GenerationId::from_bytes(self.fixed()?);
        self.key(2)?;
        let revision = self.uint()?;
        self.key(3)?;
        let role = self.small()?;
        self.key(4)?;
        let period = self.uint()?;
        self.key(5)?;
        let health = self.small()?;
        self.key(6)?;
        let artifact_digest = Digest32::from_bytes(self.fixed()?);
        Ok(Some(GenerationStatus {
            generation,
            revision,
            role,
            period,
            health,
            artifact_digest,
        }))
    }
    fn pool_status(&mut self) -> Result<Option<PoolStatus>, Error> {
        if self.null() {
            return Ok(None);
        }
        self.map(6)?;
        self.key(1)?;
        let target = self.target()?;
        self.key(2)?;
        let revision = self.uint()?;
        self.key(3)?;
        let health = self.small()?;
        self.key(4)?;
        let active = self.generation_status()?;
        self.key(5)?;
        let staged = self.generation_status()?;
        self.key(6)?;
        let publication = self.publication()?;
        if publication.revision > revision {
            return Err(Error::Schema);
        }
        Ok(Some(PoolStatus {
            target,
            revision,
            health,
            active,
            staged,
            publication,
        }))
    }
    fn live_target(&mut self) -> Result<Option<LiveTarget>, Error> {
        if self.null() {
            return Ok(None);
        }
        self.map(2)?;
        self.key(1)?;
        let tag = self.uint()?;
        self.key(2)?;
        match tag {
            0 => Ok(Some(LiveTarget::Pool(self.target()?))),
            1 => Ok(Some(LiveTarget::Generation(self.generation()?))),
            _ => Err(Error::Schema),
        }
    }
    fn commissioning_record(&mut self) -> Result<CommissioningRecord, Error> {
        self.map(9)?;
        self.key(1)?;
        let device = DeviceId::from_bytes(self.fixed()?);
        self.key(2)?;
        let public_key = self.fixed()?;
        self.key(3)?;
        let fingerprint = Digest32::from_bytes(self.fixed()?);
        self.key(4)?;
        let serial = self.serial()?;
        self.key(5)?;
        let protocol = self.code()?;
        self.key(6)?;
        let storage = self.code()?;
        self.key(7)?;
        let revision = self.uint()?;
        self.key(8)?;
        let operation = OperationId::from_bytes(self.fixed()?);
        self.key(9)?;
        let digest = Digest32::from_bytes(self.fixed()?);
        let r = CommissioningRecord::new(
            device, public_key, serial, protocol, storage, revision, operation, digest,
        );
        if r.identity_fingerprint() != fingerprint {
            return Err(Error::Schema);
        }
        Ok(r)
    }
    fn deletion(&mut self) -> Result<DeletionPublication, Error> {
        self.map(4)?;
        self.key(1)?;
        let target = self.target()?;
        self.key(2)?;
        let revision = self.uint()?;
        self.key(3)?;
        let timestamp = self.optional_uint()?;
        self.key(4)?;
        let high_water = self.uint()?;
        DeletionPublication::new(target, revision, timestamp, high_water).map_err(|_| Error::Schema)
    }
    fn committed(&mut self) -> Result<CommittedResult, Error> {
        let (major, n) = self.head()?;
        if major != 5 {
            return Err(Error::Schema);
        }
        self.key(1)?;
        let tag = self.uint()?;
        self.key(2)?;
        match (tag, n) {
            (0, 2) => Ok(CommittedResult::Commissioned(self.commissioning_record()?)),
            (1, 2) => Ok(CommittedResult::Deleted(self.deletion()?)),
            (2, 3) => {
                let target = self.target()?;
                self.key(3)?;
                Ok(CommittedResult::Enrolled {
                    target,
                    revision: self.uint()?,
                })
            }
            (3, 4) => {
                let generation = GenerationId::from_bytes(self.fixed()?);
                self.key(3)?;
                let revision = self.uint()?;
                self.key(4)?;
                Ok(CommittedResult::Generated {
                    generation,
                    revision,
                    artifact_digest: Digest32::from_bytes(self.fixed()?),
                })
            }
            (4, 2) => Ok(CommittedResult::Applied {
                revision: self.uint()?,
            }),
            _ => Err(Error::Schema),
        }
    }
    fn receipt(&mut self) -> Result<PublicReceipt, Error> {
        self.map(6)?;
        self.key(1)?;
        let sequence = self.uint()?;
        self.key(2)?;
        let operation_id = OperationId::from_bytes(self.fixed()?);
        self.key(3)?;
        let request_digest = Digest32::from_bytes(self.fixed()?);
        self.key(4)?;
        let binding = if sequence == 0 {
            ReceiptBinding::Serial(self.serial()?)
        } else {
            ReceiptBinding::Device(DeviceId::from_bytes(self.fixed()?))
        };
        self.key(5)?;
        let target = self.live_target()?;
        self.key(6)?;
        let (major, n) = self.head()?;
        if major != 5 {
            return Err(Error::Schema);
        }
        self.key(1)?;
        let tag = self.uint()?;
        let outcome = match (tag, n) {
            (0, 1) => PublicOutcome::Pending,
            (1, 1) => PublicOutcome::Unknown,
            (2, 1) => PublicOutcome::Stale,
            (3, 3) => {
                self.key(2)?;
                let result = self.committed()?;
                self.key(3)?;
                let result_digest = Digest32::from_bytes(self.fixed()?);
                PublicOutcome::Committed {
                    result,
                    result_digest,
                }
            }
            (4, 3) => {
                self.key(2)?;
                let code = self.code()?;
                self.key(3)?;
                let result_digest = Digest32::from_bytes(self.fixed()?);
                PublicOutcome::Rejected {
                    code,
                    result_digest,
                }
            }
            _ => return Err(Error::Schema),
        };
        let receipt = PublicReceipt {
            sequence,
            operation_id,
            request_digest,
            binding,
            target,
            outcome,
        };
        validate_receipt(&receipt)?;
        Ok(receipt)
    }
}

fn validate_receipt(r: &PublicReceipt) -> Result<(), Error> {
    match &r.binding {
        ReceiptBinding::Serial(s) if r.sequence == 0 => {
            let m = Mutation::commission(*s, r.operation_id, 0).map_err(|_| Error::Schema)?;
            if m.usb_digest() != r.request_digest || r.target.is_some() {
                return Err(Error::Schema);
            }
            if let PublicOutcome::Committed { result, .. } = r.outcome {
                match result {
                    CommittedResult::Commissioned(record)
                        if record.operation_id() == r.operation_id
                            && record.request_digest() == r.request_digest
                            && record.serial() == s => {}
                    _ => return Err(Error::Schema),
                }
            }
        }
        ReceiptBinding::Device(_) if r.sequence != 0 => {
            if let PublicOutcome::Committed { result, .. } = r.outcome {
                match result {
                    CommittedResult::Commissioned(_) => return Err(Error::Schema),
                    CommittedResult::Deleted(d)
                        if r.target != Some(LiveTarget::Pool(d.target())) =>
                    {
                        return Err(Error::Schema);
                    }
                    _ => {}
                }
            }
        }
        _ => return Err(Error::Schema),
    }
    Ok(())
}

impl Writer<'_> {
    fn hello(&mut self, value: &HelloResponse, signature: bool) -> Result<(), Error> {
        self.map(2)?;
        self.uint(1)?;
        self.bytes(&value.nonce)?;
        self.uint(2)?;
        match &value.state {
            HelloState::Uncommissioned => {
                self.map(1)?;
                self.uint(1)?;
                self.uint(0)
            }
            HelloState::Committed(id) => {
                if id.serial.as_slice().is_empty()
                    || id.capacity > 64
                    || id.protocol_version != MAJOR
                {
                    return Err(Error::Schema);
                }
                self.map(if signature { 9 } else { 8 })?;
                self.uint(1)?;
                self.uint(1)?;
                self.uint(2)?;
                self.bytes(id.device.as_bytes())?;
                self.uint(3)?;
                self.bytes(&id.public_key)?;
                self.uint(4)?;
                self.bytes(id.serial.as_slice())?;
                self.uint(5)?;
                self.uint(id.protocol_version.into())?;
                self.uint(6)?;
                self.uint(id.storage_version.into())?;
                self.uint(7)?;
                self.uint(id.capacity.into())?;
                self.uint(8)?;
                self.uint(id.commissioning_state.into())?;
                if signature {
                    self.uint(9)?;
                    self.bytes(&id.signature)?;
                }
                Ok(())
            }
        }
    }
}

/// Canonical hello transcript signed by the device; the signature field is
/// omitted and the host nonce is included. Only committed identities sign.
pub fn encode_hello_signing(value: &HelloResponse, out: &mut [u8]) -> Result<usize, Error> {
    if !matches!(value.state, HelloState::Committed(_)) {
        return Err(Error::Schema);
    }
    let mut w = Writer { out, pos: 0 };
    w.hello(value, false)?;
    Ok(w.pos)
}

pub fn encode_response(value: &Response<'_>, out: &mut [u8]) -> Result<(Kind, usize), Error> {
    match value {
        Response::Current(v) => return Ok((Kind::Current, encode_current_response(v, out)?)),
        Response::Artifact(v) => return Ok((Kind::Artifact, encode_artifact_response(v, out)?)),
        Response::PublicKey(v) => {
            return Ok((Kind::PublicKey, encode_public_key_response(v, out)?));
        }
        _ => {}
    }
    let mut w = Writer { out, pos: 0 };
    let kind = match value {
        Response::SecurityStatus(v) => {
            w.map(18)?;
            w.uint(1)?;
            w.uint(v.chip_revision.into())?;
            w.uint(2)?;
            w.uint(v.rom_version.into())?;
            w.uint(3)?;
            w.uint(v.critical.into())?;
            w.uint(4)?;
            w.uint(v.boot_flags0.into())?;
            w.uint(5)?;
            w.uint(v.boot_flags1.into())?;
            w.uint(6)?;
            w.bytes(&v.bootkey0)?;
            w.uint(7)?;
            w.uint(v.page2_lock0.into())?;
            w.uint(8)?;
            w.uint(v.page2_lock1.into())?;
            w.uint(9)?;
            w.uint(v.page63_lock0.into())?;
            w.uint(10)?;
            w.uint(v.page63_lock1.into())?;
            w.uint(11)?;
            w.uint(v.debugen.into())?;
            w.uint(12)?;
            w.uint(v.debugen_lock.into())?;
            w.uint(13)?;
            w.boolean(v.redundancy_ok)?;
            w.uint(14)?;
            w.bytes(&v.jedec_id)?;
            w.uint(15)?;
            w.bytes(&v.sfdp_header)?;
            w.uint(16)?;
            w.uint(v.density_bits_minus_one.into())?;
            w.uint(17)?;
            w.bytes(&v.usb_serial)?;
            w.uint(18)?;
            w.boolean(v.storage_blank_at_boot)?;
            Kind::SecurityStatus
        }
        Response::Hello(v) => {
            w.hello(v, true)?;
            Kind::Hello
        }
        Response::Status(v) => {
            w.map(7)?;
            w.uint(1)?;
            w.bytes(v.device.as_bytes())?;
            w.uint(2)?;
            w.uint(v.revision)?;
            w.uint(3)?;
            w.uint(v.health.into())?;
            w.uint(4)?;
            w.uint(v.commissioning_state.into())?;
            w.uint(5)?;
            w.boolean(v.receipt_pending)?;
            w.uint(6)?;
            w.pool_status(v.pool)?;
            w.uint(7)?;
            w.option_pool(v.next_pool)?;
            Kind::Status
        }
        Response::Context(v) => {
            w.map(5)?;
            w.uint(1)?;
            w.target(v.target)?;
            w.uint(2)?;
            w.uint(v.session)?;
            w.uint(3)?;
            w.uint(v.sequence)?;
            w.uint(4)?;
            w.uint(v.floor)?;
            w.uint(5)?;
            w.result(v.result)?;
            Kind::Context
        }
        Response::Mutate(v) => {
            if v.sequence == 0 {
                return Err(Error::Schema);
            }
            w.receipt(v)?;
            Kind::Mutate
        }
        Response::Reconcile(v) => {
            w.receipt(v)?;
            Kind::Reconcile
        }
        Response::Commission(v) => {
            if v.sequence != 0 {
                return Err(Error::Schema);
            }
            w.receipt(v)?;
            Kind::Commission
        }
        Response::ReceiptAck(v) => {
            w.map(3)?;
            w.uint(1)?;
            w.uint(v.sequence)?;
            w.uint(2)?;
            w.bytes(v.result_digest.as_bytes())?;
            w.uint(3)?;
            w.result(v.result)?;
            Kind::ReceiptAck
        }
        Response::Current(_) | Response::Artifact(_) | Response::PublicKey(_) => unreachable!(),
    };
    Ok((kind, w.pos))
}

pub fn decode_response(kind: Kind, bytes: &[u8]) -> Result<Response<'_>, Error> {
    match kind {
        Kind::Current => return Ok(Response::Current(decode_current_response(bytes)?)),
        Kind::Artifact => return Ok(Response::Artifact(decode_artifact_response(bytes)?)),
        Kind::PublicKey => return Ok(Response::PublicKey(decode_public_key_response(bytes)?)),
        _ => {}
    }
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    validate_cbor(bytes)?;
    let mut c = Cursor { bytes, pos: 0 };
    let response = match kind {
        Kind::SecurityStatus => {
            c.map(18)?;
            c.key(1)?;
            let chip_revision = c.small()?;
            c.key(2)?;
            let rom_version = c.small()?;
            c.key(3)?;
            let critical = u32::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            c.key(4)?;
            let boot_flags0 = u32::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            c.key(5)?;
            let boot_flags1 = u32::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            c.key(6)?;
            let bootkey0 = c.fixed()?;
            c.key(7)?;
            let page2_lock0 = c.small()?;
            c.key(8)?;
            let page2_lock1 = c.small()?;
            c.key(9)?;
            let page63_lock0 = c.small()?;
            c.key(10)?;
            let page63_lock1 = c.small()?;
            c.key(11)?;
            let debugen = u32::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            c.key(12)?;
            let debugen_lock = u32::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            c.key(13)?;
            let redundancy_ok = c.boolean()?;
            c.key(14)?;
            let jedec_id = c.fixed()?;
            c.key(15)?;
            let sfdp_header = c.fixed()?;
            c.key(16)?;
            let density_bits_minus_one = u32::try_from(c.uint()?).map_err(|_| Error::Schema)?;
            c.key(17)?;
            let usb_serial = c.fixed()?;
            c.key(18)?;
            let storage_blank_at_boot = c.boolean()?;
            Response::SecurityStatus(crate::security::SecurityStatus {
                chip_revision,
                rom_version,
                critical,
                boot_flags0,
                boot_flags1,
                bootkey0,
                page2_lock0,
                page2_lock1,
                page63_lock0,
                page63_lock1,
                debugen,
                debugen_lock,
                redundancy_ok,
                jedec_id,
                sfdp_header,
                density_bits_minus_one,
                usb_serial,
                storage_blank_at_boot,
            })
        }
        Kind::Hello => {
            c.map(2)?;
            c.key(1)?;
            let nonce = c.fixed()?;
            c.key(2)?;
            let (major, n) = c.head()?;
            if major != 5 {
                return Err(Error::Schema);
            }
            c.key(1)?;
            let tag = c.uint()?;
            let state = match (tag, n) {
                (0, 1) => HelloState::Uncommissioned,
                (1, 9) => {
                    c.key(2)?;
                    let device = DeviceId::from_bytes(c.fixed()?);
                    c.key(3)?;
                    let public_key = c.fixed()?;
                    c.key(4)?;
                    let serial = c.serial()?;
                    c.key(5)?;
                    let protocol_version = c.code()?;
                    c.key(6)?;
                    let storage_version = c.code()?;
                    c.key(7)?;
                    let capacity = c.small()?;
                    c.key(8)?;
                    let commissioning_state = c.small()?;
                    c.key(9)?;
                    let signature = c.fixed()?;
                    if protocol_version != MAJOR || capacity > 64 {
                        return Err(Error::Schema);
                    }
                    HelloState::Committed(HelloIdentity {
                        device,
                        public_key,
                        serial,
                        protocol_version,
                        storage_version,
                        capacity,
                        commissioning_state,
                        signature,
                    })
                }
                _ => return Err(Error::Schema),
            };
            Response::Hello(HelloResponse { nonce, state })
        }
        Kind::Status => {
            c.map(7)?;
            c.key(1)?;
            let device = DeviceId::from_bytes(c.fixed()?);
            c.key(2)?;
            let revision = c.uint()?;
            c.key(3)?;
            let health = c.small()?;
            c.key(4)?;
            let commissioning_state = c.small()?;
            c.key(5)?;
            let receipt_pending = c.boolean()?;
            c.key(6)?;
            let pool = c.pool_status()?;
            c.key(7)?;
            let next_pool = c.optional_pool()?;
            Response::Status(StatusResponse {
                device,
                revision,
                health,
                commissioning_state,
                receipt_pending,
                pool,
                next_pool,
            })
        }
        Kind::Context => {
            c.map(5)?;
            c.key(1)?;
            let target = c.target()?;
            c.key(2)?;
            let session = c.uint()?;
            c.key(3)?;
            let sequence = c.uint()?;
            c.key(4)?;
            let floor = c.uint()?;
            c.key(5)?;
            let result = c.result()?;
            Response::Context(ContextResponse {
                target,
                session,
                sequence,
                floor,
                result,
            })
        }
        Kind::Mutate => {
            let r = c.receipt()?;
            if r.sequence == 0 {
                return Err(Error::Schema);
            }
            Response::Mutate(r)
        }
        Kind::Reconcile => Response::Reconcile(c.receipt()?),
        Kind::Commission => {
            let r = c.receipt()?;
            if r.sequence != 0 {
                return Err(Error::Schema);
            }
            Response::Commission(r)
        }
        Kind::ReceiptAck => {
            c.map(3)?;
            c.key(1)?;
            let sequence = c.uint()?;
            c.key(2)?;
            let result_digest = Digest32::from_bytes(c.fixed()?);
            c.key(3)?;
            let result = c.result()?;
            Response::ReceiptAck(ReceiptAckResponse {
                sequence,
                result_digest,
                result,
            })
        }
        Kind::Current | Kind::Artifact | Kind::PublicKey => unreachable!(),
    };
    if c.pos != bytes.len() {
        return Err(Error::Schema);
    }
    Ok(response)
}
