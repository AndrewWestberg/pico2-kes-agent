//! Bounded management framing and strictly validated public JSON messages.
//!
//! The message retains the original JSON bytes; validation is performed before either
//! decoding or encoding. File paths and operational signing-key material are not wire
//! fields. Public binary fields are lower-case hex (encrypted artifacts are bounded).
use kes_core::identity::{DeviceId, Digest32, GenerationId, IncarnationId, OperationId, PoolId};

pub const MAX_FRAME: usize = 16_384;
pub const MAX_ARTIFACT_BYTES: usize = 2_048;
pub const MAX_CERTIFICATE_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Oversized,
    Incomplete,
    InvalidJson,
    InvalidField,
    DuplicateField,
    UnsupportedVersion,
    UnsupportedAction,
    InvalidOutcome,
    OutputTooSmall,
}

/// One-frame-at-a-time decoder. Call `reset` after consuming a complete frame.
pub struct FrameDecoder {
    header: [u8; 4],
    header_len: usize,
    body: [u8; MAX_FRAME],
    len: usize,
    expected: Option<usize>,
}
impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}
impl FrameDecoder {
    pub const fn new() -> Self {
        Self {
            header: [0; 4],
            header_len: 0,
            body: [0; MAX_FRAME],
            len: 0,
            expected: None,
        }
    }
    pub fn reset(&mut self) {
        self.header_len = 0;
        self.len = 0;
        self.expected = None;
    }
    /// Returns the number of input bytes consumed, leaving the next frame untouched.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, Error> {
        let mut n = 0;
        while self.header_len < 4 && n < input.len() {
            self.header[self.header_len] = input[n];
            self.header_len += 1;
            n += 1;
        }
        if self.header_len == 4 && self.expected.is_none() {
            let size = u32::from_be_bytes(self.header) as usize;
            if size > MAX_FRAME {
                return Err(Error::Oversized);
            }
            self.expected = Some(size);
        }
        if let Some(size) = self.expected {
            let take = core::cmp::min(size - self.len, input.len() - n);
            self.body[self.len..self.len + take].copy_from_slice(&input[n..n + take]);
            self.len += take;
            n += take;
        }
        Ok(n)
    }
    pub fn frame(&self) -> Option<&[u8]> {
        match self.expected {
            Some(n) if n == self.len => Some(&self.body[..n]),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    DeviceStatus,
    DeviceCommission,
    PoolList,
    PoolStatus,
    PoolEnroll,
    GenerationCreate,
    GenerationPublicKey,
    GenerationArtifact,
    GenerationCertificate,
    GenerationDiscard,
    RecipientSet,
    PoolDelete,
    OperationReconcile,
}
impl Action {
    fn parse(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "device.status" => Self::DeviceStatus,
            "device.commission" => Self::DeviceCommission,
            "pool.list" => Self::PoolList,
            "pool.status" => Self::PoolStatus,
            "pool.enroll" => Self::PoolEnroll,
            "generation.create" => Self::GenerationCreate,
            "generation.public_key" => Self::GenerationPublicKey,
            "generation.artifact" => Self::GenerationArtifact,
            "generation.certificate" => Self::GenerationCertificate,
            "generation.discard" => Self::GenerationDiscard,
            "recipient.set" => Self::RecipientSet,
            "pool.delete" => Self::PoolDelete,
            "operation.reconcile" => Self::OperationReconcile,
            _ => return Err(Error::UnsupportedAction),
        })
    }
    pub const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::DeviceCommission
                | Self::PoolEnroll
                | Self::GenerationCreate
                | Self::GenerationCertificate
                | Self::GenerationDiscard
                | Self::RecipientSet
                | Self::PoolDelete
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    Rejected,
    Pending,
    Uncertain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    UnsupportedVersion,
    InvalidInput,
    PermissionDenied,
    Busy,
    DeviceUnavailable,
    WrongDevice,
    Uncommissioned,
    AlreadyCommissioned,
    SocketConflict,
    PoolUnknown,
    PoolDuplicate,
    CapacityExceeded,
    StagedOccupied,
    TargetNotStaged,
    GenerationMismatch,
    RevisionConflict,
    OperationConflict,
    OutcomeUnknown,
    ArtifactRetired,
    CertificateInvalid,
    CertificateRegressive,
    NotYetValid,
    Expired,
    PeriodUnavailable,
    PeriodRegressive,
    EntropyFailure,
    StorageFailure,
    OutputExists,
    ArtifactInvalid,
    RecipientMismatch,
}
impl ErrorCode {
    fn parse(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "unsupported_version" => Self::UnsupportedVersion,
            "invalid_input" => Self::InvalidInput,
            "permission_denied" => Self::PermissionDenied,
            "busy" => Self::Busy,
            "device_unavailable" => Self::DeviceUnavailable,
            "wrong_device" => Self::WrongDevice,
            "uncommissioned" => Self::Uncommissioned,
            "already_commissioned" => Self::AlreadyCommissioned,
            "socket_conflict" => Self::SocketConflict,
            "pool_unknown" => Self::PoolUnknown,
            "pool_duplicate" => Self::PoolDuplicate,
            "capacity_exceeded" => Self::CapacityExceeded,
            "staged_occupied" => Self::StagedOccupied,
            "target_not_staged" => Self::TargetNotStaged,
            "generation_mismatch" => Self::GenerationMismatch,
            "revision_conflict" => Self::RevisionConflict,
            "operation_conflict" => Self::OperationConflict,
            "outcome_unknown" => Self::OutcomeUnknown,
            "artifact_retired" => Self::ArtifactRetired,
            "certificate_invalid" => Self::CertificateInvalid,
            "certificate_regressive" => Self::CertificateRegressive,
            "not_yet_valid" => Self::NotYetValid,
            "expired" => Self::Expired,
            "period_unavailable" => Self::PeriodUnavailable,
            "period_regressive" => Self::PeriodRegressive,
            "entropy_failure" => Self::EntropyFailure,
            "storage_failure" => Self::StorageFailure,
            "output_exists" => Self::OutputExists,
            "artifact_invalid" => Self::ArtifactInvalid,
            "recipient_mismatch" => Self::RecipientMismatch,
            _ => return Err(Error::InvalidField),
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Request {
        action: Action,
        request_id: OperationId,
        operation_id: Option<OperationId>,
        expected_revision: Option<u64>,
    },
    Response {
        request_id: OperationId,
        outcome: Outcome,
    },
}
/// Validated public JSON; construction is only possible through `decode`.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    json: &'a [u8],
    kind: Kind,
}
impl<'a> Message<'a> {
    pub fn decode(json: &'a [u8]) -> Result<Self, Error> {
        if json.len() > MAX_FRAME {
            return Err(Error::Oversized);
        }
        let s = core::str::from_utf8(json).map_err(|_| Error::InvalidJson)?;
        let kind = Parser::new(s).message()?;
        Ok(Self { json, kind })
    }
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    pub const fn json(&self) -> &'a [u8] {
        self.json
    }
    pub fn encode_frame(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.json.len();
        if out.len() < n + 4 {
            return Err(Error::OutputTooSmall);
        }
        out[..4].copy_from_slice(&(n as u32).to_be_bytes());
        out[4..n + 4].copy_from_slice(self.json);
        Ok(n + 4)
    }
}

// Strings are unescaped before field lookup so differently escaped duplicate keys
// cannot bypass duplicate detection. Scratch storage is fixed and never allocated.
struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}
impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            src: s.as_bytes(),
            pos: 0,
        }
    }
    fn ws(&mut self) {
        while matches!(self.src.get(self.pos), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }
    fn byte(&mut self, b: u8) -> Result<(), Error> {
        self.ws();
        if self.src.get(self.pos) != Some(&b) {
            return Err(Error::InvalidJson);
        }
        self.pos += 1;
        Ok(())
    }
    fn consume(&mut self, b: u8) -> bool {
        self.ws();
        if self.src.get(self.pos) == Some(&b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self, out: &mut [u8; MAX_FRAME]) -> Result<usize, Error> {
        self.byte(b'"')?;
        let mut n = 0;
        loop {
            let c = *self.src.get(self.pos).ok_or(Error::InvalidJson)?;
            self.pos += 1;
            if c == b'"' {
                return Ok(n);
            }
            if c < 0x20 {
                return Err(Error::InvalidJson);
            }
            if c != b'\\' {
                out[n] = c;
                n += 1;
                continue;
            }
            let e = *self.src.get(self.pos).ok_or(Error::InvalidJson)?;
            self.pos += 1;
            let c = match e {
                b'"' => b'"',
                b'\\' => b'\\',
                b'/' => b'/',
                b'b' => 8,
                b'f' => 12,
                b'n' => 10,
                b'r' => 13,
                b't' => 9,
                b'u' => {
                    let a = self.hex4()?;
                    let scalar = if (0xd800..=0xdbff).contains(&a) {
                        if self.src.get(self.pos..self.pos + 2) != Some(b"\\u") {
                            return Err(Error::InvalidJson);
                        }
                        self.pos += 2;
                        let b = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&b) {
                            return Err(Error::InvalidJson);
                        }
                        0x10000 + ((a - 0xd800) << 10) + b - 0xdc00
                    } else {
                        a
                    };
                    let ch = char::from_u32(scalar).ok_or(Error::InvalidJson)?;
                    let mut bytes = [0; 4];
                    let text = ch.encode_utf8(&mut bytes);
                    out[n..n + text.len()].copy_from_slice(text.as_bytes());
                    n += text.len();
                    continue;
                }
                _ => return Err(Error::InvalidJson),
            };
            out[n] = c;
            n += 1;
        }
    }
    fn hex4(&mut self) -> Result<u32, Error> {
        let mut v = 0;
        for _ in 0..4 {
            let c = *self.src.get(self.pos).ok_or(Error::InvalidJson)?;
            self.pos += 1;
            v = v * 16
                + match c {
                    b'0'..=b'9' => (c - b'0') as u32,
                    b'a'..=b'f' => (c - b'a' + 10) as u32,
                    b'A'..=b'F' => (c - b'A' + 10) as u32,
                    _ => return Err(Error::InvalidJson),
                };
        }
        Ok(v)
    }
    fn text<T>(&mut self, f: impl FnOnce(&str) -> Result<T, Error>) -> Result<T, Error> {
        let mut buf = [0; MAX_FRAME];
        let n = self.string(&mut buf)?;
        f(core::str::from_utf8(&buf[..n]).map_err(|_| Error::InvalidJson)?)
    }
    fn number(&mut self) -> Result<u64, Error> {
        self.ws();
        let start = self.pos;
        while matches!(self.src.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let s = &self.src[start..self.pos];
        if s.is_empty() || (s.len() > 1 && s[0] == b'0') {
            return Err(Error::InvalidField);
        }
        let mut n = 0u64;
        for &c in s {
            n = n
                .checked_mul(10)
                .and_then(|v| v.checked_add((c - b'0') as u64))
                .ok_or(Error::InvalidField)?;
        }
        Ok(n)
    }
    fn null(&mut self) -> bool {
        self.ws();
        if self.src.get(self.pos..self.pos + 4) == Some(b"null") {
            self.pos += 4;
            true
        } else {
            false
        }
    }
    fn object_start(&mut self) -> Result<(), Error> {
        self.byte(b'{')
    }
    fn next(&mut self, first: &mut bool) -> Result<bool, Error> {
        if self.consume(b'}') {
            return Ok(false);
        }
        if !*first {
            self.byte(b',')?;
            if self.consume(b'}') {
                return Err(Error::InvalidJson);
            }
        }
        *first = false;
        Ok(true)
    }
    fn key(&mut self, names: &[&str], seen: &mut u128) -> Result<usize, Error> {
        let index = self.text(|s| {
            names
                .iter()
                .position(|&x| x == s)
                .ok_or(Error::InvalidField)
        })?;
        let bit = 1u128 << index;
        if *seen & bit != 0 {
            return Err(Error::DuplicateField);
        }
        *seen |= bit;
        self.byte(b':')?;
        Ok(index)
    }
    fn id(&mut self) -> Result<OperationId, Error> {
        self.text(|s| OperationId::parse_hex(s).map_err(|_| Error::InvalidField))
    }
    fn message(mut self) -> Result<Kind, Error> {
        const N: &[&str] = &[
            "version",
            "request_id",
            "action",
            "arguments",
            "operation_id",
            "expected_revision",
            "outcome",
            "result",
            "error",
        ];
        self.object_start()?;
        let (mut first, mut seen) = (true, 0);
        let (
            mut version,
            mut id,
            mut action,
            mut args,
            mut op,
            mut rev,
            mut outcome,
            mut result,
            mut error,
        ) = (None, None, None, None, None, None, None, None, None);
        while self.next(&mut first)? {
            match self.key(N, &mut seen)? {
                0 => version = Some(self.number()?),
                1 => id = Some(self.id()?),
                2 => action = Some(self.text(Action::parse)?),
                // Arguments can precede action; record their byte range and validate after the envelope.
                3 => {
                    let start = self.pos;
                    self.skip_object()?;
                    args = Some((start, self.pos));
                }
                4 => op = Some(self.id()?),
                5 => rev = Some(self.number()?),
                6 => {
                    outcome = Some(self.text(|s| match s {
                        "success" => Ok(Outcome::Success),
                        "rejected" => Ok(Outcome::Rejected),
                        "pending" => Ok(Outcome::Pending),
                        "uncertain" => Ok(Outcome::Uncertain),
                        _ => Err(Error::InvalidOutcome),
                    })?)
                }
                7 => {
                    if !self.null() {
                        self.public_object(false)?;
                        result = Some(());
                    }
                }
                8 => {
                    if !self.null() {
                        error = Some(self.error_object()?);
                    }
                }
                _ => unreachable!(),
            }
        }
        self.ws();
        if self.pos != self.src.len() {
            return Err(Error::InvalidJson);
        }
        if version != Some(1) {
            return Err(Error::UnsupportedVersion);
        }
        let request_id = id.ok_or(Error::InvalidField)?;
        if let Some(action) = action {
            if seen & (0b111 << 6) != 0
                || seen & 0b1111 != 0b1111
                || action.is_mutation() != (op.is_some() && rev.is_some())
                || (!action.is_mutation() && (op.is_some() || rev.is_some()))
            {
                return Err(Error::InvalidField);
            }
            let (start, end) = args.ok_or(Error::InvalidField)?;
            let mut p = Parser {
                src: &self.src[start..end],
                pos: 0,
            };
            p.arguments(action)?;
            if action == Action::DeviceCommission && rev != Some(0) {
                return Err(Error::InvalidField);
            }
            Ok(Kind::Request {
                action,
                request_id,
                operation_id: op,
                expected_revision: rev,
            })
        } else {
            if seen != ((1 << 0) | (1 << 1) | (1 << 6) | (1 << 7) | (1 << 8)) {
                return Err(Error::InvalidField);
            }
            let outcome = outcome.ok_or(Error::InvalidOutcome)?;
            match (outcome, result, error) {
                (Outcome::Success, Some(()), None) => (),
                (Outcome::Rejected, None, Some(code)) if code != ErrorCode::OutcomeUnknown => (),
                (Outcome::Pending | Outcome::Uncertain, None, Some(ErrorCode::OutcomeUnknown)) => {}
                _ => return Err(Error::InvalidOutcome),
            }
            Ok(Kind::Response {
                request_id,
                outcome,
            })
        }
    }
    // The first pass locates arguments while enforcing JSON syntax; schema is checked below.
    fn skip_object(&mut self) -> Result<(), Error> {
        self.object_start()?;
        let mut first = true;
        while self.next(&mut first)? {
            self.text(|_| Ok(()))?;
            self.byte(b':')?;
            self.skip_value(0)?;
        }
        Ok(())
    }
    fn skip_value(&mut self, depth: usize) -> Result<(), Error> {
        if depth > 8 {
            return Err(Error::InvalidJson);
        }
        self.ws();
        match self.src.get(self.pos) {
            Some(b'"') => self.text(|_| Ok(())),
            Some(b'{') => {
                self.object_start()?;
                let mut first = true;
                while self.next(&mut first)? {
                    self.text(|_| Ok(()))?;
                    self.byte(b':')?;
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            Some(b'[') => {
                self.byte(b'[')?;
                let mut first = true;
                loop {
                    if self.consume(b']') {
                        break;
                    }
                    if !first {
                        self.byte(b',')?;
                        if self.consume(b']') {
                            return Err(Error::InvalidJson);
                        }
                    }
                    first = false;
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            Some(b'0'..=b'9') => {
                self.number()?;
                Ok(())
            }
            Some(b'n') if self.null() => Ok(()),
            Some(b't') if self.literal(b"true") => Ok(()),
            Some(b'f') if self.literal(b"false") => Ok(()),
            _ => Err(Error::InvalidJson),
        }
    }
    fn literal(&mut self, s: &[u8]) -> bool {
        if self.src.get(self.pos..self.pos + s.len()) == Some(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }
    fn hex(&mut self, bytes: usize) -> Result<(), Error> {
        self.text(|s| {
            if s.len() != bytes * 2
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                Err(Error::InvalidField)
            } else {
                Ok(())
            }
        })
    }
    fn bounded_hex(&mut self, max: usize) -> Result<(), Error> {
        self.text(|s| {
            if s.is_empty()
                || s.len() % 2 != 0
                || s.len() / 2 > max
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                Err(Error::InvalidField)
            } else {
                Ok(())
            }
        })
    }
    fn arguments(&mut self, action: Action) -> Result<(), Error> {
        const N: &[&str] = &[
            "usb_serial",
            "pool_id",
            "incarnation_id",
            "generation_id",
            "cold_verification_key",
            "network",
            "certificate",
            "public_key",
            "operation_id",
            "request_digest",
            "page_size",
            "cursor",
        ];
        self.object_start()?;
        let (mut first, mut seen) = (true, 0);
        while self.next(&mut first)? {
            match self.key(N, &mut seen)? {
                0 | 5 => self.text(|s| {
                    if s.is_empty() || s.len() > 4096 {
                        Err(Error::InvalidField)
                    } else {
                        Ok(())
                    }
                })?,
                1 => {
                    self.text(|s| {
                        PoolId::parse_hex(s)
                            .map(|_| ())
                            .map_err(|_| Error::InvalidField)
                    })?;
                }
                2 => {
                    self.text(|s| {
                        IncarnationId::parse_hex(s)
                            .map(|_| ())
                            .map_err(|_| Error::InvalidField)
                    })?;
                }
                3 => {
                    self.text(|s| {
                        GenerationId::parse_hex(s)
                            .map(|_| ())
                            .map_err(|_| Error::InvalidField)
                    })?;
                }
                4 | 7 | 9 => self.hex(32)?,
                6 => self.bounded_hex(MAX_CERTIFICATE_BYTES)?,
                8 => {
                    self.id()?;
                }
                10 => {
                    let n = self.number()?;
                    if n == 0 || n > 16 {
                        return Err(Error::InvalidField);
                    }
                }
                11 => self.text(|s| {
                    if s.len() <= 256 {
                        Ok(())
                    } else {
                        Err(Error::InvalidField)
                    }
                })?,
                _ => unreachable!(),
            }
        }
        let required = match action {
            Action::DeviceStatus | Action::PoolList => 0,
            Action::DeviceCommission => 1 << 0,
            Action::PoolStatus => 1 << 1,
            Action::PoolEnroll => (1 << 4) | (1 << 5),
            Action::GenerationCreate | Action::PoolDelete => (1 << 1) | (1 << 2),
            Action::GenerationPublicKey
            | Action::GenerationArtifact
            | Action::GenerationDiscard => (1 << 1) | (1 << 2) | (1 << 3),
            Action::GenerationCertificate => (1 << 1) | (1 << 2) | (1 << 3) | (1 << 6),
            Action::RecipientSet => 1 << 7,
            Action::OperationReconcile => (1 << 8) | (1 << 9),
        };
        let allowed = required
            | if action == Action::PoolList {
                (1 << 10) | (1 << 11)
            } else {
                0
            };
        if seen & required != required || seen & !allowed != 0 {
            return Err(Error::InvalidField);
        }
        Ok(())
    }
    fn error_object(&mut self) -> Result<ErrorCode, Error> {
        const N: &[&str] = &[
            "code",
            "message",
            "device_id",
            "pool_id",
            "incarnation_id",
            "generation_id",
            "operation_id",
            "revision",
            "retry_advice",
            "reconciliation_advice",
            "request_digest",
        ];
        self.object_start()?;
        let (mut first, mut seen, mut code) = (true, 0, None);
        while self.next(&mut first)? {
            match self.key(N, &mut seen)? {
                0 => code = Some(self.text(ErrorCode::parse)?),
                1 | 8 | 9 => self.text(|_| Ok(()))?,
                2 => self.text(|s| {
                    DeviceId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                3 => self.text(|s| {
                    PoolId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                4 => self.text(|s| {
                    IncarnationId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                5 => self.text(|s| {
                    GenerationId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                6 => {
                    self.id()?;
                }
                7 => {
                    self.number()?;
                }
                10 => {
                    self.text(|s| {
                        Digest32::parse_hex(s)
                            .map(|_| ())
                            .map_err(|_| Error::InvalidField)
                    })?;
                }
                _ => unreachable!(),
            }
        }
        if seen & 3 != 3 {
            return Err(Error::InvalidField);
        }
        code.ok_or(Error::InvalidField)
    }
    fn public_object(&mut self, nested: bool) -> Result<(), Error> {
        const N: &[&str] = &[
            "device_id",
            "pool_id",
            "incarnation_id",
            "generation_id",
            "operation_id",
            "revision",
            "device_revision",
            "policy_revision",
            "identity_public_key",
            "identity_fingerprint",
            "recipient_fingerprint",
            "verification_key",
            "artifact_digest",
            "request_digest",
            "artifact",
            "usb_serial",
            "network",
            "health",
            "commissioning_state",
            "protocol_version",
            "storage_version",
            "firmware_version",
            "capacity",
            "period",
            "certificate",
            "publication_state",
            "retirement_disclosure",
            "continuation_cursor",
            "pools",
            "active",
            "staged",
            "pending_operation",
            "connected",
            "version",
            "public_key_envelope",
            "certificate_state",
            "start_period",
            "counter",
            "publication_timestamp_us",
            "kind",
            "sequence",
            "result_digest",
            "drop_timestamp_us",
            "high_water_us",
            "receipt_pending",
            "unavailable_code",
            "retired",
            "cursor",
            "socket_path",
            "role",
            "action",
            "artifact_retention",
            "publication_revision",
        ];
        self.object_start()?;
        let (mut first, mut seen) = (true, 0);
        while self.next(&mut first)? {
            match self.key(N, &mut seen)? {
                0 => self.text(|s| {
                    DeviceId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                1 => self.text(|s| {
                    PoolId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                2 => self.text(|s| {
                    IncarnationId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                3 => self.text(|s| {
                    GenerationId::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                4 => {
                    self.id()?;
                }
                5..=7 | 19 | 20 | 22 | 23 | 33 | 36..=38 | 40 | 42 | 43 | 45 | 52 => {
                    self.number()?;
                }
                8..=13 | 41 => self.text(|s| {
                    Digest32::parse_hex(s)
                        .map(|_| ())
                        .map_err(|_| Error::InvalidField)
                })?,
                14 => self.bounded_hex(MAX_ARTIFACT_BYTES)?,
                24 => self.bounded_hex(MAX_CERTIFICATE_BYTES)?,
                15..=18 | 21 | 25..=27 | 34 | 35 | 39 | 48..=51 => self.text(|_| Ok(()))?,
                28 => {
                    if nested {
                        return Err(Error::InvalidField);
                    }
                    self.byte(b'[')?;
                    let mut first = true;
                    let mut count = 0;
                    loop {
                        if self.consume(b']') {
                            break;
                        }
                        if !first {
                            self.byte(b',')?;
                            if self.consume(b']') {
                                return Err(Error::InvalidJson);
                            }
                        }
                        first = false;
                        count += 1;
                        if count > 16 {
                            return Err(Error::InvalidField);
                        }
                        self.public_object(true)?;
                    }
                }
                29..=31 => {
                    if nested {
                        return Err(Error::InvalidField);
                    }
                    if !self.null() {
                        self.public_object(true)?;
                    }
                }
                32 | 44 | 46 => {
                    self.ws();
                    if !self.literal(b"true") && !self.literal(b"false") {
                        return Err(Error::InvalidField);
                    }
                }
                47 => {
                    if !self.null() {
                        self.text(|_| Ok(()))?;
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}
