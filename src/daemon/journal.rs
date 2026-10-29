//! Checksummed append-only public mutation journal.
//!
//! Every append is synced before returning. A short final record is a torn,
//! uncommitted tail and is removed on open. Any complete record with invalid
//! structure, checksum, or transition fails closed.

use rustix::fs::{self, CWD, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub const JOURNAL_LIMIT: u64 = 64 * 1024 * 1024;
pub const MAX_RECORD_PAYLOAD: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"PKAJNL01";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 104;
const TERMINAL_RESERVE: u64 = 2 * (HEADER_LEN as u64 + MAX_RECORD_PAYLOAD as u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationKey {
    pub sequence: u64,
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingMutation {
    pub key: MutationKey,
    pub intent: Vec<u8>,
    pub device_request: Option<Vec<u8>>,
    pub terminal: Option<TerminalResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalResult {
    pub result_digest: [u8; 32],
    pub public_result: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedMutation {
    pub key: MutationKey,
    pub intent: Vec<u8>,
    pub device_request: Vec<u8>,
    pub terminal: TerminalResult,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnsafePath,
    Full,
    PayloadTooLarge,
    Corrupt { offset: u64, reason: &'static str },
    Busy,
    NoPending,
    Conflict,
    InvalidTransition,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "journal I/O: {error}"),
            Self::UnsafePath => formatter.write_str("journal path is not owner-controlled"),
            Self::Full => formatter.write_str("journal 64-MiB admission bound reached"),
            Self::PayloadTooLarge => formatter.write_str("journal record exceeds payload bound"),
            Self::Corrupt { offset, reason } => {
                write!(formatter, "journal corruption at byte {offset}: {reason}")
            }
            Self::Busy => formatter.write_str("a mutation is already outstanding"),
            Self::NoPending => formatter.write_str("no mutation is outstanding"),
            Self::Conflict => {
                formatter.write_str("mutation identity does not match outstanding intent")
            }
            Self::InvalidTransition => formatter.write_str("invalid journal transition"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Kind {
    Intent = 1,
    DeviceRequest = 2,
    Terminal = 3,
    Acknowledged = 4,
    Declined = 5,
}

impl Kind {
    fn parse(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Intent),
            2 => Some(Self::DeviceRequest),
            3 => Some(Self::Terminal),
            4 => Some(Self::Acknowledged),
            5 => Some(Self::Declined),
            _ => None,
        }
    }
}

struct Record {
    kind: Kind,
    key: MutationKey,
    payload: Vec<u8>,
}

pub struct Journal {
    file: File,
    length: u64,
    next_sequence: u64,
    pending: Option<PendingMutation>,
    completed: Vec<CompletedMutation>,
    recovered_torn_tail: bool,
}

impl Journal {
    /// Opens or creates an owner-only regular journal without following the
    /// final symlink. Existing bytes are validated before any append.
    pub fn open(path: &Path) -> Result<Self, Error> {
        validate_parent(path)?;
        let fd = fs::openat(
            CWD,
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::APPEND,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io::Error::from)?;
        let mut file = File::from(fd);
        let metadata = file.metadata()?;
        let effective_uid = rustix::process::geteuid().as_raw();
        if !metadata.is_file() || metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
            return Err(Error::UnsafePath);
        }
        if metadata.len() > JOURNAL_LIMIT {
            return Err(Error::Full);
        }

        let (records, valid_length, torn) = read_records(&mut file, metadata.len())?;
        if torn {
            file.set_len(valid_length)?;
            file.sync_all()?;
        }
        let mut journal = Self {
            file,
            length: valid_length,
            next_sequence: 0,
            pending: None,
            completed: Vec::new(),
            recovered_torn_tail: torn,
        };
        for record in records {
            journal.apply(record, valid_length)?;
        }
        journal.file.seek(SeekFrom::End(0))?;
        Ok(journal)
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub const fn pending(&self) -> Option<&PendingMutation> {
        self.pending.as_ref()
    }

    pub fn completed(&self) -> &[CompletedMutation] {
        &self.completed
    }

    pub const fn recovered_torn_tail(&self) -> bool {
        self.recovered_torn_tail
    }

    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Reserves enough space for the derived request and terminal handoff so a
    /// mutation is never dispatched merely because its intent happened to fit.
    pub fn append_intent(&mut self, key: MutationKey, intent: &[u8]) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if key.sequence != self.next_sequence {
            return Err(Error::Conflict);
        }
        let record_len = checked_record_len(intent)?;
        if self
            .length
            .checked_add(record_len)
            .and_then(|length| length.checked_add(TERMINAL_RESERVE))
            .is_none_or(|length| length > JOURNAL_LIMIT)
        {
            return Err(Error::Full);
        }
        self.append(Kind::Intent, key, intent)?;
        self.pending = Some(PendingMutation {
            key,
            intent: intent.to_vec(),
            device_request: None,
            terminal: None,
        });
        Ok(())
    }

    pub fn append_device_request(
        &mut self,
        key: MutationKey,
        device_request: &[u8],
    ) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::NoPending)?;
        if pending.key != key {
            return Err(Error::Conflict);
        }
        if pending.device_request.is_some() || pending.terminal.is_some() {
            return Err(Error::InvalidTransition);
        }
        self.append(Kind::DeviceRequest, key, device_request)?;
        self.pending
            .as_mut()
            .expect("pending checked")
            .device_request = Some(device_request.to_vec());
        Ok(())
    }

    /// Persists the terminal device result before a caller may reply or
    /// acknowledge device receipt retention.
    pub fn append_terminal(
        &mut self,
        key: MutationKey,
        result_digest: [u8; 32],
        public_result: &[u8],
    ) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::NoPending)?;
        if pending.key != key {
            return Err(Error::Conflict);
        }
        if pending.device_request.is_none() || pending.terminal.is_some() {
            return Err(Error::InvalidTransition);
        }
        let mut payload = Vec::with_capacity(32 + public_result.len());
        payload.extend_from_slice(&result_digest);
        payload.extend_from_slice(public_result);
        self.append(Kind::Terminal, key, &payload)?;
        self.pending.as_mut().expect("pending checked").terminal = Some(TerminalResult {
            result_digest,
            public_result: public_result.to_vec(),
        });
        Ok(())
    }

    /// Records that the device receipt was acknowledged only after the exact
    /// terminal result is durable. The completed result remains append-only.
    pub fn append_acknowledged(
        &mut self,
        key: MutationKey,
        result_digest: [u8; 32],
    ) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::NoPending)?;
        if pending.key != key {
            return Err(Error::Conflict);
        }
        let terminal = pending.terminal.as_ref().ok_or(Error::InvalidTransition)?;
        if terminal.result_digest != result_digest {
            return Err(Error::Conflict);
        }
        self.append(Kind::Acknowledged, key, &result_digest)?;
        let pending = self.pending.take().expect("pending checked");
        self.completed.push(CompletedMutation {
            key,
            intent: pending.intent,
            device_request: pending.device_request.expect("device request checked"),
            terminal: pending.terminal.expect("terminal checked"),
        });
        self.next_sequence = key
            .sequence
            .checked_add(1)
            .ok_or(Error::InvalidTransition)?;
        Ok(())
    }

    /// Closes a rejection produced before device admission. The durable result
    /// remains reconcilable, but the sequence is reused because the device did
    /// not advance its handoff counter.
    pub fn append_declined(
        &mut self,
        key: MutationKey,
        result_digest: [u8; 32],
    ) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::NoPending)?;
        if pending.key != key {
            return Err(Error::Conflict);
        }
        let terminal = pending.terminal.as_ref().ok_or(Error::InvalidTransition)?;
        if terminal.result_digest != result_digest {
            return Err(Error::Conflict);
        }
        self.append(Kind::Declined, key, &result_digest)?;
        let pending = self.pending.take().expect("pending checked");
        self.completed.push(CompletedMutation {
            key,
            intent: pending.intent,
            device_request: pending.device_request.expect("device request checked"),
            terminal: pending.terminal.expect("terminal checked"),
        });
        Ok(())
    }

    fn append(&mut self, kind: Kind, key: MutationKey, payload: &[u8]) -> Result<(), Error> {
        let encoded = encode_record(kind, key, payload)?;
        let new_length = self
            .length
            .checked_add(encoded.len() as u64)
            .ok_or(Error::Full)?;
        if new_length > JOURNAL_LIMIT {
            return Err(Error::Full);
        }
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.length = new_length;
        Ok(())
    }

    fn apply(&mut self, record: Record, offset: u64) -> Result<(), Error> {
        match record.kind {
            Kind::Intent => {
                if self.pending.is_some() || record.key.sequence != self.next_sequence {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "invalid intent sequence",
                    });
                }
                self.pending = Some(PendingMutation {
                    key: record.key,
                    intent: record.payload,
                    device_request: None,
                    terminal: None,
                });
            }
            Kind::DeviceRequest => {
                let pending = self.pending.as_mut().ok_or(Error::Corrupt {
                    offset,
                    reason: "device request without intent",
                })?;
                if pending.key != record.key || pending.device_request.is_some() {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "conflicting device request",
                    });
                }
                pending.device_request = Some(record.payload);
            }
            Kind::Terminal => {
                let pending = self.pending.as_mut().ok_or(Error::Corrupt {
                    offset,
                    reason: "terminal result without intent",
                })?;
                if pending.key != record.key
                    || pending.device_request.is_none()
                    || pending.terminal.is_some()
                    || record.payload.len() < 32
                {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "invalid terminal result",
                    });
                }
                let result_digest = record.payload[..32]
                    .try_into()
                    .expect("length checked above");
                pending.terminal = Some(TerminalResult {
                    result_digest,
                    public_result: record.payload[32..].to_vec(),
                });
            }
            Kind::Acknowledged => {
                let pending = self.pending.take().ok_or(Error::Corrupt {
                    offset,
                    reason: "acknowledgment without terminal result",
                })?;
                let Some(terminal) = pending.terminal else {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "acknowledgment before terminal result",
                    });
                };
                if pending.key != record.key || record.payload.as_slice() != terminal.result_digest
                {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "acknowledgment result mismatch",
                    });
                }
                self.completed.push(CompletedMutation {
                    key: record.key,
                    intent: pending.intent,
                    device_request: pending.device_request.expect("device request checked"),
                    terminal,
                });
                self.next_sequence = record.key.sequence.checked_add(1).ok_or(Error::Corrupt {
                    offset,
                    reason: "sequence exhausted",
                })?;
            }
            Kind::Declined => {
                let pending = self.pending.take().ok_or(Error::Corrupt {
                    offset,
                    reason: "decline without terminal result",
                })?;
                let Some(terminal) = pending.terminal else {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "decline before terminal result",
                    });
                };
                if pending.key != record.key || record.payload.as_slice() != terminal.result_digest
                {
                    return Err(Error::Corrupt {
                        offset,
                        reason: "decline result mismatch",
                    });
                }
                self.completed.push(CompletedMutation {
                    key: record.key,
                    intent: pending.intent,
                    device_request: pending.device_request.expect("device request checked"),
                    terminal,
                });
            }
        }
        Ok(())
    }
}

fn validate_parent(path: &Path) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = std::fs::metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

fn checked_record_len(payload: &[u8]) -> Result<u64, Error> {
    if payload.len() > MAX_RECORD_PAYLOAD {
        return Err(Error::PayloadTooLarge);
    }
    Ok(HEADER_LEN as u64 + payload.len() as u64)
}

fn encode_record(kind: Kind, key: MutationKey, payload: &[u8]) -> Result<Vec<u8>, Error> {
    checked_record_len(payload)?;
    let mut encoded = Vec::with_capacity(HEADER_LEN + payload.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&VERSION.to_be_bytes());
    encoded.push(kind as u8);
    encoded.push(0);
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&key.sequence.to_be_bytes());
    encoded.extend_from_slice(&key.operation_id);
    encoded.extend_from_slice(&key.request_digest);
    let mut hash = Sha256::new();
    hash.update(&encoded);
    hash.update(payload);
    encoded.extend_from_slice(&hash.finalize());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn read_records(file: &mut File, length: u64) -> Result<(Vec<Record>, u64, bool), Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut records = Vec::new();
    let mut offset = 0u64;
    while offset < length {
        let remaining = length - offset;
        if remaining < HEADER_LEN as u64 {
            return Ok((records, offset, true));
        }
        let mut header = [0; HEADER_LEN];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC || u16::from_be_bytes(header[8..10].try_into().unwrap()) != VERSION
        {
            return Err(Error::Corrupt {
                offset,
                reason: "invalid record header",
            });
        }
        let kind = Kind::parse(header[10]).ok_or(Error::Corrupt {
            offset,
            reason: "unknown record kind",
        })?;
        if header[11] != 0 {
            return Err(Error::Corrupt {
                offset,
                reason: "nonzero reserved byte",
            });
        }
        let payload_len = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
        if payload_len > MAX_RECORD_PAYLOAD {
            return Err(Error::Corrupt {
                offset,
                reason: "record payload exceeds bound",
            });
        }
        let record_len = HEADER_LEN as u64 + payload_len as u64;
        if remaining < record_len {
            return Ok((records, offset, true));
        }
        let key = MutationKey {
            sequence: u64::from_be_bytes(header[16..24].try_into().unwrap()),
            operation_id: header[24..40].try_into().unwrap(),
            request_digest: header[40..72].try_into().unwrap(),
        };
        let mut payload = vec![0; payload_len];
        file.read_exact(&mut payload)?;
        let mut hash = Sha256::new();
        hash.update(&header[..72]);
        hash.update(&payload);
        let expected: [u8; 32] = hash.finalize().into();
        if header[72..104] != expected {
            return Err(Error::Corrupt {
                offset,
                reason: "checksum mismatch",
            });
        }
        records.push(Record { kind, key, payload });
        offset += record_len;
    }
    Ok((records, offset, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pico2-journal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn key(sequence: u64) -> MutationKey {
        MutationKey {
            sequence,
            operation_id: [sequence as u8; 16],
            request_digest: [sequence as u8 + 1; 32],
        }
    }

    #[test]
    fn restart_preserves_outstanding_and_completed_results() {
        let dir = TestDir::new();
        let path = dir.0.join("journal");
        let mut journal = Journal::open(&path).unwrap();
        journal.append_intent(key(0), b"cli").unwrap();
        journal.append_device_request(key(0), b"usb").unwrap();
        journal
            .append_terminal(key(0), [7; 32], b"commissioned")
            .unwrap();
        drop(journal);

        let mut journal = Journal::open(&path).unwrap();
        let pending = journal.pending().unwrap();
        assert_eq!(pending.intent, b"cli");
        assert_eq!(pending.device_request.as_deref(), Some(b"usb".as_slice()));
        assert_eq!(
            pending.terminal.as_ref().unwrap().public_result,
            b"commissioned"
        );
        journal.append_acknowledged(key(0), [7; 32]).unwrap();
        drop(journal);

        let journal = Journal::open(&path).unwrap();
        assert!(journal.pending().is_none());
        assert_eq!(journal.next_sequence(), 1);
        assert_eq!(
            journal.completed()[0].terminal.public_result,
            b"commissioned"
        );
    }

    #[test]
    fn torn_tail_is_removed_but_complete_corruption_fails_closed() {
        let dir = TestDir::new();
        let path = dir.0.join("journal");
        let mut journal = Journal::open(&path).unwrap();
        journal.append_intent(key(0), b"intent").unwrap();
        let valid = journal.length();
        drop(journal);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"PKAJ").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let journal = Journal::open(&path).unwrap();
        assert!(journal.recovered_torn_tail());
        assert_eq!(journal.length(), valid);
        drop(journal);

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[72] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(Journal::open(&path), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn declined_pre_admission_result_is_reconcilable_without_consuming_sequence() {
        let dir = TestDir::new();
        let path = dir.0.join("journal");
        let mut journal = Journal::open(&path).unwrap();
        journal.append_intent(key(0), b"first").unwrap();
        journal.append_device_request(key(0), b"wire").unwrap();
        journal
            .append_terminal(key(0), [9; 32], b"revision conflict")
            .unwrap();
        journal.append_declined(key(0), [9; 32]).unwrap();
        assert_eq!(journal.next_sequence(), 0);
        assert_eq!(journal.completed().len(), 1);
        journal
            .append_intent(
                MutationKey {
                    sequence: 0,
                    operation_id: [7; 16],
                    request_digest: [8; 32],
                },
                b"retry",
            )
            .unwrap();
        drop(journal);

        let journal = Journal::open(&path).unwrap();
        assert_eq!(journal.next_sequence(), 0);
        assert_eq!(journal.completed().len(), 1);
        assert_eq!(journal.pending().unwrap().intent, b"retry");
    }

    #[test]
    fn conflicts_and_ordering_cannot_advance_state() {
        let dir = TestDir::new();
        let path = dir.0.join("journal");
        let mut journal = Journal::open(&path).unwrap();
        assert!(matches!(
            journal.append_intent(key(1), b"x"),
            Err(Error::Conflict)
        ));
        journal.append_intent(key(0), b"x").unwrap();
        assert!(matches!(
            journal.append_intent(key(0), b"x"),
            Err(Error::Busy)
        ));
        assert!(matches!(
            journal.append_terminal(key(0), [2; 32], b"result"),
            Err(Error::InvalidTransition)
        ));
        journal.append_device_request(key(0), b"wire").unwrap();
        journal.append_terminal(key(0), [2; 32], b"result").unwrap();
        assert!(matches!(
            journal.append_acknowledged(key(0), [3; 32]),
            Err(Error::Conflict)
        ));
        assert_eq!(journal.next_sequence(), 0);
    }
}
