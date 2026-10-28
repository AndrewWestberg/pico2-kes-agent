use crate::identity::{Digest32, StorageSlot};
use crate::platform::{Entropy, fill_secret};
use crate::platform::{Flash, FlashError, PAGE_SIZE, SECTOR_SIZE};
use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const CONFIG_START: u32 = 0x100000;
pub const CONFIG_BANK_BYTES: u32 = 0x2000;
pub const POOLS_START: u32 = 0x104000;
pub const POOL_REGION_BYTES: u32 = 0x8000;
pub const POOL_BANK_BYTES: u32 = 0x1000;
pub const PUBLIC_OBJECT_BYTES: u32 = 0x2000;
pub const HANDOFF_START: u32 = 0x304000;
pub const HANDOFF_BANK_BYTES: u32 = 0x2000;
pub const ALLOCATED_END: u32 = 0x308000;
pub const MAX_SNAPSHOT_BYTES: usize = 7_400;
pub const MAX_PUBLIC_OBJECT_BYTES: usize = PUBLIC_OBJECT_BYTES as usize;
const HEADER_BYTES: usize = PAGE_SIZE as usize;
const MARKER_BYTES: usize = PAGE_SIZE as usize;
const TAG_BYTES: usize = 16;
const HEADER_MAGIC: &[u8; 8] = b"PKASNP01";
const COMMIT_MAGIC: &[u8; 8] = b"PKACMT01";
const CLEAN_MAGIC: &[u8; 8] = b"PKACLN01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Flash(FlashError),
    Geometry,
    Bounds,
    Entropy,
    Crypto,
    InvalidRecord,
    InvalidMarker,
    UnsupportedVersion,
    RevisionOverflow,
    ParentConflict,
    EqualRevisionConflict,
    CommittedBodyInvalid,
    PublicObjectInvalid,
    Unavailable,
}

impl From<FlashError> for StorageError {
    fn from(error: FlashError) -> Self {
        Self::Flash(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDomain {
    Configuration,
    Pool(StorageSlot),
    Handoff,
}

impl RecordDomain {
    fn id(self) -> (u8, u8) {
        match self {
            Self::Configuration => (0, 0),
            Self::Pool(slot) => (1, slot.get()),
            Self::Handoff => (2, 0),
        }
    }

    pub const fn layout(self) -> BankLayout {
        match self {
            Self::Configuration => BankLayout {
                first: CONFIG_START,
                second: CONFIG_START + CONFIG_BANK_BYTES,
                bank_bytes: CONFIG_BANK_BYTES,
            },
            Self::Pool(slot) => {
                let base = POOLS_START + slot.get() as u32 * POOL_REGION_BYTES;
                BankLayout {
                    first: base,
                    second: base + POOL_BANK_BYTES,
                    bank_bytes: POOL_BANK_BYTES,
                }
            }
            Self::Handoff => BankLayout {
                first: HANDOFF_START,
                second: HANDOFF_START + HANDOFF_BANK_BYTES,
                bank_bytes: HANDOFF_BANK_BYTES,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BankLayout {
    pub first: u32,
    pub second: u32,
    pub bank_bytes: u32,
}

impl BankLayout {
    pub fn payload_capacity(self) -> Result<usize, StorageError> {
        let reserved = HEADER_BYTES + 2 * MARKER_BYTES + TAG_BYTES;
        usize::try_from(self.bank_bytes)
            .map_err(|_| StorageError::Bounds)?
            .checked_sub(reserved)
            .ok_or(StorageError::Bounds)
    }

    fn addresses(self, bank: Bank) -> BankAddresses {
        let start = match bank {
            Bank::First => self.first,
            Bank::Second => self.second,
        };
        BankAddresses {
            start,
            commit: start + self.bank_bytes - 2 * PAGE_SIZE,
            clean: start + self.bank_bytes - PAGE_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bank {
    First,
    Second,
}

impl Bank {
    const fn other(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BankAddresses {
    start: u32,
    commit: u32,
    clean: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicObjectRef {
    pub generation: [u8; 16],
    pub digest: Digest32,
    pub region: u8,
    pub length: u16,
}

pub struct PublicObjectWrite<'a> {
    pub reference: PublicObjectRef,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotMeta {
    pub revision: u64,
    pub parent_revision: Option<u64>,
    pub parent_digest: Digest32,
    pub object: Option<PublicObjectRef>,
}

pub struct Snapshot {
    meta: SnapshotMeta,
    digest: Digest32,
    payload: [u8; MAX_SNAPSHOT_BYTES],
    len: u16,
}

impl Snapshot {
    pub const fn meta(&self) -> SnapshotMeta {
        self.meta
    }

    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovered {
    Empty,
    Clean(Bank),
    CleanupRequired(Bank),
}

pub struct Storage<F, E> {
    flash: F,
    entropy: E,
    root_key: Zeroizing<[u8; 32]>,
}

impl<F: Flash, E: Entropy> Storage<F, E> {
    pub fn new(flash: F, entropy: E, root_key: [u8; 32]) -> Result<Self, StorageError> {
        let geometry = flash.geometry();
        if geometry.capacity() < ALLOCATED_END {
            return Err(StorageError::Geometry);
        }
        Ok(Self {
            flash,
            entropy,
            root_key: Zeroizing::new(root_key),
        })
    }

    pub const fn flash(&self) -> &F {
        &self.flash
    }

    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    pub fn entropy_mut(&mut self) -> &mut E {
        &mut self.entropy
    }

    pub fn into_flash(self) -> F {
        self.flash
    }

    pub fn transact(
        &mut self,
        domain: RecordDomain,
        authoritative: Option<(Bank, &Snapshot)>,
        payload: &[u8],
        object: Option<PublicObjectWrite<'_>>,
    ) -> Result<Snapshot, StorageError> {
        let layout = domain.layout();
        if payload.len() > layout.payload_capacity()? || payload.len() > MAX_SNAPSHOT_BYTES {
            return Err(StorageError::Bounds);
        }
        let (candidate, revision, parent_revision, parent_digest) = match authoritative {
            Some((bank, snapshot)) => (
                bank.other(),
                snapshot
                    .meta
                    .revision
                    .checked_add(1)
                    .ok_or(StorageError::RevisionOverflow)?,
                Some(snapshot.meta.revision),
                snapshot.digest,
            ),
            None => (Bank::First, 0, None, Digest32::from_bytes([0; 32])),
        };
        let object_ref = object.as_ref().map(|value| value.reference);
        if let Some(value) = object {
            self.write_public_object(domain, &value)?;
        }
        let meta = SnapshotMeta {
            revision,
            parent_revision,
            parent_digest,
            object: object_ref,
        };
        let digest = snapshot_digest(domain, meta, payload);
        let addresses = layout.addresses(candidate);
        self.erase_verify(addresses.start, layout.bank_bytes)?;
        let keys = DomainKeys::derive(&self.root_key, domain)?;
        let mut nonce = [0; 24];
        fill_secret(&mut self.entropy, &mut nonce).map_err(|_| StorageError::Entropy)?;
        let header = Header::new(domain, meta, digest, nonce, payload.len())?;
        let encoded_header = header.encode();
        let cipher = XChaCha20Poly1305::new((&keys.snapshot).into());
        let mut encrypted = Zeroizing::new([0; MAX_SNAPSHOT_BYTES + TAG_BYTES]);
        encrypted[..payload.len()].copy_from_slice(payload);
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &encoded_header,
                &mut encrypted[..payload.len()],
            )
            .map_err(|_| StorageError::Crypto)?;
        encrypted[payload.len()..payload.len() + TAG_BYTES].copy_from_slice(&tag);
        self.program_pages(addresses.start, &encoded_header)?;
        self.program_pages(
            addresses.start + PAGE_SIZE,
            &encrypted[..payload.len() + TAG_BYTES],
        )?;
        let candidate_snapshot = self
            .read_snapshot(domain, candidate, &keys)?
            .ok_or(StorageError::InvalidRecord)?;
        if candidate_snapshot.digest != digest || candidate_snapshot.payload() != payload {
            return Err(StorageError::InvalidRecord);
        }
        let commit = marker(COMMIT_MAGIC, domain, revision, digest, &keys.commit)?;
        self.program_marker_verify(addresses.commit, &commit)?;
        if let Some((predecessor, _)) = authoritative {
            let old = layout.addresses(predecessor);
            self.erase_verify(old.start, layout.bank_bytes)?;
        }
        let clean = marker(CLEAN_MAGIC, domain, revision, digest, &keys.clean)?;
        self.program_marker_verify(addresses.clean, &clean)?;
        self.verify_public_reference(domain, candidate_snapshot.meta.object)?;
        Ok(candidate_snapshot)
    }

    pub fn recover(
        &mut self,
        domain: RecordDomain,
        directory_allows_empty: bool,
    ) -> Result<(Recovered, Option<Snapshot>), StorageError> {
        let layout = domain.layout();
        let keys = DomainKeys::derive(&self.root_key, domain)?;
        let first = self.scan_bank(domain, Bank::First, &keys)?;
        let second = self.scan_bank(domain, Bank::Second, &keys)?;
        let chosen = choose(first.as_ref(), second.as_ref(), directory_allows_empty)?;
        let Some((bank, clean)) = chosen else {
            self.erase_if_nonblank(layout.addresses(Bank::First).start, layout.bank_bytes)?;
            self.erase_if_nonblank(layout.addresses(Bank::Second).start, layout.bank_bytes)?;
            return Ok((Recovered::Empty, None));
        };
        let snapshot = match bank {
            Bank::First => first.unwrap().snapshot.unwrap(),
            Bank::Second => second.unwrap().snapshot.unwrap(),
        };
        self.verify_public_reference(domain, snapshot.meta.object)?;
        let other = bank.other();
        self.erase_if_nonblank(layout.addresses(other).start, layout.bank_bytes)?;
        if !clean {
            let clean_marker = marker(
                CLEAN_MAGIC,
                domain,
                snapshot.meta.revision,
                snapshot.digest,
                &keys.clean,
            )?;
            self.program_marker_verify(layout.addresses(bank).clean, &clean_marker)?;
            Ok((Recovered::CleanupRequired(bank), Some(snapshot)))
        } else {
            Ok((Recovered::Clean(bank), Some(snapshot)))
        }
    }

    fn scan_bank(
        &mut self,
        domain: RecordDomain,
        bank: Bank,
        keys: &DomainKeys,
    ) -> Result<Option<Scanned>, StorageError> {
        let addresses = domain.layout().addresses(bank);
        let mut commit = [0; MARKER_BYTES];
        self.flash.read_marker(addresses.commit, &mut commit)?;
        if commit.iter().all(|byte| *byte == 0xff) {
            return Ok(None);
        }
        let Ok(marker) = parse_marker(&commit, COMMIT_MAGIC, domain, &keys.commit) else {
            return Ok(None);
        };
        let snapshot = match self.read_snapshot(domain, bank, keys) {
            Ok(Some(snapshot))
                if marker.revision == snapshot.meta.revision
                    && marker.digest == snapshot.digest =>
            {
                Some(snapshot)
            }
            Ok(_) | Err(StorageError::InvalidRecord | StorageError::UnsupportedVersion) => None,
            Err(error) => return Err(error),
        };
        let mut clean_bytes = [0; MARKER_BYTES];
        self.flash.read_marker(addresses.clean, &mut clean_bytes)?;
        let clean = snapshot.is_some()
            && clean_bytes.iter().any(|byte| *byte != 0xff)
            && parse_marker(&clean_bytes, CLEAN_MAGIC, domain, &keys.clean)
                .is_ok_and(|clean| clean == marker);
        Ok(Some(Scanned {
            marker,
            snapshot,
            clean,
        }))
    }

    fn read_snapshot(
        &mut self,
        domain: RecordDomain,
        bank: Bank,
        keys: &DomainKeys,
    ) -> Result<Option<Snapshot>, StorageError> {
        let addresses = domain.layout().addresses(bank);
        let mut header_bytes = [0; HEADER_BYTES];
        self.flash.read(addresses.start, &mut header_bytes)?;
        if header_bytes.iter().all(|byte| *byte == 0xff) {
            return Ok(None);
        }
        let header = Header::decode(domain, &header_bytes)?;
        if header.payload_len > domain.layout().payload_capacity()?
            || header.payload_len > MAX_SNAPSHOT_BYTES
        {
            return Err(StorageError::Bounds);
        }
        let mut encrypted = Zeroizing::new([0; MAX_SNAPSHOT_BYTES + TAG_BYTES]);
        self.flash.read(
            addresses.start + PAGE_SIZE,
            &mut encrypted[..header.payload_len + TAG_BYTES],
        )?;
        let tag_bytes: [u8; TAG_BYTES] = encrypted
            [header.payload_len..header.payload_len + TAG_BYTES]
            .try_into()
            .map_err(|_| StorageError::InvalidRecord)?;
        XChaCha20Poly1305::new((&keys.snapshot).into())
            .decrypt_in_place_detached(
                XNonce::from_slice(&header.nonce),
                &header_bytes,
                &mut encrypted[..header.payload_len],
                Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| StorageError::InvalidRecord)?;
        let digest = snapshot_digest(domain, header.meta, &encrypted[..header.payload_len]);
        if digest != header.digest {
            return Err(StorageError::InvalidRecord);
        }
        let mut payload = [0; MAX_SNAPSHOT_BYTES];
        payload[..header.payload_len].copy_from_slice(&encrypted[..header.payload_len]);
        Ok(Some(Snapshot {
            meta: header.meta,
            digest,
            payload,
            len: header.payload_len as u16,
        }))
    }

    fn write_public_object(
        &mut self,
        domain: RecordDomain,
        object: &PublicObjectWrite<'_>,
    ) -> Result<(), StorageError> {
        let RecordDomain::Pool(slot) = domain else {
            return Err(StorageError::PublicObjectInvalid);
        };
        if object.reference.region > 1
            || object.bytes.len() > MAX_PUBLIC_OBJECT_BYTES
            || usize::from(object.reference.length) != object.bytes.len()
        {
            return Err(StorageError::Bounds);
        }
        if Digest32::from_bytes(Sha256::digest(object.bytes).into()) != object.reference.digest {
            return Err(StorageError::PublicObjectInvalid);
        }
        let base = POOLS_START
            + slot.get() as u32 * POOL_REGION_BYTES
            + 2 * POOL_BANK_BYTES
            + u32::from(object.reference.region) * PUBLIC_OBJECT_BYTES;
        self.erase_verify(base, PUBLIC_OBJECT_BYTES)?;
        self.program_pages(base, object.bytes)?;
        let mut verify = [0; MAX_PUBLIC_OBJECT_BYTES];
        self.flash.read(base, &mut verify[..object.bytes.len()])?;
        if verify[..object.bytes.len()] != *object.bytes {
            return Err(StorageError::PublicObjectInvalid);
        }
        Ok(())
    }

    fn verify_public_reference(
        &mut self,
        domain: RecordDomain,
        object: Option<PublicObjectRef>,
    ) -> Result<(), StorageError> {
        let Some(object) = object else {
            return Ok(());
        };
        let RecordDomain::Pool(slot) = domain else {
            return Err(StorageError::PublicObjectInvalid);
        };
        let len = usize::from(object.length);
        if object.region > 1 || len == 0 || len > MAX_PUBLIC_OBJECT_BYTES {
            return Err(StorageError::PublicObjectInvalid);
        }
        let base = POOLS_START
            + slot.get() as u32 * POOL_REGION_BYTES
            + 2 * POOL_BANK_BYTES
            + u32::from(object.region) * PUBLIC_OBJECT_BYTES;
        let mut bytes = [0; MAX_PUBLIC_OBJECT_BYTES];
        self.flash.read(base, &mut bytes[..len])?;
        if Digest32::from_bytes(Sha256::digest(&bytes[..len]).into()) != object.digest {
            return Err(StorageError::PublicObjectInvalid);
        }
        Ok(())
    }

    fn erase_if_nonblank(&mut self, start: u32, len: u32) -> Result<(), StorageError> {
        let mut page = [0; PAGE_SIZE as usize];
        let mut address = start;
        while address < start + len {
            self.flash.read(address, &mut page)?;
            if page.iter().any(|byte| *byte != 0xff) {
                return self.erase_verify(start, len);
            }
            address += PAGE_SIZE;
        }
        Ok(())
    }

    fn erase_verify(&mut self, start: u32, len: u32) -> Result<(), StorageError> {
        if !start.is_multiple_of(SECTOR_SIZE) || !len.is_multiple_of(SECTOR_SIZE) {
            return Err(StorageError::Geometry);
        }
        let mut sector = start;
        while sector < start + len {
            self.flash.erase_sector(sector)?;
            sector += SECTOR_SIZE;
        }
        let mut page = [0; PAGE_SIZE as usize];
        let mut address = start;
        while address < start + len {
            self.flash.read(address, &mut page)?;
            if page.iter().any(|byte| *byte != 0xff) {
                return Err(StorageError::Flash(FlashError::RequiresErase));
            }
            address += PAGE_SIZE;
        }
        Ok(())
    }

    fn program_pages(&mut self, start: u32, bytes: &[u8]) -> Result<(), StorageError> {
        for (index, chunk) in bytes.chunks(PAGE_SIZE as usize).enumerate() {
            let mut page = [0xff; PAGE_SIZE as usize];
            page[..chunk.len()].copy_from_slice(chunk);
            let address = start + index as u32 * PAGE_SIZE;
            self.flash.program_page(address, &page)?;
            let mut verify = [0; PAGE_SIZE as usize];
            self.flash.read(address, &mut verify)?;
            if verify != page {
                return Err(StorageError::InvalidRecord);
            }
        }
        Ok(())
    }

    fn program_marker_verify(
        &mut self,
        address: u32,
        marker: &[u8; MARKER_BYTES],
    ) -> Result<(), StorageError> {
        self.flash.program_marker(address, marker)?;
        let mut verify = [0; MARKER_BYTES];
        self.flash.read_marker(address, &mut verify)?;
        if verify != *marker {
            return Err(StorageError::InvalidMarker);
        }
        Ok(())
    }
}

struct DomainKeys {
    snapshot: [u8; 32],
    commit: [u8; 32],
    clean: [u8; 32],
}

impl DomainKeys {
    fn derive(root: &[u8; 32], domain: RecordDomain) -> Result<Self, StorageError> {
        let (kind, slot) = domain.id();
        let hkdf = Hkdf::<Sha256>::new(Some(b"pico2-kes-storage-v1"), root);
        let mut keys = Self {
            snapshot: [0; 32],
            commit: [0; 32],
            clean: [0; 32],
        };
        let mut info = [0; 34];
        info[..31].copy_from_slice(b"pico2-kes-storage-domain-key-v1");
        info[31] = kind;
        info[32] = slot;
        info[33] = b'S';
        hkdf.expand(&info, &mut keys.snapshot)
            .map_err(|_| StorageError::Crypto)?;
        info[33] = b'C';
        hkdf.expand(&info, &mut keys.commit)
            .map_err(|_| StorageError::Crypto)?;
        info[33] = b'L';
        hkdf.expand(&info, &mut keys.clean)
            .map_err(|_| StorageError::Crypto)?;
        Ok(keys)
    }
}

impl Drop for DomainKeys {
    fn drop(&mut self) {
        self.snapshot.zeroize();
        self.commit.zeroize();
        self.clean.zeroize();
    }
}

struct Header {
    meta: SnapshotMeta,
    digest: Digest32,
    nonce: [u8; 24],
    payload_len: usize,
    domain: RecordDomain,
}

impl Header {
    fn new(
        domain: RecordDomain,
        meta: SnapshotMeta,
        digest: Digest32,
        nonce: [u8; 24],
        payload_len: usize,
    ) -> Result<Self, StorageError> {
        if payload_len > u16::MAX as usize {
            return Err(StorageError::Bounds);
        }
        Ok(Self {
            meta,
            digest,
            nonce,
            payload_len,
            domain,
        })
    }

    fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut output = [0; HEADER_BYTES];
        output[..8].copy_from_slice(HEADER_MAGIC);
        output[8..10].copy_from_slice(&1u16.to_be_bytes());
        let (kind, slot) = self.domain.id();
        output[10] = kind;
        output[11] = slot;
        output[12..20].copy_from_slice(&self.meta.revision.to_be_bytes());
        output[20] = self.meta.parent_revision.is_some() as u8;
        output[21..29].copy_from_slice(&self.meta.parent_revision.unwrap_or(0).to_be_bytes());
        output[29..61].copy_from_slice(self.meta.parent_digest.as_bytes());
        output[61..93].copy_from_slice(self.digest.as_bytes());
        output[93..117].copy_from_slice(&self.nonce);
        output[117..119].copy_from_slice(&(self.payload_len as u16).to_be_bytes());
        if let Some(object) = self.meta.object {
            output[119] = 1;
            output[120] = object.region;
            output[121..137].copy_from_slice(&object.generation);
            output[137..169].copy_from_slice(object.digest.as_bytes());
            output[169..171].copy_from_slice(&object.length.to_be_bytes());
        }
        output
    }

    fn decode(domain: RecordDomain, bytes: &[u8; HEADER_BYTES]) -> Result<Self, StorageError> {
        if &bytes[..8] != HEADER_MAGIC {
            return Err(StorageError::InvalidRecord);
        }
        if u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let (kind, slot) = domain.id();
        if bytes[10] != kind || bytes[11] != slot {
            return Err(StorageError::InvalidRecord);
        }
        let revision = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        let parent_revision = match bytes[20] {
            0 => None,
            1 => Some(u64::from_be_bytes(bytes[21..29].try_into().unwrap())),
            _ => return Err(StorageError::InvalidRecord),
        };
        let parent_digest = Digest32::from_bytes(bytes[29..61].try_into().unwrap());
        let digest = Digest32::from_bytes(bytes[61..93].try_into().unwrap());
        let nonce = bytes[93..117].try_into().unwrap();
        let payload_len = usize::from(u16::from_be_bytes(bytes[117..119].try_into().unwrap()));
        let object = match bytes[119] {
            0 => None,
            1 => Some(PublicObjectRef {
                region: bytes[120],
                generation: bytes[121..137].try_into().unwrap(),
                digest: Digest32::from_bytes(bytes[137..169].try_into().unwrap()),
                length: u16::from_be_bytes(bytes[169..171].try_into().unwrap()),
            }),
            _ => return Err(StorageError::InvalidRecord),
        };
        if bytes[171..].iter().any(|byte| *byte != 0) {
            return Err(StorageError::InvalidRecord);
        }
        Ok(Self {
            meta: SnapshotMeta {
                revision,
                parent_revision,
                parent_digest,
                object,
            },
            digest,
            nonce,
            payload_len,
            domain,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Marker {
    revision: u64,
    digest: Digest32,
}

fn marker(
    magic: &[u8; 8],
    domain: RecordDomain,
    revision: u64,
    digest: Digest32,
    key: &[u8; 32],
) -> Result<[u8; MARKER_BYTES], StorageError> {
    let mut output = [0; MARKER_BYTES];
    output[..8].copy_from_slice(magic);
    output[8..10].copy_from_slice(&1u16.to_be_bytes());
    let (kind, slot) = domain.id();
    output[10] = kind;
    output[11] = slot;
    output[12..20].copy_from_slice(&revision.to_be_bytes());
    output[20..52].copy_from_slice(digest.as_bytes());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| StorageError::Crypto)?;
    mac.update(&output[..52]);
    output[52..84].copy_from_slice(&mac.finalize().into_bytes());
    Ok(output)
}

fn parse_marker(
    bytes: &[u8; MARKER_BYTES],
    magic: &[u8; 8],
    domain: RecordDomain,
    key: &[u8; 32],
) -> Result<Marker, StorageError> {
    if &bytes[..8] != magic || bytes[84..].iter().any(|byte| *byte != 0) {
        return Err(StorageError::InvalidMarker);
    }
    let revision = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    let digest = Digest32::from_bytes(bytes[20..52].try_into().unwrap());
    if marker(magic, domain, revision, digest, key)? != *bytes {
        return Err(StorageError::InvalidMarker);
    }
    Ok(Marker { revision, digest })
}

struct Scanned {
    marker: Marker,
    snapshot: Option<Snapshot>,
    clean: bool,
}

fn choose(
    first: Option<&Scanned>,
    second: Option<&Scanned>,
    directory_allows_empty: bool,
) -> Result<Option<(Bank, bool)>, StorageError> {
    match (first, second) {
        (None, None) if directory_allows_empty => Ok(None),
        (None, None) => Err(StorageError::Unavailable),
        (Some(value), None) => choose_single(Bank::First, value),
        (None, Some(value)) => choose_single(Bank::Second, value),
        (Some(left), Some(right)) => match (&left.snapshot, &right.snapshot) {
            (None, None) => Err(StorageError::CommittedBodyInvalid),
            (Some(_), None) => choose_over_invalid(Bank::First, left, right),
            (None, Some(_)) => choose_over_invalid(Bank::Second, right, left),
            (Some(left_snapshot), Some(right_snapshot)) => {
                if left_snapshot.meta.revision == right_snapshot.meta.revision {
                    return Err(StorageError::EqualRevisionConflict);
                }
                let (new_bank, new, old) =
                    if left_snapshot.meta.revision > right_snapshot.meta.revision {
                        (Bank::First, left, right)
                    } else {
                        (Bank::Second, right, left)
                    };
                let new_snapshot = new.snapshot.as_ref().unwrap();
                let old_snapshot = old.snapshot.as_ref().unwrap();
                if new_snapshot.meta.parent_revision != Some(old_snapshot.meta.revision)
                    || new_snapshot.meta.parent_digest != old_snapshot.digest
                {
                    return Err(StorageError::ParentConflict);
                }
                Ok(Some((new_bank, new.clean)))
            }
        },
    }
}

fn choose_single(bank: Bank, value: &Scanned) -> Result<Option<(Bank, bool)>, StorageError> {
    if value.snapshot.is_some() {
        Ok(Some((bank, value.clean)))
    } else {
        Err(StorageError::CommittedBodyInvalid)
    }
}

fn choose_over_invalid(
    valid_bank: Bank,
    valid: &Scanned,
    invalid: &Scanned,
) -> Result<Option<(Bank, bool)>, StorageError> {
    let snapshot = valid.snapshot.as_ref().unwrap();
    if snapshot.meta.revision > invalid.marker.revision
        && snapshot.meta.parent_revision == Some(invalid.marker.revision)
        && snapshot.meta.parent_digest == invalid.marker.digest
    {
        Ok(Some((valid_bank, valid.clean)))
    } else {
        Err(StorageError::CommittedBodyInvalid)
    }
}

fn snapshot_digest(domain: RecordDomain, meta: SnapshotMeta, payload: &[u8]) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(b"pico2-kes-snapshot-v1");
    let (kind, slot) = domain.id();
    digest.update([kind, slot]);
    digest.update(meta.revision.to_be_bytes());
    digest.update([meta.parent_revision.is_some() as u8]);
    digest.update(meta.parent_revision.unwrap_or(0).to_be_bytes());
    digest.update(meta.parent_digest.as_bytes());
    if let Some(object) = meta.object {
        digest.update([1, object.region]);
        digest.update(object.generation);
        digest.update(object.digest.as_bytes());
        digest.update(object.length.to_be_bytes());
    } else {
        digest.update([0, 0]);
        digest.update([0; 16]);
        digest.update([0; 32]);
        digest.update([0; 2]);
    }
    digest.update((payload.len() as u32).to_be_bytes());
    digest.update(payload);
    Digest32::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::platform::{EntropyError, Geometry};
    use std::vec;
    use std::vec::Vec;

    struct TestFlash {
        geometry: Geometry,
        bytes: Vec<u8>,
        marker_programs: usize,
    }

    impl TestFlash {
        fn new() -> Self {
            Self {
                geometry: Geometry::new(0x400000, PAGE_SIZE, SECTOR_SIZE).unwrap(),
                bytes: vec![0xff; 0x400000],
                marker_programs: 0,
            }
        }
    }

    impl Flash for TestFlash {
        fn geometry(&self) -> Geometry {
            self.geometry
        }

        fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
            self.geometry.range(address, output.len())?;
            output.copy_from_slice(&self.bytes[address as usize..address as usize + output.len()]);
            Ok(())
        }

        fn program_page(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
            self.geometry.program(address, data.len())?;
            let target = &mut self.bytes[address as usize..address as usize + data.len()];
            if target.iter().zip(data).any(|(old, new)| old & new != *new) {
                return Err(FlashError::RequiresErase);
            }
            for (old, new) in target.iter_mut().zip(data) {
                *old &= *new;
            }
            Ok(())
        }

        fn erase_sector(&mut self, address: u32) -> Result<(), FlashError> {
            self.geometry.erase(address)?;
            self.bytes[address as usize..address as usize + SECTOR_SIZE as usize].fill(0xff);
            Ok(())
        }

        fn read_marker(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
            self.read(address, output)
        }

        fn program_marker(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
            self.marker_programs += 1;
            self.program_page(address, data)
        }
    }

    struct CounterEntropy(u8);

    impl Entropy for CounterEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn geometry_proves_maximum_payload_and_public_object_bounds() {
        assert_eq!(
            RecordDomain::Pool(StorageSlot::new(63).unwrap())
                .layout()
                .payload_capacity(),
            Ok(3_312)
        );
        assert_eq!(
            RecordDomain::Configuration.layout().payload_capacity(),
            Ok(7_408)
        );
        assert_eq!(RecordDomain::Handoff.layout().payload_capacity(), Ok(7_408));
        assert_eq!(
            RecordDomain::Handoff.layout().second + HANDOFF_BANK_BYTES,
            ALLOCATED_END
        );
        assert_eq!(MAX_PUBLIC_OBJECT_BYTES, 8_192);
        assert_eq!(
            RecordDomain::Pool(StorageSlot::new(63).unwrap())
                .layout()
                .second
                + POOL_BANK_BYTES,
            POOLS_START + 63 * POOL_REGION_BYTES + 2 * POOL_BANK_BYTES
        );
    }

    #[test]
    fn transaction_writes_object_body_commit_clean_and_recovers() {
        let slot = StorageSlot::new(0).unwrap();
        let domain = RecordDomain::Pool(slot);
        let mut storage = Storage::new(TestFlash::new(), CounterEntropy(1), [9; 32]).unwrap();
        let mut object = [7; 64];
        object[63] = 0xff;
        let object_ref = PublicObjectRef {
            generation: [3; 16],
            digest: Digest32::from_bytes(Sha256::digest(object).into()),
            region: 0,
            length: object.len() as u16,
        };
        let first = storage
            .transact(
                domain,
                None,
                &[1; 3_000],
                Some(PublicObjectWrite {
                    reference: object_ref,
                    bytes: &object,
                }),
            )
            .unwrap();
        assert_eq!(first.meta().revision, 0);
        assert_eq!(storage.flash().marker_programs, 2);
        let (status, recovered) = storage.recover(domain, false).unwrap();
        assert_eq!(status, Recovered::Clean(Bank::First));
        assert_eq!(recovered.unwrap().payload(), &[1; 3_000]);

        let second = storage
            .transact(domain, Some((Bank::First, &first)), &[2; 3_000], None)
            .unwrap();
        assert_eq!(second.meta().parent_digest, first.digest());
        let (status, recovered) = storage.recover(domain, false).unwrap();
        assert_eq!(status, Recovered::Clean(Bank::Second));
        assert_eq!(recovered.unwrap().payload(), &[2; 3_000]);
    }

    #[test]
    fn empty_enrolled_slot_fails_closed() {
        let mut storage = Storage::new(TestFlash::new(), CounterEntropy(1), [9; 32]).unwrap();
        let domain = RecordDomain::Pool(StorageSlot::new(0).unwrap());
        assert!(matches!(
            storage.recover(domain, false),
            Err(StorageError::Unavailable)
        ));
        assert!(matches!(
            storage.recover(domain, true),
            Ok((Recovered::Empty, None))
        ));
    }
}
