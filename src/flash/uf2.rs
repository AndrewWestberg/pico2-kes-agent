//! Native UF2/ELF header, sector, and signed-metadata validation and BOOTSEL mass-storage transfer.

use rustix::fs::{self as fs_at, AtFlags, CWD, FileType, Mode, OFlags};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const UF2_MAGIC_START0: u32 = 0x0A32_4655;
pub const UF2_MAGIC_START1: u32 = 0x9E5D_5157;
pub const UF2_MAGIC_END: u32 = 0x0AB1_6F30;
pub const UF2_BLOCK_SIZE: usize = 512;
pub const UF2_FLAGS_FAMILY_ID_PRESENT: u32 = 0x0000_2000;
pub const UF2_FAMILY_RP2350_ARM_S: u32 = 0xE48B_FF59;
pub const UF2_PAGE_SIZE: u32 = 256;
pub const FLASH_SECTOR_SIZE: u32 = 4096;
pub const MAX_UF2_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ELF_BYTES: usize = 16 * 1024 * 1024;
pub const FIRMWARE_START: u32 = 0x1000_0000;
pub const FIRMWARE_END: u32 = 0x1010_0000;
pub const STATE_END: u32 = 0x1030_8000;
const SRAM_START: u32 = 0x2000_0000;
const SRAM_END: u32 = 0x2008_2000;

pub fn parse_uf2_pages(bytes: &[u8]) -> Result<BTreeMap<u32, [u8; 256]>, String> {
    if bytes.is_empty()
        || bytes.len() > MAX_UF2_BYTES
        || !bytes.len().is_multiple_of(UF2_BLOCK_SIZE)
    {
        return Err("UF2 length must be a non-zero multiple of 512 bytes (<= 4 MiB)".into());
    }
    let blocks = bytes.len() / UF2_BLOCK_SIZE;
    let mut pages = BTreeMap::new();
    for (idx, chunk) in bytes.as_chunks::<UF2_BLOCK_SIZE>().0.iter().enumerate() {
        let m0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let m1 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let flags = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let target_addr = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        let payload_size = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
        let block_no = u32::from_le_bytes(chunk[20..24].try_into().unwrap());
        let num_blocks = u32::from_le_bytes(chunk[24..28].try_into().unwrap());
        let family_id = u32::from_le_bytes(chunk[28..32].try_into().unwrap());
        let mend = u32::from_le_bytes(chunk[508..512].try_into().unwrap());

        if m0 != UF2_MAGIC_START0 || m1 != UF2_MAGIC_START1 || mend != UF2_MAGIC_END {
            return Err(format!("invalid UF2 magic in block {idx}"));
        }
        if flags != UF2_FLAGS_FAMILY_ID_PRESENT {
            return Err(format!(
                "invalid UF2 flags 0x{flags:08x} in block {idx} (expected 0x{UF2_FLAGS_FAMILY_ID_PRESENT:08x})"
            ));
        }
        if family_id != UF2_FAMILY_RP2350_ARM_S {
            return Err(format!(
                "invalid UF2 family_id 0x{family_id:08x} in block {idx} (expected RP2350 ARM-S 0x{UF2_FAMILY_RP2350_ARM_S:08x})"
            ));
        }
        if payload_size != UF2_PAGE_SIZE {
            return Err(format!(
                "invalid UF2 payload_size {payload_size} in block {idx} (expected {UF2_PAGE_SIZE})"
            ));
        }
        if block_no as usize != idx || num_blocks as usize != blocks {
            return Err(format!("UF2 block sequence mismatch at {idx}"));
        }
        if !target_addr.is_multiple_of(UF2_PAGE_SIZE) {
            return Err(format!(
                "unaligned UF2 target_addr 0x{target_addr:08x} in block {idx} (must be 256-byte aligned)"
            ));
        }
        if !(FIRMWARE_START..FIRMWARE_END).contains(&target_addr) {
            return Err(format!(
                "UF2 target_addr 0x{target_addr:08x} outside RP2350 firmware partition [0x{FIRMWARE_START:08x}, 0x{FIRMWARE_END:08x})"
            ));
        }
        if chunk[288..508].iter().any(|&b| b != 0) {
            return Err(format!(
                "non-zero UF2 padding bytes in block {idx} at 0x{target_addr:08x}"
            ));
        }
        let page: [u8; 256] = chunk[32..288].try_into().unwrap();
        if pages.insert(target_addr, page).is_some() {
            return Err(format!(
                "duplicate UF2 target_addr 0x{target_addr:08x} in block {idx}"
            ));
        }
    }
    Ok(pages)
}

pub fn validate_uf2(bytes: &[u8]) -> Result<usize, String> {
    parse_uf2_pages(bytes).map(|pages| pages.len())
}

pub fn elf_segments(elf_bytes: &[u8]) -> Result<Vec<(u32, &[u8])>, String> {
    if elf_bytes.len() < 52
        || elf_bytes.len() > MAX_ELF_BYTES
        || &elf_bytes[..7] != b"\x7fELF\x01\x01\x01"
    {
        return Err("invalid or oversized ELF32 little-endian firmware image".into());
    }
    let e_type = u16::from_le_bytes(elf_bytes[16..18].try_into().unwrap());
    let e_machine = u16::from_le_bytes(elf_bytes[18..20].try_into().unwrap());
    let e_version = u32::from_le_bytes(elf_bytes[20..24].try_into().unwrap());
    let e_phoff = u32::from_le_bytes(elf_bytes[28..32].try_into().unwrap()) as usize;
    let e_ehsize = u16::from_le_bytes(elf_bytes[40..42].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(elf_bytes[42..44].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf_bytes[44..46].try_into().unwrap()) as usize;

    if e_type != 2
        || e_machine != 40
        || e_version != 1
        || e_ehsize != 52
        || e_phentsize != 32
        || e_phnum == 0
        || e_phnum > 128
    {
        return Err("unsupported Arm ELF header".into());
    }
    let ph_end = e_phoff
        .checked_add(e_phentsize * e_phnum)
        .ok_or("ELF program header table overflow")?;
    if ph_end > elf_bytes.len() {
        return Err("truncated ELF program headers".into());
    }

    let mut segments: Vec<(u32, &[u8])> = Vec::new();
    for i in 0..e_phnum {
        let off_hdr = e_phoff + i * 32;
        let p_type = u32::from_le_bytes(elf_bytes[off_hdr..off_hdr + 4].try_into().unwrap());
        if p_type != 1 {
            continue;
        }
        let p_offset =
            u32::from_le_bytes(elf_bytes[off_hdr + 4..off_hdr + 8].try_into().unwrap()) as usize;
        let p_vaddr = u32::from_le_bytes(elf_bytes[off_hdr + 8..off_hdr + 12].try_into().unwrap());
        let p_paddr = u32::from_le_bytes(elf_bytes[off_hdr + 12..off_hdr + 16].try_into().unwrap());
        let p_filesz =
            u32::from_le_bytes(elf_bytes[off_hdr + 16..off_hdr + 20].try_into().unwrap());
        let p_memsz = u32::from_le_bytes(elf_bytes[off_hdr + 20..off_hdr + 24].try_into().unwrap());

        let file_end = p_offset
            .checked_add(p_filesz as usize)
            .ok_or("ELF load segment file offset overflow")?;
        if p_filesz > p_memsz
            || file_end > elf_bytes.len()
            || (p_paddr as u64) + (p_memsz as u64) > 0x1_0000_0000
            || (p_vaddr as u64) + (p_memsz as u64) > 0x1_0000_0000
        {
            return Err("invalid ELF load segment bounds".into());
        }
        if p_filesz == 0 && p_memsz > 0 {
            if p_vaddr < SRAM_START
                || (p_vaddr as u64) + (p_memsz as u64) > SRAM_END as u64
                || p_paddr < SRAM_START
                || (p_paddr as u64) + (p_memsz as u64) > SRAM_END as u64
            {
                return Err("firmware BSS outside RP2350 SRAM".into());
            }
            continue;
        }
        if p_filesz == 0 {
            continue;
        }
        let pa_end = (p_paddr as u64) + (p_filesz as u64);
        if !p_paddr.is_multiple_of(4)
            || !p_filesz.is_multiple_of(4)
            || p_paddr < FIRMWARE_START
            || pa_end > FIRMWARE_END as u64
        {
            return Err("ELF load segment outside firmware partition or unaligned".into());
        }
        if segments.iter().any(|&(other_pa, other_data)| {
            let other_end = (other_pa as u64) + (other_data.len() as u64);
            !(pa_end <= other_pa as u64 || other_end <= p_paddr as u64)
        }) {
            return Err("overlapping ELF load segments".into());
        }
        segments.push((p_paddr, &elf_bytes[p_offset..file_end]));
    }
    if segments.is_empty() {
        return Err("no file-backed ELF load segments".into());
    }
    Ok(segments)
}

struct PicobinItem {
    typ: u8,
    header: u32,
    values: Vec<u32>,
    pos: u32,
}

fn read_mapped_byte(segments: &[(u32, &[u8])], addr: u32) -> Option<u8> {
    for &(start, data) in segments {
        if addr >= start {
            let offset = (addr - start) as usize;
            if offset < data.len() {
                return Some(data[offset]);
            }
        }
    }
    None
}

fn read_mapped_word(segments: &[(u32, &[u8])], addr: u32) -> Result<u32, String> {
    if !addr.is_multiple_of(4) {
        return Err("unaligned PICOBIN metadata word access".into());
    }
    let mut bytes = [0u8; 4];
    for (i, slot) in bytes.iter_mut().enumerate() {
        let a = addr
            .checked_add(i as u32)
            .ok_or("PICOBIN word address overflow")?;
        *slot = read_mapped_byte(segments, a)
            .ok_or_else(|| format!("PICOBIN metadata references unmapped address 0x{a:08x}"))?;
    }
    Ok(u32::from_le_bytes(bytes))
}

pub fn verify_signed_picobin_metadata(segments: &[(u32, &[u8])]) -> Result<(), String> {
    let mut first_marker = None;
    for offset in (0..FLASH_SECTOR_SIZE).step_by(4) {
        let addr = FIRMWARE_START + offset;
        if (0..4).all(|i| read_mapped_byte(segments, addr + i).is_some())
            && read_mapped_word(segments, addr)? == 0xffff_ded3
        {
            first_marker = Some(addr);
            break;
        }
    }
    let start = first_marker.ok_or("no first-sector PICOBIN image definition")?;

    let mut current = start;
    let mut visited = HashSet::new();
    let mut blocks: Vec<Vec<PicobinItem>> = Vec::new();
    let mut ends: Vec<u32> = Vec::new();
    loop {
        if visited.len() >= 16 || !visited.insert(current) {
            return Err("lollipop or oversized PICOBIN metadata loop".into());
        }
        if read_mapped_word(segments, current)? != 0xffff_ded3 {
            return Err("invalid PICOBIN block marker".into());
        }
        let mut pos = current
            .checked_add(4)
            .ok_or("PICOBIN block address overflow")?;
        let mut items = Vec::new();
        let mut terminator = None;
        for _ in 0..96 {
            let header = read_mapped_word(segments, pos)?;
            let typ = (header & 0xff) as u8;
            let size = if typ & 0x80 != 0 {
                (header >> 8) & 0xffff
            } else {
                (header >> 8) & 0xff
            };
            if typ == 0xff {
                let expected_words = (pos - current - 4) / 4;
                let end_marker_addr = pos
                    .checked_add(8)
                    .ok_or("PICOBIN terminator address overflow")?;
                if size != expected_words
                    || read_mapped_word(segments, end_marker_addr)? != 0xab12_3579
                {
                    return Err("invalid PICOBIN metadata terminator".into());
                }
                let delta = read_mapped_word(segments, pos + 4)? as i32;
                let block_end = pos.checked_add(12).ok_or("PICOBIN block end overflow")?;
                terminator = Some((delta, block_end));
                break;
            }
            if size == 0 || (pos as u64) + (size as u64) * 4 > (current as u64) + 0x280 {
                return Err("invalid PICOBIN metadata item size".into());
            }
            let mut values = Vec::with_capacity((size - 1) as usize);
            for i in 1..size {
                values.push(read_mapped_word(segments, pos + 4 * i)?);
            }
            items.push(PicobinItem {
                typ,
                header,
                values,
                pos,
            });
            pos += size * 4;
        }
        let (delta, block_end) = terminator.ok_or("unterminated PICOBIN metadata block")?;
        if items.is_empty() || items[0].typ != 0x42 || items.iter().any(|it| it.typ == 0x0a) {
            return Err("partition table or non-image PICOBIN metadata".into());
        }
        let flags = items[0].header >> 16;
        if (flags & 0x773f) != 0x1021 {
            return Err("unexpected PICOBIN image type".into());
        }
        blocks.push(items);
        ends.push(block_end);

        let next = (current as i64) + (delta as i64);
        current = u32::try_from(next).map_err(|_| "PICOBIN loop link overflow")?;
        if current == start {
            break;
        }
    }

    if blocks[0].len() != 1 || blocks[0][0].typ != 0x42 || blocks[0][0].header != 0x1021_0142 {
        return Err("discovery image definition is not canonical".into());
    }
    if blocks.len() != 2 {
        return Err(
            "signed firmware image must contain discovery and signed metadata blocks".into(),
        );
    }
    let signed_blocks: Vec<&Vec<PicobinItem>> = blocks
        .iter()
        .filter(|items| items.iter().any(|it| it.typ == 9))
        .collect();
    if signed_blocks.len() != 1 {
        return Err("missing or ambiguous signed PICOBIN metadata block".into());
    }
    let signed = signed_blocks[0];
    let has_vector = signed.iter().any(|it| it.typ == 3);
    let has_entry = signed.iter().any(|it| it.typ == 0x44);
    if ((signed[0].header >> 16) & 0x800) == 0 || !has_vector || !has_entry {
        return Err("missing signed PICOBIN entry metadata".into());
    }
    if ((blocks[0][0].header >> 16) & !0x800) != ((signed[0].header >> 16) & !0x800) {
        return Err("discovery and signed PICOBIN image types differ".into());
    }

    let maps: Vec<&PicobinItem> = signed.iter().filter(|it| it.typ == 6).collect();
    if maps.len() != 1 {
        return Err("signed PICOBIN block must contain exactly one load map".into());
    }
    let map = maps[0];
    let count = ((map.header >> 24) & 0x7f) as usize;
    let absolute = (map.header & 0x8000_0000) != 0;
    if count == 0 || map.values.len() != 3 * count {
        return Err("malformed signed PICOBIN load map".into());
    }
    let mut covered: Vec<(u64, u64)> = Vec::new();
    for i in 0..count {
        let mut source = map.values[3 * i];
        let target = map.values[3 * i + 1];
        let mut size = map.values[3 * i + 2];
        if source != 0 {
            if absolute {
                if size < target {
                    return Err("invalid absolute PICOBIN load map".into());
                }
                size -= target;
            } else {
                source = source.wrapping_add(map.pos);
            }
            let end = (source as u64) + (size as u64);
            if size == 0 || source < FIRMWARE_START || end > FIRMWARE_END as u64 {
                return Err("signed PICOBIN load map outside firmware partition".into());
            }
            covered.push((source as u64, end));
        }
    }
    if !covered
        .iter()
        .any(|&(lo, hi)| lo <= start as u64 && ends[0] as u64 <= hi)
    {
        return Err("discovery image definition is not covered by signature load map".into());
    }

    let vectors: Vec<&PicobinItem> = signed.iter().filter(|it| it.typ == 3).collect();
    let entries: Vec<&PicobinItem> = signed.iter().filter(|it| it.typ == 0x44).collect();
    if vectors.len() != 1
        || vectors[0].values.len() != 1
        || entries.len() != 1
        || !matches!(entries[0].values.len(), 2 | 3)
    {
        return Err("invalid PICOBIN vector or entry metadata".into());
    }
    let vector = vectors[0].values[0];
    if !covered
        .iter()
        .any(|&(lo, hi)| lo <= vector as u64 && (vector as u64) + 8 <= hi)
    {
        return Err("vector table is not covered by signature load map".into());
    }
    let vector_pc_addr = vector
        .checked_add(4)
        .ok_or("PICOBIN vector address overflow")?;
    if read_mapped_word(segments, vector)? != entries[0].values[1]
        || read_mapped_word(segments, vector_pc_addr)? != entries[0].values[0]
    {
        return Err("signed PICOBIN entry does not match vector table".into());
    }
    Ok(())
}

pub fn expected_pages(segments: &[(u32, &[u8])]) -> Result<BTreeMap<u32, [u8; 256]>, String> {
    if segments.is_empty() {
        return Err("empty ELF segments".into());
    }
    let mut pages: BTreeMap<u32, [u8; 256]> = BTreeMap::new();
    for &(address, data) in segments {
        for (i, &byte) in data.iter().enumerate() {
            let target = address
                .checked_add(i as u32)
                .ok_or("ELF segment address overflow")?;
            let page = target & !(UF2_PAGE_SIZE - 1);
            let offset = (target & (UF2_PAGE_SIZE - 1)) as usize;
            pages.entry(page).or_insert([0u8; 256])[offset] = byte;
        }
    }
    let last = *pages.keys().next_back().ok_or("no ELF flash pages")?;
    let sectors: BTreeSet<u32> = pages
        .keys()
        .map(|&p| p & !(FLASH_SECTOR_SIZE - 1))
        .collect();
    for sector in sectors {
        if sector < FIRMWARE_START
            || (sector as u64) + (FLASH_SECTOR_SIZE as u64) > FIRMWARE_END as u64
        {
            return Err(format!(
                "UF2 erase sector 0x{sector:08x} outside firmware partition [0x{FIRMWARE_START:08x}, 0x{FIRMWARE_END:08x})"
            ));
        }
        for step in (0..FLASH_SECTOR_SIZE).step_by(UF2_PAGE_SIZE as usize) {
            let page = sector + step;
            if page < last {
                pages.entry(page).or_insert([0u8; 256]);
            }
        }
    }
    Ok(pages)
}

pub fn validate_signed_elf_and_uf2(elf_bytes: &[u8], uf2_bytes: &[u8]) -> Result<usize, String> {
    let uf2_pages = parse_uf2_pages(uf2_bytes)?;
    let segments = elf_segments(elf_bytes)?;
    verify_signed_picobin_metadata(&segments)?;
    let elf_pages = expected_pages(&segments)?;
    if uf2_pages != elf_pages {
        return Err("UF2 pages do not exactly match signed ELF pages".into());
    }
    Ok(uf2_pages.len())
}

pub fn find_bootsel_mount() -> Option<PathBuf> {
    for base in ["/media", "/mnt", "/run/media"] {
        let Ok(entries) = fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("INFO_UF2.TXT").is_file() {
                return Some(p);
            }
            if let Ok(sub) = fs::read_dir(&p) {
                for s in sub.flatten() {
                    if s.path().join("INFO_UF2.TXT").is_file() {
                        return Some(s.path());
                    }
                }
            }
        }
    }
    None
}

pub fn write_uf2_to_bootsel(
    uf2_bytes: &[u8],
    file_name: &OsStr,
    mount: &Path,
) -> Result<(), String> {
    validate_uf2(uf2_bytes)?;
    let name = file_name.to_str().ok_or("invalid UF2 filename")?;
    if name.is_empty()
        || !name.ends_with(".uf2")
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(format!("invalid UF2 destination filename: {name}"));
    }
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mount_dir = fs_at::openat(CWD, mount, dir_flags, Mode::empty())
        .map_err(|e| format!("failed to open BOOTSEL mount {}: {e}", mount.display()))?;
    let info_meta =
        fs_at::statat(&mount_dir, "INFO_UF2.TXT", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
            format!(
                "BOOTSEL mount {} missing INFO_UF2.TXT: {e}",
                mount.display()
            )
        })?;
    if FileType::from_raw_mode(info_meta.st_mode) != FileType::RegularFile {
        return Err(format!(
            "BOOTSEL mount {} INFO_UF2.TXT is not a regular file",
            mount.display()
        ));
    }
    let out_flags =
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = fs_at::openat(&mount_dir, name, out_flags, Mode::from_raw_mode(0o600))
        .map_err(|e| format!("failed to create {name} on {}: {e}", mount.display()))?;
    let mut out = File::from(fd);
    out.write_all(uf2_bytes)
        .map_err(|e| format!("failed to write UF2 to {}/{name}: {e}", mount.display()))?;
    out.sync_all()
        .map_err(|e| format!("failed to sync UF2 on {}/{name}: {e}", mount.display()))?;
    Ok(())
}
