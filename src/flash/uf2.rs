//! Native UF2 header/sector validation and BOOTSEL mass-storage discovery.

use rustix::fs::{self as fs_at, CWD, Mode, OFlags};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const UF2_MAGIC_START0: u32 = 0x0A32_4655;
pub const UF2_MAGIC_START1: u32 = 0x9E5D_5157;
pub const UF2_MAGIC_END: u32 = 0x0AB1_6F30;
pub const UF2_BLOCK_SIZE: usize = 512;
pub const FIRMWARE_START: u32 = 0x1000_0000;
pub const FIRMWARE_END: u32 = 0x1040_0000;

const RP2350_USB_VENDOR: &str = "2e8a";
const RP2350_BOOTSEL_PRODUCT: &str = "000f";
const INFO_UF2_NAME: &str = "INFO_UF2.TXT";
const INFO_UF2_MAX_BYTES: usize = 4096;
const NO_BOOTSEL_MSG: &str =
    "no RP2350 BOOTSEL mass-storage device found (hold BOOTSEL and replug)";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const CREATE_EXCLUSIVE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Debug)]
pub struct MountProbe {
    pub usb_devices: PathBuf,
    pub block_devices: PathBuf,
    pub mountinfo: PathBuf,
    pub fdinfo: PathBuf,
}

impl MountProbe {
    pub fn system() -> Self {
        Self {
            usb_devices: PathBuf::from("/sys/bus/usb/devices"),
            block_devices: PathBuf::from("/sys/dev/block"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            fdinfo: PathBuf::from("/proc/self/fdinfo"),
        }
    }
}

#[derive(Debug)]
pub struct BootselMount {
    path: PathBuf,
    dir: File,
    mount_id: String,
    device: String,
    probe: MountProbe,
}

impl BootselMount {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify(&self) -> Result<(), String> {
        let pinned = self
            .dir
            .metadata()
            .map_err(|_| "verified BOOTSEL mount detached or replaced".to_owned())?;
        let current = fs::symlink_metadata(&self.path)
            .map_err(|_| "verified BOOTSEL mount detached or replaced".to_owned())?;
        let attached = current.file_type().is_dir()
            && (current.dev(), current.ino()) == (pinned.dev(), pinned.ino())
            && dev_id(pinned.dev()) == self.device
            && mount_attached(
                &self.probe.mountinfo,
                &self.mount_id,
                &self.device,
                &self.path,
            )
            .unwrap_or(false);
        if !attached {
            return Err("verified BOOTSEL mount detached or replaced".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UsbDevice {
    path: PathBuf,
    busnum: u16,
    devnum: u16,
}

pub fn validate_uf2(bytes: &[u8]) -> Result<usize, String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(UF2_BLOCK_SIZE) {
        return Err("UF2 length must be a non-zero multiple of 512 bytes".into());
    }
    let blocks = bytes.len() / UF2_BLOCK_SIZE;
    for (idx, chunk) in bytes.as_chunks::<UF2_BLOCK_SIZE>().0.iter().enumerate() {
        let m0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let m1 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let target_addr = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        let payload_size = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
        let block_no = u32::from_le_bytes(chunk[20..24].try_into().unwrap());
        let num_blocks = u32::from_le_bytes(chunk[24..28].try_into().unwrap());
        let mend = u32::from_le_bytes(chunk[508..512].try_into().unwrap());
        if m0 != UF2_MAGIC_START0 || m1 != UF2_MAGIC_START1 || mend != UF2_MAGIC_END {
            return Err(format!("invalid UF2 magic in block {idx}"));
        }
        if block_no as usize != idx || num_blocks as usize != blocks {
            return Err(format!("UF2 block sequence mismatch at {idx}"));
        }
        if payload_size > 476 {
            return Err(format!("UF2 payload_size > 476 in block {idx}"));
        }
        if !(FIRMWARE_START..FIRMWARE_END).contains(&target_addr) {
            return Err(format!(
                "UF2 target_addr 0x{target_addr:08x} outside RP2350 flash range"
            ));
        }
    }
    Ok(blocks)
}

fn dev_id(dev: u64) -> String {
    format!("{}:{}", fs_at::major(dev), fs_at::minor(dev))
}

fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn is_dev_id(value: &str) -> bool {
    let Some((major, minor)) = value.split_once(':') else {
        return false;
    };
    major.parse::<u32>().is_ok()
        && minor.parse::<u32>().is_ok()
        && is_digits(major)
        && is_digits(minor)
}

fn is_strict_ancestor(ancestor: &Path, descendant: &Path) -> bool {
    descendant != ancestor && descendant.starts_with(ancestor)
}

pub fn decode_mountinfo_path(raw: &str) -> Result<PathBuf, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 3 >= bytes.len() {
                return Err("truncated octal escape in mountinfo path".into());
            }
            let (d0, d1, d2) = (bytes[i + 1], bytes[i + 2], bytes[i + 3]);
            if !(b'0'..=b'3').contains(&d0)
                || !(b'0'..=b'7').contains(&d1)
                || !(b'0'..=b'7').contains(&d2)
            {
                return Err("invalid octal escape in mountinfo path".into());
            }
            let val = ((d0 - b'0') << 6) | ((d1 - b'0') << 3) | (d2 - b'0');
            if val == 0 {
                return Err("NUL byte in mountinfo path".into());
            }
            out.push(val);
            i += 4;
        } else {
            if bytes[i] == 0 {
                return Err("NUL byte in mountinfo path".into());
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    if out.is_empty() {
        return Err("empty mountinfo path".into());
    }
    Ok(PathBuf::from(OsString::from_vec(out)))
}

fn read_ascii_trimmed(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut buf = Vec::new();
    file.take(256).read_to_end(&mut buf)?;
    if buf.len() >= 256 || !buf.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid sysfs attribute",
        ));
    }
    let text = String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(text.trim().to_ascii_lowercase())
}

fn selected_bootsel_usb(usb_devices: &Path) -> Result<UsbDevice, String> {
    let entries = match fs::read_dir(usb_devices) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(NO_BOOTSEL_MSG.into()),
        Err(e) => {
            return Err(format!(
                "failed to inspect USB sysfs {}: {e}",
                usb_devices.display()
            ));
        }
    };
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "failed to read USB sysfs entry in {}: {e}",
                usb_devices.display()
            )
        })?;
        let path = entry.path();
        let vendor = match read_ascii_trimmed(&path.join("idVendor")) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "failed to read USB idVendor in {}: {e}",
                    path.display()
                ));
            }
        };
        let product = match read_ascii_trimmed(&path.join("idProduct")) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "failed to read USB idProduct in {}: {e}",
                    path.display()
                ));
            }
        };
        if (vendor.as_str(), product.as_str()) != (RP2350_USB_VENDOR, RP2350_BOOTSEL_PRODUCT) {
            continue;
        }
        let busnum: u16 = read_ascii_trimmed(&path.join("busnum"))
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&b| b <= 255)
            .ok_or("USB enumeration changed during discovery")?;
        let devnum: u16 = read_ascii_trimmed(&path.join("devnum"))
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&d| (1..=127).contains(&d))
            .ok_or("USB enumeration changed during discovery")?;
        let canonical = fs::canonicalize(&path)
            .map_err(|_| "USB enumeration changed during discovery".to_owned())?;
        matches.push(UsbDevice {
            path: canonical,
            busnum,
            devnum,
        });
    }
    match matches.len() {
        0 => Err(NO_BOOTSEL_MSG.into()),
        1 => Ok(matches.pop().unwrap()),
        _ => Err("multiple RP2350 BOOTSEL USB devices attached".into()),
    }
}

fn bootsel_volumes(
    usb_device: &Path,
    mountinfo_path: &Path,
    block_devices: &Path,
) -> Result<Vec<PathBuf>, String> {
    let content = fs::read_to_string(mountinfo_path)
        .map_err(|e| format!("failed to read {}: {e}", mountinfo_path.display()))?;
    let mut volumes = Vec::new();
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() < 6
            || !fields[5..].contains(&"-")
            || !is_digits(fields[0])
            || !is_dev_id(fields[2])
        {
            continue;
        }
        let block_path = match fs::canonicalize(block_devices.join(fields[2])) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!("failed to resolve block device {}: {e}", fields[2]));
            }
        };
        if is_strict_ancestor(usb_device, &block_path) {
            volumes.push(decode_mountinfo_path(fields[4])?);
        }
    }
    Ok(volumes)
}

fn mount_attached(
    mountinfo_path: &Path,
    mount_id: &str,
    device: &str,
    volume: &Path,
) -> Result<bool, String> {
    let content = fs::read_to_string(mountinfo_path)
        .map_err(|e| format!("failed to read {}: {e}", mountinfo_path.display()))?;
    let mut matches = Vec::new();
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() >= 6 && fields[5..].contains(&"-") && fields[0] == mount_id {
            let mountpoint = decode_mountinfo_path(fields[4])?;
            matches.push((fields[2].to_owned(), mountpoint));
        }
    }
    Ok(matches.len() == 1 && matches[0].0 == device && matches[0].1 == volume)
}

fn parse_fdinfo_mnt_id(fdinfo: &str) -> Result<String, String> {
    let mut ids = Vec::new();
    for line in fdinfo.lines() {
        if let Some(rest) = line.strip_prefix("mnt_id:") {
            let id = rest.trim();
            if !is_digits(id) {
                return Err("invalid mount identity in fdinfo".into());
            }
            ids.push(id.to_owned());
        }
    }
    if ids.len() != 1 {
        return Err("mount identity unavailable".into());
    }
    Ok(ids.pop().unwrap())
}

fn has_rp2350_board_id(info: &str) -> bool {
    info.split('\n').any(|line| {
        line.strip_prefix("Board-ID: RP2350")
            .is_some_and(|rest| rest.bytes().all(|b| b == b' ' || b == b'\r'))
    })
}

fn verify_info_uf2(dir: &File) -> Result<(), String> {
    let fd = fs_at::openat(
        dir,
        INFO_UF2_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("failed to open {INFO_UF2_NAME}: {e}"))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat {INFO_UF2_NAME}: {e}"))?;
    if !meta.is_file() {
        return Err("INFO_UF2.TXT is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take((INFO_UF2_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read {INFO_UF2_NAME}: {e}"))?;
    if bytes.len() > INFO_UF2_MAX_BYTES || !bytes.is_ascii() {
        return Err("volume is not an RP2350 bootloader".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "volume is not an RP2350 bootloader")?;
    if !has_rp2350_board_id(text) {
        return Err("volume is not an RP2350 bootloader".into());
    }
    Ok(())
}

pub fn find_bootsel_mount() -> Result<BootselMount, String> {
    find_bootsel_mount_with(&MountProbe::system())
}

pub fn find_bootsel_mount_with(probe: &MountProbe) -> Result<BootselMount, String> {
    let usb = selected_bootsel_usb(&probe.usb_devices)?;
    let mut volumes = bootsel_volumes(&usb.path, &probe.mountinfo, &probe.block_devices)?;
    if volumes.is_empty() {
        return Err(NO_BOOTSEL_MSG.into());
    }
    if volumes.len() > 1 {
        return Err("multiple mounted volumes belong to the RP2350 BOOTSEL USB device".into());
    }
    let raw_volume = volumes.pop().unwrap();
    if !raw_volume.is_absolute() {
        return Err("invalid mass-storage mount path".into());
    }
    let lstat = fs::symlink_metadata(&raw_volume)
        .map_err(|e| format!("invalid mass-storage mount {}: {e}", raw_volume.display()))?;
    if lstat.file_type().is_symlink() || !lstat.file_type().is_dir() {
        return Err("invalid mass-storage mount".into());
    }
    let volume = fs::canonicalize(&raw_volume)
        .map_err(|e| format!("invalid mass-storage mount {}: {e}", raw_volume.display()))?;
    let fd = fs_at::openat(CWD, &volume, DIRECTORY_FLAGS, Mode::empty())
        .map_err(|e| format!("failed to open BOOTSEL mount {}: {e}", volume.display()))?;
    let dir = File::from(fd);

    let fdinfo_path = probe.fdinfo.join(dir.as_raw_fd().to_string());
    let fdinfo = fs::read_to_string(&fdinfo_path).map_err(|e| {
        format!(
            "mount identity unavailable ({}): {e}",
            fdinfo_path.display()
        )
    })?;
    let mount_id = parse_fdinfo_mnt_id(&fdinfo)?;

    let meta = dir
        .metadata()
        .map_err(|e| format!("failed to stat BOOTSEL mount {}: {e}", volume.display()))?;
    if !meta.file_type().is_dir() {
        return Err("invalid mass-storage mount".into());
    }
    let device = dev_id(meta.dev());
    if !mount_attached(&probe.mountinfo, &mount_id, &device, &volume)? {
        return Err("path is not a distinct mounted volume".into());
    }
    let block_path = fs::canonicalize(probe.block_devices.join(&device))
        .map_err(|_| "volume block device unavailable".to_owned())?;
    let current_usb = selected_bootsel_usb(&probe.usb_devices)?;
    if current_usb != usb {
        return Err("selected USB device changed".into());
    }
    if !is_strict_ancestor(&usb.path, &block_path) {
        return Err("volume belongs to another USB device".into());
    }

    verify_info_uf2(&dir)?;

    let mount = BootselMount {
        path: volume,
        dir,
        mount_id,
        device,
        probe: probe.clone(),
    };
    mount.verify()?;
    Ok(mount)
}

fn validate_output_name(file_name: &OsStr) -> Result<&OsStr, String> {
    let raw = file_name.as_bytes();
    if raw.is_empty() || raw == b"." || raw == b".." || raw.contains(&b'/') || raw.contains(&0) {
        return Err("invalid UF2 filename".into());
    }
    Ok(file_name)
}

pub fn copy_uf2_to_bootsel(
    mount: &BootselMount,
    file_name: &OsStr,
    bytes: &[u8],
) -> Result<(), String> {
    copy_uf2_with_sync(mount, file_name, bytes, File::sync_all)
}

fn copy_uf2_with_sync(
    mount: &BootselMount,
    file_name: &OsStr,
    bytes: &[u8],
    sync: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), String> {
    validate_uf2(bytes)?;
    let name = validate_output_name(file_name)?;
    mount.verify()?;
    let vfs = fs_at::fstatvfs(&mount.dir)
        .map_err(|e| format!("failed to inspect BOOTSEL filesystem space: {e}"))?;
    if vfs.f_bavail.saturating_mul(vfs.f_frsize) < bytes.len() as u64 {
        return Err("insufficient mass-storage space".into());
    }
    let fd = fs_at::openat(
        &mount.dir,
        name,
        CREATE_EXCLUSIVE_FLAGS,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| {
        format!(
            "failed to create UF2 destination {} on {}: {e}",
            Path::new(name).display(),
            mount.path.display()
        )
    })?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|e| {
        format!(
            "failed to write UF2 to {}: {e}",
            mount.path.join(name).display()
        )
    })?;
    mount.verify()?;
    sync(&file).map_err(|e| {
        format!(
            "failed to sync UF2 on {}: {e}",
            mount.path.join(name).display()
        )
    })?;
    drop(file);
    mount.verify()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn make_valid_uf2() -> [u8; UF2_BLOCK_SIZE] {
        let mut block = [0u8; UF2_BLOCK_SIZE];
        block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
        block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
        block[12..16].copy_from_slice(&FIRMWARE_START.to_le_bytes());
        block[16..20].copy_from_slice(&256u32.to_le_bytes());
        block[20..24].copy_from_slice(&0u32.to_le_bytes());
        block[24..28].copy_from_slice(&1u32.to_le_bytes());
        block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
        block
    }

    #[test]
    fn copy_uf2_fails_closed_if_mount_detaches_during_sync() {
        let root = std::env::temp_dir().join(format!(
            "p2kes-uf2-unit-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let usb_real = root.join("sys/devices/pci0/usb1/1-2");
        let block_real = usb_real.join("1-2:1.0/block/sda/sda1");
        let usb_bus = root.join("sys/bus/usb/devices");
        let block_dir = root.join("sys/dev/block");
        let volume = root.join("media/RP2350");
        fs::create_dir_all(&block_real).unwrap();
        fs::create_dir_all(&usb_bus).unwrap();
        fs::create_dir_all(&block_dir).unwrap();
        fs::create_dir_all(&volume).unwrap();

        fs::write(usb_real.join("idVendor"), "2e8a\n").unwrap();
        fs::write(usb_real.join("idProduct"), "000f\n").unwrap();
        fs::write(usb_real.join("busnum"), "1\n").unwrap();
        fs::write(usb_real.join("devnum"), "2\n").unwrap();
        std::os::unix::fs::symlink(&usb_real, usb_bus.join("1-2")).unwrap();

        let vol_file = File::open(&volume).unwrap();
        let vol_dev = dev_id(vol_file.metadata().unwrap().dev());
        let fdinfo =
            fs::read_to_string(format!("/proc/self/fdinfo/{}", vol_file.as_raw_fd())).unwrap();
        let mnt_id = parse_fdinfo_mnt_id(&fdinfo).unwrap();
        drop(vol_file);

        std::os::unix::fs::symlink(&block_real, block_dir.join(&vol_dev)).unwrap();
        fs::write(
            volume.join(INFO_UF2_NAME),
            "UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n",
        )
        .unwrap();

        let canonical_vol = fs::canonicalize(&volume).unwrap();
        let mountinfo = root.join("mountinfo");
        fs::write(
            &mountinfo,
            format!(
                "{mnt_id} 1 {vol_dev} / {} rw - vfat /dev/sda1 rw\n",
                canonical_vol.display()
            ),
        )
        .unwrap();

        let probe = MountProbe {
            usb_devices: usb_bus,
            block_devices: block_dir,
            mountinfo: mountinfo.clone(),
            fdinfo: PathBuf::from("/proc/self/fdinfo"),
        };
        let mount = find_bootsel_mount_with(&probe).unwrap();
        let uf2 = make_valid_uf2();
        let err = copy_uf2_with_sync(&mount, OsStr::new("firmware.uf2"), &uf2, |f| {
            f.sync_all()?;
            // Simulate volume unmounting before post-sync verification completes
            fs::write(&mountinfo, "").unwrap();
            Ok(())
        })
        .unwrap_err();
        assert!(
            err.contains("detached or replaced"),
            "unexpected error: {err}"
        );

        fs::remove_dir_all(&root).unwrap();
    }
}
