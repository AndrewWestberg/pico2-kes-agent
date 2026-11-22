use pico2_kes_agent::flash::uf2::{
    FIRMWARE_START, UF2_BLOCK_SIZE, UF2_MAGIC_END, UF2_MAGIC_START0, UF2_MAGIC_START1, validate_uf2,
};
use pico2_kes_agent::release::ReleaseError;
use pico2_kes_agent::updater;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("p2kes-test-{name}-{}", std::process::id()));
    fs::create_dir(&p).unwrap();
    p
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_unsigned_legacy_bundle(dir: &std::path::Path, payload: &[u8]) {
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("p2kes"), payload).unwrap();
    let manifest = serde_json::json!({
        "schema_version": 2,
        "version": "0.2.0",
        "firmware_version": "0.2.0",
        "usb_protocol_major": 1,
        "platform": {
            "arch": "x86_64",
            "os": "linux",
            "min_glibc": "2.36",
        },
        "artifacts": [{
            "name": "p2kes",
            "path": "bin/p2kes",
            "size": payload.len(),
            "sha256": sha256_hex(payload),
            "mode": "0o755",
        }],
    });
    fs::write(
        dir.join("release-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn updater_rejects_unsigned_legacy_manifest_without_installing() {
    let bundle = temp_dir("bundle");
    let prefix = temp_dir("prefix");
    write_unsigned_legacy_bundle(&bundle, b"unsigned binary");

    assert!(updater::install_or_update(&bundle, &prefix, false).is_err());
    assert_eq!(fs::read_dir(&prefix).unwrap().count(), 0);
    assert!(updater::load_state(&prefix).unwrap().is_none());

    fs::remove_dir_all(&bundle).unwrap();
    fs::remove_dir_all(&prefix).unwrap();
}

#[test]
fn uninstall_rejects_unmanaged_paths_before_removing_files() {
    let prefix = temp_dir("unmanaged");
    let managed = prefix.join("bin/p2kes");
    let unmanaged = prefix.join("install.sh");
    let state = updater::state_path(&prefix);
    fs::create_dir_all(managed.parent().unwrap()).unwrap();
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    fs::write(&managed, b"managed").unwrap();
    fs::write(&unmanaged, b"unmanaged").unwrap();
    fs::write(
        &state,
        br#"{"schema_version":2,"version":"0.2.0","firmware_version":null,"artifacts":["bin/p2kes","install.sh"]}"#,
    )
    .unwrap();

    assert!(matches!(
        updater::uninstall(&prefix),
        Err(ReleaseError::PathConfinement(_))
    ));
    assert!(managed.is_file());
    assert!(unmanaged.is_file());
    assert!(state.is_file());
    fs::remove_dir_all(&prefix).unwrap();
}

#[test]
fn uf2_validation_accepts_valid_and_rejects_malformed() {
    assert!(validate_uf2(&[]).is_err());
    assert!(validate_uf2(&[0u8; 511]).is_err());

    let mut block = [0u8; UF2_BLOCK_SIZE];
    block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
    block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
    block[12..16].copy_from_slice(&FIRMWARE_START.to_le_bytes());
    block[16..20].copy_from_slice(&256u32.to_le_bytes());
    block[20..24].copy_from_slice(&0u32.to_le_bytes());
    block[24..28].copy_from_slice(&1u32.to_le_bytes());
    block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
    assert_eq!(validate_uf2(&block).unwrap(), 1);

    // Out-of-range target_addr
    block[12..16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    assert!(validate_uf2(&block).is_err());
}

fn valid_uf2_block() -> [u8; UF2_BLOCK_SIZE] {
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

struct BootselFixture {
    root: PathBuf,
    usb_real: PathBuf,
    block_real: PathBuf,
    probe: pico2_kes_agent::flash::uf2::MountProbe,
}

impl BootselFixture {
    fn new(name: &str) -> Self {
        let root = temp_dir(name);
        let usb_real = root.join("sys/devices/pci0000:00/usb1/1-2");
        let block_real = usb_real.join("1-2:1.0/host0/target0:0:0/block/sda/sda1");
        let usb_devices = root.join("sys/bus/usb/devices");
        let block_devices = root.join("sys/dev/block");
        let mountinfo = root.join("mountinfo");
        fs::create_dir_all(&block_real).unwrap();
        fs::create_dir_all(&usb_devices).unwrap();
        fs::create_dir_all(&block_devices).unwrap();
        fs::write(&mountinfo, "").unwrap();

        fs::write(usb_real.join("idVendor"), "2e8a\n").unwrap();
        fs::write(usb_real.join("idProduct"), "000f\n").unwrap();
        fs::write(usb_real.join("busnum"), "1\n").unwrap();
        fs::write(usb_real.join("devnum"), "2\n").unwrap();
        std::os::unix::fs::symlink(&usb_real, usb_devices.join("1-2")).unwrap();

        Self {
            root,
            usb_real,
            block_real,
            probe: pico2_kes_agent::flash::uf2::MountProbe {
                usb_devices,
                block_devices,
                mountinfo,
                fdinfo: PathBuf::from("/proc/self/fdinfo"),
            },
        }
    }

    fn dev_and_mnt_id(dir: &std::path::Path) -> (String, String) {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        let f = fs::File::open(dir).unwrap();
        let dev = f.metadata().unwrap().dev();
        let dev_str = format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev));
        let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", f.as_raw_fd())).unwrap();
        let mnt_id = fdinfo
            .lines()
            .find_map(|l| l.strip_prefix("mnt_id:").map(|v| v.trim().to_owned()))
            .unwrap();
        (dev_str, mnt_id)
    }

    fn encode_mountinfo_path(path: &std::path::Path) -> String {
        path.to_str()
            .unwrap()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
    }
}

impl Drop for BootselFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn bootsel_mount_rejects_spoofed_unmounted_info_uf2_directory() {
    use pico2_kes_agent::flash::uf2::find_bootsel_mount_with;

    let fx = BootselFixture::new("spoof-unmounted");
    let protected = fx.root.join("protected");
    let spoof = fx.root.join("mnt/localuser/fake_bootsel");
    fs::create_dir_all(&protected).unwrap();
    fs::create_dir_all(&spoof).unwrap();

    let canary = protected.join("canary_target.txt");
    fs::write(&canary, b"ORIGINAL_PROTECTED_CANARY_CONTENT").unwrap();
    fs::write(
        spoof.join("INFO_UF2.TXT"),
        b"UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&canary, spoof.join("firmware.uf2")).unwrap();

    // Case 1: USB device present, no mounted volume in mountinfo.
    assert!(find_bootsel_mount_with(&fx.probe).is_err());

    // Case 2: Spoof directory lives inside a parent mount whose backing block device is NOT the
    // distinct mountpoint for spoof (e.g. parent `/` mounted on `dev_str`, spoof is a subdir).
    let parent_mnt = fx.root.join("mnt");
    let canonical_parent = fs::canonicalize(&parent_mnt).unwrap();
    let (dev_str, mnt_id) = BootselFixture::dev_and_mnt_id(&spoof);
    std::os::unix::fs::symlink(&fx.block_real, fx.probe.block_devices.join(&dev_str)).unwrap();
    fs::write(
        &fx.probe.mountinfo,
        format!(
            "{mnt_id} 1 {dev_str} / {} rw - vfat /dev/sda1 rw\n",
            BootselFixture::encode_mountinfo_path(&canonical_parent)
        ),
    )
    .unwrap();
    // Even if parent_mnt is listed without INFO_UF2.TXT, subdir `localuser/fake_bootsel` is never scanned.
    assert!(find_bootsel_mount_with(&fx.probe).is_err());

    // Case 3: Fake mountinfo claims `spoof` is mounted with a different mnt_id than kernel fdinfo reports.
    let canonical_spoof = fs::canonicalize(&spoof).unwrap();
    let fake_mnt_id = format!("{}999", mnt_id);
    fs::write(
        &fx.probe.mountinfo,
        format!(
            "{fake_mnt_id} 1 {dev_str} / {} rw - vfat /dev/sda1 rw\n",
            BootselFixture::encode_mountinfo_path(&canonical_spoof)
        ),
    )
    .unwrap();
    let err = find_bootsel_mount_with(&fx.probe).unwrap_err();
    assert!(
        err.contains("not a distinct mounted volume"),
        "unexpected error: {err}"
    );
    assert_eq!(
        fs::read(&canary).unwrap(),
        b"ORIGINAL_PROTECTED_CANARY_CONTENT"
    );
}

#[test]
fn bootsel_mount_rejects_ambiguous_multiple_mounts_and_usb_devices() {
    use pico2_kes_agent::flash::uf2::find_bootsel_mount_with;

    let fx = BootselFixture::new("ambiguous");
    let vol_a = fx.root.join("media/vol_a");
    let vol_b = fx.root.join("media/vol_b");
    fs::create_dir_all(&vol_a).unwrap();
    fs::create_dir_all(&vol_b).unwrap();

    let (dev_str, mnt_id) = BootselFixture::dev_and_mnt_id(&vol_a);
    std::os::unix::fs::symlink(&fx.block_real, fx.probe.block_devices.join(&dev_str)).unwrap();
    fs::write(
        &fx.probe.mountinfo,
        format!(
            "{mnt_id} 1 {dev_str} / {} rw - vfat /dev/sda1 rw\n\
             999999 1 {dev_str} / {} rw - vfat /dev/sda1 rw\n",
            vol_a.display(),
            vol_b.display()
        ),
    )
    .unwrap();

    let err = find_bootsel_mount_with(&fx.probe).unwrap_err();
    assert!(
        err.contains("multiple mounted volumes"),
        "unexpected error: {err}"
    );

    // Multiple attached 2e8a:000f USB devices also fail closed.
    let second_usb = fx.root.join("sys/devices/pci0000:00/usb1/1-3");
    fs::create_dir_all(&second_usb).unwrap();
    fs::write(second_usb.join("idVendor"), "2e8a\n").unwrap();
    fs::write(second_usb.join("idProduct"), "000f\n").unwrap();
    fs::write(second_usb.join("busnum"), "1\n").unwrap();
    fs::write(second_usb.join("devnum"), "3\n").unwrap();
    std::os::unix::fs::symlink(&second_usb, fx.probe.usb_devices.join("1-3")).unwrap();

    let err = find_bootsel_mount_with(&fx.probe).unwrap_err();
    assert!(
        err.contains("multiple RP2350 BOOTSEL USB devices"),
        "unexpected error: {err}"
    );
}

#[test]
fn bootsel_mount_rejects_wrong_board_id_and_symlinked_info_uf2() {
    use pico2_kes_agent::flash::uf2::find_bootsel_mount_with;

    let fx = BootselFixture::new("board-id");
    let volume = fx.root.join("media/RPI-RP2");
    fs::create_dir_all(&volume).unwrap();
    let canonical_vol = fs::canonicalize(&volume).unwrap();
    let (dev_str, mnt_id) = BootselFixture::dev_and_mnt_id(&canonical_vol);
    std::os::unix::fs::symlink(&fx.block_real, fx.probe.block_devices.join(&dev_str)).unwrap();
    fs::write(
        &fx.probe.mountinfo,
        format!(
            "{mnt_id} 1 {dev_str} / {} rw - vfat /dev/sda1 rw\n",
            BootselFixture::encode_mountinfo_path(&canonical_vol)
        ),
    )
    .unwrap();

    // Wrong Board-ID (RP2040 instead of RP2350)
    let info_path = canonical_vol.join("INFO_UF2.TXT");
    fs::write(
        &info_path,
        b"UF2 Bootloader v3.0\r\nModel: Raspberry Pi RP2\r\nBoard-ID: RPI-RP2\r\n",
    )
    .unwrap();
    let err = find_bootsel_mount_with(&fx.probe).unwrap_err();
    assert!(
        err.contains("not an RP2350 bootloader"),
        "unexpected error: {err}"
    );

    // Symlinked INFO_UF2.TXT pointing to valid RP2350 content
    fs::remove_file(&info_path).unwrap();
    let outside_info = fx.root.join("outside_info.txt");
    fs::write(
        &outside_info,
        b"UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside_info, &info_path).unwrap();
    assert!(find_bootsel_mount_with(&fx.probe).is_err());

    // Confirm USB ancestry check rejects block device belonging to a non-2e8a:000f device
    fs::remove_file(&info_path).unwrap();
    fs::write(
        &info_path,
        b"UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n",
    )
    .unwrap();
    assert!(find_bootsel_mount_with(&fx.probe).is_ok());
    fs::write(fx.usb_real.join("idProduct"), "0003\n").unwrap();
    assert!(find_bootsel_mount_with(&fx.probe).is_err());
}

#[test]
fn bootsel_copy_decodes_octal_escapes_blocks_symlinks_and_detects_detach() {
    use pico2_kes_agent::flash::uf2::{
        copy_uf2_to_bootsel, decode_mountinfo_path, find_bootsel_mount_with,
    };
    use std::ffi::OsStr;

    assert_eq!(
        decode_mountinfo_path("/media/Pico\\040Drive\\011Tab\\134Slash").unwrap(),
        PathBuf::from("/media/Pico Drive\tTab\\Slash")
    );
    assert!(decode_mountinfo_path("/media/bad\\000null").is_err());
    assert!(decode_mountinfo_path("/media/bad\\777overflow").is_err());
    assert!(decode_mountinfo_path("/media/truncated\\04").is_err());

    let fx = BootselFixture::new("copy-symlinks");
    let protected = fx.root.join("protected");
    let volume = fx.root.join("media/Pico Drive");
    fs::create_dir_all(&protected).unwrap();
    fs::create_dir_all(&volume).unwrap();
    let canonical_vol = fs::canonicalize(&volume).unwrap();
    let (dev_str, mnt_id) = BootselFixture::dev_and_mnt_id(&canonical_vol);
    std::os::unix::fs::symlink(&fx.block_real, fx.probe.block_devices.join(&dev_str)).unwrap();
    fs::write(
        &fx.probe.mountinfo,
        format!(
            "{mnt_id} 1 {dev_str} / {} rw - vfat /dev/sda1 rw\n",
            BootselFixture::encode_mountinfo_path(&canonical_vol)
        ),
    )
    .unwrap();
    fs::write(
        canonical_vol.join("INFO_UF2.TXT"),
        b"UF2 Bootloader v1.0\r\nModel: Raspberry Pi RP2350\r\nBoard-ID: RP2350\r\n",
    )
    .unwrap();

    let canary = protected.join("canary_target.txt");
    fs::write(&canary, b"ORIGINAL_PROTECTED_CANARY_CONTENT").unwrap();
    std::os::unix::fs::symlink(&canary, canonical_vol.join("firmware.uf2")).unwrap();

    let dangling_target = protected.join("must_not_be_created.uf2");
    std::os::unix::fs::symlink(&dangling_target, canonical_vol.join("dangling.uf2")).unwrap();

    let existing = canonical_vol.join("existing.uf2");
    fs::write(&existing, b"EXISTING_CONTENT").unwrap();

    let mount = find_bootsel_mount_with(&fx.probe).unwrap();
    assert_eq!(mount.path(), canonical_vol);

    let uf2 = valid_uf2_block();

    // Symlink to existing protected file must fail closed without touching canary
    assert!(copy_uf2_to_bootsel(&mount, OsStr::new("firmware.uf2"), &uf2).is_err());
    assert_eq!(
        fs::read(&canary).unwrap(),
        b"ORIGINAL_PROTECTED_CANARY_CONTENT"
    );

    // Dangling symlink must fail closed without creating target
    assert!(copy_uf2_to_bootsel(&mount, OsStr::new("dangling.uf2"), &uf2).is_err());
    assert!(!dangling_target.exists());

    // Existing regular file must fail closed (O_EXCL) without overwriting
    assert!(copy_uf2_to_bootsel(&mount, OsStr::new("existing.uf2"), &uf2).is_err());
    assert_eq!(fs::read(&existing).unwrap(), b"EXISTING_CONTENT");

    // Path traversal / non-normal filenames must fail closed
    for bad in ["", ".", "..", "../escape.uf2", "sub/firmware.uf2"] {
        assert!(copy_uf2_to_bootsel(&mount, OsStr::new(bad), &uf2).is_err());
    }

    // Fresh destination on verified mount writes exact validated bytes
    copy_uf2_to_bootsel(&mount, OsStr::new("fresh.uf2"), &uf2).unwrap();
    assert_eq!(fs::read(canonical_vol.join("fresh.uf2")).unwrap(), uf2);

    // Replacing mount directory path invalidates pinned mount verification
    let moved = fx.root.join("media/moved_away");
    fs::rename(&canonical_vol, &moved).unwrap();
    fs::create_dir_all(&canonical_vol).unwrap();
    assert!(mount.verify().is_err());
    assert!(copy_uf2_to_bootsel(&mount, OsStr::new("after_replace.uf2"), &uf2).is_err());
    assert!(!canonical_vol.join("after_replace.uf2").exists());
}

#[test]
fn flash_cli_namespace_spoof_fails_closed_and_preserves_canary() {
    use std::process::Command;

    let work = temp_dir("ns-spoof");
    let protected = work.join("protected");
    let empty_media = work.join("empty_media");
    let fake_bootsel = work.join("fake_mnt/localuser/fake_bootsel");
    fs::create_dir_all(&protected).unwrap();
    fs::create_dir_all(&empty_media).unwrap();
    fs::create_dir_all(&fake_bootsel).unwrap();

    let canary = protected.join("canary_target.txt");
    fs::write(&canary, b"ORIGINAL_PROTECTED_CANARY_CONTENT").unwrap();
    fs::write(
        fake_bootsel.join("INFO_UF2.TXT"),
        b"UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&canary, fake_bootsel.join("firmware.uf2")).unwrap();

    let uf2_file = work.join("firmware.uf2");
    fs::write(&uf2_file, valid_uf2_block()).unwrap();
    let bin = env!("CARGO_BIN_EXE_p2kes-flash");

    let unshare_available = Command::new("unshare")
        .args(["-Umr", "true"])
        .status()
        .is_ok_and(|s| s.success());

    let out = if unshare_available {
        Command::new("unshare")
            .args([
                "-Umr",
                "sh",
                "-c",
                r#"mount --bind "$1/empty_media" /media && mount --bind "$1/fake_mnt" /mnt && "$2" flash "$3""#,
                "_",
            ])
            .arg(&work)
            .arg(bin)
            .arg(&uf2_file)
            .output()
            .unwrap()
    } else {
        Command::new(bin)
            .arg("flash")
            .arg(&uf2_file)
            .output()
            .unwrap()
    };

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "p2kes-flash flash must fail closed (stderr: {stderr})"
    );
    assert!(
        stderr.contains("RP2350 BOOTSEL"),
        "expected clear RP2350 BOOTSEL error message, got: {stderr}"
    );
    assert_eq!(
        fs::read(&canary).unwrap(),
        b"ORIGINAL_PROTECTED_CANARY_CONTENT"
    );

    fs::remove_dir_all(&work).unwrap();
}
