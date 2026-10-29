//! Public security configuration only. This module never exposes OTP writes or
//! reads factory secrets; row numbers are from the RP2350 OTP_DATA layout.
use embassy_rp::{otp, rom_data};
use kes_protocol::security::SecurityStatus;
use rp_pac as pac;

use crate::flash::{Admission, Identity};

const DEBUG_MASK: u32 = 0x10f;

/// Lock the volatile debug overrides before any wrapping root or state is opened.
pub fn harden_debug() -> Result<(), ()> {
    let critical = pac::OTP.critical().read();
    if critical.debug_disable() || critical.secure_debug_disable() {
        let enabled = pac::OTP.debugen().read().0;
        pac::OTP
            .debugen()
            .write_value(pac::otp::regs::Debugen(enabled & !DEBUG_MASK));
        pac::OTP
            .debugen_lock()
            .write_value(pac::otp::regs::DebugenLock(DEBUG_MASK));
        if pac::OTP.debugen().read().0 & DEBUG_MASK != 0
            || pac::OTP.debugen_lock().read().0 & DEBUG_MASK != DEBUG_MASK
        {
            return Err(());
        }
    }
    Ok(())
}

// BOOT_FLAGS use three distinct 24-bit rows, with a bitwise majority vote.
fn flags(row: usize) -> Result<(u32, bool), ()> {
    let a = otp::read_raw_word(row).map_err(|_| ())?;
    let b = otp::read_raw_word(row + 1).map_err(|_| ())?;
    let c = otp::read_raw_word(row + 2).map_err(|_| ())?;
    Ok(((a & b) | (a & c) | (b & c), a == b && b == c))
}

// PAGE_LOCK words contain three redundant byte copies within one raw row.
fn lock(row: usize) -> Result<(u8, bool), ()> {
    let raw = otp::read_raw_word(row).map_err(|_| ())?;
    let a = raw as u8;
    let b = (raw >> 8) as u8;
    let c = (raw >> 16) as u8;
    Ok(((a & b) | (a & c) | (b & c), a == b && b == c))
}

pub fn read(identity: Identity, admission: Admission, serial: &[u8]) -> Result<SecurityStatus, ()> {
    let serial: [u8; 16] = serial.try_into().map_err(|_| ())?;
    let critical = pac::OTP.critical().read().0;
    // CRIT1 RBIT-8: inspect each of the eight raw rows rather than an ECC
    // view. Check all policy-controlled bits and the architecture selection.
    let first = otp::read_raw_word(0x40).map_err(|_| ())?;
    let mut redundancy_ok = (first & 0x0f) == (critical & 0x0f);
    for row in 0x41..0x48 {
        let copy = otp::read_raw_word(row).map_err(|_| ())?;
        redundancy_ok &= (copy & 0x0f) == (first & 0x0f);
    }
    let (boot_flags0, ok0) = flags(0x48)?;
    let (boot_flags1, ok1) = flags(0x4b)?;
    let (page2_lock0, ok2a) = lock(0xf84)?;
    let (page2_lock1, ok2b) = lock(0xf85)?;
    let (page63_lock0, ok63a) = lock(0xffe)?;
    let (page63_lock1, ok63b) = lock(0xfff)?;
    redundancy_ok &= ok0 && ok1 && ok2a && ok2b && ok63a && ok63b;

    // BOOTKEY0 is an ECC-protected 16-row SHA-256 digest. Picotool writes
    // each adjacent digest byte pair as a little-endian 16-bit OTP value.
    let mut bootkey0 = [0; 32];
    for (index, pair) in bootkey0.chunks_exact_mut(2).enumerate() {
        pair.copy_from_slice(
            &otp::read_ecc_word(0x80 + index)
                .map_err(|_| ())?
                .to_le_bytes(),
        );
    }
    let rom_version = rom_data::rom_version_number();
    let chip_revision = pac::SYSINFO.chip_id().read().revision();
    Ok(SecurityStatus {
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
        debugen: pac::OTP.debugen().read().0,
        debugen_lock: pac::OTP.debugen_lock().read().0,
        redundancy_ok,
        jedec_id: identity.jedec_id,
        sfdp_header: identity.sfdp_header,
        density_bits_minus_one: identity.density_bits_minus_one,
        usb_serial: serial,
        storage_blank_at_boot: admission == Admission::Blank,
    })
}
