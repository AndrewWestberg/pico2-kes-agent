//! Read-only fitted-part identification and the sole raw-state flash adapter.
//! The QMI identification path is adapted from the reviewed predecessor and
//! Pico SDK `hardware_flash/flash.c:flash_do_cmd_cs` sequence.
use core::{
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

use embassy_rp::{
    flash::{BOOTRAM_BASE, Blocking, Error as HalError, Flash as HalFlash},
    multicore::{self, CoreId, current_core},
    peripherals::FLASH,
    rom_data,
};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use kes_core::{
    platform::{Flash, FlashError, Geometry, PAGE_SIZE, SECTOR_SIZE},
    storage::{ALLOCATED_END, CONFIG_START},
};
use rp_pac as pac;

pub const FLASH_BYTES: usize = 4 * 1024 * 1024;
pub const APPROVED_JEDEC: [u8; 3] = [0xef, 0x40, 0x16];
const APPROVED_SFDP_HEADER: [u8; 16] = [
    0x53, 0x46, 0x44, 0x50, 0x0a, 0x01, 0x00, 0xff, 0x00, 0x08, 0x01, 0x17, 0x80, 0x00, 0x00, 0xff,
];
const APPROVED_DENSITY_BITS_MINUS_ONE: u32 = 0x01ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentificationError {
    Busy,
    UnsupportedBus,
    MissingRomData,
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub jedec_id: [u8; 3],
    pub sfdp_header: [u8; 16],
    pub density_bits_minus_one: u32,
}

impl Identity {
    pub fn approved(self) -> bool {
        self.jedec_id == APPROVED_JEDEC
            && self.sfdp_header == APPROVED_SFDP_HEADER
            && self.density_bits_minus_one == APPROVED_DENSITY_BITS_MINUS_ONE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    WrongCore,
    Identification(IdentificationError),
    WrongFlashProfile(Identity),
    OutOfStateRegion,
    Unaligned,
    Hal,
}

impl From<HalError> for StorageError {
    fn from(_: HalError) -> Self {
        Self::Hal
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Blank,
    NonBlank,
}

/// Sole owner of fitted flash mutations. Embassy's blocking erase/program path
/// runs ROM operations from SRAM, pauses core1, masks interrupts, drains DMA,
/// restores XIP, and flushes cache before returning.
pub struct FittedFlash<'d> {
    inner: HalFlash<'d, FLASH, Blocking, FLASH_BYTES>,
    identity: Identity,
}

impl<'d> FittedFlash<'d> {
    pub fn new(inner: HalFlash<'d, FLASH, Blocking, FLASH_BYTES>) -> Result<Self, StorageError> {
        Self::require_core0()?;
        let identity = identify().map_err(StorageError::Identification)?;
        if !identity.approved() {
            return Err(StorageError::WrongFlashProfile(identity));
        }
        Ok(Self { inner, identity })
    }

    /// Read-verifies every byte reserved for configuration and all 64 pools.
    pub fn classify_allocated(&mut self) -> Result<Admission, StorageError> {
        Self::require_core0()?;
        let mut page = [0; PAGE_SIZE as usize];
        let mut address = CONFIG_START;
        let mut blank = true;
        while address < ALLOCATED_END {
            self.inner.blocking_read(address, &mut page)?;
            blank &= page.iter().all(|byte| *byte == 0xff);
            address += PAGE_SIZE;
        }
        Ok(if blank {
            Admission::Blank
        } else {
            Admission::NonBlank
        })
    }

    pub const fn identity(&self) -> Identity {
        self.identity
    }

    fn require_core0() -> Result<(), StorageError> {
        if current_core() == CoreId::Core0 {
            Ok(())
        } else {
            Err(StorageError::WrongCore)
        }
    }

    fn check(address: u32, len: usize, alignment: u32) -> Result<(), StorageError> {
        Self::require_core0()?;
        if !address.is_multiple_of(alignment) {
            return Err(StorageError::Unaligned);
        }
        let end = address
            .checked_add(u32::try_from(len).map_err(|_| StorageError::OutOfStateRegion)?)
            .ok_or(StorageError::OutOfStateRegion)?;
        if address < CONFIG_START || end > ALLOCATED_END {
            return Err(StorageError::OutOfStateRegion);
        }
        Ok(())
    }
}

impl Flash for FittedFlash<'_> {
    fn geometry(&self) -> Geometry {
        Geometry::new(FLASH_BYTES as u32, PAGE_SIZE, SECTOR_SIZE).expect("qualified fixed geometry")
    }

    fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        Self::check(address, output.len(), 1).map_err(map_storage)?;
        self.inner.blocking_read(address, output).map_err(map_hal)?;
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    fn program_page(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        if data.len() != PAGE_SIZE as usize {
            return Err(FlashError::Alignment);
        }
        Self::check(address, data.len(), PAGE_SIZE).map_err(map_storage)?;
        self.inner.blocking_write(address, data).map_err(map_hal)?;
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    fn erase_sector(&mut self, address: u32) -> Result<(), FlashError> {
        Self::check(address, SECTOR_SIZE as usize, SECTOR_SIZE).map_err(map_storage)?;
        self.inner
            .blocking_erase(address, address + SECTOR_SIZE)
            .map_err(map_hal)?;
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    fn read_marker(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.read(address, output)
    }

    fn program_marker(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.program_page(address, data)
    }
}

fn map_storage(error: StorageError) -> FlashError {
    match error {
        StorageError::Unaligned => FlashError::Alignment,
        StorageError::OutOfStateRegion => FlashError::Bounds,
        _ => FlashError::Io,
    }
}

fn map_hal(error: HalError) -> FlashError {
    match error {
        HalError::OutOfBounds => FlashError::Bounds,
        HalError::Unaligned => FlashError::Alignment,
        _ => FlashError::Io,
    }
}

type RomFn = unsafe extern "C" fn();

struct Functions {
    connect: RomFn,
    exit_xip: RomFn,
    flush: RomFn,
    boot2: RomFn,
}

pub(crate) fn identify() -> Result<Identity, IdentificationError> {
    let entry = rom_data::rom_data_lookup(*b"FD", 0x0040);
    if entry == 0 {
        return Err(IdentificationError::MissingRomData);
    }
    // SAFETY: FD is the SDK-defined ROM pointer-to-pointer data entry.
    let devinfo = unsafe { ptr::read_volatile(entry as *const *const u16) };
    if devinfo.is_null() {
        return Err(IdentificationError::MissingRomData);
    }
    // Exclude CS1 and writable external-memory configurations.
    if unsafe { ptr::read_volatile(devinfo) } & 0xf000 != 0
        || pac::XIP_CTRL.ctrl().read().writable_m1()
        || pac::XIP_CTRL.ctrl().read().writable_m0()
    {
        return Err(IdentificationError::UnsupportedBus);
    }

    multicore::pause_core1();
    let result = CriticalSectionRawMutex::new().lock(|| {
        if (0..16).any(|channel| pac::DMA.ch(channel).ctrl_trig().read().busy())
            || pac::XIP_CTRL.stream_ctr().read().0 != 0
            || pac::QMI.direct_csr().read().en()
        {
            return Err(IdentificationError::Busy);
        }
        let mut boot2 = [0u32; 64];
        unsafe { ptr::copy_nonoverlapping(BOOTRAM_BASE, boot2.as_mut_ptr(), 64) };
        let functions = Functions {
            connect: rom_data::connect_internal_flash::ptr(),
            exit_xip: rom_data::flash_exit_xip::ptr(),
            flush: rom_data::flash_flush_cache::ptr(),
            boot2: unsafe { core::mem::transmute::<usize, RomFn>(boot2.as_ptr() as usize | 1) },
        };
        let mut jedec = [0x9f, 0, 0, 0];
        command(&functions, &mut jedec)?;
        let mut repeated = [0x9f, 0, 0, 0];
        command(&functions, &mut repeated)?;
        if jedec != repeated {
            return Err(IdentificationError::Busy);
        }
        let jedec_id = [jedec[1], jedec[2], jedec[3]];
        if jedec_id != APPROVED_JEDEC {
            return Ok(Identity {
                jedec_id,
                sfdp_header: [0; 16],
                density_bits_minus_one: 0,
            });
        }
        let mut sfdp = [0; 149];
        sfdp[0] = 0x5a;
        command(&functions, &mut sfdp)?;
        let mut sfdp_header = [0; 16];
        sfdp_header.copy_from_slice(&sfdp[5..21]);
        Ok(Identity {
            jedec_id,
            sfdp_header,
            density_bits_minus_one: u32::from_le_bytes([
                sfdp[137], sfdp[138], sfdp[139], sfdp[140],
            ]),
        })
    });
    multicore::resume_core1();
    result
}

fn command(functions: &Functions, bytes: &mut [u8]) -> Result<(), IdentificationError> {
    let qmi = pac::QMI;
    let direct = qmi.direct_csr().read();
    let windows = [
        (
            qmi.mem(0).timing().read(),
            qmi.mem(0).rfmt().read(),
            qmi.mem(0).rcmd().read(),
            qmi.mem(0).wfmt().read(),
            qmi.mem(0).wcmd().read(),
        ),
        (
            qmi.mem(1).timing().read(),
            qmi.mem(1).rfmt().read(),
            qmi.mem(1).rcmd().read(),
            qmi.mem(1).wfmt().read(),
            qmi.mem(1).wcmd().read(),
        ),
    ];
    let mut pads = [0; 6];
    for (index, pad) in pads.iter_mut().enumerate() {
        *pad = unsafe { ptr::read_volatile((0x4004_0004 + index * 4) as *const u32) };
    }
    compiler_fence(Ordering::SeqCst);
    let complete = unsafe { command_ram(functions, bytes.as_mut_ptr(), bytes.len()) };
    for (index, state) in windows.into_iter().enumerate() {
        qmi.mem(index).timing().write_value(state.0);
        qmi.mem(index).rfmt().write_value(state.1);
        qmi.mem(index).rcmd().write_value(state.2);
        qmi.mem(index).wfmt().write_value(state.3);
        qmi.mem(index).wcmd().write_value(state.4);
    }
    qmi.direct_csr().write_value(direct);
    for (index, pad) in pads.into_iter().enumerate() {
        unsafe { ptr::write_volatile((0x4004_0004 + index * 4) as *mut u32, pad) };
    }
    compiler_fence(Ordering::SeqCst);
    if complete {
        Ok(())
    } else {
        Err(IdentificationError::Timeout)
    }
}

#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
unsafe fn command_ram(functions: &Functions, bytes: *mut u8, count: usize) -> bool {
    unsafe {
        (functions.connect)();
        (functions.exit_xip)();
        let csr = 0x400d_0000 as *mut u32;
        let tx = 0x400d_0004 as *mut u32;
        let rx = 0x400d_0008 as *const u32;
        let config = 12 << 22;
        ptr::write_volatile(csr, config | 1);
        let mut budget = 2_000_000u32;
        while ptr::read_volatile(csr) & 2 != 0 && budget != 0 {
            budget = budget.wrapping_sub(1);
        }
        let mut complete = budget != 0;
        if complete {
            ptr::write_volatile(csr, config | 5);
            let mut offset = 0usize;
            while offset < count && budget != 0 {
                while ptr::read_volatile(csr) & (1 << 10) != 0 && budget != 0 {
                    budget = budget.wrapping_sub(1);
                }
                if budget == 0 {
                    break;
                }
                ptr::write_volatile(tx, ptr::read(bytes.wrapping_add(offset)) as u32);
                while ptr::read_volatile(csr) & (1 << 16) != 0 && budget != 0 {
                    budget = budget.wrapping_sub(1);
                }
                if budget == 0 {
                    break;
                }
                ptr::write(bytes.wrapping_add(offset), ptr::read_volatile(rx) as u8);
                offset = offset.wrapping_add(1);
            }
            complete = offset == count;
        }
        while ptr::read_volatile(csr) & 2 != 0 && budget != 0 {
            budget = budget.wrapping_sub(1);
        }
        complete &= budget != 0;
        ptr::write_volatile(csr, config);
        (functions.flush)();
        (functions.boot2)();
        complete
    }
}
