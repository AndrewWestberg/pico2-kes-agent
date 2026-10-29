//! Public, read-only RP2350 security configuration snapshot.

include!(concat!(env!("OUT_DIR"), "/authorized_bootkey.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityStatus {
    pub chip_revision: u8,
    pub rom_version: u8,
    pub critical: u32,
    pub boot_flags0: u32,
    pub boot_flags1: u32,
    pub bootkey0: [u8; 32],
    pub page2_lock0: u8,
    pub page2_lock1: u8,
    pub page63_lock0: u8,
    pub page63_lock1: u8,
    pub debugen: u32,
    pub debugen_lock: u32,
    pub redundancy_ok: bool,
    pub jedec_id: [u8; 3],
    pub sfdp_header: [u8; 16],
    pub density_bits_minus_one: u32,
    pub usb_serial: [u8; 16],
    pub storage_blank_at_boot: bool,
}

impl SecurityStatus {
    pub fn stepping(&self) -> &'static str {
        match self.rom_version {
            2 => "A2",
            4 => "A4",
            _ => "unsupported",
        }
    }

    /// A matching authority is mandatory; absence never proves a locked profile.
    pub fn profile(&self, expected: Option<&[u8; 32]>) -> &'static str {
        if self.critical & 1 == 0 {
            return "unlocked";
        }
        const REQUIRED: u32 =
            0x20_0000 | 0x08_0000 | 0x04_0000 | 0x01_0000 | 0x8000 | 0x2000 | 0x100 | 0x80;
        const FORBIDDEN: u32 = 0x02_0000 | 0x4000 | 0x1000 | 0x800 | 0x40;
        fn locks(lock0: u8, lock1: u8) -> bool {
            lock0 == 0
                && lock1 & 0xc0 == 0
                && lock1 & 3 == 1
                && matches!((lock1 >> 2) & 3, 1 | 3)
                && matches!((lock1 >> 4) & 3, 1 | 3)
        }
        if self.stepping() != "unsupported"
            && self.critical & 0x1000f == 7
            && self.boot_flags0 & REQUIRED == REQUIRED
            && self.boot_flags0 & FORBIDDEN == 0
            && self.boot_flags1 & 0xf0f == 0xe01
            && expected == Some(&self.bootkey0)
            && locks(self.page2_lock0, self.page2_lock1)
            && locks(self.page63_lock0, self.page63_lock1)
            && self.debugen & 0x10f == 0
            && self.debugen_lock & 0x10f == 0x10f
            && self.redundancy_ok
            && self.jedec_id == [0xef, 0x40, 0x16]
            && self.sfdp_header
                == [
                    0x53, 0x46, 0x44, 0x50, 0x0a, 0x01, 0x00, 0xff, 0x00, 0x08, 0x01, 0x17, 0x80,
                    0x00, 0x00, 0xff,
                ]
            && self.density_bits_minus_one == 0x01ff_ffff
        {
            "rp2350-signed-msd-v1"
        } else {
            "incomplete"
        }
    }
}
