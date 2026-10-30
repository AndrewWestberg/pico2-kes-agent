//! Allocation-free boundaries for qualified raw NOR, monotonic time and entropy.
//! Geometry describes the fitted part; accepting it here is not hardware qualification.

pub const PAGE_SIZE: u32 = 256;
pub const SECTOR_SIZE: u32 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashError {
    Geometry,
    Bounds,
    Alignment,
    CrossPage,
    RequiresErase,
    Io,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    capacity: u32,
}

impl Geometry {
    pub fn new(capacity: u32, page_size: u32, sector_size: u32) -> Result<Self, FlashError> {
        if capacity == 0
            || page_size != PAGE_SIZE
            || sector_size != SECTOR_SIZE
            || !capacity.is_multiple_of(sector_size)
        {
            return Err(FlashError::Geometry);
        }
        Ok(Self { capacity })
    }

    pub const fn capacity(self) -> u32 {
        self.capacity
    }

    pub fn range(self, address: u32, len: usize) -> Result<(), FlashError> {
        let len = u32::try_from(len).map_err(|_| FlashError::Bounds)?;
        let end = address.checked_add(len).ok_or(FlashError::Bounds)?;
        if end > self.capacity {
            return Err(FlashError::Bounds);
        }
        Ok(())
    }

    pub fn program(self, address: u32, len: usize) -> Result<(), FlashError> {
        self.range(address, len)?;
        if len == 0 {
            return Err(FlashError::Bounds);
        }
        let end = address + u32::try_from(len).map_err(|_| FlashError::Bounds)? - 1;
        if address / PAGE_SIZE != end / PAGE_SIZE {
            return Err(FlashError::CrossPage);
        }
        Ok(())
    }

    pub fn erase(self, address: u32) -> Result<(), FlashError> {
        if !address.is_multiple_of(SECTOR_SIZE) {
            return Err(FlashError::Alignment);
        }
        self.range(address, SECTOR_SIZE as usize)
    }
}

/// Backend methods are individual physical boundaries. Implementations must not
/// bypass fitted-part restrictions (including any stricter partial-page limits).
pub trait Flash {
    fn geometry(&self) -> Geometry;
    fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError>;
    fn program_page(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError>;
    fn erase_sector(&mut self, address: u32) -> Result<(), FlashError>;
    fn read_marker(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError>;
    fn program_marker(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError>;
}

/// Validates every operation before dispatch, including NOR bit transitions.
pub struct CheckedFlash<F>(pub F);

impl<F: Flash> CheckedFlash<F> {
    fn check_program(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.0.geometry().program(address, data.len())?;
        let mut old = [0u8; PAGE_SIZE as usize];
        self.0.read(address, &mut old[..data.len()])?;
        if old[..data.len()]
            .iter()
            .zip(data)
            .any(|(&a, &b)| a & b != b)
        {
            return Err(FlashError::RequiresErase);
        }
        Ok(())
    }
}

impl<F: Flash> Flash for CheckedFlash<F> {
    fn geometry(&self) -> Geometry {
        self.0.geometry()
    }
    fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.geometry().range(address, output.len())?;
        self.0.read(address, output)
    }
    fn program_page(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.check_program(address, data)?;
        self.0.program_page(address, data)
    }
    fn erase_sector(&mut self, address: u32) -> Result<(), FlashError> {
        self.geometry().erase(address)?;
        self.0.erase_sector(address)
    }
    fn read_marker(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.geometry().range(address, output.len())?;
        self.0.read_marker(address, output)
    }
    fn program_marker(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.check_program(address, data)?;
        self.0.program_marker(address, data)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    Unavailable,
    Regression,
}

/// Monotonic ticks in microseconds, invalidated across reboot or reconnect by the caller.
pub trait Clock {
    fn now_us(&mut self) -> Result<u64, ClockError>;
}

pub fn is_fresh<C: Clock>(
    clock: &mut C,
    observed_us: u64,
    lease_us: u64,
) -> Result<bool, ClockError> {
    let elapsed = clock
        .now_us()?
        .checked_sub(observed_us)
        .ok_or(ClockError::Regression)?;
    Ok(elapsed < lease_us)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyError;
/// Non-secret cause retained by an entropy implementation after failure.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyFailure {
    Unknown = 1,
    Timeout = 2,
    Configuration = 3,
    Autocorrelation = 4,
    ContinuousTest = 5,
    VonNeumann = 6,
}

impl EntropyFailure {
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Unknown),
            2 => Some(Self::Timeout),
            3 => Some(Self::Configuration),
            4 => Some(Self::Autocorrelation),
            5 => Some(Self::ContinuousTest),
            6 => Some(Self::VonNeumann),
            _ => None,
        }
    }
}

pub trait Entropy {
    /// Implementations may have written a prefix on failure; use `fill_secret`.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError>;
    fn failure(&self) -> Option<EntropyFailure> {
        None
    }
}

/// On failure no partially generated secret remains in the destination.
pub fn fill_secret<E: Entropy>(entropy: &mut E, output: &mut [u8]) -> Result<(), EntropyError> {
    use zeroize::Zeroize;
    match entropy.fill(output) {
        Ok(()) => Ok(()),
        Err(error) => {
            output.zeroize();
            Err(error)
        }
    }
}
