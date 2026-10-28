//! Deterministic byte-prefix NOR model only. It is not physical flash evidence;
//! this test-only type has no conversion to a qualification result.
#![allow(dead_code)]

use kes_core::platform::{Flash, FlashError, Geometry, SECTOR_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Boundary {
    Read,
    Program,
    Erase,
    MarkerRead,
    MarkerProgram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Cut,
    FailBefore,
    FailAfter,
    Torn(usize),
    ReadError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub boundary: Boundary,
    pub address: u32,
    pub length: usize,
}

pub struct ModelFlash {
    geometry: Geometry,
    bytes: Vec<u8>,
    pub trace: Vec<Event>,
    /// Zero-based boundary index and the fault to inject there, once.
    pub fault: Option<(usize, Fault)>,
}

impl ModelFlash {
    pub fn new(capacity: u32) -> Self {
        let geometry = Geometry::new(capacity, 256, 4096).unwrap();
        Self {
            geometry,
            bytes: vec![0xff; capacity as usize],
            trace: Vec::new(),
            fault: None,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn count(&self, kind: Boundary) -> usize {
        self.trace
            .iter()
            .filter(|event| event.boundary == kind)
            .count()
    }
    fn boundary(&mut self, kind: Boundary, address: u32, length: usize) -> Option<Fault> {
        let index = self.trace.len();
        self.trace.push(Event {
            boundary: kind,
            address,
            length,
        });
        if self.fault.is_some_and(|(at, _)| at == index) {
            self.fault.take().map(|(_, fault)| fault)
        } else {
            None
        }
    }
    fn read_inner(
        &mut self,
        kind: Boundary,
        address: u32,
        output: &mut [u8],
    ) -> Result<(), FlashError> {
        self.geometry.range(address, output.len())?;
        let fault = self.boundary(kind, address, output.len());
        match fault {
            Some(Fault::Cut) => return Err(FlashError::Interrupted),
            Some(Fault::FailBefore | Fault::ReadError | Fault::Torn(_)) => {
                return Err(FlashError::Io);
            }
            _ => {}
        }
        output.copy_from_slice(&self.bytes[address as usize..address as usize + output.len()]);
        if fault == Some(Fault::FailAfter) {
            return Err(FlashError::Io);
        }
        Ok(())
    }
    fn program_inner(
        &mut self,
        kind: Boundary,
        address: u32,
        data: &[u8],
    ) -> Result<(), FlashError> {
        self.geometry.program(address, data.len())?;
        let start = address as usize;
        if self.bytes[start..start + data.len()]
            .iter()
            .zip(data)
            .any(|(&a, &b)| a & b != b)
        {
            return Err(FlashError::RequiresErase);
        }
        let fault = self.boundary(kind, address, data.len());
        match fault {
            Some(Fault::Cut) => return Err(FlashError::Interrupted),
            Some(Fault::FailBefore | Fault::ReadError) => return Err(FlashError::Io),
            _ => {}
        }
        let count = match fault {
            Some(Fault::Torn(n)) => n.min(data.len()),
            _ => data.len(),
        };
        for (old, new) in self.bytes[start..start + count].iter_mut().zip(data) {
            *old &= *new;
        }
        match fault {
            Some(Fault::Torn(_)) => Err(FlashError::Interrupted),
            Some(Fault::FailAfter) => Err(FlashError::Io),
            _ => Ok(()),
        }
    }
}

impl Flash for ModelFlash {
    fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.read_inner(Boundary::Read, address, output)
    }
    fn read_marker(&mut self, address: u32, output: &mut [u8]) -> Result<(), FlashError> {
        self.read_inner(Boundary::MarkerRead, address, output)
    }
    fn program_page(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.program_inner(Boundary::Program, address, data)
    }
    fn program_marker(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
        self.program_inner(Boundary::MarkerProgram, address, data)
    }
    fn erase_sector(&mut self, address: u32) -> Result<(), FlashError> {
        self.geometry.erase(address)?;
        let fault = self.boundary(Boundary::Erase, address, SECTOR_SIZE as usize);
        match fault {
            Some(Fault::Cut) => return Err(FlashError::Interrupted),
            Some(Fault::FailBefore | Fault::ReadError) => return Err(FlashError::Io),
            _ => {}
        }
        let count = match fault {
            Some(Fault::Torn(n)) => n.min(SECTOR_SIZE as usize),
            _ => SECTOR_SIZE as usize,
        };
        self.bytes[address as usize..address as usize + count].fill(0xff);
        match fault {
            Some(Fault::Torn(_)) => Err(FlashError::Interrupted),
            Some(Fault::FailAfter) => Err(FlashError::Io),
            _ => Ok(()),
        }
    }
}
