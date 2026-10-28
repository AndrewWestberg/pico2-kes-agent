#[path = "support/flash.rs"]
mod flash;

use flash::{Boundary, Fault, ModelFlash};
use kes_core::platform::{
    CheckedFlash, Clock, ClockError, Entropy, EntropyError, Flash, FlashError, Geometry,
    fill_secret, is_fresh,
};

#[test]
fn geometry_and_nor_constraints_are_enforced_before_mutation() {
    assert_eq!(Geometry::new(0, 256, 4096), Err(FlashError::Geometry));
    assert_eq!(Geometry::new(4097, 256, 4096), Err(FlashError::Geometry));
    assert_eq!(Geometry::new(4096, 128, 4096), Err(FlashError::Geometry));
    assert_eq!(Geometry::new(4096, 256, 2048), Err(FlashError::Geometry));
    let mut flash = CheckedFlash(ModelFlash::new(4096));
    assert_eq!(flash.program_page(255, &[0, 0]), Err(FlashError::CrossPage));
    assert_eq!(flash.program_page(0, &[]), Err(FlashError::Bounds));
    assert_eq!(flash.program_page(4096, &[0]), Err(FlashError::Bounds));
    assert_eq!(flash.read(u32::MAX, &mut [0; 2]), Err(FlashError::Bounds));
    assert_eq!(flash.erase_sector(1), Err(FlashError::Alignment));
    assert_eq!(flash.erase_sector(4096), Err(FlashError::Bounds));
    assert!(flash.0.trace.is_empty());
    flash.program_page(255, &[0x0f]).unwrap();
    assert_eq!(
        flash.program_page(255, &[0xf0]),
        Err(FlashError::RequiresErase)
    );
    assert_eq!(flash.0.count(Boundary::Program), 1);
    flash.erase_sector(0).unwrap();
    flash.program_page(255, &[0xf0]).unwrap();
}

#[test]
fn every_program_and_marker_torn_byte_boundary_is_reproducible() {
    for marker in [false, true] {
        for cut in 0..=256 {
            let mut flash = ModelFlash::new(4096);
            flash.fault = Some((0, Fault::Torn(cut)));
            let result = if marker {
                flash.program_marker(0, &[0x35; 256])
            } else {
                flash.program_page(0, &[0x35; 256])
            };
            assert_eq!(result, Err(FlashError::Interrupted));
            assert!(flash.bytes()[..cut].iter().all(|&x| x == 0x35));
            assert!(flash.bytes()[cut..256].iter().all(|&x| x == 0xff));
            assert_eq!(
                flash.trace[0].boundary,
                if marker {
                    Boundary::MarkerProgram
                } else {
                    Boundary::Program
                }
            );
        }
    }
}

#[test]
fn every_erase_torn_byte_boundary_has_the_expected_model_effect() {
    for cut in 0..=4096 {
        let mut flash = ModelFlash::new(4096);
        for page in 0..16 {
            flash.program_page(page * 256, &[0; 256]).unwrap();
        }
        flash.fault = Some((flash.trace.len(), Fault::Torn(cut)));
        assert_eq!(flash.erase_sector(0), Err(FlashError::Interrupted));
        assert!(flash.bytes()[..cut].iter().all(|&x| x == 0xff));
        assert!(flash.bytes()[cut..].iter().all(|&x| x == 0));
        assert_eq!(flash.count(Boundary::Erase), 1);
    }
}

#[test]
fn fault_ordering_and_marker_read_boundaries_are_distinct() {
    for (fault, expected, changed) in [
        (Fault::Cut, FlashError::Interrupted, false),
        (Fault::FailBefore, FlashError::Io, false),
        (Fault::FailAfter, FlashError::Io, true),
    ] {
        let mut flash = CheckedFlash(ModelFlash::new(4096));
        // The checked adapter first reads for NOR validation, then programs.
        flash.0.fault = Some((1, fault));
        assert_eq!(flash.program_marker(20, &[0x42]), Err(expected));
        assert_eq!(flash.0.bytes()[20], if changed { 0x42 } else { 0xff });
        assert_eq!(
            flash.0.trace.iter().map(|e| e.boundary).collect::<Vec<_>>(),
            [Boundary::Read, Boundary::MarkerProgram]
        );
    }
    let mut flash = ModelFlash::new(4096);
    flash.program_marker(0, &[0]).unwrap();
    flash.fault = Some((1, Fault::ReadError));
    let mut out = [0xaa];
    assert_eq!(flash.read_marker(0, &mut out), Err(FlashError::Io));
    assert_eq!(out, [0xaa]);
    assert_eq!(flash.count(Boundary::MarkerRead), 1);
    flash.fault = Some((2, Fault::FailAfter));
    assert_eq!(flash.read(0, &mut out), Err(FlashError::Io));
    assert_eq!(out, [0]);
    flash.fault = Some((3, Fault::ReadError));
    assert_eq!(flash.read(0, &mut out), Err(FlashError::Io));
}

#[test]
fn erase_faults_and_validation_read_faults_preserve_ordering() {
    for (fault, error, erased) in [
        (Fault::Cut, FlashError::Interrupted, false),
        (Fault::FailBefore, FlashError::Io, false),
        (Fault::FailAfter, FlashError::Io, true),
    ] {
        let mut flash = ModelFlash::new(4096);
        flash.program_page(0, &[0]).unwrap();
        flash.fault = Some((1, fault));
        assert_eq!(flash.erase_sector(0), Err(error));
        assert_eq!(flash.bytes()[0], if erased { 0xff } else { 0 });
    }
    let mut flash = CheckedFlash(ModelFlash::new(4096));
    flash.0.fault = Some((0, Fault::ReadError));
    assert_eq!(flash.program_page(0, &[0]), Err(FlashError::Io));
    assert_eq!(flash.0.trace.len(), 1);
    assert_eq!(flash.0.count(Boundary::Program), 0);
    assert_eq!(flash.0.bytes()[0], 0xff);
}

struct TestClock(Result<u64, ClockError>);
impl Clock for TestClock {
    fn now_us(&mut self) -> Result<u64, ClockError> {
        self.0
    }
}
struct TestEntropy(bool);
impl Entropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        output[0] = 0x53;
        if self.0 {
            output.fill(0x53);
            Ok(())
        } else {
            Err(EntropyError)
        }
    }
}

#[test]
fn freshness_uses_monotonic_elapsed_time_and_entropy_failure_wipes() {
    let mut clock = TestClock(Ok(100));
    assert_eq!(is_fresh(&mut clock, 100, 10), Ok(true));
    clock.0 = Ok(109);
    assert_eq!(is_fresh(&mut clock, 100, 10), Ok(true));
    clock.0 = Ok(110);
    assert_eq!(is_fresh(&mut clock, 100, 10), Ok(false));
    clock.0 = Ok(99);
    assert_eq!(is_fresh(&mut clock, 100, 10), Err(ClockError::Regression));
    clock.0 = Err(ClockError::Unavailable);
    assert_eq!(is_fresh(&mut clock, 100, 10), Err(ClockError::Unavailable));
    let mut secret = [0xaa; 32];
    assert_eq!(
        fill_secret(&mut TestEntropy(false), &mut secret),
        Err(EntropyError)
    );
    assert_eq!(secret, [0; 32]);
    assert_eq!(fill_secret(&mut TestEntropy(true), &mut secret), Ok(()));
    assert_eq!(secret, [0x53; 32]);
}
