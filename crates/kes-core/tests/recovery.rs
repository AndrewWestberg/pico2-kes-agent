//! Power-cut regressions against the production lifecycle and raw-flash recovery path.
//! The NOR adapter is a deterministic fault model, not hardware qualification.
#[path = "support/flash.rs"]
mod flash;

use ed25519_dalek::{Signer, SigningKey};
use flash::{Boundary, Fault, ModelFlash};
use kes_core::{
    certificate::Certificate,
    identity::{Digest32, GenerationId, IncarnationId, NetworkBinding, OperationId, PoolId},
    lifecycle::{CommissionRequest, Context, Device, Enrollment, Error, PublicationKind},
    operation::{Handoff, MAX_HANDOFF_BYTES},
    platform::{Entropy, EntropyError, Flash},
    storage::{RecordDomain, Recovered, Storage},
};

const CAPACITY: u32 = 0x400000;
const CONFIG: u32 = 0x100000;
const POOL: u32 = 0x104000;
const BANK: u32 = 0x1000;
const PUBLIC: u32 = 0x2000;

// Disposable, reproducible entropy; no persistent private test fixture is used.
struct EntropyStream(u64);
impl Entropy for EntropyStream {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        for byte in out {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}

type TestDevice = Device<ModelFlash, EntropyStream>;

fn boot(flash: ModelFlash) -> TestDevice {
    Device::open(flash, EntropyStream(0x1234_5678_9abc_def1))
}

fn commission_request(n: u8) -> CommissionRequest {
    CommissionRequest {
        serial: b"disposable-board-1",
        operation_id: OperationId::from_bytes([n; 16]),
        request_digest: Digest32::from_bytes([n; 32]),
        expected_revision: 0,
        sequence: 0,
    }
}

fn network() -> NetworkBinding {
    NetworkBinding::new(Digest32::from_bytes([7; 32]), 42, 100, 16).unwrap()
}

fn cold(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn enrollment(n: u8) -> Enrollment {
    let key = cold(n).verifying_key().to_bytes();
    Enrollment {
        pool_id: PoolId::from_cold_verification_key(&key),
        cold_verification_key: key,
        incarnation_id: IncarnationId::from_bytes([n; 16]),
        network: network(),
        publication_floor_us: 0,
    }
}

fn context(n: u8, period: u64, sample: u64, sequence: u64) -> Context {
    Context {
        pool_id: enrollment(n).pool_id,
        incarnation_id: enrollment(n).incarnation_id,
        network: network(),
        absolute_period: period,
        publication_time_us: sample,
        session: [9; 16],
        sequence,
        observed_us: 100,
        lease_us: 30_000_000,
    }
}

fn commissioned() -> TestDevice {
    let mut device = boot(ModelFlash::new(CAPACITY));
    device.commission(&commission_request(1)).unwrap();
    device
}

fn enrolled(n: u8) -> TestDevice {
    let mut device = commissioned();
    device.enroll(&enrollment(n)).unwrap();
    device
}

// Generate and certify through production code. Only the cold signing key is
// disposable host material; the KES seed is generated inside the device.
fn ready(n: u8) -> (TestDevice, GenerationId) {
    let mut device = enrolled(n);
    device.set_recipient([3; 32]).unwrap();
    device
        .accept_context(&context(n, 5, 1_000, 1), 100)
        .unwrap();
    let generation = device
        .generate(enrollment(n).pool_id, OperationId::from_bytes([31; 16]))
        .unwrap();
    let vkey = device
        .public_key(enrollment(n).pool_id, generation)
        .unwrap();
    let message = Certificate::signing_bytes(&vkey, 1, 0);
    let signature = cold(n).sign(&message).to_bytes();
    let cert = Certificate::new(vkey, 1, 0, signature);
    device
        .install_certificate(enrollment(n).pool_id, generation, &cert)
        .unwrap();
    (device, generation)
}

fn reboot(device: TestDevice) -> TestDevice {
    boot(device.into_flash())
}

fn recovery(device: &mut TestDevice) {
    device.recover().unwrap();
}

fn current(device: &mut TestDevice, n: u8) -> kes_core::lifecycle::Current {
    device
        .current(enrollment(n).pool_id, enrollment(n).incarnation_id, 100)
        .unwrap()
}

fn erased(flash: &ModelFlash, start: u32, len: u32) -> bool {
    flash.bytes()[start as usize..(start + len) as usize]
        .iter()
        .all(|&x| x == 0xff)
}

// Fault indexes refer to the adapter's actual read/program/erase boundaries,
// including independent COMMIT and CLEAN marker operations.
fn cuts(trace: &[flash::Event]) -> impl Iterator<Item = (usize, Fault)> + '_ {
    trace.iter().enumerate().flat_map(|(i, event)| {
        let mut faults = vec![(i, Fault::Cut), (i, Fault::FailAfter)];
        if matches!(
            event.boundary,
            Boundary::Program | Boundary::MarkerProgram | Boundary::Erase
        ) {
            faults.push((i, Fault::Torn(event.length / 2)));
        }
        faults
    })
}

#[test]
fn durable_handoff_sequence_and_receipt_state_survive_device_reboot() {
    let mut device = commissioned();
    let record = *device.hello().unwrap().public();
    let handoff = Handoff::commissioned(record, 17);
    let mut encoded = [0; MAX_HANDOFF_BYTES];
    let length = handoff.encode(&mut encoded).unwrap();
    device.persist_handoff(&encoded[..length]).unwrap();

    let mut restarted = reboot(device);
    recovery(&mut restarted);
    let recovered = Handoff::decode(restarted.persisted_handoff().unwrap().unwrap()).unwrap();
    assert_eq!(recovered, handoff);
    assert_eq!(recovered.next_sequence(), Some(17));
}
#[test]
fn discard_operation_identity_survives_reboot_for_exact_receipt_recovery() {
    let (mut device, _) = ready(2);
    let pool = enrollment(2);
    let create = OperationId::from_bytes([32; 16]);
    let discard = OperationId::from_bytes([33; 16]);
    let staged = device.generate(pool.pool_id, create).unwrap();
    device
        .discard(pool.pool_id, pool.incarnation_id, staged, discard)
        .unwrap();
    let revision = device
        .discarded_by_operation(pool.pool_id, staged, discard)
        .unwrap()
        .unwrap();

    let mut restarted = reboot(device);
    recovery(&mut restarted);
    assert_eq!(
        restarted
            .discarded_by_operation(pool.pool_id, staged, discard)
            .unwrap(),
        Some(revision)
    );
    assert_eq!(
        restarted
            .discarded_by_operation(pool.pool_id, staged, create)
            .unwrap(),
        None
    );
}

#[test]
fn deletion_terminal_publication_survives_reboot_for_receipt_recovery() {
    let mut device = enrolled(2);
    let target = kes_core::operation::PoolTarget {
        pool: enrollment(2).pool_id,
        incarnation: enrollment(2).incarnation_id,
    };
    let terminal = device.delete_pool(target.pool, None).unwrap();
    let mut entropy = EntropyStream(0x1234_5678_9abc_def1);
    let mut root = [0; 32];
    entropy.fill(&mut root).unwrap();
    let mut storage = Storage::new(device.into_flash(), entropy, root).unwrap();
    assert!(storage.recover(RecordDomain::Configuration, false).is_ok());
    assert_eq!(
        storage.recover(RecordDomain::Handoff, true).unwrap().0,
        Recovered::Empty
    );
    let mut restarted = boot(storage.into_flash());
    recovery(&mut restarted);
    assert_eq!(restarted.deletion(target).unwrap(), Some(terminal));
    assert!(matches!(
        restarted.pool_status(target.pool),
        Err(Error::UnknownPool)
    ));
}

#[test]
fn every_prepare_commit_clean_boundary_recovers_without_rollback_or_unclean_delivery() {
    let (mut baseline, generation) = ready(2);
    let old = current(&mut baseline, 2);
    let image = baseline.into_flash();
    let mut probe = boot(copy_image(&image));
    recovery(&mut probe);
    probe.accept_context(&context(2, 8, 2_000, 2), 100).unwrap();
    let start = probe.flash().trace.len();
    probe.evolve(enrollment(2).pool_id, 100).unwrap();
    let trace = &probe.flash().trace[start..];
    assert!(
        trace
            .iter()
            .filter(|e| e.boundary == Boundary::MarkerProgram)
            .count()
            >= 2
    );

    for (offset, fault) in cuts(trace) {
        let mut d = boot(copy_image(&image));
        recovery(&mut d);
        d.accept_context(&context(2, 8, 2_000, 2), 100).unwrap();
        let at = d.flash().trace.len() + offset;
        d.flash_mut().fault = Some((at, fault));
        let result = d.evolve(enrollment(2).pool_id, 100);
        let acknowledged = result.is_ok();
        let mut d = reboot(d);
        recovery(&mut d);
        // Reboot invalidates the lease, even if a snapshot/floor survived.
        assert_eq!(
            d.current(enrollment(2).pool_id, enrollment(2).incarnation_id, 100),
            Err(Error::PeriodUnavailable)
        );
        d.accept_context(&context(2, 8, 2_000, 3), 100).unwrap();
        d.catch_up(enrollment(2).pool_id, 100).unwrap();
        let now = current(&mut d, 2);
        assert_eq!(now.generation_id, generation, "cut {offset} {fault:?}");
        assert_eq!(now.relative_period, 8, "cut {offset} {fault:?}");
        assert!(now.publication.timestamp_us >= old.publication.timestamp_us);
        if acknowledged {
            assert!(
                now.revision > old.revision,
                "acknowledged transition rolled back at {offset} {fault:?}"
            );
        }
    }
}

// Reproduce an image only with the same NOR interface used by production. This
// preserves flash contents, not internal recovery state or a fake transaction.
fn copy_image(source: &ModelFlash) -> ModelFlash {
    let mut dest = ModelFlash::new(CAPACITY);
    for (page, bytes) in source.bytes().chunks(256).enumerate() {
        if bytes.iter().any(|&b| b != 0xff) {
            dest.program_page((page * 256) as u32, bytes).unwrap();
        }
    }
    dest.trace.clear();
    dest
}

#[test]
fn abandoned_candidate_and_orphan_public_objects_are_erased_before_old_key_delivery() {
    let (mut d, _) = ready(2);
    let before = current(&mut d, 2);
    let image = d.into_flash();
    let mut probe = boot(copy_image(&image));
    recovery(&mut probe);
    let start = probe.flash().trace.len();
    probe
        .generate(enrollment(2).pool_id, OperationId::from_bytes([44; 16]))
        .unwrap();
    let trace = &probe.flash().trace[start..];
    let commit = trace
        .iter()
        .position(|e| e.boundary == Boundary::MarkerProgram)
        .unwrap();
    let object = trace[..commit]
        .iter()
        .find(|e| {
            e.boundary == Boundary::Program && (POOL + PUBLIC..POOL + 0x6000).contains(&e.address)
        })
        .unwrap()
        .address;
    let object_start = POOL + PUBLIC + ((object - (POOL + PUBLIC)) / 0x2000) * 0x2000;
    let candidate = trace[..commit]
        .iter()
        .find(|e| e.boundary == Boundary::Program && (POOL..POOL + 2 * BANK).contains(&e.address))
        .unwrap()
        .address;
    let candidate_start = POOL + ((candidate - POOL) / BANK) * BANK;
    for (offset, fault) in cuts(&trace[..=commit]) {
        // Fail before the COMMIT itself; a complete COMMIT has successor precedence.
        if offset == commit && fault == Fault::FailAfter {
            continue;
        }
        let mut d = boot(copy_image(&image));
        recovery(&mut d);
        let at = d.flash().trace.len() + offset;
        d.flash_mut().fault = Some((at, fault));
        let _ = d.generate(enrollment(2).pool_id, OperationId::from_bytes([44; 16]));
        let mut d = reboot(d);
        recovery(&mut d);
        d.accept_context(&context(2, 5, 1_000, 4), 100).unwrap();
        assert_eq!(current(&mut d, 2), before, "cut {offset} {fault:?}");
        assert!(
            erased(d.flash(), object_start, 0x2000),
            "orphan object at cut {offset} {fault:?}"
        );
        assert!(
            erased(d.flash(), candidate_start, BANK),
            "uncommitted candidate at cut {offset} {fault:?}"
        );
    }
}

fn bank_image(flash: &ModelFlash) -> Vec<u8> {
    let banks = &flash.bytes()[POOL as usize..(POOL + 2 * BANK) as usize];
    let first = &banks[..BANK as usize];
    let second = &banks[BANK as usize..];
    match (
        first.iter().any(|&b| b != 0xff),
        second.iter().any(|&b| b != 0xff),
    ) {
        (true, false) => first.to_vec(),
        (false, true) => second.to_vec(),
        _ => panic!("a clean pool must have exactly one live secret bank"),
    }
}

fn put_bank(flash: &mut ModelFlash, address: u32, image: &[u8]) {
    flash.erase_sector(address).unwrap();
    for (page, bytes) in image.chunks(256).enumerate() {
        if bytes.iter().any(|&b| b != 0xff) {
            flash
                .program_page(address + (page * 256) as u32, bytes)
                .unwrap();
        }
    }
}

#[test]
fn independently_committed_equal_revisions_and_conflicting_parent_chains_quarantine_pool() {
    let base = enrolled(2).into_flash();
    let mut left = boot(copy_image(&base));
    recovery(&mut left);
    left.accept_context(&context(2, 5, 1_000, 1), 100).unwrap();
    let left_bank = bank_image(left.flash());

    let mut right = boot(copy_image(&base));
    recovery(&mut right);
    right.accept_context(&context(2, 6, 1_000, 1), 100).unwrap();
    let right_bank = bank_image(right.flash());
    assert_ne!(left_bank, right_bank);

    // Both records are genuine, authenticated, committed successors of the
    // same parent, but describe different floors at the same revision.
    let mut divergent = copy_image(&base);
    put_bank(&mut divergent, POOL, &left_bank);
    put_bank(&mut divergent, POOL + BANK, &right_bank);
    let mut device = boot(divergent);
    recovery(&mut device);
    assert_eq!(
        device.pool_status(enrollment(2).pool_id),
        Err(Error::StorageFailure)
    );

    // The next right-hand record is valid, but its parent is right_bank, not
    // the independently committed left_bank placed beside it.
    right.accept_context(&context(2, 8, 1_100, 2), 100).unwrap();
    let successor = bank_image(right.flash());
    let mut conflict = copy_image(&base);
    put_bank(&mut conflict, POOL, &left_bank);
    put_bank(&mut conflict, POOL + BANK, &successor);
    let mut device = boot(conflict);
    recovery(&mut device);
    assert_eq!(
        device.pool_status(enrollment(2).pool_id),
        Err(Error::StorageFailure)
    );
}

#[test]
fn committed_successor_with_corrupt_body_never_falls_back_to_predecessor() {
    let (d, _) = ready(2);
    let image = d.into_flash();
    let mut probe = boot(copy_image(&image));
    recovery(&mut probe);
    probe.accept_context(&context(2, 8, 2_000, 2), 100).unwrap();
    let start = probe.flash().trace.len();
    probe.evolve(enrollment(2).pool_id, 100).unwrap();
    let trace = &probe.flash().trace[start..];
    let commit = trace
        .iter()
        .position(|e| e.boundary == Boundary::MarkerProgram)
        .unwrap();
    let body = trace[..commit]
        .iter()
        .find(|e| e.boundary == Boundary::Program && (POOL..POOL + 2 * BANK).contains(&e.address))
        .unwrap()
        .address;
    let mut d = boot(copy_image(&image));
    recovery(&mut d);
    d.accept_context(&context(2, 8, 2_000, 2), 100).unwrap();
    let at = d.flash().trace.len() + commit;
    d.flash_mut().fault = Some((at, Fault::FailAfter));
    assert!(d.evolve(enrollment(2).pool_id, 100).is_err());
    let mut flash = d.into_flash();
    let region = &flash.bytes()[body as usize..(body + 256) as usize];
    let index = region.iter().position(|&b| b != 0).unwrap();
    flash.program_page(body + index as u32, &[0]).unwrap();
    let mut d = boot(flash);
    recovery(&mut d);
    assert_eq!(
        d.current(enrollment(2).pool_id, enrollment(2).incarnation_id, 100),
        Err(Error::StorageFailure)
    );
}

#[test]
fn directory_intents_recover_before_slot_reuse_for_enroll_and_delete() {
    for deleting in [false, true] {
        let base = if deleting {
            enrolled(2)
        } else {
            commissioned()
        }
        .into_flash();
        let mut probe = boot(copy_image(&base));
        recovery(&mut probe);
        let start = probe.flash().trace.len();
        if deleting {
            probe.delete_pool(enrollment(2).pool_id, None).unwrap();
        } else {
            probe.enroll(&enrollment(2)).unwrap();
        }
        let trace = &probe.flash().trace[start..];
        for (offset, fault) in cuts(trace) {
            let mut d = boot(copy_image(&base));
            recovery(&mut d);
            let at = d.flash().trace.len() + offset;
            d.flash_mut().fault = Some((at, fault));
            let outcome = if deleting {
                d.delete_pool(enrollment(2).pool_id, None).map(|_| ())
            } else {
                d.enroll(&enrollment(2)).map(|_| ())
            };
            let mut d = reboot(d);
            recovery(&mut d);
            let status = d.pool_status(enrollment(2).pool_id);
            if outcome.is_ok() {
                assert_eq!(status.is_ok(), !deleting, "{offset} {fault:?}");
            }
            if let Ok(status) = status {
                assert_eq!(status.incarnation_id, enrollment(2).incarnation_id);
                assert_eq!(d.enroll(&enrollment(3)), Ok(()));
                assert_ne!(
                    d.pool_status(enrollment(2).pool_id).unwrap().slot,
                    d.pool_status(enrollment(3).pool_id).unwrap().slot
                );
            } else {
                d.enroll(&enrollment(3)).unwrap();
                assert_eq!(
                    d.pool_status(enrollment(3).pool_id).unwrap().incarnation_id,
                    enrollment(3).incarnation_id
                );
            }
        }
    }
}

#[test]
fn commissioning_blank_partial_committed_and_retry_are_distinct() {
    let mut blank = boot(ModelFlash::new(CAPACITY));
    assert_eq!(blank.hello(), Err(Error::Uncommissioned));
    let mut probe = boot(ModelFlash::new(CAPACITY));
    let record = probe.commission(&commission_request(1)).unwrap();
    let trace = &probe.flash().trace;
    let first_write = trace
        .iter()
        .position(|e| e.boundary == Boundary::Program)
        .unwrap();
    let commit = trace
        .iter()
        .position(|e| e.boundary == Boundary::MarkerProgram)
        .unwrap();
    for (offset, fault) in cuts(trace) {
        let mut d = boot(ModelFlash::new(CAPACITY));
        d.flash_mut().fault = Some((offset, fault));
        let result = d.commission(&commission_request(1));
        let mut d = reboot(d);
        if result.is_ok() || (offset == commit && fault == Fault::FailAfter) || offset > commit {
            recovery(&mut d);
            assert_eq!(d.commission(&commission_request(1)).unwrap(), record);
            assert_eq!(
                d.commission(&commission_request(2)),
                Err(Error::AlreadyCommissioned)
            );
        } else if offset < first_write
            || (offset == first_write && matches!(fault, Fault::Cut | Fault::Torn(0)))
        {
            assert_eq!(d.commission(&commission_request(1)).unwrap(), record);
        } else {
            let evidence = d.flash().bytes().to_vec();
            assert_eq!(
                d.commission(&commission_request(1)),
                Err(Error::StorageFailure),
                "{offset} {fault:?}"
            );
            assert_eq!(d.flash().bytes(), evidence);
        }
    }
    // Blank configuration alone is not a blank device.
    blank.flash_mut().program_page(POOL, &[0]).unwrap();
    assert_eq!(
        blank.commission(&commission_request(1)),
        Err(Error::StorageFailure)
    );
    assert_eq!(blank.flash().bytes()[POOL as usize], 0);
}

#[test]
fn pool_floor_is_durable_incarnation_local_and_equal_refresh_does_not_write() {
    let mut d = enrolled(2);
    d.enroll(&enrollment(3)).unwrap();
    d.accept_context(&context(2, 12, 100, 1), 100).unwrap();
    d.accept_context(&context(3, 7, 100, 1), 100).unwrap();
    let writes = d.flash().count(Boundary::Program)
        + d.flash().count(Boundary::MarkerProgram)
        + d.flash().count(Boundary::Erase);
    d.accept_context(&context(2, 12, 101, 2), 100).unwrap();
    assert_eq!(
        writes,
        d.flash().count(Boundary::Program)
            + d.flash().count(Boundary::MarkerProgram)
            + d.flash().count(Boundary::Erase)
    );
    let mut d = reboot(d);
    recovery(&mut d);
    assert_eq!(
        d.accept_context(&context(2, 11, 200, 3), 100),
        Err(Error::PeriodRegressive)
    );
    assert_eq!(
        d.accept_context(&context(3, 6, 200, 3), 100),
        Err(Error::PeriodRegressive)
    );
    d.accept_context(&context(3, 8, 200, 4), 100).unwrap();
    d.delete_pool(enrollment(2).pool_id, None).unwrap();
    let mut next = enrollment(2);
    next.incarnation_id = IncarnationId::from_bytes([99; 16]);
    d.enroll(&next).unwrap();
    assert_eq!(d.pool_status(next.pool_id).unwrap().period_floor, None);
    let mut fresh = context(2, 1, 300, 5);
    fresh.incarnation_id = next.incarnation_id;
    d.accept_context(&fresh, 100).unwrap();
}

#[test]
fn raised_floor_never_acknowledges_before_clean_or_recovers_below_acknowledged_value() {
    let mut initial = enrolled(2);
    initial.accept_context(&context(2, 5, 100, 1), 100).unwrap();
    let base = initial.into_flash();
    let mut probe = boot(copy_image(&base));
    recovery(&mut probe);
    let start = probe.flash().trace.len();
    probe.accept_context(&context(2, 12, 200, 2), 100).unwrap();
    let trace = &probe.flash().trace[start..];
    for (offset, fault) in cuts(trace) {
        let mut d = boot(copy_image(&base));
        recovery(&mut d);
        let at = d.flash().trace.len() + offset;
        d.flash_mut().fault = Some((at, fault));
        let acknowledged = d.accept_context(&context(2, 12, 200, 2), 100).is_ok();
        let mut d = reboot(d);
        recovery(&mut d);
        let floor = d.pool_status(enrollment(2).pool_id).unwrap().period_floor;
        assert!(
            floor == Some(5) || floor == Some(12),
            "{offset} {fault:?}: {floor:?}"
        );
        if acknowledged {
            assert_eq!(
                floor,
                Some(12),
                "acknowledged floor rolled back at {offset} {fault:?}"
            );
        }
        if floor == Some(12) {
            assert_eq!(
                d.accept_context(&context(2, 11, 300, 3), 100),
                Err(Error::PeriodRegressive)
            );
        }
    }
}

#[test]
fn expired_outage_retires_instead_of_releasing_an_old_key() {
    let (d, _) = ready(2);
    let mut d = reboot(d);
    recovery(&mut d);
    d.accept_context(&context(2, 16, 4_000, 2), 100).unwrap();
    d.catch_up(enrollment(2).pool_id, 100).unwrap();
    let publication = d.publication(enrollment(2).pool_id).unwrap();
    assert_eq!(publication.kind, PublicationKind::Drop);
    assert_eq!(
        d.current(enrollment(2).pool_id, enrollment(2).incarnation_id, 100),
        Err(Error::Expired)
    );
}

#[test]
fn corrupt_pool_is_quarantined_but_corrupt_shared_configuration_stops_device() {
    let mut d = enrolled(2);
    d.enroll(&enrollment(3)).unwrap();
    let mut flash = d.into_flash();
    // Change a programmed byte without erasing, so the authenticated record fails.
    corrupt_programmed_byte(&mut flash, POOL, 2 * BANK);
    let mut d = boot(flash);
    recovery(&mut d);
    assert_eq!(
        d.pool_status(enrollment(2).pool_id),
        Err(Error::StorageFailure)
    );
    d.accept_context(&context(3, 7, 100, 1), 100).unwrap();
    assert_eq!(
        d.pool_status(enrollment(3).pool_id).unwrap().period_floor,
        Some(7)
    );
    let mut flash = d.into_flash();
    corrupt_programmed_byte(&mut flash, CONFIG, 0x4000);
    let mut d = boot(flash);
    assert_eq!(d.recover(), Err(Error::StorageFailure));
    assert_eq!(
        d.pool_status(enrollment(3).pool_id),
        Err(Error::StorageFailure)
    );
}

fn corrupt_programmed_byte(flash: &mut ModelFlash, start: u32, len: u32) {
    let bytes = &flash.bytes()[start as usize..(start + len) as usize];
    let offset = bytes.iter().position(|&b| b != 0xff && b != 0).unwrap() as u32;
    flash.program_page(start + offset, &[0]).unwrap();
}

#[test]
fn committed_publication_and_key_recover_atomically_and_retries_reuse_timestamp() {
    let (mut d, _) = ready(2);
    let old = current(&mut d, 2);
    let image = d.into_flash();
    let mut probe = boot(copy_image(&image));
    recovery(&mut probe);
    probe.accept_context(&context(2, 8, 500, 2), 100).unwrap();
    let start = probe.flash().trace.len();
    probe.evolve(enrollment(2).pool_id, 100).unwrap();
    let trace = probe.flash().trace[start..].to_vec();
    let expected = current(&mut probe, 2);
    assert_eq!(
        expected.publication.timestamp_us,
        old.publication.timestamp_us + 1
    );
    for (offset, fault) in cuts(&trace) {
        let mut d = boot(copy_image(&image));
        recovery(&mut d);
        d.accept_context(&context(2, 8, 500, 2), 100).unwrap();
        let at = d.flash().trace.len() + offset;
        d.flash_mut().fault = Some((at, fault));
        let acknowledged = d.evolve(enrollment(2).pool_id, 100).is_ok();
        let mut d = reboot(d);
        recovery(&mut d);
        d.accept_context(&context(2, 8, 500, 3), 100).unwrap();
        d.catch_up(enrollment(2).pool_id, 100).unwrap();
        let first = current(&mut d, 2);
        assert_eq!(first, expected, "{offset} {fault:?}");
        assert_eq!(current(&mut d, 2), first);
        if acknowledged {
            assert!(first.revision > old.revision);
        }
    }
}

#[test]
fn failed_cleanup_prevents_acknowledgment_and_key_release_until_verified() {
    let (mut d, _) = ready(2);
    d.accept_context(&context(2, 8, 2_000, 2), 100).unwrap();
    let image = d.into_flash();
    let mut probe = boot(copy_image(&image));
    recovery(&mut probe);
    probe.accept_context(&context(2, 8, 2_000, 3), 100).unwrap();
    let start = probe.flash().trace.len();
    probe.evolve(enrollment(2).pool_id, 100).unwrap();
    let trace = &probe.flash().trace[start..];
    let commit = trace
        .iter()
        .position(|e| e.boundary == Boundary::MarkerProgram)
        .unwrap();
    let cleanup = commit
        + 1
        + trace[commit + 1..]
            .iter()
            .position(|e| e.boundary == Boundary::Erase)
            .unwrap();
    let mut d = boot(copy_image(&image));
    recovery(&mut d);
    d.accept_context(&context(2, 8, 2_000, 3), 100).unwrap();
    let at = d.flash().trace.len() + cleanup;
    d.flash_mut().fault = Some((at, Fault::FailBefore));
    assert!(d.evolve(enrollment(2).pool_id, 100).is_err());
    assert_eq!(
        d.current(enrollment(2).pool_id, enrollment(2).incarnation_id, 100),
        Err(Error::StorageFailure)
    );
    let mut d = reboot(d);
    recovery(&mut d);
    d.accept_context(&context(2, 8, 2_000, 4), 100).unwrap();
    let now = current(&mut d, 2);
    assert_eq!(now.relative_period, 8);
    assert!(erased(d.flash(), trace[cleanup].address, BANK));
}
