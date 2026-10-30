//! Bounded RP2350 entropy acquisition with all hardware health tests enabled.
use embassy_rp::{Peri, peripherals::TRNG};
use kes_core::platform::{Entropy, EntropyError as CoreEntropyError, EntropyFailure};
use rp_pac as pac;
use zeroize::{Zeroize, Zeroizing};

pub const SAMPLE_COUNT: u32 = 200;
pub const INVERTER_CHAIN_LENGTH: u8 = 1;
pub const ENTROPY_BITS_PER_BLOCK: usize = 192;
pub const MAX_STATUS_POLLS_PER_BLOCK: u32 = 2_000_000;
const BLOCK_BYTES: usize = ENTROPY_BITS_PER_BLOCK / 8;

/// A health error is sticky until reboot; callers cannot retry through failure.
pub struct HealthCheckedEntropy<'d> {
    _peripheral: Peri<'d, TRNG>,
    failure: Option<EntropyFailure>,
}

impl<'d> HealthCheckedEntropy<'d> {
    pub fn new(peripheral: Peri<'d, TRNG>) -> Result<Self, EntropyFailure> {
        let mut entropy = Self {
            _peripheral: peripheral,
            failure: None,
        };
        entropy.configure()?;
        // Startup consumes two independent hardware blocks. The RP2350 CRNGT
        // remains enabled for every later block; these checks also reject a
        // stuck all-zero/all-one result before any key operation.
        let first = entropy.block()?;
        let second = entropy.block()?;
        if first == second
            || first.iter().all(|byte| *byte == 0)
            || first.iter().all(|byte| *byte == 0xff)
            || second.iter().all(|byte| *byte == 0)
            || second.iter().all(|byte| *byte == 0xff)
        {
            return Err(EntropyFailure::ContinuousTest);
        }
        Ok(entropy)
    }

    fn configure(&mut self) -> Result<(), EntropyFailure> {
        let registers = pac::TRNG;
        registers
            .rnd_source_enable()
            .write(|value| value.set_rnd_src_en(false));
        registers
            .rst_bits_counter()
            .write(|value| value.set_rst_bits_counter(true));
        registers
            .trng_sw_reset()
            .write(|value| value.set_trng_sw_reset(true));
        let _ = registers.trng_sw_reset().read();
        registers.rng_imr().write(|value| {
            value.set_ehr_valid_int_mask(true);
            value.set_autocorr_err_int_mask(true);
            value.set_crngt_err_int_mask(true);
            value.set_vn_err_int_mask(true);
        });
        registers
            .trng_config()
            .write(|value| value.set_rnd_src_sel(INVERTER_CHAIN_LENGTH));
        registers.sample_cnt1().write_value(SAMPLE_COUNT);
        registers.trng_debug_control().write(|value| {
            value.set_auto_correlate_bypass(false);
            value.set_trng_crngt_bypass(false);
            value.set_vnc_bypass(false);
        });
        registers
            .rng_debug_en_input()
            .write(|value| value.set_rng_debug_en(false));
        registers.rng_icr().write(|value| {
            value.set_ehr_valid(true);
            value.set_crngt_err(true);
            value.set_vn_err(true);
        });
        let masks = registers.rng_imr().read();
        let debug = registers.trng_debug_control().read();
        if registers.trng_config().read().rnd_src_sel() != INVERTER_CHAIN_LENGTH
            || registers.sample_cnt1().read() != SAMPLE_COUNT
            || !masks.ehr_valid_int_mask()
            || !masks.autocorr_err_int_mask()
            || !masks.crngt_err_int_mask()
            || !masks.vn_err_int_mask()
            || debug.auto_correlate_bypass()
            || debug.trng_crngt_bypass()
            || debug.vnc_bypass()
            || registers.rng_debug_en_input().read().rng_debug_en()
        {
            self.failure = Some(EntropyFailure::Configuration);
            return Err(EntropyFailure::Configuration);
        }
        Ok(())
    }

    fn block(&mut self) -> Result<Zeroizing<[u8; BLOCK_BYTES]>, EntropyFailure> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let registers = pac::TRNG;
        registers
            .rnd_source_enable()
            .write(|value| value.set_rnd_src_en(true));
        for _ in 0..MAX_STATUS_POLLS_PER_BLOCK {
            let status = registers.rng_isr().read();
            if status.autocorr_err() {
                return self.fail(EntropyFailure::Autocorrelation);
            }
            if status.crngt_err() {
                return self.fail(EntropyFailure::ContinuousTest);
            }
            if status.vn_err() {
                return self.fail(EntropyFailure::VonNeumann);
            }
            if registers.trng_valid().read().ehr_valid() {
                let words = Zeroizing::new([
                    registers.ehr_data0().read(),
                    registers.ehr_data1().read(),
                    registers.ehr_data2().read(),
                    registers.ehr_data3().read(),
                    registers.ehr_data4().read(),
                    registers.ehr_data5().read(),
                ]);
                self.stop();
                let mut block = Zeroizing::new([0; BLOCK_BYTES]);
                for (index, word) in words.iter().copied().enumerate() {
                    block[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                return Ok(block);
            }
            core::hint::spin_loop();
        }
        self.fail(EntropyFailure::Timeout)
    }

    fn stop(&self) {
        let registers = pac::TRNG;
        registers
            .rnd_source_enable()
            .write(|value| value.set_rnd_src_en(false));
        registers
            .rst_bits_counter()
            .write(|value| value.set_rst_bits_counter(true));
    }

    fn fail<T>(&mut self, error: EntropyFailure) -> Result<T, EntropyFailure> {
        self.stop();
        self.failure = Some(error);
        Err(error)
    }
}

impl Entropy for HealthCheckedEntropy<'_> {
    fn failure(&self) -> Option<EntropyFailure> {
        self.failure
    }

    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CoreEntropyError> {
        for chunk in destination.chunks_mut(BLOCK_BYTES) {
            let mut block = self.block().map_err(|_| CoreEntropyError)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }
        Ok(())
    }
}
