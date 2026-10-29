#![no_std]
#![no_main]

mod entropy;
mod flash;
mod scheduler;
mod service;
mod usb;

use core::{panic::PanicInfo, str};

use cortex_m_rt::entry;
use embassy_futures::{block_on, join::join};
use embassy_rp::{flash::Flash as HalFlash, otp};
use embassy_usb::UsbVersion;
use entropy::HealthCheckedEntropy;
use flash::{Admission, FLASH_BYTES, FittedFlash, Identity};
use hkdf::Hkdf;
use kes_core::{
    device::{EnrollmentRecord, HardwareIdentity},
    identity::{Digest32, OperationId},
    lifecycle::{Device as LifecycleDevice, Error as LifecycleError},
    operation::{Handoff, MAX_HANDOFF_BYTES, UsbSerial},
};
use scheduler::Scheduler;
use service::Service;
use sha2::{Digest, Sha256};
use usb::VendorBulk;
use zeroize::Zeroizing;

embassy_rp::bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => embassy_rp::usb::InterruptHandler<embassy_rp::peripherals::USB>;
});

type Device<'d> = LifecycleDevice<FittedFlash<'d>, HealthCheckedEntropy<'d>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    Flash,
    Otp,
    KeyDerivation,
    InvalidConfiguration,
    AttentionRequired,
    WrongSerial,
    Handoff,
}

pub struct AttendedCommissioning<'a> {
    pub attended: bool,
    pub serial: &'a [u8],
    pub operation_id: OperationId,
    pub request_digest: Digest32,
    pub expected_revision: u64,
    pub sequence: u64,
}

/// Owns the only flash and entropy capabilities. Startup recovers committed
/// state but never creates or replaces an identity.
pub struct Runtime<'d> {
    device: Device<'d>,
    serial: UsbSerial,
    handoff: Handoff,
    scheduler: Scheduler,
    handoff_buffer: [u8; MAX_HANDOFF_BYTES],
}

impl<'d> Runtime<'d> {
    pub fn start(
        mut flash: FittedFlash<'d>,
        entropy: HealthCheckedEntropy<'d>,
        serial: UsbSerial,
    ) -> Result<Self, StartupError> {
        let identity = flash.identity();
        let admission = flash
            .classify_allocated()
            .map_err(|_| StartupError::Flash)?;
        let hardware = hardware_identity(identity)?;
        let root_key = configuration_root(identity)?;
        let mut device = LifecycleDevice::open_with_root(flash, entropy, root_key, hardware)
            .map_err(|_| StartupError::InvalidConfiguration)?;
        if admission == Admission::NonBlank {
            device
                .recover()
                .map_err(|_| StartupError::InvalidConfiguration)?;
        }
        let identity = device
            .identity()
            .map(|identity| *identity.enrollment_record());
        let (handoff, had_persisted) = {
            let persisted = device
                .persisted_handoff()
                .map_err(|_| StartupError::Handoff)?;
            let handoff = match (identity, persisted) {
                (None, None) => Handoff::blank(),
                (Some(record), Some(bytes)) => {
                    let handoff = Handoff::decode(bytes).map_err(|_| StartupError::Handoff)?;
                    if handoff.commissioning_record() != Some(record.public()) {
                        return Err(StartupError::Handoff);
                    }
                    handoff
                }
                (Some(record), None) => Handoff::recover_commissioning(*record.public())
                    .map_err(|_| StartupError::Handoff)?,
                (None, Some(_)) => return Err(StartupError::Handoff),
            };
            (handoff, persisted.is_some())
        };
        let mut runtime = Self {
            device,
            serial,
            handoff,
            scheduler: Scheduler::new(),
            handoff_buffer: [0; MAX_HANDOFF_BYTES],
        };
        if !had_persisted && identity.is_some() {
            runtime
                .persist_handoff()
                .map_err(|_| StartupError::Handoff)?;
        }
        Ok(runtime)
    }

    pub fn commission(
        &mut self,
        request: AttendedCommissioning<'_>,
    ) -> Result<EnrollmentRecord, StartupError> {
        if !request.attended {
            return Err(StartupError::AttentionRequired);
        }
        if request.serial != self.serial.as_slice() {
            return Err(StartupError::WrongSerial);
        }
        self.device
            .commission_values(
                request.serial,
                request.operation_id,
                request.request_digest,
                request.expected_revision,
                request.sequence,
            )
            .map_err(|_| StartupError::InvalidConfiguration)
    }

    pub fn device(&self) -> &Device<'d> {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut Device<'d> {
        &mut self.device
    }

    pub fn handoff(&self) -> &Handoff {
        &self.handoff
    }

    pub fn handoff_mut(&mut self) -> &mut Handoff {
        &mut self.handoff
    }

    pub fn persist_handoff(&mut self) -> Result<(), LifecycleError> {
        let length = self
            .handoff
            .encode(&mut self.handoff_buffer)
            .map_err(|_| LifecycleError::StorageFailure)?;
        self.device.persist_handoff(&self.handoff_buffer[..length])
    }

    pub fn serial(&self) -> UsbSerial {
        self.serial
    }

    pub fn reconnect(&mut self) {
        self.device.reconnect();
    }

    pub fn map_error(error: LifecycleError) -> u16 {
        service::lifecycle_error_code(error)
    }
}

fn configuration_root(identity: Identity) -> Result<[u8; 32], StartupError> {
    let private = otp::get_private_random_number().map_err(|_| StartupError::Otp)?;
    let chip = otp::get_chipid().map_err(|_| StartupError::Otp)?;
    let private_bytes = Zeroizing::new(private.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(b"pico2-kes-config-wrap-v1"), &*private_bytes);
    let mut info = [0; 39];
    info[..8].copy_from_slice(&chip.to_be_bytes());
    info[8..11].copy_from_slice(&identity.jedec_id);
    info[11..27].copy_from_slice(&identity.sfdp_header);
    info[27..31].copy_from_slice(&identity.density_bits_minus_one.to_be_bytes());
    info[31..].copy_from_slice(b"root-key");
    let mut root = [0; 32];
    hkdf.expand(&info, &mut root)
        .map_err(|_| StartupError::KeyDerivation)?;
    Ok(root)
}

fn hardware_identity(identity: Identity) -> Result<HardwareIdentity, StartupError> {
    let chip = otp::get_chipid().map_err(|_| StartupError::Otp)?;
    let mut silicon = Sha256::new();
    silicon.update(b"pico2-kes-silicon-v1\0");
    silicon.update(chip.to_be_bytes());
    let mut fitted_flash = Sha256::new();
    fitted_flash.update(b"pico2-kes-flash-v1\0");
    fitted_flash.update(identity.jedec_id);
    fitted_flash.update(identity.sfdp_header);
    fitted_flash.update(identity.density_bits_minus_one.to_be_bytes());
    Ok(HardwareIdentity::new(
        Digest32::from_bytes(silicon.finalize().into()),
        Digest32::from_bytes(fitted_flash.finalize().into()),
    ))
}

fn usb_serial(bytes: &mut [u8; 16]) -> Result<UsbSerial, StartupError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let chip = otp::get_chipid().map_err(|_| StartupError::Otp)?;
    for (index, value) in chip.to_be_bytes().iter().enumerate() {
        bytes[index * 2] = HEX[usize::from(value >> 4)];
        bytes[index * 2 + 1] = HEX[usize::from(value & 0x0f)];
    }
    UsbSerial::new(bytes).map_err(|_| StartupError::InvalidConfiguration)
}

#[entry]
fn main() -> ! {
    let peripherals = embassy_rp::init(Default::default());
    let mut serial_bytes = [0; 16];
    let serial = match usb_serial(&mut serial_bytes) {
        Ok(serial) => serial,
        Err(_) => halt(),
    };
    let serial_text = match str::from_utf8(&serial_bytes) {
        Ok(serial_text) => serial_text,
        Err(_) => halt(),
    };
    let flash = match FittedFlash::new(HalFlash::<_, _, FLASH_BYTES>::new_blocking(
        peripherals.FLASH,
    )) {
        Ok(flash) => flash,
        Err(_) => halt(),
    };
    let entropy = match HealthCheckedEntropy::new(peripherals.TRNG) {
        Ok(entropy) => entropy,
        Err(_) => halt(),
    };
    let runtime = match Runtime::start(flash, entropy, serial) {
        Ok(runtime) => runtime,
        Err(_) => halt(),
    };

    let mut config = embassy_usb::Config::new(0x1209, 0x4b45);
    config.bcd_usb = UsbVersion::Two;
    config.manufacturer = Some("Pico2 KES Agent");
    config.product = Some("Pico2 KES Agent");
    config.serial_number = Some(serial_text);
    config.max_power = 100;

    let driver = embassy_rp::usb::Driver::new(peripherals.USB, Irqs);
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 64];
    let mut msos_descriptor = [0; 64];
    let mut control = [0; 64];
    let mut builder = embassy_usb::Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control,
    );
    let mut transport = VendorBulk::new(&mut builder);
    let mut device = builder.build();
    let mut service = Service::new(runtime);
    block_on(join(device.run(), transport.run(&mut service)));
    halt()
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt()
}
