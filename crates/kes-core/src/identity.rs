//! Fixed-width public identities and bounded values.
use blake2::{Blake2b, Digest, digest::consts::U28};
use core::{fmt, num::NonZeroU64, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueError {
    Length,
    InvalidHex,
    OutOfRange,
    Overflow,
    NetworkMismatch,
}

macro_rules! identifier {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub struct $name([u8; $len]);
        impl $name {
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
            pub fn parse_hex(s: &str) -> Result<Self, ValueError> {
                if s.len() != $len * 2 {
                    return Err(ValueError::Length);
                }
                let mut out = [0u8; $len];
                let bytes = s.as_bytes();
                let mut i = 0;
                while i < $len {
                    fn nibble(c: u8) -> Result<u8, ValueError> {
                        match c {
                            b'0'..=b'9' => Ok(c - b'0'),
                            b'a'..=b'f' => Ok(c - b'a' + 10),
                            _ => Err(ValueError::InvalidHex),
                        }
                    }
                    out[i] = (nibble(bytes[2 * i])? << 4) | nibble(bytes[2 * i + 1])?;
                    i += 1;
                }
                Ok(Self(out))
            }
            pub fn write_hex(&self, out: &mut [u8]) -> Result<(), ValueError> {
                if out.len() != $len * 2 {
                    return Err(ValueError::Length);
                }
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for (i, b) in self.0.iter().copied().enumerate() {
                    out[2 * i] = HEX[(b >> 4) as usize];
                    out[2 * i + 1] = HEX[(b & 15) as usize];
                }
                Ok(())
            }
        }
        impl FromStr for $name {
            type Err = ValueError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse_hex(s)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}
identifier!(DeviceId, 16);
identifier!(IncarnationId, 16);
identifier!(GenerationId, 16);
identifier!(OperationId, 16);
identifier!(SessionId, 16);
identifier!(PoolId, 28);
identifier!(Digest32, 32);

impl PoolId {
    pub fn from_cold_verification_key(key: &[u8; 32]) -> Self {
        let digest = Blake2b::<U28>::digest(key);
        let mut bytes = [0; 28];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageSlot(u8);
impl StorageSlot {
    pub const CAPACITY: u8 = 64;
    pub const fn new(value: u8) -> Result<Self, ValueError> {
        if value < Self::CAPACITY {
            Ok(Self(value))
        } else {
            Err(ValueError::OutOfRange)
        }
    }
    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolCapacity(u8);
impl PoolCapacity {
    pub const fn new(value: u8) -> Result<Self, ValueError> {
        if value <= StorageSlot::CAPACITY {
            Ok(Self(value))
        } else {
            Err(ValueError::OutOfRange)
        }
    }
    pub const fn get(self) -> u8 {
        self.0
    }
    pub const fn checked_add(self) -> Result<Self, ValueError> {
        match self.0.checked_add(1) {
            Some(n) => Self::new(n),
            None => Err(ValueError::Overflow),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedBytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> BoundedBytes<N> {
    pub fn new(value: &[u8]) -> Result<Self, ValueError> {
        if value.len() > N {
            return Err(ValueError::Length);
        }
        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            bytes,
            len: value.len(),
        })
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkBinding {
    genesis: Digest32,
    magic: u32,
    slots_per_period: NonZeroU64,
    lifetime: u8,
}
impl NetworkBinding {
    pub fn new(
        genesis: Digest32,
        magic: u32,
        slots_per_period: u64,
        lifetime: u8,
    ) -> Result<Self, ValueError> {
        let slots_per_period = NonZeroU64::new(slots_per_period).ok_or(ValueError::OutOfRange)?;
        if !(1..=64).contains(&lifetime) {
            return Err(ValueError::OutOfRange);
        }
        Ok(Self {
            genesis,
            magic,
            slots_per_period,
            lifetime,
        })
    }
    pub const fn genesis(self) -> Digest32 {
        self.genesis
    }
    pub const fn magic(self) -> u32 {
        self.magic
    }
    pub const fn slots_per_period(self) -> u64 {
        self.slots_per_period.get()
    }
    pub const fn lifetime(self) -> u8 {
        self.lifetime
    }
    pub fn require_match(self, other: Self) -> Result<(), ValueError> {
        if self == other {
            Ok(())
        } else {
            Err(ValueError::NetworkMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_identifiers() {
        let id = DeviceId::from_bytes([0xab; 16]);
        let mut out = [0; 32];
        id.write_hex(&mut out).unwrap();
        assert_eq!(&out, b"abababababababababababababababab");
        assert_eq!(
            DeviceId::parse_hex(core::str::from_utf8(&out).unwrap()),
            Ok(id)
        );
        assert!(DeviceId::parse_hex("ABABABABABABABABABABABABABABABAB").is_err());
        assert!(DeviceId::parse_hex("zbababababababababababababababab").is_err());
        assert!(DeviceId::parse_hex("ab").is_err());
        assert!(PoolId::parse_hex(core::str::from_utf8(&out).unwrap()).is_err());
    }
    #[test]
    fn pool_blake2b_224_vector() {
        let mut key = [0; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            PoolId::from_cold_verification_key(&key),
            PoolId::parse_hex("491112dd01155c07dab485f71b572e0cae759e2cd38b1c0e97554297").unwrap()
        );
    }
    #[test]
    fn bounds_and_network_binding() {
        assert!(StorageSlot::new(63).is_ok());
        assert!(StorageSlot::new(64).is_err());
        assert!(PoolCapacity::new(64).unwrap().checked_add().is_err());
        assert!(BoundedBytes::<2>::new(b"abc").is_err());
        let a = NetworkBinding::new(Digest32::from_bytes([1; 32]), 1, 10, 64).unwrap();
        let b = NetworkBinding::new(Digest32::from_bytes([2; 32]), 1, 10, 64).unwrap();
        assert_eq!(a.require_match(b), Err(ValueError::NetworkMismatch));
        assert!(NetworkBinding::new(Digest32::from_bytes([1; 32]), 1, 0, 1).is_err());
        assert!(NetworkBinding::new(Digest32::from_bytes([1; 32]), 1, 1, 65).is_err());
    }
}
