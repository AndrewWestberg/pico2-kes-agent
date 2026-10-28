//! Exact `kes-agent` Service V2 direct stream codec.

use kes_core::kes::STATE_BYTES;

pub const IDENTIFIER_BYTES: usize = 32;
pub const SERVICE_V2: [u8; IDENTIFIER_BYTES] = {
    let mut value = [0; IDENTIFIER_BYTES];
    value[0] = b'S';
    value[1] = b'e';
    value[2] = b'r';
    value[3] = b'v';
    value[4] = b'i';
    value[5] = b'c';
    value[6] = b'e';
    value[7] = b':';
    value[8] = b'2';
    value[9] = b'.';
    value[10] = b'0';
    value
};
pub const OFFER_BYTES: usize = 4 + IDENTIFIER_BYTES;
pub const CHOICE_BYTES: usize = 1 + IDENTIFIER_BYTES;
pub const DIRECT_CERTIFICATE_BYTES: usize = 112;
pub const BUNDLE_BYTES: usize = STATE_BYTES + 4 + DIRECT_CERTIFICATE_BYTES;
pub const KEY_PUBLICATION_BYTES: usize = 1 + 8 + BUNDLE_BYTES;
pub const DROP_PUBLICATION_BYTES: usize = 1 + 8;
pub const CONFIRMATION_BYTES: usize = 4;
pub const MAX_SERVICE_MESSAGE_BYTES: usize = KEY_PUBLICATION_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Length,
    Count,
    Boolean,
    UnsupportedVersion,
    Tag,
    Period,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Choice {
    Rejected,
    ServiceV2,
}

#[derive(Clone, Copy)]
pub struct Bundle<'a> {
    pub state: &'a [u8; STATE_BYTES],
    pub relative_period: u32,
    /// Hot verification key, counter, start period, then cold signature.
    pub certificate: &'a [u8; DIRECT_CERTIFICATE_BYTES],
}

pub enum Publication<'a> {
    Key {
        timestamp_us: u64,
        bundle: Bundle<'a>,
    },
    Drop {
        timestamp_us: u64,
    },
}

pub fn encode_offer(output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < OFFER_BYTES {
        return Err(Error::Length);
    }
    output[..4].copy_from_slice(&1u32.to_be_bytes());
    output[4..OFFER_BYTES].copy_from_slice(&SERVICE_V2);
    Ok(OFFER_BYTES)
}

pub fn decode_offer(input: &[u8]) -> Result<(), Error> {
    if input.len() != OFFER_BYTES {
        return Err(Error::Length);
    }
    if u32::from_be_bytes(input[..4].try_into().map_err(|_| Error::Length)?) != 1 {
        return Err(Error::Count);
    }
    if input[4..] != SERVICE_V2 {
        return Err(Error::UnsupportedVersion);
    }
    Ok(())
}

pub fn encode_choice(choice: Choice, output: &mut [u8]) -> Result<usize, Error> {
    match choice {
        Choice::Rejected => {
            if output.is_empty() {
                return Err(Error::Length);
            }
            output[0] = 0;
            Ok(1)
        }
        Choice::ServiceV2 => {
            if output.len() < CHOICE_BYTES {
                return Err(Error::Length);
            }
            output[0] = 1;
            output[1..CHOICE_BYTES].copy_from_slice(&SERVICE_V2);
            Ok(CHOICE_BYTES)
        }
    }
}

pub fn decode_choice(input: &[u8]) -> Result<Choice, Error> {
    match input {
        [0] => Ok(Choice::Rejected),
        [1, identifier @ ..] if identifier.len() == IDENTIFIER_BYTES => {
            if identifier == SERVICE_V2 {
                Ok(Choice::ServiceV2)
            } else {
                Err(Error::UnsupportedVersion)
            }
        }
        [0, ..] | [1, ..] => Err(Error::Length),
        _ => Err(Error::Boolean),
    }
}

pub fn encode_initialization(output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < IDENTIFIER_BYTES {
        return Err(Error::Length);
    }
    output[..IDENTIFIER_BYTES].copy_from_slice(&SERVICE_V2);
    Ok(IDENTIFIER_BYTES)
}

pub fn decode_initialization(input: &[u8]) -> Result<(), Error> {
    if input.len() != IDENTIFIER_BYTES {
        return Err(Error::Length);
    }
    if input != SERVICE_V2 {
        return Err(Error::UnsupportedVersion);
    }
    Ok(())
}

pub fn encode_publication(value: &Publication<'_>, output: &mut [u8]) -> Result<usize, Error> {
    match value {
        Publication::Drop { timestamp_us } => {
            if output.len() < DROP_PUBLICATION_BYTES {
                return Err(Error::Length);
            }
            output[0] = 1;
            output[1..9].copy_from_slice(&timestamp_us.to_be_bytes());
            Ok(DROP_PUBLICATION_BYTES)
        }
        Publication::Key {
            timestamp_us,
            bundle,
        } => {
            if output.len() < KEY_PUBLICATION_BYTES {
                return Err(Error::Length);
            }
            output[0] = 0;
            output[1..9].copy_from_slice(&timestamp_us.to_be_bytes());
            output[9..9 + STATE_BYTES].copy_from_slice(bundle.state);
            let period_start = 9 + STATE_BYTES;
            output[period_start..period_start + 4]
                .copy_from_slice(&bundle.relative_period.to_be_bytes());
            output[period_start + 4..KEY_PUBLICATION_BYTES].copy_from_slice(bundle.certificate);
            Ok(KEY_PUBLICATION_BYTES)
        }
    }
}

pub fn decode_publication(input: &[u8]) -> Result<Publication<'_>, Error> {
    match input.first().copied() {
        Some(1) => {
            if input.len() != DROP_PUBLICATION_BYTES {
                return Err(Error::Length);
            }
            Ok(Publication::Drop {
                timestamp_us: u64::from_be_bytes(
                    input[1..9].try_into().map_err(|_| Error::Length)?,
                ),
            })
        }
        Some(0) => {
            if input.len() != KEY_PUBLICATION_BYTES {
                return Err(Error::Length);
            }
            let period_start = 9 + STATE_BYTES;
            Ok(Publication::Key {
                timestamp_us: u64::from_be_bytes(
                    input[1..9].try_into().map_err(|_| Error::Length)?,
                ),
                bundle: Bundle {
                    state: input[9..period_start]
                        .try_into()
                        .map_err(|_| Error::Length)?,
                    relative_period: u32::from_be_bytes(
                        input[period_start..period_start + 4]
                            .try_into()
                            .map_err(|_| Error::Length)?,
                    ),
                    certificate: input[period_start + 4..]
                        .try_into()
                        .map_err(|_| Error::Length)?,
                },
            })
        }
        Some(_) => Err(Error::Tag),
        None => Err(Error::Length),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confirmation {
    Ok,
    Outdated,
    InvalidCertificate,
    NoKey,
    Unsupported,
    Unknown,
}

pub const fn encode_confirmation(value: Confirmation) -> [u8; CONFIRMATION_BYTES] {
    let raw = match value {
        Confirmation::Ok => 0u32,
        Confirmation::Outdated => 1,
        Confirmation::InvalidCertificate => 2,
        Confirmation::NoKey => 3,
        Confirmation::Unsupported => 4,
        Confirmation::Unknown => 0xffff,
    };
    raw.to_be_bytes()
}

pub fn decode_confirmation(input: &[u8]) -> Result<Confirmation, Error> {
    if input.len() != CONFIRMATION_BYTES {
        return Err(Error::Length);
    }
    Ok(
        match u32::from_be_bytes(input.try_into().map_err(|_| Error::Length)?) {
            0 => Confirmation::Ok,
            1 => Confirmation::Outdated,
            2 => Confirmation::InvalidCertificate,
            3 => Confirmation::NoKey,
            4 => Confirmation::Unsupported,
            0xffff => Confirmation::Unknown,
            _ => Confirmation::Unknown,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_v2_offer_choice_and_publication_layout() {
        let mut offer = [0; OFFER_BYTES];
        assert_eq!(encode_offer(&mut offer), Ok(OFFER_BYTES));
        assert_eq!(&offer[..4], &1u32.to_be_bytes());
        assert_eq!(&offer[4..15], b"Service:2.0");
        assert!(offer[15..].iter().all(|byte| *byte == 0));
        assert_eq!(decode_offer(&offer), Ok(()));

        let mut choice = [0; CHOICE_BYTES];
        assert_eq!(
            encode_choice(Choice::ServiceV2, &mut choice),
            Ok(CHOICE_BYTES)
        );
        assert_eq!(decode_choice(&choice), Ok(Choice::ServiceV2));

        let state = [0x11; STATE_BYTES];
        let certificate = [0x22; DIRECT_CERTIFICATE_BYTES];
        let publication = Publication::Key {
            timestamp_us: 0x0102_0304_0506_0708,
            bundle: Bundle {
                state: &state,
                relative_period: 0x1122_3344,
                certificate: &certificate,
            },
        };
        let mut encoded = [0; KEY_PUBLICATION_BYTES];
        assert_eq!(
            encode_publication(&publication, &mut encoded),
            Ok(KEY_PUBLICATION_BYTES)
        );
        assert_eq!(encoded[0], 0);
        assert_eq!(&encoded[1..9], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&encoded[9..9 + STATE_BYTES], &state);
        assert_eq!(
            &encoded[9 + STATE_BYTES..13 + STATE_BYTES],
            &0x1122_3344u32.to_be_bytes()
        );
        assert_eq!(&encoded[13 + STATE_BYTES..], &certificate);
    }
}
