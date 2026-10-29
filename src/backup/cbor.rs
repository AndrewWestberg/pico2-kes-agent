use core::fmt;

pub const MAX_ENCODED_BYTES: usize = 8192;
const MAX_NESTING_DEPTH: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Oversize,
    Incomplete,
    NonCanonical,
    DuplicateOrUnsortedKey,
    Nesting,
    InvalidType,
    InvalidUtf8,
    TrailingBytes,
    MissingField,
    BufferTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid canonical CBOR: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Value<'a> {
    raw: &'a [u8],
}

impl<'a> Value<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() > MAX_ENCODED_BYTES {
            return Err(Error::Oversize);
        }
        let mut parser = Parser { input: raw, pos: 0 };
        parser.item(0)?;
        if parser.pos != raw.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(Self { raw })
    }

    pub const fn encoded(self) -> &'a [u8] {
        self.raw
    }

    pub fn uint(self) -> Result<u64, Error> {
        let (major, value, _) = header(self.raw)?;
        (major == 0).then_some(value).ok_or(Error::InvalidType)
    }

    pub fn bytes(self) -> Result<&'a [u8], Error> {
        let (major, _, head) = header(self.raw)?;
        (major == 2)
            .then_some(&self.raw[head..])
            .ok_or(Error::InvalidType)
    }

    pub fn text(self) -> Result<&'a str, Error> {
        let (major, _, head) = header(self.raw)?;
        if major != 3 {
            return Err(Error::InvalidType);
        }
        core::str::from_utf8(&self.raw[head..]).map_err(|_| Error::InvalidUtf8)
    }

    pub fn map(self) -> Result<Map<'a>, Error> {
        let (major, length, head) = header(self.raw)?;
        if major != 5 {
            return Err(Error::InvalidType);
        }
        Ok(Map {
            raw: self.raw,
            pos: head,
            remaining: length as usize,
        })
    }
}

fn header(raw: &[u8]) -> Result<(u8, u64, usize), Error> {
    let byte = *raw.first().ok_or(Error::Incomplete)?;
    let additional = byte & 31;
    let major = byte >> 5;
    let count = match additional {
        0..=23 => return Ok((major, u64::from(additional), 1)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(Error::NonCanonical),
    };
    let bytes = raw.get(1..1 + count).ok_or(Error::Incomplete)?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    let minimum = match count {
        1 => 24,
        2 => 256,
        4 => 65_536,
        _ => 4_294_967_296,
    };
    if value < minimum {
        return Err(Error::NonCanonical);
    }
    Ok((major, value, 1 + count))
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn item(&mut self, depth: usize) -> Result<(), Error> {
        let start = self.pos;
        let (major, length, head) = header(self.input.get(start..).ok_or(Error::Incomplete)?)?;
        self.pos += head;
        match major {
            0 => {}
            2 | 3 => {
                let length = usize::try_from(length).map_err(|_| Error::Oversize)?;
                let end = self.pos.checked_add(length).ok_or(Error::Oversize)?;
                let bytes = self.input.get(self.pos..end).ok_or(Error::Incomplete)?;
                if major == 3 {
                    core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                }
                self.pos = end;
            }
            5 => {
                if depth >= MAX_NESTING_DEPTH || length > MAX_ENCODED_BYTES as u64 {
                    return Err(Error::Nesting);
                }
                let mut previous: Option<&[u8]> = None;
                for _ in 0..length {
                    let key_start = self.pos;
                    self.item(depth + 1)?;
                    let encoded = &self.input[key_start..self.pos];
                    Value { raw: encoded }.text()?;
                    if previous.is_some_and(|value| value >= encoded) {
                        return Err(Error::DuplicateOrUnsortedKey);
                    }
                    previous = Some(encoded);
                    self.item(depth + 1)?;
                }
            }
            _ => return Err(Error::InvalidType),
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Map<'a> {
    raw: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Map<'a> {
    pub fn get(self, key: &str) -> Result<Option<Value<'a>>, Error> {
        for field in self {
            let (found, value) = field?;
            if found == key {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub fn required(self, key: &str) -> Result<Value<'a>, Error> {
        self.get(key)?.ok_or(Error::MissingField)
    }
}

impl<'a> Iterator for Map<'a> {
    type Item = Result<(&'a str, Value<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some((|| {
            let mut parser = Parser {
                input: self.raw,
                pos: self.pos,
            };
            let key_start = parser.pos;
            parser.item(0)?;
            let key = Value {
                raw: &self.raw[key_start..parser.pos],
            }
            .text()?;
            let value_start = parser.pos;
            parser.item(0)?;
            self.pos = parser.pos;
            Ok((
                key,
                Value {
                    raw: &self.raw[value_start..parser.pos],
                },
            ))
        })())
    }
}

fn encode_head(major: u8, value: u64, output: &mut [u8; 9]) -> usize {
    if value < 24 {
        output[0] = (major << 5) | value as u8;
        return 1;
    }
    let width = if value <= u8::MAX as u64 {
        1
    } else if value <= u16::MAX as u64 {
        2
    } else if value <= u32::MAX as u64 {
        4
    } else {
        8
    };
    output[0] = (major << 5)
        | match width {
            1 => 24,
            2 => 25,
            4 => 26,
            _ => 27,
        };
    let bytes = value.to_be_bytes();
    output[1..1 + width].copy_from_slice(&bytes[8 - width..]);
    1 + width
}

pub struct Encoder<'a> {
    output: &'a mut [u8],
    pos: usize,
}

impl<'a> Encoder<'a> {
    pub const fn new(output: &'a mut [u8]) -> Self {
        Self { output, pos: 0 }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(bytes.len()).ok_or(Error::Oversize)?;
        if end > MAX_ENCODED_BYTES {
            return Err(Error::Oversize);
        }
        self.output
            .get_mut(self.pos..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn head(&mut self, major: u8, value: u64) -> Result<(), Error> {
        let mut encoded = [0; 9];
        let length = encode_head(major, value, &mut encoded);
        self.append(&encoded[..length])
    }

    pub fn uint(&mut self, value: u64) -> Result<(), Error> {
        self.head(0, value)
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.head(2, bytes.len() as u64)?;
        self.append(bytes)
    }

    pub fn text(&mut self, text: &str) -> Result<(), Error> {
        self.head(3, text.len() as u64)?;
        self.append(text.as_bytes())
    }

    pub fn map(&mut self, fields: usize) -> Result<(), Error> {
        self.head(5, fields as u64)
    }

    pub fn value(&mut self, value: Value<'_>) -> Result<(), Error> {
        self.append(value.encoded())
    }

    pub fn finish(self) -> Result<Value<'a>, Error> {
        Value::parse(&self.output[..self.pos])
    }
}
