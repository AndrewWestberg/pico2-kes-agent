use kes_protocol::management::MAX_FRAME;
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct RequestError {
    source: io::Error,
    outcome_uncertain: bool,
}

impl RequestError {
    fn before_admission(source: io::Error) -> Self {
        Self {
            source,
            outcome_uncertain: false,
        }
    }

    fn after_connect(source: io::Error) -> Self {
        Self {
            source,
            outcome_uncertain: true,
        }
    }

    pub const fn outcome_uncertain(&self) -> bool {
        self.outcome_uncertain
    }

    pub fn into_io(self) -> io::Error {
        self.source
    }
}

pub fn request(socket: &Path, json: &[u8]) -> Result<Vec<u8>, RequestError> {
    if json.len() > MAX_FRAME {
        return Err(RequestError::before_admission(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request exceeds 16384 bytes",
        )));
    }
    let mut stream = UnixStream::connect(socket).map_err(RequestError::before_admission)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(RequestError::before_admission)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(RequestError::before_admission)?;
    stream
        .write_all(&(json.len() as u32).to_be_bytes())
        .map_err(RequestError::after_connect)?;
    stream
        .write_all(json)
        .map_err(RequestError::after_connect)?;
    stream.flush().map_err(RequestError::after_connect)?;
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(RequestError::after_connect)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(RequestError::after_connect(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds 16384 bytes",
        )));
    }
    let mut response = vec![0; length];
    stream
        .read_exact(&mut response)
        .map_err(RequestError::after_connect)?;
    Ok(response)
}
