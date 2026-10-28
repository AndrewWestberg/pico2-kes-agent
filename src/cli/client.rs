use kes_protocol::management::MAX_FRAME;
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn request(socket: &Path, json: &[u8]) -> io::Result<Vec<u8>> {
    if json.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request exceeds 16384 bytes",
        ));
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&(json.len() as u32).to_be_bytes())?;
    stream.write_all(json)?;
    stream.flush()?;
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds 16384 bytes",
        ));
    }
    let mut response = vec![0; length];
    stream.read_exact(&mut response)?;
    Ok(response)
}
