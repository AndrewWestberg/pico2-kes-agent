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

/// A read-only request bounded by one monotonic deadline, including connect.
pub fn request_until(
    socket: &Path,
    json: &[u8],
    deadline: std::time::Instant,
) -> Result<Vec<u8>, RequestError> {
    request_until_inner(socket, json, deadline, None)
}

/// Bind a read-only observation to the approved daemon before sending any bytes.
pub fn request_until_peer(
    socket: &Path,
    json: &[u8],
    deadline: std::time::Instant,
    expected_pid: u32,
    expected_uid: u32,
) -> Result<Vec<u8>, RequestError> {
    request_until_inner(socket, json, deadline, Some((expected_pid, expected_uid)))
}

fn request_until_inner(
    socket: &Path,
    json: &[u8],
    deadline: std::time::Instant,
    peer: Option<(u32, u32)>,
) -> Result<Vec<u8>, RequestError> {
    use std::os::{
        unix::ffi::OsStrExt,
    };
    if json.len() > MAX_FRAME || socket.as_os_str().as_bytes().contains(&0) {
        return Err(RequestError::before_admission(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid request or socket path",
        )));
    }
    let addr = rustix::net::SocketAddrUnix::new(socket)
        .map_err(|e| RequestError::before_admission(io::Error::from(e)))?;
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| RequestError::before_admission(io::Error::from(e)))?;
    let stream = UnixStream::from(fd);
    let wait = |flags: rustix::event::PollFlags| -> io::Result<()> {
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "observation deadline"))?;
            let ts = rustix::event::Timespec {
                tv_sec: remaining.as_secs() as _,
                tv_nsec: remaining.subsec_nanos() as _,
            };
            let mut pfd = [rustix::event::PollFd::new(&stream, flags)];
            match rustix::event::poll(&mut pfd, Some(&ts)) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "observation deadline",
                    ));
                }
                Ok(_) => return Ok(()),
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(io::Error::from(e)),
            }
        }
    };
    match rustix::net::connect(&stream, &addr) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            wait(rustix::event::PollFlags::OUT).map_err(RequestError::before_admission)?;
            if let Some(e) = stream
                .take_error()
                .map_err(RequestError::before_admission)?
            {
                return Err(RequestError::before_admission(e));
            }
        }
        Err(e) => return Err(RequestError::before_admission(io::Error::from(e))),
    }
    if let Some((pid, uid)) = peer {
        let actual = rustix::net::sockopt::socket_peercred(&stream)
            .map_err(|error| RequestError::before_admission(error.into()))?;
        if actual.pid.as_raw_pid() as u32 != pid || actual.uid.as_raw() != uid {
            return Err(RequestError::before_admission(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "management peer does not match the approved daemon",
            )));
        }
    }
    let header = (json.len() as u32).to_be_bytes();
    for part in [&header[..], json] {
        let mut sent = 0;
        while sent < part.len() {
            wait(rustix::event::PollFlags::OUT).map_err(RequestError::after_connect)?;
            match (&stream).write(&part[sent..]) {
                Ok(0) => {
                    return Err(RequestError::after_connect(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "socket closed",
                    )));
                }
                Ok(n) => sent += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(RequestError::after_connect(e)),
            }
        }
    }
    let mut header = [0; 4];
    let read = |buf: &mut [u8]| -> io::Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            wait(rustix::event::PollFlags::IN)?;
            match (&stream).read(&mut buf[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "socket closed",
                    ));
                }
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    };
    read(&mut header).map_err(RequestError::after_connect)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(RequestError::after_connect(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds 16384 bytes",
        )));
    }
    let mut response = vec![0; length];
    read(&mut response).map_err(RequestError::after_connect)?;
    Ok(response)
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    fn stalled_frame_respects_overall_deadline() {
        use std::{os::unix::net::UnixListener, thread, time::Instant};
        let dir = std::env::temp_dir().join(format!("p2kes-deadline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 6];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(&[0, 0, 0, 3, b'a']).unwrap();
            thread::sleep(Duration::from_millis(60));
            let _ = stream.write_all(b"b");
            thread::sleep(Duration::from_millis(190));
        });
        let start = Instant::now();
        let error = request_until(&path, b"{}", start + Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.into_io().kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_millis(240));
        peer.join().unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn peer_gate_refuses_wrong_pid_or_uid_before_sending() {
        use std::{
            os::unix::net::UnixListener,
            thread,
            time::{Instant, SystemTime, UNIX_EPOCH},
        };
        let dir = std::env::temp_dir().join(format!(
            "p2kes-peer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            }
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = [0; 6];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"\0\0\0\x08accepted").unwrap();
        });
        let pid = std::process::id();
        let uid = rustix::process::geteuid().as_raw();
        for (expected_pid, expected_uid) in [(0, uid), (pid, uid ^ 1)] {
            let error = request_until_peer(
                &path,
                b"{}",
                Instant::now() + Duration::from_secs(1),
                expected_pid,
                expected_uid,
            )
            .unwrap_err();
            assert!(!error.outcome_uncertain());
            assert_eq!(error.into_io().kind(), io::ErrorKind::PermissionDenied);
        }
        assert_eq!(
            request_until_peer(
                &path,
                b"{}",
                Instant::now() + Duration::from_secs(1),
                pid,
                uid
            )
            .unwrap(),
            b"accepted"
        );
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
