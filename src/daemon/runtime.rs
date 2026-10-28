//! Process runtime wiring for the sole-owner USB daemon.

use crate::{
    config::{Config, RunMode},
    daemon::{
        journal::Journal,
        management::{self, Management},
        node_service::PoolSubscription,
        sockets::SocketRegistry,
        usb::{self, Mode, Transport},
    },
};
use kes_core::{identity::Digest32, operation::PoolTarget};
use kes_protocol::management::MAX_FRAME;
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::{Arc, Mutex},
    time::Duration,
};

const MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum Error {
    Journal(crate::daemon::journal::Error),
    Socket(crate::daemon::sockets::Error),
    Usb(usb::Error),
    Io(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "{error}"),
            Self::Socket(error) => write!(formatter, "{error}"),
            Self::Usb(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "daemon I/O: {error}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::daemon::journal::Error> for Error {
    fn from(value: crate::daemon::journal::Error) -> Self {
        Self::Journal(value)
    }
}
impl From<crate::daemon::sockets::Error> for Error {
    fn from(value: crate::daemon::sockets::Error) -> Self {
        Self::Socket(value)
    }
}
impl From<usb::Error> for Error {
    fn from(value: usb::Error) -> Self {
        Self::Usb(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct DeviceState {
    journal: Journal,
    usb: Transport,
}

/// Opens durable state and verifies the selected device before exposing any
/// socket. The function then serves until the process is terminated.
pub fn serve(config: Config) -> Result<(), Error> {
    let journal_path = config.state_directory.join("operations.journal");
    let journal = Journal::open(&journal_path)?;
    let mode = match (config.mode, config.pin) {
        (RunMode::Commissioning, _) => Mode::Commissioning {
            selected_serial: config.selected_serial,
        },
        (RunMode::Normal, Some(pin)) => Mode::Normal { pin },
        (RunMode::Normal, None) => return Err(Error::Usb(usb::Error::IdentityMismatch)),
    };
    let mut usb = Transport::connect(mode, MANAGEMENT_TIMEOUT)?;
    if let Some(pending) = journal.pending() {
        usb.set_outstanding(
            pending.key.sequence,
            Digest32::from_bytes(pending.key.request_digest),
        );
    }
    let sockets = SocketRegistry::bind(&config)?;
    let management = sockets
        .listener(&config.management_socket)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "management listener missing"))?
        .try_clone()?;
    let config = Arc::new(config);
    let state = Arc::new(Mutex::new(DeviceState { journal, usb }));

    for pool in &config.pools {
        let listener = sockets
            .listener(&pool.socket_path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "pool listener missing"))?
            .try_clone()?;
        let subscription = PoolSubscription::new(PoolTarget {
            pool: pool.pool,
            incarnation: pool.incarnation,
        });
        std::thread::Builder::new()
            .name(format!("kes-pool-{}", pool.pool))
            .spawn(move || serve_pool(listener, subscription))
            .map_err(Error::Io)?;
    }

    // Keep the registry alive for inode-safe endpoint cleanup and runtime lock
    // ownership. Management dispatch is serialized with all USB access.
    let _sockets = sockets;
    for connection in management.incoming() {
        let mut stream = connection?;
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("kes-management".to_owned())
            .spawn(move || {
                if let Err(error) = serve_management(&config, &state, &mut stream) {
                    let _ = writeln!(io::stderr(), "management connection: {error}");
                }
            })
            .map_err(Error::Io)?;
    }
    Ok(())
}

fn serve_pool(listener: UnixListener, subscription: PoolSubscription) {
    for connection in listener.incoming() {
        let Ok(stream) = connection else { return };
        let service = subscription.clone();
        let _ = std::thread::Builder::new()
            .name("kes-node-client".to_owned())
            .spawn(move || {
                let _ = service.serve(stream);
            });
    }
}

fn serve_management(
    config: &Config,
    state: &Mutex<DeviceState>,
    stream: &mut UnixStream,
) -> io::Result<()> {
    stream.set_read_timeout(Some(MANAGEMENT_TIMEOUT))?;
    stream.set_write_timeout(Some(MANAGEMENT_TIMEOUT))?;
    let request = read_frame(stream)?;
    let request_id = request_id(&request);
    let response = {
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("device state mutex poisoned"))?;
        let DeviceState { journal, usb } = &mut *state;
        let mut management = Management::new(config, journal, usb);
        match management.dispatch(&request) {
            Ok(response) => response,
            Err(error) => error_response(request_id.as_deref(), &error),
        }
    };
    write_frame(stream, &response)
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid management frame length",
        ));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "management response exceeds frame bound",
        ));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn request_id(request: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(request)
        .ok()?
        .get("request_id")?
        .as_str()
        .map(str::to_owned)
}

fn error_response(request_id: Option<&str>, error: &management::Error) -> Vec<u8> {
    let (outcome, code, message, request_digest) = match error {
        management::Error::Protocol | management::Error::InvalidInput => {
            ("rejected", "invalid_input", "request is invalid", None)
        }
        management::Error::ModeDenied => (
            "rejected",
            "permission_denied",
            "action is not allowed in this daemon mode",
            None,
        ),
        management::Error::Journal(crate::daemon::journal::Error::Busy)
        | management::Error::Usb(usb::Error::Busy) => (
            "rejected",
            "busy",
            "another mutation requires reconciliation",
            None,
        ),
        management::Error::Usb(usb::Error::Uncertain { digest, .. }) => (
            "uncertain",
            "outcome_unknown",
            "device request outcome is uncertain; reconcile before another mutation",
            Some(digest.to_string()),
        ),
        management::Error::Usb(usb::Error::IdentityMismatch | usb::Error::Signature) => (
            "rejected",
            "wrong_device",
            "connected device failed pinned identity verification",
            None,
        ),
        management::Error::Usb(usb::Error::NotFound | usb::Error::PreAdmission) => (
            "rejected",
            "device_unavailable",
            "selected device is unavailable",
            None,
        ),
        management::Error::Usb(_) => (
            "rejected",
            "device_unavailable",
            "device transport failed",
            None,
        ),
        management::Error::Journal(_) => (
            "rejected",
            "storage_failure",
            "durable operation journal failed",
            None,
        ),
    };
    let mut public_error = serde_json::Map::new();
    public_error.insert("code".into(), Value::String(code.into()));
    public_error.insert("message".into(), Value::String(message.into()));
    if let Some(digest) = request_digest {
        public_error.insert("request_digest".into(), Value::String(digest));
    }
    serde_json::to_vec(&json!({
        "version": 1,
        "request_id": request_id.unwrap_or("00000000000000000000000000000000"),
        "outcome": outcome,
        "result": null,
        "error": public_error
    }))
    .expect("fixed error response is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kes_protocol::management::{Kind, Message, Outcome};

    #[test]
    fn rejected_runtime_errors_are_valid_management_responses() {
        let response = error_response(
            Some("00112233445566778899aabbccddeeff"),
            &management::Error::InvalidInput,
        );
        let message = Message::decode(&response).unwrap();
        assert!(matches!(
            message.kind(),
            Kind::Response {
                outcome: Outcome::Rejected,
                ..
            }
        ));
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["result"],
            Value::Null
        );
    }

    #[test]
    fn uncertain_runtime_errors_put_digest_in_the_error_object() {
        let digest = Digest32::from_bytes([7; 32]);
        let response = error_response(
            Some("00112233445566778899aabbccddeeff"),
            &management::Error::Usb(usb::Error::Uncertain {
                sequence: 9,
                digest,
            }),
        );
        let message = Message::decode(&response).unwrap();
        assert!(matches!(
            message.kind(),
            Kind::Response {
                outcome: Outcome::Uncertain,
                ..
            }
        ));
        let value: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(value["result"], Value::Null);
        assert_eq!(value["error"]["request_digest"], digest.to_string());
        assert!(value["error"].get("sequence").is_none());
    }
}
