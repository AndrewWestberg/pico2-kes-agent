//! Per-pool Service V2 subscriptions with latest-only publication coalescing.

use kes_core::{
    identity::{Digest32, GenerationId},
    kes::STATE_BYTES,
    operation::PoolTarget,
};
use kes_protocol::node_service::{
    self as wire, Bundle, Choice, DIRECT_CERTIFICATE_BYTES, MAX_SERVICE_MESSAGE_BYTES, Publication,
};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};
use zeroize::Zeroize;

pub const SERVICE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_SUBSCRIBERS_PER_POOL: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationKind {
    Key {
        generation: GenerationId,
        relative_period: u32,
        certificate_digest: Digest32,
        state: Box<[u8; STATE_BYTES]>,
        certificate: [u8; DIRECT_CERTIFICATE_BYTES],
    },
    Drop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationUpdate {
    pub target: PoolTarget,
    pub revision: u64,
    pub timestamp_us: u64,
    pub kind: PublicationKind,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol,
    Busy,
    WrongTarget,
    RegressiveRevision,
    ConflictingRevision,
    RegressiveTimestamp,
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "node service I/O: {error}"),
            Self::Protocol => formatter.write_str("invalid Service V2 peer message"),
            Self::Busy => formatter.write_str("pool already has two subscribers"),
            Self::WrongTarget => {
                formatter.write_str("publication target does not match socket binding")
            }
            Self::RegressiveRevision => formatter.write_str("publication revision regressed"),
            Self::ConflictingRevision => {
                formatter.write_str("same revision has different publication bytes")
            }
            Self::RegressiveTimestamp => {
                formatter.write_str("later publication timestamp is not increasing")
            }
        }
    }
}
impl std::error::Error for Error {}

struct State {
    latest: Option<Arc<PublicationUpdate>>,
    subscribers: usize,
    available: bool,
    stopped: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Clone)]
pub struct PoolSubscription {
    target: PoolTarget,
    shared: Arc<Shared>,
}

impl PoolSubscription {
    pub fn new(target: PoolTarget) -> Self {
        Self {
            target,
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    latest: None,
                    subscribers: 0,
                    available: true,
                    stopped: false,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    pub const fn target(&self) -> PoolTarget {
        self.target
    }

    /// Accepts only committed device descriptors. Temporary device/context
    /// unavailability is represented by not calling this method, never Drop.
    pub fn publish(&self, update: PublicationUpdate) -> Result<(), Error> {
        if update.target != self.target {
            return Err(Error::WrongTarget);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .expect("subscription mutex poisoned");
        if let Some(current) = &state.latest {
            if update.revision < current.revision {
                return Err(Error::RegressiveRevision);
            }
            if update.revision == current.revision {
                if update == **current {
                    state.available = true;
                    self.shared.changed.notify_all();
                    return Ok(());
                }
                return Err(Error::ConflictingRevision);
            }
            if update.timestamp_us <= current.timestamp_us {
                return Err(Error::RegressiveTimestamp);
            }
        }
        state.available = true;
        state.latest = Some(Arc::new(update));
        self.shared.changed.notify_all();
        Ok(())
    }

    pub fn latest(&self) -> Option<Arc<PublicationUpdate>> {
        self.shared
            .state
            .lock()
            .expect("subscription mutex poisoned")
            .latest
            .clone()
    }

    /// Pauses delivery after transport/session loss without publishing Drop or
    /// discarding the last committed descriptor. A later `publish` resumes all
    /// subscribers with the device-confirmed descriptor.
    pub fn suspend(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .expect("subscription mutex poisoned");
        state.available = false;
        self.shared.changed.notify_all();
    }

    pub fn stop(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .expect("subscription mutex poisoned");
        state.stopped = true;
        self.shared.changed.notify_all();
    }

    pub fn serve(&self, mut stream: UnixStream) -> Result<(), Error> {
        let _guard = self.admit()?;
        stream.set_read_timeout(Some(SERVICE_TIMEOUT))?;
        stream.set_write_timeout(Some(SERVICE_TIMEOUT))?;
        if !handshake(&mut stream)? {
            return Ok(());
        }

        let mut last_revision = None;
        loop {
            let update = {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .expect("subscription mutex poisoned");
                while !state.stopped
                    && (!state.available
                        || state
                            .latest
                            .as_ref()
                            .is_none_or(|latest| Some(latest.revision) == last_revision))
                {
                    state = self
                        .shared
                        .changed
                        .wait(state)
                        .expect("subscription mutex poisoned");
                }
                if state.stopped {
                    return Ok(());
                }
                state.latest.clone().expect("latest checked")
            };

            let mut bytes = [0; MAX_SERVICE_MESSAGE_BYTES];
            let len = encode_update(&update, &mut bytes)?;
            let sent = stream.write_all(&bytes[..len]);
            bytes[..len].zeroize();
            sent?;
            stream.flush()?;

            let mut confirmation = [0; 4];
            stream.read_exact(&mut confirmation)?;
            let _result = wire::decode_confirmation(&confirmation).map_err(|_| Error::Protocol)?;
            confirmation.zeroize();
            last_revision = Some(update.revision);
        }
    }

    fn admit(&self) -> Result<SubscriberGuard<'_>, Error> {
        let mut state = self
            .shared
            .state
            .lock()
            .expect("subscription mutex poisoned");
        if state.subscribers >= MAX_SUBSCRIBERS_PER_POOL {
            return Err(Error::Busy);
        }
        state.subscribers += 1;
        Ok(SubscriberGuard { subscription: self })
    }
}

struct SubscriberGuard<'a> {
    subscription: &'a PoolSubscription,
}
impl Drop for SubscriberGuard<'_> {
    fn drop(&mut self) {
        let mut state = self
            .subscription
            .shared
            .state
            .lock()
            .expect("subscription mutex poisoned");
        state.subscribers -= 1;
    }
}

fn handshake(stream: &mut UnixStream) -> Result<bool, Error> {
    let mut offer = [0; wire::OFFER_BYTES];
    let len = wire::encode_offer(&mut offer).map_err(|_| Error::Protocol)?;
    stream.write_all(&offer[..len])?;
    stream.flush()?;

    let mut boolean = [0; 1];
    stream.read_exact(&mut boolean)?;
    match boolean[0] {
        0 => return Ok(false),
        1 => {}
        _ => return Err(Error::Protocol),
    }
    let mut choice = [0; wire::CHOICE_BYTES];
    choice[0] = 1;
    stream.read_exact(&mut choice[1..])?;
    if wire::decode_choice(&choice).map_err(|_| Error::Protocol)? != Choice::ServiceV2 {
        return Err(Error::Protocol);
    }
    let mut initialization = [0; wire::IDENTIFIER_BYTES];
    let len = wire::encode_initialization(&mut initialization).map_err(|_| Error::Protocol)?;
    stream.write_all(&initialization[..len])?;
    stream.flush()?;
    Ok(true)
}

fn encode_update(update: &PublicationUpdate, output: &mut [u8]) -> Result<usize, Error> {
    let publication = match &update.kind {
        PublicationKind::Drop => Publication::Drop {
            timestamp_us: update.timestamp_us,
        },
        PublicationKind::Key {
            relative_period,
            state,
            certificate,
            ..
        } => Publication::Key {
            timestamp_us: update.timestamp_us,
            bundle: Bundle {
                state,
                relative_period: *relative_period,
                certificate,
            },
        },
    };
    wire::encode_publication(&publication, output).map_err(|_| Error::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kes_core::identity::{IncarnationId, PoolId};

    fn target() -> PoolTarget {
        PoolTarget {
            pool: PoolId::from_bytes([1; 28]),
            incarnation: IncarnationId::from_bytes([2; 16]),
        }
    }

    fn key(revision: u64, timestamp_us: u64, byte: u8) -> PublicationUpdate {
        PublicationUpdate {
            target: target(),
            revision,
            timestamp_us,
            kind: PublicationKind::Key {
                generation: GenerationId::from_bytes([byte; 16]),
                relative_period: u32::from(byte),
                certificate_digest: Digest32::from_bytes([byte; 32]),
                state: Box::new([byte; STATE_BYTES]),
                certificate: [byte; DIRECT_CERTIFICATE_BYTES],
            },
        }
    }

    #[test]
    fn coalesces_latest_and_rejects_conflicting_descriptors() {
        let subscription = PoolSubscription::new(target());
        subscription.publish(key(1, 10, 1)).unwrap();
        subscription.publish(key(2, 20, 2)).unwrap();
        assert_eq!(subscription.latest().unwrap().revision, 2);
        assert!(matches!(
            subscription.publish(key(2, 20, 3)),
            Err(Error::ConflictingRevision)
        ));
        assert!(matches!(
            subscription.publish(key(3, 20, 3)),
            Err(Error::RegressiveTimestamp)
        ));
    }

    #[test]
    fn serves_exact_latest_bundle_and_waits_for_four_byte_confirmation() {
        let subscription = PoolSubscription::new(target());
        subscription.publish(key(4, 99, 7)).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let serving = subscription.clone();
        let thread = std::thread::spawn(move || serving.serve(server));

        let mut offer = [0; wire::OFFER_BYTES];
        client.read_exact(&mut offer).unwrap();
        wire::decode_offer(&offer).unwrap();
        let mut choice = [0; wire::CHOICE_BYTES];
        let choice_len = wire::encode_choice(Choice::ServiceV2, &mut choice).unwrap();
        for byte in &choice[..choice_len] {
            client.write_all(&[*byte]).unwrap();
        }
        let mut initialization = [0; wire::IDENTIFIER_BYTES];
        client.read_exact(&mut initialization).unwrap();
        wire::decode_initialization(&initialization).unwrap();

        let mut publication = [0; wire::KEY_PUBLICATION_BYTES];
        client.read_exact(&mut publication).unwrap();
        match wire::decode_publication(&publication).unwrap() {
            Publication::Key {
                timestamp_us,
                bundle,
            } => {
                assert_eq!(timestamp_us, 99);
                assert_eq!(bundle.relative_period, 7);
                assert_eq!(bundle.state, &[7; STATE_BYTES]);
                assert_eq!(bundle.certificate, &[7; DIRECT_CERTIFICATE_BYTES]);
            }
            Publication::Drop { .. } => panic!("unexpected Drop"),
        }
        client
            .write_all(&wire::encode_confirmation(wire::Confirmation::Ok))
            .unwrap();
        subscription.stop();
        thread.join().unwrap().unwrap();
    }
}
