//! Process runtime wiring for the sole-owner USB daemon.

use crate::{
    config::{Config, PoolBinding, RunMode},
    daemon::{
        context::{ContextProvider, REFRESH_INTERVAL, SystemClock, TargetContext},
        journal::Journal,
        management::{self, Management},
        node_service::{
            PoolSubscription, PublicationKind as NodePublicationKind, PublicationUpdate,
        },
        registry::PoolRegistry,
        scheduler::Scheduler,
        sockets::SocketRegistry,
        usb::{self, DeviceTransport, Mode, Transport},
    },
    memory,
};
use kes_core::{identity::Digest32, operation::PoolTarget};
use kes_protocol::{
    management::MAX_FRAME,
    node_service::DIRECT_CERTIFICATE_BYTES,
    usb::{CurrentResult, PublicationKind, Request, Response},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MANAGEMENT_CONNECTIONS: usize = 16;
static PROCESS_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn request_process_shutdown(_signal: libc::c_int) {
    PROCESS_SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_shutdown_handlers() -> io::Result<()> {
    PROCESS_SHUTDOWN.store(false, Ordering::SeqCst);
    // SAFETY: the handler only performs a lock-free atomic store, and the
    // daemon installs it before creating worker threads.
    unsafe {
        if libc::signal(
            libc::SIGTERM,
            request_process_shutdown as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
            || libc::signal(
                libc::SIGINT,
                request_process_shutdown as *const () as libc::sighandler_t,
            ) == libc::SIG_ERR
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn shutting_down(local: &AtomicBool) -> bool {
    local.load(Ordering::Acquire) || PROCESS_SHUTDOWN.load(Ordering::Acquire)
}

fn sleep_until_shutdown(shutdown: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !shutting_down(shutdown) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

#[derive(Debug)]
pub enum Error {
    Context(crate::daemon::context::Error),
    Journal(crate::daemon::journal::Error),
    Socket(crate::daemon::sockets::Error),
    Usb(usb::Error),
    Io(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context(error) => write!(formatter, "{error}"),
            Self::Journal(error) => write!(formatter, "{error}"),
            Self::Socket(error) => write!(formatter, "{error}"),
            Self::Usb(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "daemon I/O: {error}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::daemon::context::Error> for Error {
    fn from(value: crate::daemon::context::Error) -> Self {
        Self::Context(value)
    }
}
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

struct RuntimeTransport {
    mode: Mode,
    timeout: Duration,
    inner: Option<Transport>,
    outstanding: Option<(u64, Digest32)>,
    epoch: u64,
}

impl RuntimeTransport {
    fn connect(
        mode: Mode,
        timeout: Duration,
        outstanding: Option<(u64, Digest32)>,
    ) -> Result<Self, usb::Error> {
        let inner = match Transport::connect(mode, timeout) {
            Ok(mut transport) => {
                if let Some((sequence, digest)) = outstanding {
                    transport.set_outstanding(sequence, digest);
                }
                Some(transport)
            }
            Err(usb::Error::NotFound) => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            mode,
            timeout,
            inner,
            outstanding,
            epoch: 1,
        })
    }

    fn ensure_connected(&mut self) -> Result<u64, usb::Error> {
        if self.inner.is_none() {
            let mut transport = Transport::connect(self.mode, self.timeout)?;
            if let Some((sequence, digest)) = self.outstanding {
                transport.set_outstanding(sequence, digest);
            }
            self.inner = Some(transport);
            self.epoch = self.epoch.checked_add(1).ok_or(usb::Error::Protocol)?;
        }
        Ok(self.epoch)
    }

    fn disconnect(&mut self) {
        self.inner = None;
    }

    const fn has_outstanding(&self) -> bool {
        self.outstanding.is_some()
    }
}

impl DeviceTransport for RuntimeTransport {
    fn request(&mut self, request: &Request) -> Result<usb::Reply, usb::Error> {
        self.ensure_connected()?;
        let mutation = match request {
            Request::Mutate(mutation) | Request::Commission(mutation) => {
                Some((mutation.sequence(), mutation.usb_digest()))
            }
            _ => None,
        };
        let result = self
            .inner
            .as_mut()
            .ok_or(usb::Error::NotFound)?
            .request(request);
        if (result.is_ok() || matches!(result, Err(usb::Error::Uncertain { .. })))
            && let Some(outstanding) = mutation
        {
            self.outstanding = Some(outstanding);
        }
        if result.is_err() && !matches!(result, Err(usb::Error::Busy)) {
            self.disconnect();
        }
        result
    }

    fn clear_outstanding(&mut self, sequence: u64, digest: Digest32) -> Result<(), usb::Error> {
        self.inner
            .as_mut()
            .ok_or(usb::Error::NotFound)?
            .clear_outstanding(sequence, digest)?;
        if self.outstanding == Some((sequence, digest)) {
            self.outstanding = None;
            Ok(())
        } else {
            Err(usb::Error::Busy)
        }
    }
}

struct DeviceState {
    journal: Journal,
    usb: RuntimeTransport,
}

struct ManagementConnectionGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for ManagementConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Debug)]
enum PollError {
    Protocol,
    Memory,
    Usb,
}

impl From<usb::Error> for PollError {
    fn from(_value: usb::Error) -> Self {
        Self::Usb
    }
}

fn poll_target<T: DeviceTransport>(
    usb: &mut T,
    context: TargetContext,
) -> Result<Option<PublicationUpdate>, PollError> {
    let context_reply = usb.request(&Request::Context {
        target: context.target,
        network: context.network,
        period: context.period,
        session: context.session,
        sequence: context.sequence,
        lease_seconds: context.lease_seconds,
        publication_time_us: context.publication_time_us,
    })?;
    let Response::Context(accepted) = context_reply.decode().map_err(|_| PollError::Protocol)?
    else {
        return Err(PollError::Protocol);
    };
    if accepted.target != context.target
        || accepted.session != context.session
        || accepted.sequence != context.sequence
    {
        return Err(PollError::Protocol);
    }
    if accepted.result.is_err() {
        return Ok(None);
    }

    let current_reply = usb.request(&Request::Current {
        target: context.target,
    })?;
    let Response::Current(current) = current_reply.decode().map_err(|_| PollError::Protocol)?
    else {
        return Err(PollError::Protocol);
    };
    if current.target != context.target
        || current.snapshot_revision < current.publication.revision
        || current.publication.high_water_us < current.publication.timestamp_us
    {
        return Err(PollError::Protocol);
    }

    let kind = match current.result {
        CurrentResult::Unavailable { .. } => return Ok(None),
        CurrentResult::Drop => {
            if current.publication.kind != PublicationKind::Drop {
                return Err(PollError::Protocol);
            }
            NodePublicationKind::Drop
        }
        CurrentResult::Key {
            generation,
            period,
            state,
            certificate,
        } => {
            let PublicationKind::Key {
                generation: published_generation,
                period: published_period,
                certificate_digest,
            } = current.publication.kind
            else {
                return Err(PollError::Protocol);
            };
            if generation != published_generation || period != published_period {
                return Err(PollError::Protocol);
            }
            let certificate: [u8; DIRECT_CERTIFICATE_BYTES] =
                certificate.try_into().map_err(|_| PollError::Protocol)?;
            if Digest32::from_bytes(Sha256::digest(certificate).into()) != certificate_digest {
                return Err(PollError::Protocol);
            }
            let state =
                memory::SecretBuffer::copy_from_slice(state).map_err(|_| PollError::Memory)?;
            NodePublicationKind::Key {
                generation,
                relative_period: u32::try_from(period).map_err(|_| PollError::Protocol)?,
                certificate_digest,
                state,
                certificate,
            }
        }
    };
    Ok(Some(PublicationUpdate {
        target: current.target,
        revision: current.publication.revision,
        timestamp_us: current.publication.timestamp_us,
        kind,
    }))
}

fn suspend_all(pools: &[(PoolBinding, PoolSubscription)]) {
    for (_, subscription) in pools {
        subscription.suspend();
    }
}

fn poll_pools(
    state: &Mutex<DeviceState>,
    config: &Config,
    mut provider: ContextProvider<SystemClock>,
    pools: &[(PoolBinding, PoolSubscription)],
    shutdown: &AtomicBool,
) {
    let mut scheduler = Scheduler::new();
    for (_, subscription) in pools {
        let _ = scheduler.upsert(subscription.target());
    }
    let mut observed_epoch = 1;
    while !shutting_down(shutdown) {
        let recovery = state.lock().map_err(|_| ()).and_then(|mut state| {
            let epoch = state.usb.ensure_connected().map_err(|_| ())?;
            if state.journal.pending().is_some() {
                let DeviceState { journal, usb } = &mut *state;
                let mut management = Management::new(config, journal, usb);
                match management.reconcile_pending() {
                    Ok(Some(_)) => return Ok((epoch, true)),
                    Ok(None) => {}
                    Err(management::Error::Usb(usb::Error::Busy)) => return Err(()),
                    Err(_) => {
                        state.usb.disconnect();
                        return Err(());
                    }
                }
            }
            if state.usb.has_outstanding() {
                state.usb.disconnect();
                return Err(());
            }
            Ok((epoch, false))
        });
        let Ok((epoch, reconciled)) = recovery else {
            suspend_all(pools);
            sleep_until_shutdown(shutdown, REFRESH_INTERVAL);
            continue;
        };
        if reconciled {
            // Re-enter through the connection/session gate before publishing.
            suspend_all(pools);
            continue;
        }
        if epoch != observed_epoch {
            if provider.restart_session().is_err() {
                suspend_all(pools);
                sleep_until_shutdown(shutdown, REFRESH_INTERVAL);
                continue;
            }
            observed_epoch = epoch;
            suspend_all(pools);
        }

        let mut transport_failed = false;
        scheduler.request_all();
        while let Some(target) = scheduler.next_target() {
            if shutting_down(shutdown) {
                break;
            }
            let Some((binding, subscription)) = pools
                .iter()
                .find(|(_, subscription)| subscription.target() == target)
            else {
                continue;
            };
            let Ok(context) = provider.context_for(&binding.network, target) else {
                subscription.suspend();
                continue;
            };
            let result = state
                .lock()
                .map_err(|_| PollError::Usb)
                .and_then(|mut state| poll_target(&mut state.usb, context));
            match result {
                Ok(Some(update)) => {
                    if subscription.publish(update).is_err() {
                        subscription.suspend();
                    }
                }
                Ok(None) => subscription.suspend(),
                Err(_) => {
                    suspend_all(pools);
                    if let Ok(mut state) = state.lock() {
                        state.usb.disconnect();
                    }
                    transport_failed = true;
                    break;
                }
            }
        }
        if !transport_failed {
            sleep_until_shutdown(shutdown, REFRESH_INTERVAL);
        }
    }
    suspend_all(pools);
}
struct LiveEndpoints {
    sockets: SocketRegistry,
    pools: PoolRegistry,
}

impl LiveEndpoints {
    fn new(sockets: SocketRegistry, config: &Config) -> Self {
        Self {
            sockets,
            pools: PoolRegistry::new(config.socket_directory.clone(), config.socket_gid),
        }
    }

    fn reconcile(&mut self, bindings: &[PoolBinding]) -> Result<(), Error> {
        let desired: Vec<_> = bindings
            .iter()
            .map(|binding| PoolTarget {
                pool: binding.pool,
                incarnation: binding.incarnation,
            })
            .collect();
        let stale: Vec<_> = self
            .pools
            .targets()
            .filter(|target| !desired.contains(target))
            .collect();
        for target in stale {
            self.pools.remove(&mut self.sockets, target)?;
        }
        for target in desired {
            if self.pools.upsert(&mut self.sockets, target)? {
                let listener = self
                    .sockets
                    .listener(
                        self.pools
                            .path(target)
                            .ok_or_else(|| io::Error::other("pool endpoint path missing"))?,
                    )
                    .ok_or_else(|| io::Error::other("pool endpoint listener missing"))?
                    .try_clone()?;
                let subscription = self
                    .pools
                    .subscription(target)
                    .ok_or_else(|| io::Error::other("pool subscription missing"))?
                    .clone();
                std::thread::Builder::new()
                    .name(format!("kes-pool-{}", target.pool))
                    .spawn(move || serve_pool(listener, subscription))
                    .map_err(Error::Io)?;
            }
        }
        Ok(())
    }
    fn stop_all(&self) {
        for target in self.pools.targets() {
            if let Some(subscription) = self.pools.subscription(target) {
                subscription.stop();
            }
        }
    }
}

/// Opens durable state, owns the configured sockets while the selected device
/// is absent, and permits USB use only after the configured identity verifies.
pub fn serve(config: Config) -> Result<(), Error> {
    memory::protect_process()?;
    install_shutdown_handlers()?;
    serve_until(config, Arc::new(AtomicBool::new(false)))
}

fn serve_until(config: Config, shutdown: Arc<AtomicBool>) -> Result<(), Error> {
    let journal_path = config.state_directory.join("operations.journal");
    let journal = Journal::open(&journal_path)?;
    let mode = match (config.mode, config.pin) {
        (RunMode::Commissioning, _) => Mode::Commissioning {
            selected_serial: config.selected_serial,
        },
        (RunMode::Normal, Some(pin)) => Mode::Normal { pin },
        (RunMode::Normal, None) => return Err(Error::Usb(usb::Error::IdentityMismatch)),
    };
    let pending = journal.pending().map(|pending| {
        (
            pending.key.sequence,
            Digest32::from_bytes(pending.key.request_digest),
        )
    });
    // Absence is a recoverable startup state. Any device that is present must
    // pass the configured pin before the transport becomes usable.
    let usb = RuntimeTransport::connect(mode, MANAGEMENT_TIMEOUT, pending)?;
    let sockets = SocketRegistry::bind(&config)?;
    let management = sockets
        .listener(&config.management_socket)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "management listener missing"))?
        .try_clone()?;
    management.set_nonblocking(true)?;
    let mut endpoints = LiveEndpoints::new(sockets, &config);
    endpoints.reconcile(&config.pools)?;
    let mut pools = Vec::with_capacity(config.pools.len());
    for pool in &config.pools {
        let target = PoolTarget {
            pool: pool.pool,
            incarnation: pool.incarnation,
        };
        let subscription = endpoints
            .pools
            .subscription(target)
            .ok_or_else(|| io::Error::other("configured pool subscription missing"))?
            .clone();
        pools.push((pool.clone(), subscription));
    }
    let endpoints = Arc::new(Mutex::new(endpoints));
    let config = Arc::new(config);
    let state = Arc::new(Mutex::new(DeviceState { journal, usb }));

    let poller = if config.mode == RunMode::Normal && !pools.is_empty() {
        let provider = ContextProvider::new(SystemClock, config.networks.clone())?;
        let poll_state = Arc::clone(&state);
        let poll_config = Arc::clone(&config);
        let poll_shutdown = Arc::clone(&shutdown);
        Some(
            std::thread::Builder::new()
                .name("kes-device-poller".to_owned())
                .spawn(move || {
                    poll_pools(&poll_state, &poll_config, provider, &pools, &poll_shutdown)
                })
                .map_err(Error::Io)?,
        )
    } else {
        None
    };
    let active_management = Arc::new(AtomicUsize::new(0));

    while !shutting_down(&shutdown) {
        match management.accept() {
            Ok((mut stream, _)) => {
                if active_management
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        (active < MAX_MANAGEMENT_CONNECTIONS).then_some(active + 1)
                    })
                    .is_err()
                {
                    let _ = stream.set_write_timeout(Some(MANAGEMENT_TIMEOUT));
                    let response = error_response(None, &management::Error::Usb(usb::Error::Busy));
                    let _ = write_frame(&mut stream, &response);
                    continue;
                }
                let guard = ManagementConnectionGuard {
                    active: Arc::clone(&active_management),
                };
                let config = Arc::clone(&config);
                let state = Arc::clone(&state);
                let endpoints = Arc::clone(&endpoints);
                std::thread::Builder::new()
                    .name("kes-management".to_owned())
                    .spawn(move || {
                        let _guard = guard;
                        if let Err(error) =
                            serve_management(&config, &state, &endpoints, &mut stream)
                        {
                            let _ = writeln!(io::stderr(), "management connection: {error}");
                        }
                    })
                    .map_err(Error::Io)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep_until_shutdown(&shutdown, Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }

    shutdown.store(true, Ordering::Release);
    endpoints
        .lock()
        .map_err(|_| io::Error::other("endpoint registry mutex poisoned"))?
        .stop_all();
    if let Some(poller) = poller {
        poller
            .join()
            .map_err(|_| io::Error::other("device poller panicked"))?;
    }
    Ok(())
}

fn serve_pool(listener: UnixListener, subscription: PoolSubscription) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !subscription.is_stopped() {
        match listener.accept() {
            Ok((stream, _)) => {
                let Ok(permit) = subscription.reserve() else {
                    drop(stream);
                    continue;
                };
                let service = subscription.clone();
                let _ = std::thread::Builder::new()
                    .name("kes-node-client".to_owned())
                    .spawn(move || {
                        let _ = service.serve_reserved(stream, permit);
                    });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return,
        }
    }
}

fn serve_management(
    config: &Config,
    state: &Mutex<DeviceState>,
    endpoints: &Mutex<LiveEndpoints>,
    stream: &mut UnixStream,
) -> io::Result<()> {
    stream.set_read_timeout(Some(MANAGEMENT_TIMEOUT))?;
    stream.set_write_timeout(Some(MANAGEMENT_TIMEOUT))?;
    let request = read_frame(stream)?;
    let request_id = request_id(&request);
    let (response, bindings) = {
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("device state mutex poisoned"))?;
        let DeviceState { journal, usb } = &mut *state;
        let mut management = Management::new(config, journal, usb);
        match management.dispatch(&request) {
            Ok(response) => {
                let bindings = management
                    .reconstructed_registry()
                    .map_err(|_| io::Error::other("failed to reconstruct durable pool registry"))?;
                (response, Some(bindings))
            }
            Err(error) => (error_response(request_id.as_deref(), &error), None),
        }
    };
    if let Some(bindings) = bindings {
        endpoints
            .lock()
            .map_err(|_| io::Error::other("endpoint registry mutex poisoned"))?
            .reconcile(&bindings)
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
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
        management::Error::ArtifactRetired => (
            "rejected",
            "artifact_retired",
            "device-side artifact retrieval ended when the generation retired; external copies are unaffected",
            None,
        ),
        management::Error::GenerationUnknown => (
            "rejected",
            "generation_mismatch",
            "generation was not created for the requested pool incarnation",
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
    use crate::daemon::usb::{DeviceTransport, Reply};
    use kes_core::{
        identity::{IncarnationId, NetworkBinding, PoolId},
        operation::PoolTarget,
    };
    use kes_protocol::{
        management::{Kind, Message, Outcome},
        node_service::DIRECT_CERTIFICATE_BYTES,
        usb::{
            self as wire, CurrentResponse, CurrentResult, Publication, PublicationKind, Response,
        },
    };
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Seen {
        Context {
            target: PoolTarget,
            period: u64,
            session: u64,
            sequence: u64,
        },
        Current(PoolTarget),
    }

    struct FakeTransport {
        replies: VecDeque<Reply>,
        seen: Vec<Seen>,
    }

    impl DeviceTransport for FakeTransport {
        fn request(&mut self, request: &wire::Request) -> Result<Reply, usb::Error> {
            self.seen.push(match request {
                wire::Request::Context {
                    target,
                    period,
                    session,
                    sequence,
                    ..
                } => Seen::Context {
                    target: *target,
                    period: *period,
                    session: *session,
                    sequence: *sequence,
                },
                wire::Request::Current { target } => Seen::Current(*target),
                _ => panic!("unexpected request"),
            });
            self.replies.pop_front().ok_or(usb::Error::Protocol)
        }

        fn clear_outstanding(
            &mut self,
            _sequence: u64,
            _digest: Digest32,
        ) -> Result<(), usb::Error> {
            Ok(())
        }
    }

    fn target() -> PoolTarget {
        PoolTarget {
            pool: PoolId::from_bytes([1; 28]),
            incarnation: IncarnationId::from_bytes([2; 16]),
        }
    }

    fn context() -> crate::daemon::context::TargetContext {
        crate::daemon::context::TargetContext {
            target: target(),
            network: NetworkBinding::new(Digest32::from_bytes([3; 32]), 42, 100, 64).unwrap(),
            period: 7,
            session: 11,
            sequence: 13,
            lease_seconds: 30,
            publication_time_us: 17,
        }
    }

    fn reply(response: &Response<'_>) -> Reply {
        let mut output = [0; wire::MAX_PAYLOAD];
        let (kind, length) = wire::encode_response(response, &mut output).unwrap();
        Reply::from_parts(kind, output[..length].to_vec())
    }

    #[test]
    fn polling_commits_context_before_forwarding_exact_device_publication() {
        let target = target();
        let state = [5; 608];
        let certificate = [6; DIRECT_CERTIFICATE_BYTES];
        let certificate_digest = Digest32::from_bytes(Sha256::digest(certificate).into());
        let publication = Publication {
            revision: 19,
            timestamp_us: 23,
            high_water_us: 23,
            kind: PublicationKind::Key {
                generation: kes_core::identity::GenerationId::from_bytes([4; 16]),
                period: 7,
                certificate_digest,
            },
        };
        let mut transport = FakeTransport {
            replies: VecDeque::from([
                reply(&Response::Context(wire::ContextResponse {
                    target,
                    session: 11,
                    sequence: 13,
                    floor: 7,
                    result: Ok(()),
                })),
                reply(&Response::Current(CurrentResponse {
                    target,
                    snapshot_revision: 21,
                    publication,
                    result: CurrentResult::Key {
                        generation: kes_core::identity::GenerationId::from_bytes([4; 16]),
                        period: 7,
                        state: &state,
                        certificate: &certificate,
                    },
                })),
            ]),
            seen: Vec::new(),
        };

        let update = poll_target(&mut transport, context()).unwrap().unwrap();

        assert_eq!(
            transport.seen,
            [
                Seen::Context {
                    target,
                    period: 7,
                    session: 11,
                    sequence: 13,
                },
                Seen::Current(target),
            ]
        );
        assert_eq!(update.target, target);
        assert_eq!(update.revision, 19);
        assert_eq!(update.timestamp_us, 23);
        let crate::daemon::node_service::PublicationKind::Key {
            generation,
            relative_period,
            certificate_digest: actual_digest,
            state: actual_state,
            certificate: actual_certificate,
        } = update.kind
        else {
            panic!("expected key publication");
        };
        assert_eq!(generation.as_bytes(), &[4; 16]);
        assert_eq!(relative_period, 7);
        assert_eq!(actual_digest, certificate_digest);
        assert_eq!(actual_state.as_slice(), state);
        assert_eq!(actual_certificate, certificate);
    }

    #[test]
    fn rejected_context_withholds_current_polling() {
        let target = target();
        let mut transport = FakeTransport {
            replies: VecDeque::from([reply(&Response::Context(wire::ContextResponse {
                target,
                session: 11,
                sequence: 13,
                floor: 6,
                result: Err(9),
            }))]),
            seen: Vec::new(),
        };

        assert!(poll_target(&mut transport, context()).unwrap().is_none());
        assert_eq!(
            transport.seen,
            [Seen::Context {
                target,
                period: 7,
                session: 11,
                sequence: 13,
            }]
        );
    }
    #[test]
    fn temporary_device_unavailability_never_becomes_a_drop_publication() {
        let target = target();
        let publication = Publication {
            revision: 0,
            timestamp_us: 0,
            high_water_us: 0,
            kind: PublicationKind::Drop,
        };
        let mut transport = FakeTransport {
            replies: VecDeque::from([
                reply(&Response::Context(wire::ContextResponse {
                    target,
                    session: 11,
                    sequence: 13,
                    floor: 7,
                    result: Ok(()),
                })),
                reply(&Response::Current(CurrentResponse {
                    target,
                    snapshot_revision: 0,
                    publication,
                    result: CurrentResult::Unavailable { code: 105 },
                })),
            ]),
            seen: Vec::new(),
        };

        assert!(poll_target(&mut transport, context()).unwrap().is_none());
        assert_eq!(
            transport.seen,
            [
                Seen::Context {
                    target,
                    period: 7,
                    session: 11,
                    sequence: 13,
                },
                Seen::Current(target),
            ]
        );
    }

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
