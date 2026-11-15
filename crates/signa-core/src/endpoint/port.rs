/*!
Ports that several endpoints share, and what the application decides about
their datagrams.

[`DatagramPort`] states the contract. Inside, the port's task owns the backend
through a `Port` with no limits of its own, since the shared write budget
admits every write before it reaches the task. Each registered endpoint drives
a `Proxy` as its backend, so its driver and its own `Port` work as over any
backend, and the application delivers to it straight into the proxy's queue,
past the port's task.
*/

use std::{
    collections::HashMap,
    fmt,
    future::{Future, poll_fn},
    io, mem,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::{Instant, sleep_until},
};

use super::{
    BindError, Error, ShutdownOutcome,
    datagram::Port,
    driver::{ABANDONED_FLUSH, ReceptionCounters, increment},
    path::{self, PathSelection},
};
use crate::{
    message::{Message, error::InvalidMessage},
    transport::{
        Flow, Transport, WriteLimits,
        budget::{Budget, Permit},
        datagram::{
            Binding, Capabilities, Datagram, DatagramIo, DatagramWrite, Owner,
            Path, RecvError, Submit, TransportContext, WriteId,
        },
        udp, unmap,
    },
};

mod writes;

pub(super) use writes::WritePermit;
use writes::{Admission, WriteAdmission};

/// How many commands or datagrams the port's task handles before it lets
/// the runtime run other tasks.
const BATCH: usize = 64;

const OPEN: u8 = 0;
const QUIESCED: u8 = 1;
const CLOSING: u8 = 2;

/// Configures and starts a [`DatagramPort`] or a [`Capture`].
///
/// # Example
///
/// A port on a socket, whose every request goes to one endpoint and every
/// response is forwarded unchanged.
///
/// ```no_run
/// use signa_core::{
///     Message,
///     endpoint::{DatagramPort, Endpoint, PathSelection},
/// };
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let (port, mut ingress) = DatagramPort::builder()
///     .udp("192.0.2.10:5060".parse()?)
///     .intercept()?;
/// let (endpoint, _incoming) = Endpoint::builder().port(&port).bind()?;
/// let to_endpoint = endpoint.ingress().expect("an endpoint on a port");
/// let upstream = port
///     .prepare_path(PathSelection::new(
///         "192.0.2.10:5060".parse()?,
///         "198.51.100.7:5060".parse()?,
///     ))
///     .await?;
///
/// while let Some(datagram) = ingress.recv().await {
///     match datagram.parse() {
///         Ok(Message::Request(_)) => {
///             let _ = datagram.try_deliver(&to_endpoint);
///         }
///         Ok(Message::Response(_)) => {
///             let _ = datagram.try_forward(&upstream);
///         }
///         Err(_) => datagram.discard(),
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct PortBuilder {
    backend: Option<Backend>,
    write_limits: WriteLimits,
    ingress_limits: WriteLimits,
    context_limits: WriteLimits,
    decision_deadline: Duration,
    delivery_queue: usize,
    max_registrations: usize,
}

enum Backend {
    Bind(SocketAddr),
    Io(Box<dyn DatagramIo>),
}

impl PortBuilder {
    fn new() -> PortBuilder {
        PortBuilder {
            backend: None,
            write_limits: WriteLimits {
                messages: 4096,
                ..WriteLimits::default()
            },
            ingress_limits: WriteLimits {
                messages: 4096,
                bytes: 16 * 1024 * 1024,
            },
            context_limits: WriteLimits {
                messages: 8192,
                bytes: 4 * 1024 * 1024,
            },
            decision_deadline: Duration::from_secs(1),
            delivery_queue: 1024,
            max_registrations: 64,
        }
    }

    /// Binds a UDP socket of the port's own to `addr`.
    ///
    /// This replaces a backend set with [`PortBuilder::udp_io`].
    pub fn udp(mut self, addr: SocketAddr) -> PortBuilder {
        self.backend = Some(Backend::Bind(addr));
        self
    }

    /// Carries the port's datagrams over `io`, as [`Builder::udp_io`] does
    /// for an endpoint.
    ///
    /// This replaces an address set with [`PortBuilder::udp`].
    ///
    /// [`Builder::udp_io`]: super::Builder::udp_io
    pub fn udp_io(mut self, io: impl DatagramIo) -> PortBuilder {
        self.backend = Some(Backend::Io(Box::new(io)));
        self
    }

    /// Bounds the writes of every endpoint on the port and its raw sends
    /// together, by count and payload bytes, from admission to completion.
    /// Raw sends take at most three quarters of them, so that endpoints keep
    /// room for their responses.
    ///
    /// The bytes must hold the backend's largest payload. The default is
    /// 4096 writes and the default bytes of [`WriteLimits`].
    pub fn write_limits(mut self, limits: WriteLimits) -> PortBuilder {
        self.write_limits = limits;
        self
    }

    /// Bounds the datagrams received and not yet disposed of, by count and
    /// payload and context bytes. A datagram over them is dropped and
    /// counted in [`PortStats::overflow`].
    ///
    /// The port copies each datagram's context, but not its payload, which
    /// shares the backend's buffer. A backend that slices payloads out of a
    /// large buffer keeps that buffer alive with them.
    ///
    /// The default is 4096 datagrams and 16 MiB.
    pub fn ingress_limits(mut self, limits: WriteLimits) -> PortBuilder {
        self.ingress_limits = limits;
        self
    }

    /// Bounds the raw paths alive at once, by count and the bytes they keep,
    /// as [`Builder::context_limits`] does for an endpoint's paths.
    ///
    /// The default is 8192 paths and 4 MiB.
    ///
    /// [`Builder::context_limits`]: super::Builder::context_limits
    pub fn context_limits(mut self, limits: WriteLimits) -> PortBuilder {
        self.context_limits = limits;
        self
    }

    /// How long after its receipt a datagram can still be delivered or
    /// forwarded.
    ///
    /// It is a bound on the application's decision, not a protocol timer,
    /// and the one second default is my choice. A retransmission comes
    /// after T1 (500 ms) at the earliest and is a datagram of its own.
    pub fn decision_deadline(mut self, deadline: Duration) -> PortBuilder {
        self.decision_deadline = deadline;
        self
    }

    /// How many delivered datagrams may wait for each endpoint's driver.
    /// [`ReceivedDatagram::try_deliver`] refuses one more with
    /// [`Error::is_busy`].
    ///
    /// The default is 1024.
    pub fn delivery_queue(mut self, datagrams: usize) -> PortBuilder {
        self.delivery_queue = datagrams;
        self
    }

    /// How many endpoints may be registered on the port at once.
    ///
    /// The default is 64.
    pub fn max_registrations(mut self, endpoints: usize) -> PortBuilder {
        self.max_registrations = endpoints;
        self
    }

    /// Starts the port's task and returns the port and its one [`Ingress`].
    ///
    /// Must be called within a tokio runtime.
    ///
    /// # Errors
    ///
    /// * [`BindError::is_invalid_config`] without a backend, with a zero
    ///   limit, deadline or queue, or with a backend that names no specific
    ///   address or sends no payload.
    /// * [`BindError::is_io`] when the socket cannot be bound.
    pub fn intercept(self) -> Result<(DatagramPort, Ingress), BindError> {
        for (reason, value) in [
            (
                "write_limits.messages must be positive",
                self.write_limits.messages,
            ),
            ("write_limits.bytes must be positive", self.write_limits.bytes),
            (
                "ingress_limits.messages must be positive",
                self.ingress_limits.messages,
            ),
            (
                "ingress_limits.bytes must be positive",
                self.ingress_limits.bytes,
            ),
            (
                "context_limits.messages must be positive",
                self.context_limits.messages,
            ),
            (
                "context_limits.bytes must be positive",
                self.context_limits.bytes,
            ),
            ("delivery_queue must be positive", self.delivery_queue),
            ("max_registrations must be positive", self.max_registrations),
        ] {
            if value == 0 {
                return Err(BindError::invalid_config(reason));
            }
        }
        if self.decision_deadline.is_zero() {
            return Err(BindError::invalid_config(
                "decision_deadline must be positive",
            ));
        }
        let io = open(self.backend)?;
        let local = io.local_addr();
        let capabilities = io.capabilities();
        // An endpoint's write waits for room in the port's limits, so one
        // larger than the byte limit would wait forever.
        if self.write_limits.bytes < capabilities.max_payload {
            return Err(BindError::invalid_config(
                "write_limits.bytes must hold the backend's largest payload",
            ));
        }

        let reception = Arc::<ReceptionCounters>::default();
        let port = Port::new(
            io,
            WriteLimits { messages: usize::MAX, bytes: usize::MAX },
            reception.clone(),
        );
        let shared = Arc::new(Shared {
            id: path::next_id(),
            local,
            capabilities,
            deadline: self.decision_deadline,
            delivery_queue: self.delivery_queue,
            max_registrations: self.max_registrations,
            phase: AtomicU8::new(OPEN),
            lifecycle: Mutex::new(0),
            writes: WriteAdmission::new(self.write_limits),
            ingress: Budget::new(self.ingress_limits),
            context_limits: Budget::new(self.context_limits),
            stats: Counters::default(),
            reception,
            done: watch::channel(None).0,
        });
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (ingress, ingress_rx) = mpsc::unbounded_channel();
        let task = PortTask {
            port,
            shared: shared.clone(),
            commands: commands_rx,
            weak: commands.downgrade(),
            ingress: Some(ingress),
            registrations: HashMap::new(),
        };
        tokio::spawn(task.run());

        Ok((
            DatagramPort { shared, commands },
            Ingress { receiver: ingress_rx },
        ))
    }

    /// Opens the backend for passive capture, which only receives.
    ///
    /// No task starts. [`Capture::recv`] polls the backend in the caller's
    /// task, and nothing is buffered beyond what the backend holds. The
    /// limits, deadline and queue settings do not apply.
    ///
    /// # Errors
    ///
    /// As for [`PortBuilder::intercept`], for the backend.
    pub fn capture(self) -> Result<Capture, BindError> {
        let io = open(self.backend)?;
        Ok(Capture { io, reception: Arc::default(), closed: false })
    }
}

impl fmt::Debug for PortBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = match &self.backend {
            None => "none".to_owned(),
            Some(Backend::Bind(addr)) => addr.to_string(),
            Some(Backend::Io(io)) => format!("backend at {}", io.local_addr()),
        };
        f.debug_struct("PortBuilder")
            .field("backend", &backend)
            .field("write_limits", &self.write_limits)
            .field("ingress_limits", &self.ingress_limits)
            .field("context_limits", &self.context_limits)
            .field("decision_deadline", &self.decision_deadline)
            .field("delivery_queue", &self.delivery_queue)
            .field("max_registrations", &self.max_registrations)
            .finish()
    }
}

/// Opens a builder's backend, with the checks an endpoint's builder makes.
fn open(backend: Option<Backend>) -> Result<Box<dyn DatagramIo>, BindError> {
    match backend {
        None => {
            Err(BindError::invalid_config("a port needs `udp` or `udp_io`"))
        }
        Some(Backend::Bind(addr)) => udp::Socket::bind(addr)
            .map(|socket| {
                Box::new(udp::Io::new(socket)) as Box<dyn DatagramIo>
            })
            .map_err(BindError::io),
        Some(Backend::Io(io)) => {
            let local = io.local_addr();
            if local.ip().is_unspecified() || local.port() == 0 {
                return Err(BindError::invalid_config(
                    "a UDP backend needs a specified local address and port",
                ));
            }
            if io.capabilities().max_payload == 0 {
                return Err(BindError::invalid_config(
                    "a UDP backend must send a payload of at least one byte",
                ));
            }
            Ok(io)
        }
    }
}

/// A UDP port that several endpoints share, with the application deciding what
/// becomes of each datagram before any endpoint sees it.
///
/// An endpoint built with [`Builder::udp`] or [`Builder::udp_io`] owns its
/// socket or backend, and its driver polls it. A `DatagramPort` owns one
/// backend for many. [`PortBuilder::intercept`] starts a task of its own that
/// alone polls the backend, and hands every datagram it receives to the
/// application through [`Ingress`]. Each [`ReceivedDatagram`] is the original
/// payload with how it arrived and one disposition:
///
/// * [`ReceivedDatagram::try_deliver`] gives it to one endpoint registered on
///   the port, which receives it as it would from its own socket: parsed, with
///   `received` and `rport`, matched to its transactions and answered as usual.
/// * [`ReceivedDatagram::try_forward`] sends the payload once along a
///   [`RawPath`], unchanged, with no SIP processing at all.
/// * [`ReceivedDatagram::discard`], or dropping it, drops it.
///
/// [`PortBuilder::capture`] makes a receive-only [`Capture`] instead, which can
/// neither deliver nor send.
///
/// # Endpoints on a port
///
/// [`Builder::port`] registers an endpoint on the port. Each registration has
/// its own transactions, reception policy and paths, so endpoints for network
/// domains whose addresses overlap stay apart. A path one endpoint prepared, or
/// a [`RawPath`] of the port, is refused by every other endpoint
/// ([`Error::is_stale_path`]). The endpoint's writes go through the port's
/// task, which numbers them in one sequence with the raw sends, and their
/// outcomes come back to the endpoint that made them.
///
/// A datagram reaches an endpoint through two queues, the port's ingress and
/// the endpoint's, with the application deciding in between. An endpoint's
/// write takes one hop to the port's task, and its outcome one hop back. An
/// endpoint with a socket of its own takes neither, and nothing here touches
/// it.
///
/// # Limits
///
/// The port bounds what it holds for the application and what it writes:
///
/// * [`PortBuilder::ingress_limits`] counts the datagrams between receipt and
///   disposition, with their payload and context bytes. A datagram that finds
///   it full is dropped and counted in [`PortStats::overflow`]. An application
///   that holds datagrams, or reads them slowly, loses traffic. ACK and CANCEL
///   progress is the endpoint's to guarantee once a datagram reaches it, not
///   the port's.
/// * [`PortBuilder::decision_deadline`] bounds how long a datagram can wait for
///   its disposition. After it the datagram can no longer be delivered or
///   forwarded. It still counts against the ingress limits until it is dropped,
///   since the application holds its bytes.
/// * [`PortBuilder::write_limits`] bounds the writes of every endpoint and raw
///   send together, from admission to completion. An endpoint's own
///   [`Builder::udp_write_limits`] bounds its share. An endpoint that finds the
///   port's limits full waits. A raw send is refused once three quarters of
///   them are taken, so that endpoints keep room for their responses.
///
/// The endpoints waiting for room are woken together as it frees up, and race
/// for it. The limits bound how much they contend for, but the port promises
/// no endpoint a share of them or a bound on its wait, and the quarter that
/// raw sends leave is the endpoints' together, not each one's.
///
/// # Shutdown
///
/// Stopping takes three steps, in this order:
///
/// 1. [`DatagramPort::quiesce`] refuses new endpoints and new raw paths.
///    Reception, delivery and every write go on, so that registered endpoints
///    can finish their work, ACKs and late 2xx included.
/// 2. [`Endpoint::shutdown`] drains one endpoint and ends its registration. The
///    others go on. At its deadline the port drops the endpoint's writes it
///    still queues. A write the backend already took cannot be taken back and
///    may still go out after the endpoint has stopped.
/// 3. [`DatagramPort::close`] stops reception, invalidates the datagrams the
///    application still holds and every path of the port, refuses new writes
///    and drains the rest, then closes the backend, as [`Endpoint::shutdown`]
///    closes its own. An endpoint still registered sees its writes fail.
///
/// That no backend task sends after the close rests on the backend, whose
/// `Drop` must stop what `poll_close` would have stopped. The port cannot join
/// a task it does not own. Dropping every [`DatagramPort`] and stopping every
/// endpoint on it closes the port with five seconds to write what is queued.
///
/// [`Builder::udp`]: super::Builder::udp
/// [`Builder::udp_io`]: super::Builder::udp_io
/// [`Builder::port`]: super::Builder::port
/// [`Builder::udp_write_limits`]: super::Builder::udp_write_limits
/// [`Endpoint::shutdown`]: super::Endpoint::shutdown
///
/// Clones are handles to one port. Its task runs while a handle or a registered
/// endpoint is left, or until [`DatagramPort::close`] finishes.
#[derive(Clone)]
pub struct DatagramPort {
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
}

/// What the port's handles and its task share.
struct Shared {
    /// Names the port to its capabilities, see [`Binding`].
    id: u64,
    local: SocketAddr,
    capabilities: Capabilities,
    deadline: Duration,
    delivery_queue: usize,
    max_registrations: usize,
    /// `OPEN`, `QUIESCED` or `CLOSING`. Changed only under `lifecycle`.
    phase: AtomicU8,
    /// The registered endpoints. A registration checks the phase and joins
    /// under this lock, so that none slips past a quiesce or a close.
    lifecycle: Mutex<usize>,
    /// The port-wide write limits, which endpoints and raw sends share, with
    /// the endpoints waiting for room in them.
    writes: WriteAdmission,
    ingress: Budget,
    context_limits: Budget,
    stats: Counters,
    reception: Arc<ReceptionCounters>,
    done: watch::Sender<Option<ShutdownOutcome>>,
}

impl Shared {
    fn phase(&self) -> u8 {
        self.phase.load(Ordering::Acquire)
    }

    fn closing(&self) -> bool {
        self.phase() == CLOSING
    }

    /// Moves the port on to `phase`, never back. Closing also closes the
    /// write limits, which wakes the endpoints waiting for room.
    fn set_phase(&self, phase: u8) {
        {
            let _lifecycle = self.lifecycle.lock().expect("not poisoned");
            if self.phase() < phase {
                self.phase.store(phase, Ordering::Release);
            }
        }
        if phase == CLOSING {
            self.writes.close();
        }
    }
}

#[derive(Default)]
struct Counters {
    received: AtomicU64,
    delivered: AtomicU64,
    forwarded: AtomicU64,
    discarded: AtomicU64,
    abandoned: AtomicU64,
    expired: AtomicU64,
    overflow: AtomicU64,
}

/// What the port's handles ask of its task.
enum Command {
    Register {
        registration: u64,
        completions: mpsc::UnboundedSender<(WriteId, io::Result<()>)>,
    },
    Unregister {
        registration: u64,
        done: oneshot::Sender<()>,
    },
    Write {
        registration: u64,
        write: DatagramWrite,
        permit: WritePermit,
    },
    Raw {
        payload: Bytes,
        path: Arc<Path>,
        done: oneshot::Sender<io::Result<()>>,
        permit: WritePermit,
    },
    CheckPath {
        path: Path,
        done: oneshot::Sender<Result<Path, Error>>,
    },
    Close {
        deadline: Instant,
    },
}

/// Counts of what became of the port's datagrams.
///
/// Each datagram is counted once in `received`, then once in exactly one of
/// the others when it ends, apart from those still held. Counters saturate at
/// `u64::MAX`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct PortStats {
    /// Datagrams the backend delivered whole.
    pub received: u64,
    /// Datagrams an endpoint took.
    pub delivered: u64,
    /// Datagrams forwarded along a raw path.
    pub forwarded: u64,
    /// Datagrams the application discarded before their deadline.
    pub discarded: u64,
    /// Datagrams dropped without a disposition before their deadline,
    /// including those received while no [`Ingress`] was left to take them.
    pub abandoned: u64,
    /// Datagrams that ended undelivered after their deadline.
    pub expired: u64,
    /// Datagrams dropped on receipt because [`PortBuilder::ingress_limits`]
    /// was full.
    pub overflow: u64,
    /// Datagrams the backend reported truncated.
    pub truncated_datagrams: u64,
    /// Errors the backend returned instead of a datagram.
    pub receive_errors: u64,
}

impl DatagramPort {
    /// Returns a builder for a port.
    pub fn builder() -> PortBuilder {
        PortBuilder::new()
    }

    /// The address the backend names as its own.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local
    }

    /// What the backend can do.
    pub fn capabilities(&self) -> Capabilities {
        self.shared.capabilities
    }

    /// Returns the counts of what became of the port's datagrams.
    pub fn stats(&self) -> PortStats {
        let stats = &self.shared.stats;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        PortStats {
            received: load(&stats.received),
            delivered: load(&stats.delivered),
            forwarded: load(&stats.forwarded),
            discarded: load(&stats.discarded),
            abandoned: load(&stats.abandoned),
            expired: load(&stats.expired),
            overflow: load(&stats.overflow),
            truncated_datagrams: load(
                &self.shared.reception.truncated_datagrams,
            ),
            receive_errors: load(&self.shared.reception.receive_errors),
        }
    }

    /// Prepares a path for raw sends from `selection`, once the backend
    /// accepts it.
    ///
    /// The path belongs to the port, not to an endpoint, so every endpoint
    /// refuses it. It counts against [`PortBuilder::context_limits`] until
    /// its last clone drops.
    ///
    /// # Cancellation
    ///
    /// Dropping the future discards the path. Preparing has no effect on the
    /// wire.
    ///
    /// # Errors
    ///
    /// * [`Error::is_path_refused`] when the backend refuses the path, or an
    ///   address is unspecified, multicast or broadcast or has port 0.
    /// * [`Error::is_busy`] when the context limits are full.
    /// * [`Error::is_closed`] once the port is quiesced or closing.
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn prepare_path(
        &self,
        selection: PathSelection,
    ) -> impl Future<Output = Result<RawPath, Error>> + Send + '_ {
        async move {
            if self.shared.phase() != OPEN {
                return Err(Error::closed());
            }
            let binding = Binding { port: self.shared.id, owner: Owner::Port };
            let path = path::unchecked(
                selection,
                binding,
                &self.shared.context_limits,
            )?;
            let path = check_path(&self.commands, path).await?;
            if self.shared.closing() {
                return Err(Error::closed());
            }
            Ok(RawPath(Arc::new(path)))
        }
    }

    /// Sends `payload` once along `path`, unchanged.
    ///
    /// Nothing about SIP applies. The payload need not parse, its Via is not
    /// touched, nothing retransmits it, and no response is generated or
    /// expected. The only size limit is the backend's
    /// [`max_payload`](Capabilities::max_payload), with no 1300-byte rule.
    ///
    /// # Commit point
    ///
    /// The send is committed when this returns `Ok`. The returned [`RawWrite`]
    /// resolves with its local outcome, and dropping it does not take the
    /// send back.
    ///
    /// # Errors
    ///
    /// * [`Error::is_stale_path`] for a path of another port.
    /// * [`Error::is_too_large`] for a payload over the backend's maximum.
    /// * [`Error::is_busy`] when [`PortBuilder::write_limits`] is full.
    /// * [`Error::is_closed`] once the port is closing.
    pub fn send_bytes(
        &self,
        payload: Bytes,
        path: &RawPath,
    ) -> Result<RawWrite, Error> {
        submit_raw(&self.shared, &self.commands, payload, path)
    }

    /// Refuses new endpoints and new raw paths from now on.
    ///
    /// Everything already admitted goes on: reception, delivery, the writes
    /// of registered endpoints, raw sends on existing paths and the paths
    /// those endpoints prepare. It is the first step of stopping, which the
    /// [`DatagramPort`] docs describe.
    pub fn quiesce(&self) {
        self.shared.set_phase(QUIESCED);
    }

    /// Closes the port, with `timeout` to drain its writes, and resolves with
    /// the outcome once the backend has closed.
    ///
    /// Reception stops, the datagrams the application holds and every path
    /// of the port turn invalid, and new writes are refused at once. The
    /// writes already admitted get until the deadline. At the deadline the
    /// rest fail, and the backend gets one more poll to close before it is
    /// dropped. Closing does not wait for registered endpoints, which see
    /// their writes fail. Stop them first.
    ///
    /// Another call can bring the deadline forward. Every caller gets the
    /// same outcome.
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn close(
        &self,
        timeout: Duration,
    ) -> impl Future<Output = ShutdownOutcome> + Send + 'static {
        let deadline = Instant::now() + timeout;
        self.shared.set_phase(CLOSING);
        let _ = self.commands.send(Command::Close { deadline });
        let mut done = self.shared.done.subscribe();
        async move {
            match done.wait_for(Option::is_some).await {
                Ok(outcome) => outcome.expect("waited for one"),
                // The task ended without an outcome only if it was dropped
                // with its runtime.
                Err(_) => ShutdownOutcome::DeadlineExpired,
            }
        }
    }

    /// Registers an endpoint, for [`Builder::bind`](super::Builder::bind).
    pub(super) fn register(&self) -> Result<Registration, BindError> {
        let registration = path::next_id();
        let (completions, completions_rx) = mpsc::unbounded_channel();
        {
            let mut registrations =
                self.shared.lifecycle.lock().expect("not poisoned");
            if self.shared.phase() != OPEN {
                return Err(BindError::port_closed());
            }
            if *registrations >= self.shared.max_registrations {
                return Err(BindError::port_full());
            }
            self.commands
                .send(Command::Register { registration, completions })
                .map_err(|_| BindError::port_closed())?;
            *registrations += 1;
        }

        let (deliveries, deliveries_rx) =
            mpsc::channel(self.shared.delivery_queue);
        let state = Arc::new(RegistrationState::default());
        let proxy = Proxy {
            registration,
            shared: self.shared.clone(),
            commands: self.commands.clone(),
            deliveries: deliveries_rx,
            completions: completions_rx,
            state: state.clone(),
            unregistering: None,
        };
        Ok(Registration {
            io: Box::new(proxy),
            binding: Binding {
                port: self.shared.id,
                owner: Owner::Endpoint(registration),
            },
            registration,
            ingress: EndpointIngress { port: self.shared.id, deliveries },
            client: PortClient {
                shared: self.shared.clone(),
                commands: self.commands.downgrade(),
                state,
            },
        })
    }
}

impl fmt::Debug for DatagramPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramPort")
            .field("local_addr", &self.shared.local)
            .field("closing", &self.shared.closing())
            .finish()
    }
}

/// Asks the port's task to have the backend check `path`.
async fn check_path(
    commands: &mpsc::UnboundedSender<Command>,
    path: Path,
) -> Result<Path, Error> {
    let (done, result) = oneshot::channel();
    commands
        .send(Command::CheckPath { path, done })
        .map_err(|_| Error::closed())?;
    result.await.map_err(|_| Error::closed())?
}

/// Admits a raw send and hands it to the port's task.
fn submit_raw(
    shared: &Shared,
    commands: &mpsc::UnboundedSender<Command>,
    payload: Bytes,
    path: &RawPath,
) -> Result<RawWrite, Error> {
    if path.binding().port != shared.id {
        return Err(Error::stale_path());
    }
    if shared.closing() {
        return Err(Error::closed());
    }
    let len = payload.len();
    let max = shared.capabilities.max_payload;
    if len > max {
        return Err(Error::over_payload(len, max));
    }
    // A raw send leaves a quarter of the limits to the endpoints' writes, so
    // that a busy forwarder cannot hold back their responses and
    // retransmissions. This is my policy, as the endpoint's own reserve for
    // transaction output is.
    let permit = match shared.writes.admit_raw(len) {
        Admission::Admitted(permit) => permit,
        Admission::Full => return Err(Error::busy()),
        Admission::Closed => return Err(Error::closed()),
    };

    let (done, receipt) = oneshot::channel();
    commands
        .send(Command::Raw { payload, path: path.0.clone(), done, permit })
        .map_err(|_| Error::closed())?;
    Ok(RawWrite(receipt))
}

/// What an endpoint gets from registering on a port.
pub(super) struct Registration {
    /// The backend the endpoint's driver uses, which passes through the
    /// port's task.
    pub(super) io: Box<dyn DatagramIo>,
    pub(super) binding: Binding,
    pub(super) registration: u64,
    pub(super) ingress: EndpointIngress,
    pub(super) client: PortClient,
}

/// What an endpoint keeps of its port, to prepare paths on it.
///
/// It holds the port's commands weakly, so that an endpoint handle left
/// after its endpoint stopped does not keep the port's task running.
#[derive(Clone)]
pub(super) struct PortClient {
    shared: Arc<Shared>,
    commands: mpsc::WeakUnboundedSender<Command>,
    state: Arc<RegistrationState>,
}

#[derive(Default)]
struct RegistrationState {
    /// Set once the endpoint's driver has started to close its backend.
    closed: AtomicBool,
}

impl PortClient {
    /// Has the backend check `path` for the endpoint, and refuses it if the
    /// endpoint stopped or the port started closing meanwhile.
    pub(super) async fn check_path(
        &self,
        path: Path,
    ) -> Result<Arc<Path>, Error> {
        let commands = self.commands.upgrade().ok_or_else(Error::closed)?;
        let path = check_path(&commands, path).await?;
        if self.state.closed.load(Ordering::Acquire) || self.shared.closing() {
            return Err(Error::closed());
        }
        Ok(Arc::new(path))
    }
}

/// The backend an endpoint on a port drives, which passes its writes to the
/// port's task and receives what the application delivers to it.
///
/// The endpoint's own `Port` keeps its writes and limits as for any backend.
/// The proxy adds one step to each write: admission to the port's limits,
/// then a command to the port's task, which offers it to the real backend
/// under an ID of its own and sends the outcome back by the endpoint's ID.
/// An accepted write here is only admitted, not written.
struct Proxy {
    registration: u64,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
    deliveries: mpsc::Receiver<ReceivedDatagram>,
    completions: mpsc::UnboundedReceiver<(WriteId, io::Result<()>)>,
    state: Arc<RegistrationState>,
    unregistering: Option<oneshot::Receiver<()>>,
}

fn closing_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "the port is closing")
}

impl DatagramIo for Proxy {
    fn local_addr(&self) -> SocketAddr {
        self.shared.local
    }

    fn capabilities(&self) -> Capabilities {
        self.shared.capabilities
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        match ready!(self.deliveries.poll_recv(cx)) {
            Some(datagram) => {
                let (payload, flow, context) = datagram.into_delivered();
                let datagram = Datagram::new(payload, flow.remote, flow.local)
                    .with_context(context);
                Poll::Ready(Ok(datagram))
            }
            // Nothing can deliver to the endpoint any more.
            None => Poll::Pending,
        }
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        if self.shared.closing() || self.state.closed.load(Ordering::Acquire) {
            return Submit::Rejected(write, closing_error());
        }
        let len = write.payload().len();
        let permit =
            match self.shared.writes.admit(self.registration, len, cx.waker())
            {
                Admission::Admitted(permit) => permit,
                Admission::Full => return Submit::Pending(write),
                Admission::Closed => {
                    return Submit::Rejected(write, closing_error());
                }
            };
        let command =
            Command::Write { registration: self.registration, write, permit };
        match self.commands.send(command) {
            Ok(()) => Submit::Accepted,
            Err(mpsc::error::SendError(Command::Write { write, .. })) => {
                Submit::Rejected(write, closing_error())
            }
            Err(_) => unreachable!("sent a write"),
        }
    }

    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, io::Result<()>)> {
        match ready!(self.completions.poll_recv(cx)) {
            Some(completion) => Poll::Ready(completion),
            // The port's task has ended. What it never reported stays
            // unreported, and the endpoint counts it lost when it stops.
            None => Poll::Pending,
        }
    }

    // The endpoint asks the port's task through `PortClient` instead, since
    // only that task may touch the backend.
    fn check_path(
        &mut self,
        _source: SocketAddr,
        _destination: SocketAddr,
        _context: &TransportContext,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a shared port checks paths in its own task",
        ))
    }

    /// Ends the registration. The port's task fails the endpoint's writes
    /// that the backend has not taken, and the outcomes reach the endpoint
    /// before this finishes, so that it counts them as lost.
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.unregistering.is_none() {
            self.state.closed.store(true, Ordering::Release);
            self.deliveries.close();
            let (done, wait) = oneshot::channel();
            let command =
                Command::Unregister { registration: self.registration, done };
            if self.commands.send(command).is_err() {
                return Poll::Ready(());
            }
            self.unregistering = Some(wait);
        }
        let wait = self.unregistering.as_mut().expect("set above");
        let _ = ready!(Pin::new(wait).poll(cx));
        // Datagrams delivered before the close were taken, and stop with the
        // endpoint.
        while let Ok(datagram) = self.deliveries.try_recv() {
            drop(datagram.into_delivered());
        }
        Poll::Ready(())
    }
}

impl Drop for Proxy {
    // A backend dropped without closing, such as at a forced deadline, still
    // ends its registration, so that the port forgets it.
    fn drop(&mut self) {
        if self.unregistering.is_none() {
            self.state.closed.store(true, Ordering::Release);
            let (done, _) = oneshot::channel();
            let _ = self.commands.send(Command::Unregister {
                registration: self.registration,
                done,
            });
        }
        // What the queue still holds was counted as delivered, and stops
        // with the endpoint without being counted again.
        self.deliveries.close();
        while let Ok(datagram) = self.deliveries.try_recv() {
            drop(datagram.into_delivered());
        }
    }
}

/// The task that owns a port's backend.
struct PortTask {
    port: Port,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedReceiver<Command>,
    /// For the datagrams it hands out, which forward through it while it
    /// runs but do not keep it running.
    weak: mpsc::WeakUnboundedSender<Command>,
    ingress: Option<mpsc::UnboundedSender<ReceivedDatagram>>,
    /// Where each registered endpoint takes its writes' outcomes.
    registrations:
        HashMap<u64, mpsc::UnboundedSender<(WriteId, io::Result<()>)>>,
}

impl PortTask {
    async fn run(mut self) {
        let deadline = poll_fn(|cx| self.poll_serve(cx)).await;
        let outcome = self.close(deadline).await;
        self.shared.done.send_replace(Some(outcome));
    }

    /// Serves until a close or until every handle is gone, and returns the
    /// close's deadline.
    fn poll_serve(&mut self, cx: &mut Context<'_>) -> Poll<Instant> {
        // A source that stopped at its batch, rather than at `Pending`, has
        // registered no waker, so the task wakes itself for it.
        let mut more = true;
        for _ in 0..BATCH {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(Command::Close { deadline })) => {
                    return Poll::Ready(deadline);
                }
                Poll::Ready(Some(command)) => self.on_command(command),
                Poll::Ready(None) => {
                    return Poll::Ready(Instant::now() + ABANDONED_FLUSH);
                }
                Poll::Pending => {
                    more = false;
                    break;
                }
            }
        }

        // Writes the commands started were offered with a waker that does
        // nothing, as `Port` does for an endpoint's driver. Flushing leaves
        // this task's waker with the backend instead.
        self.port.poll_flush(cx);
        self.route();

        let mut received = 0;
        while received < BATCH {
            match self.port.poll_recv(cx) {
                Poll::Ready((payload, flow, context)) => {
                    self.on_datagram(payload, flow, context);
                    received += 1;
                }
                Poll::Pending => break,
            }
        }

        if more || received == BATCH {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Register { registration, completions } => {
                self.registrations.insert(registration, completions);
            }
            Command::Unregister { registration, done } => {
                self.unregister(registration);
                let _ = done.send(());
            }
            Command::Write { registration, write, permit } => {
                // The permit of a write whose endpoint has gone returns its
                // room as it drops.
                if self.registrations.contains_key(&registration) {
                    self.port.submit_routed(write, registration, permit);
                }
            }
            Command::Raw { payload, path, done, permit } => {
                self.port.submit_raw(payload, path, done, permit);
            }
            Command::CheckPath { path, done } => {
                let result = match self.port.check_path(&path) {
                    Ok(()) => Ok(path),
                    Err(error) => Err(Error::path_refused(error)),
                };
                let _ = done.send(result);
            }
            Command::Close { .. } => unreachable!("handled by the caller"),
        }
        self.route();
    }

    /// Ends a registration once its queued writes have failed and their
    /// outcomes have gone to its endpoint.
    fn unregister(&mut self, registration: u64) {
        self.port.withdraw(registration);
        self.route();
        if self.registrations.remove(&registration).is_some() {
            *self.shared.lifecycle.lock().expect("not poisoned") -= 1;
        }
        self.shared.writes.forget(registration);
    }

    /// Passes the outcomes of finished writes to their endpoints. An
    /// endpoint that has unregistered gets none, and a later one never gets
    /// another's, since registration numbers never repeat.
    fn route(&mut self) {
        while let Some((registration, local, result)) = self.port.take_routed()
        {
            if let Some(completions) = self.registrations.get(&registration) {
                let _ = completions.send((local, result));
            }
        }
    }

    fn on_datagram(
        &mut self,
        payload: Bytes,
        flow: Flow,
        context: TransportContext,
    ) {
        let stats = &self.shared.stats;
        increment(&stats.received);
        let Some(permit) =
            self.shared.ingress.acquire(payload.len() + context.len())
        else {
            increment(&stats.overflow);
            return;
        };
        let datagram = ReceivedDatagram {
            payload,
            flow,
            // A backend may slice its context out of a capture buffer, which
            // a held datagram would keep alive. See `path::retain`.
            context: context.detached(),
            deadline: Instant::now() + self.shared.deadline,
            held: Some(Held {
                shared: self.shared.clone(),
                commands: self.weak.clone(),
                _permit: permit,
            }),
        };
        // Without an `Ingress` the datagram drops here and counts as
        // abandoned.
        if let Some(ingress) = &self.ingress {
            let _ = ingress.send(datagram);
        }
    }

    /// Drains what the port admitted until `deadline`, then closes the
    /// backend, as an endpoint's driver closes its own.
    async fn close(&mut self, deadline: Instant) -> ShutdownOutcome {
        // An endpoint waiting for room in the limits is woken, tries again
        // and finds the port closing.
        self.shared.set_phase(CLOSING);
        self.ingress = None;
        let mut sleep = Box::pin(sleep_until(deadline));
        let mut closing = false;
        let mut overdue = false;
        let mut commands_open = true;

        let lost = poll_fn(|cx| {
            loop {
                while commands_open {
                    match self.commands.poll_recv(cx) {
                        Poll::Ready(Some(Command::Close { deadline })) => {
                            if deadline < sleep.deadline() {
                                sleep.as_mut().reset(deadline);
                            }
                        }
                        Poll::Ready(Some(command)) => {
                            self.on_closing_command(command);
                        }
                        Poll::Ready(None) => commands_open = false,
                        Poll::Pending => break,
                    }
                }
                if !closing {
                    let drained = self.port.poll_drain(cx).is_ready();
                    self.route();
                    closing = drained;
                }
                if closing {
                    if self.port.poll_close(cx).is_ready() {
                        self.route();
                        return Poll::Ready(self.port.lost());
                    }
                    if overdue {
                        // A backend still closing at the deadline gets this
                        // one more poll, and is dropped with the task. What
                        // it took and never reported may have gone out.
                        self.port.give_up();
                        self.route();
                        return Poll::Ready(true);
                    }
                }
                if !overdue && sleep.as_mut().poll(cx).is_ready() {
                    overdue = true;
                    if !closing {
                        self.port.abort();
                        closing = true;
                    }
                    continue;
                }
                return Poll::Pending;
            }
        })
        .await;

        // Commands sent after the last poll would otherwise drop with the
        // task, and an endpoint would wait for a write's outcome forever.
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            match command {
                Command::Close { .. } => {}
                command => self.on_closing_command(command),
            }
        }
        self.route();

        if lost {
            ShutdownOutcome::DeadlineExpired
        } else {
            ShutdownOutcome::Drained
        }
    }

    /// Refuses what a closing port no longer takes.
    fn on_closing_command(&mut self, command: Command) {
        match command {
            Command::Register { .. } => {
                *self.shared.lifecycle.lock().expect("not poisoned") -= 1;
            }
            Command::Unregister { registration, done } => {
                self.unregister(registration);
                let _ = done.send(());
            }
            Command::Write { registration, write, permit } => {
                drop(permit);
                if let Some(completions) =
                    self.registrations.get(&registration)
                {
                    let _ =
                        completions.send((write.id(), Err(closing_error())));
                }
            }
            Command::Raw { done, permit, .. } => {
                drop(permit);
                let _ = done.send(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the port closed before the write went out",
                )));
            }
            Command::CheckPath { done, .. } => {
                let _ = done.send(Err(Error::closed()));
            }
            Command::Close { .. } => unreachable!("handled by the caller"),
        }
    }
}

/// The datagrams a port received, for the application to dispose of.
///
/// There is one per port. [`Ingress::recv`] ends once the port starts closing
/// and what it queued has been taken. Dropping it does not stop the port, whose
/// later datagrams then count as [`PortStats::abandoned`].
pub struct Ingress {
    receiver: mpsc::UnboundedReceiver<ReceivedDatagram>,
}

impl Ingress {
    /// Receives the next datagram, or `None` once the port is closing and
    /// nothing is left.
    ///
    /// It is cancellation-safe.
    pub async fn recv(&mut self) -> Option<ReceivedDatagram> {
        self.receiver.recv().await
    }

    /// Polls for the next datagram, as [`Ingress::recv`] does.
    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ReceivedDatagram>> {
        self.receiver.poll_recv(cx)
    }
}

impl fmt::Debug for Ingress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ingress").finish_non_exhaustive()
    }
}

/// One datagram a port received, with the one decision about it.
///
/// The payload is the original bytes, which nothing has parsed or changed.
/// The datagram is not `Clone`. Copying its bytes gives data, not a second
/// disposition. Delivering, forwarding and discarding consume it, and
/// dropping it discards it. Each is counted in [`PortStats`]. It holds its
/// share of [`PortBuilder::ingress_limits`] until then, even after its
/// [deadline](ReceivedDatagram::deadline), since its bytes are still held.
///
/// ```compile_fail
/// // A datagram has one disposition, so it cannot be cloned into two.
/// fn twice(datagram: signa_core::endpoint::ReceivedDatagram) {
///     let copy = datagram.clone();
///     datagram.discard();
///     copy.discard();
/// }
/// ```
pub struct ReceivedDatagram {
    payload: Bytes,
    flow: Flow,
    context: TransportContext,
    deadline: Instant,
    /// The disposition, until one is made.
    held: Option<Held>,
}

struct Held {
    shared: Arc<Shared>,
    commands: mpsc::WeakUnboundedSender<Command>,
    _permit: Permit,
}

impl ReceivedDatagram {
    /// The UDP payload, as it arrived.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// The flow the datagram arrived on, with the address it came from as
    /// its remote end. For an intercepting backend the local end need not be
    /// an address of this host.
    pub fn flow(&self) -> Flow {
        self.flow
    }

    /// The address the datagram came from.
    pub fn source(&self) -> SocketAddr {
        self.flow.remote
    }

    /// The address the datagram was sent to.
    pub fn destination(&self) -> SocketAddr {
        self.flow.local
    }

    /// The backend's context, which may share its buffer.
    pub fn context(&self) -> &TransportContext {
        &self.context
    }

    /// When the datagram stops being deliverable or forwardable.
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline.into_std()
    }

    /// Parses the payload as a SIP message, without changing anything.
    ///
    /// This is a view. A delivered datagram is parsed again by its endpoint,
    /// which adds `received` and `rport` to that copy only. A payload that
    /// does not parse can still be forwarded.
    pub fn parse(&self) -> Result<Message<Bytes>, InvalidMessage> {
        Message::from_shared(self.payload.clone())
    }

    /// Gives the datagram to the endpoint `to` names, which receives it as it
    /// would from a socket of its own.
    ///
    /// # Commit point
    ///
    /// The datagram is delivered once the endpoint's queue takes it, and
    /// `Ok` says so. The endpoint processes it once, unless it stops first,
    /// which drops what its queue holds. Delivery does not mean that the
    /// datagram produced an event or was valid SIP. The endpoint parses it,
    /// fills in `received` and `rport`, matches it, sends any automatic
    /// response, and queues it for the TU. A delivery that races a close of
    /// the port may still be taken, and the endpoint's writes then fail.
    ///
    /// # Errors
    ///
    /// The datagram comes back undelivered in [`Refused`], with:
    ///
    /// * [`Error::is_stale_path`] for an endpoint on another port.
    /// * [`Error::is_expired`] after the deadline.
    /// * [`Error::is_busy`] when the endpoint's
    ///   [queue](PortBuilder::delivery_queue) is full.
    /// * [`Error::is_closed`] when the endpoint has stopped or the port is
    ///   closing.
    pub fn try_deliver(self, to: &EndpointIngress) -> Result<(), Refused> {
        if let Err(error) = self.check(to.port) {
            return Err(self.refuse(error));
        }
        let shared = self.held.as_ref().expect("held").shared.clone();
        match to.deliveries.try_send(self) {
            Ok(()) => {
                increment(&shared.stats.delivered);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(datagram)) => {
                Err(datagram.refuse(Error::busy()))
            }
            Err(mpsc::error::TrySendError::Closed(datagram)) => {
                Err(datagram.refuse(Error::closed()))
            }
        }
    }

    /// Sends the payload once along `path`, unchanged, as
    /// [`DatagramPort::send_bytes`] does.
    ///
    /// # Commit point
    ///
    /// The datagram is forwarded once this returns `Ok`. The [`RawWrite`]
    /// resolves with the write's local outcome, and dropping it does not
    /// take the send back.
    ///
    /// # Errors
    ///
    /// The datagram comes back unsent in [`Refused`], with:
    ///
    /// * [`Error::is_stale_path`] for a path of another port.
    /// * [`Error::is_expired`] after the deadline.
    /// * [`Error::is_too_large`] for a payload over the backend's maximum.
    /// * [`Error::is_busy`] when [`PortBuilder::write_limits`] is full.
    /// * [`Error::is_closed`] once the port is closing.
    pub fn try_forward(mut self, path: &RawPath) -> Result<RawWrite, Refused> {
        if let Err(error) = self.check(path.binding().port) {
            return Err(self.refuse(error));
        }
        let held = self.held.as_ref().expect("held");
        let Some(commands) = held.commands.upgrade() else {
            return Err(self.refuse(Error::closed()));
        };
        let shared = held.shared.clone();
        match submit_raw(&shared, &commands, self.payload.clone(), path) {
            Ok(write) => {
                self.held = None;
                increment(&shared.stats.forwarded);
                Ok(write)
            }
            Err(error) => Err(self.refuse(error)),
        }
    }

    /// Drops the datagram, and counts it as discarded, or as expired after
    /// its deadline.
    pub fn discard(mut self) {
        if let Some(held) = self.held.take() {
            let stats = &held.shared.stats;
            if self.is_expired() {
                increment(&stats.expired);
            } else {
                increment(&stats.discarded);
            }
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Checks what both dispositions need: a port that is not closing, a
    /// target on this port, and the deadline not passed.
    fn check(&self, port: u64) -> Result<(), Error> {
        let shared = &self.held.as_ref().expect("held").shared;
        if shared.closing() {
            Err(Error::closed())
        } else if port != shared.id {
            Err(Error::stale_path())
        } else if self.is_expired() {
            Err(Error::expired())
        } else {
            Ok(())
        }
    }

    fn refuse(self, error: Error) -> Refused {
        Refused(Box::new((self, error)))
    }

    /// Takes the parts an endpoint's driver receives, ending the datagram
    /// without counting it again.
    fn into_delivered(mut self) -> (Bytes, Flow, TransportContext) {
        self.held = None;
        (mem::take(&mut self.payload), self.flow, mem::take(&mut self.context))
    }
}

impl Drop for ReceivedDatagram {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            let stats = &held.shared.stats;
            if self.is_expired() {
                increment(&stats.expired);
            } else {
                increment(&stats.abandoned);
            }
        }
    }
}

impl fmt::Debug for ReceivedDatagram {
    // The payload is SIP traffic, which can carry credentials. Only its length
    // goes into a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedDatagram")
            .field("len", &self.payload.len())
            .field("flow", &self.flow)
            .field("context", &self.context)
            .finish()
    }
}

/// A datagram that was not delivered or forwarded, with the reason.
///
/// The datagram still holds its disposition, unless it
/// [expired](Error::is_expired), and can be tried again or discarded.
// Boxed, since a refusal is rare and the datagram is large for an `Err`.
pub struct Refused(Box<(ReceivedDatagram, Error)>);

impl Refused {
    /// Why the datagram was refused.
    pub fn error(&self) -> &Error {
        &self.0.1
    }

    /// Takes the datagram back.
    pub fn into_datagram(self) -> ReceivedDatagram {
        self.0.0
    }

    /// Takes the datagram and the reason apart.
    pub fn into_parts(self) -> (ReceivedDatagram, Error) {
        *self.0
    }
}

impl fmt::Debug for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("datagram", &self.0.0)
            .field("error", &self.0.1)
            .finish()
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the datagram was refused: {}", self.0.1)
    }
}

impl std::error::Error for Refused {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0.1)
    }
}

/// Where [`ReceivedDatagram::try_deliver`] gives datagrams to one endpoint on
/// a port, from [`Endpoint::ingress`](super::Endpoint::ingress).
///
/// It names a target, not a datagram, so clones are fine. It refuses
/// datagrams of another port, and once its endpoint has stopped.
#[derive(Clone)]
pub struct EndpointIngress {
    port: u64,
    deliveries: mpsc::Sender<ReceivedDatagram>,
}

impl fmt::Debug for EndpointIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointIngress")
            .field("closed", &self.deliveries.is_closed())
            .finish()
    }
}

/// A way to send raw datagrams that a port's backend has accepted.
///
/// [`DatagramPort::prepare_path`] makes one. It belongs to the port alone:
/// every endpoint refuses it, and it is not a [`SendPath`](super::SendPath).
/// It is invalid once the port closes. Clones share one path, which counts
/// against [`PortBuilder::context_limits`] until the last drops.
#[derive(Clone)]
pub struct RawPath(Arc<Path>);

impl RawPath {
    fn binding(&self) -> Binding {
        self.0.prepared.as_deref().expect("a raw path is prepared").binding
    }

    /// The address datagrams on the path are sent from.
    pub fn source(&self) -> SocketAddr {
        self.0.prepared.as_deref().expect("prepared").source
    }

    /// The address datagrams on the path are sent to.
    pub fn destination(&self) -> SocketAddr {
        self.0.prepared.as_deref().expect("prepared").destination
    }

    /// The backend's context.
    pub fn context(&self) -> &TransportContext {
        &self.0.context
    }
}

impl fmt::Debug for RawPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawPath")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("context", self.context())
            .finish()
    }
}

/// The local outcome of a raw send, which resolves once the backend reports
/// it.
///
/// `Ok` means the backend wrote the datagram locally, not that the peer got
/// it. [`Error::is_transport`] carries the backend's failure, and
/// [`Error::is_closed`] says the port closed before the outcome was known,
/// so whether it went out is unknown. Dropping it does not take the send
/// back.
#[must_use = "dropping a write does not cancel it, but its outcome is lost"]
pub struct RawWrite(oneshot::Receiver<io::Result<()>>);

impl Future for RawWrite {
    type Output = Result<(), Error>;

    fn poll(
        mut self: Pin<&mut RawWrite>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(match ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Error::transport(error)),
            Err(_) => Err(Error::closed()),
        })
    }
}

impl fmt::Debug for RawWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawWrite").finish_non_exhaustive()
    }
}

/// A backend opened for passive capture, which only receives.
///
/// It has no send, path or delivery operation, and its datagrams carry no
/// disposition, so capturing traffic can cause nothing on the wire.
///
/// ```compile_fail
/// // Capture has no way to send.
/// fn sends(
///     capture: &signa_core::endpoint::Capture,
///     path: &signa_core::endpoint::RawPath,
/// ) {
///     let _ = capture.send_bytes(bytes::Bytes::new(), path);
/// }
/// ```
///
/// ```compile_fail
/// // A captured datagram cannot be delivered to an endpoint.
/// fn delivers(
///     datagram: signa_core::endpoint::CapturedDatagram,
///     to: &signa_core::endpoint::EndpointIngress,
/// ) {
///     let _ = datagram.try_deliver(to);
/// }
/// ```
pub struct Capture {
    io: Box<dyn DatagramIo>,
    reception: Arc<ReceptionCounters>,
    closed: bool,
}

impl Capture {
    /// Receives the next datagram, or `None` once the capture is closed.
    ///
    /// A truncated datagram or a receive error is counted and skipped. It
    /// is cancellation-safe as far as the backend's `poll_recv` is.
    pub async fn recv(&mut self) -> Option<CapturedDatagram> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Polls for the next datagram, as [`Capture::recv`] does.
    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<CapturedDatagram>> {
        if self.closed {
            return Poll::Ready(None);
        }
        for _ in 0..BATCH {
            match ready!(self.io.poll_recv(cx)) {
                Ok(datagram) => {
                    let (payload, source, destination, context) =
                        datagram.into_parts();
                    let flow = Flow {
                        transport: Transport::Udp,
                        local: unmap(destination),
                        remote: unmap(source),
                    };
                    return Poll::Ready(Some(CapturedDatagram {
                        payload,
                        flow,
                        context,
                    }));
                }
                Err(RecvError::Truncated) => {
                    increment(&self.reception.truncated_datagrams);
                }
                Err(RecvError::Io(_)) => {
                    increment(&self.reception.receive_errors);
                    break;
                }
            }
        }
        // A backend failing over and over yields to other tasks.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Counts of what the backend could not deliver whole. The other counts
    /// stay zero, since a capture disposes of nothing.
    pub fn stats(&self) -> PortStats {
        PortStats {
            truncated_datagrams: self
                .reception
                .truncated_datagrams
                .load(Ordering::Relaxed),
            receive_errors: self
                .reception
                .receive_errors
                .load(Ordering::Relaxed),
            ..PortStats::default()
        }
    }

    /// Closes the backend, giving it `timeout` before it is dropped.
    pub async fn close(mut self, timeout: Duration) -> ShutdownOutcome {
        self.closed = true;
        let closed = tokio::time::timeout(
            timeout,
            poll_fn(|cx| self.io.poll_close(cx)),
        )
        .await;
        match closed {
            Ok(()) => ShutdownOutcome::Drained,
            Err(_) => ShutdownOutcome::DeadlineExpired,
        }
    }
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture")
            .field("local_addr", &self.io.local_addr())
            .field("closed", &self.closed)
            .finish()
    }
}

/// A datagram a [`Capture`] received: data, with no disposition.
#[derive(Clone)]
pub struct CapturedDatagram {
    payload: Bytes,
    flow: Flow,
    context: TransportContext,
}

impl CapturedDatagram {
    /// The UDP payload, as it arrived.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// The flow the datagram arrived on, with the address it came from as
    /// its remote end.
    pub fn flow(&self) -> Flow {
        self.flow
    }

    /// The address the datagram came from.
    pub fn source(&self) -> SocketAddr {
        self.flow.remote
    }

    /// The address the datagram was sent to.
    pub fn destination(&self) -> SocketAddr {
        self.flow.local
    }

    /// The backend's context.
    pub fn context(&self) -> &TransportContext {
        &self.context
    }

    /// Parses the payload as a SIP message, without changing anything.
    pub fn parse(&self) -> Result<Message<Bytes>, InvalidMessage> {
        Message::from_shared(self.payload.clone())
    }
}

impl fmt::Debug for CapturedDatagram {
    // See the `Debug` of `ReceivedDatagram`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedDatagram")
            .field("len", &self.payload.len())
            .field("flow", &self.flow)
            .field("context", &self.context)
            .finish()
    }
}
