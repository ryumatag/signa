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
    sync::{Notify, futures::OwnedNotified, mpsc, oneshot, watch},
    time::{Instant, sleep_until},
};

use super::{
    BindError, Error, ShutdownOutcome,
    datagram::{Port, Received},
    driver::{ABANDONED_FLUSH, ReceptionCounters, increment},
    observe::{self, ObservationConfig, Observer, Tap},
    path::{self, PathSelection},
};
use crate::{
    message::{Message, error::InvalidMessage},
    transport::{
        Flow, ReceiveId, Stamp, Stamps, Transport, WriteLimits,
        budget::{Budget, Permit},
        datagram::{
            Binding, Capabilities, Datagram, DatagramIo, DatagramWrite, Owner,
            Path, RecvError, Submit, TransportContext, WriteId, WriteOutcome,
        },
        udp, unmap,
    },
};

mod withdrawal;
mod writes;

pub(super) use withdrawal::Withdrawal;
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
        let (port, ingress, task) = self.build()?;
        tokio::spawn(task.run());
        Ok((port, ingress))
    }

    /// Checks the configuration and opens the backend, and returns the port
    /// with the task that is to own the backend, not yet started.
    fn build(self) -> Result<(DatagramPort, Ingress, PortTask), BindError> {
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
        let id = crate::transport::next_id();
        let port = Port::new(
            io,
            WriteLimits { messages: usize::MAX, bytes: usize::MAX },
            reception.clone(),
            Stamps::in_domain(id),
            id,
        );
        let shared = Arc::new(Shared {
            id,
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
            close: Mutex::new(None),
            closer: Arc::new(Notify::new()),
            done: watch::channel(None).0,
            observing: Arc::default(),
        });
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (ingress, ingress_rx) = mpsc::unbounded_channel();
        let task = PortTask {
            port,
            close_requested: Box::pin(shared.closer.clone().notified_owned()),
            shared: shared.clone(),
            commands: commands_rx,
            weak: commands.downgrade(),
            ingress: Some(ingress),
            registrations: HashMap::new(),
            tap: None,
        };

        Ok((
            DatagramPort { shared, commands },
            Ingress { receiver: ingress_rx },
            task,
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
///    others go on. Once it returns, whether drained or at its deadline, the
///    backend takes none of the endpoint's writes, and those the port still
///    queued fail. A write the backend took before cannot be taken back and
///    may still go out after the endpoint has stopped.
/// 3. [`DatagramPort::close`] stops reception, invalidates the datagrams the
///    application still holds and every path of the port, refuses new writes
///    and drains the rest, then closes the backend, as [`Endpoint::shutdown`]
///    closes its own. An endpoint still registered sees its writes fail, or
///    their outcomes unknown for those the backend took and never reported.
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
    /// The earliest deadline any close asked for, once one has.
    close: Mutex<Option<Instant>>,
    /// Wakes the port's task for a close request. Only that task waits on
    /// it, and its one stored permit stands for every request since the task
    /// last looked, so requests keep no more than this and `close`.
    closer: Arc<Notify>,
    /// The close's outcome, for every caller of `close`.
    done: watch::Sender<Option<ShutdownOutcome>>,
    /// Set while an [`Observer`] of the port is alive.
    observing: Arc<AtomicBool>,
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

    /// Asks the port's task to close by `deadline`, or sooner if another
    /// request asked for sooner.
    ///
    /// The deadline is kept here rather than in a message, so that however
    /// many times `close` is called, the request holds one deadline and one
    /// wakeup. `notify_one` keeps a permit when the task is not waiting, so
    /// a request made before the task looks is not lost.
    fn request_close(&self, deadline: Instant) {
        {
            let mut close = self.close.lock().expect("not poisoned");
            *close =
                Some(close.map_or(deadline, |earlier| earlier.min(deadline)));
        }
        self.closer.notify_one();
    }

    /// The earliest deadline asked for so far.
    fn close_deadline(&self) -> Option<Instant> {
        *self.close.lock().expect("not poisoned")
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
        completions: mpsc::UnboundedSender<(WriteId, WriteOutcome)>,
        withdrawal: Arc<Withdrawal>,
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
        done: oneshot::Sender<WriteOutcome>,
        permit: WritePermit,
        /// The datagram a forward sends on, for the port's records.
        cause: Option<ReceiveId>,
    },
    /// An observer attaches, replacing any earlier one. `attached` learns
    /// that the task records from now on.
    Observe {
        tap: Tap,
        attached: oneshot::Sender<()>,
    },
    CheckPath {
        path: Path,
        done: oneshot::Sender<Result<Path, Error>>,
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
        submit_raw(&self.shared, &self.commands, payload, path, None)
    }

    /// Attaches an observer to the port, which records what its backend
    /// receives and every write the port offers it, within the limits of
    /// `config`.
    ///
    /// A datagram is recorded as the port's task takes it, before the
    /// ingress limits, the application or an endpoint see it, under the ID
    /// the endpoint it is delivered to keeps. The writes are the backend's:
    /// a write of a registered endpoint names that endpoint's own record of
    /// it in [`WriteOrigin::Endpoint`], and a raw send or forward is
    /// [`WriteOrigin::Raw`]. The endpoints' observers see why they wrote,
    /// and this one when the backend took and finished each write.
    ///
    /// It resolves once the port's task records. See [`Endpoint::observe`]
    /// for how records are bounded.
    ///
    /// # Cancellation
    ///
    /// Dropping the future detaches the observer it would have returned.
    ///
    /// # Errors
    ///
    /// * [`Error::is_busy`] while another observer of this port is alive.
    /// * [`Error::is_closed`] once the port's task has ended.
    ///
    /// [`Endpoint::observe`]: super::Endpoint::observe
    /// [`WriteOrigin::Endpoint`]: super::WriteOrigin::Endpoint
    /// [`WriteOrigin::Raw`]: super::WriteOrigin::Raw
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn observe(
        &self,
        config: ObservationConfig,
    ) -> impl Future<Output = Result<Observer, Error>> + Send + '_ {
        async move {
            if self.commands.is_closed() {
                return Err(Error::closed());
            }
            let observing = &self.shared.observing;
            if observing
                .compare_exchange(
                    false,
                    true,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(Error::busy());
            }

            // From here on a failure drops the observer, which clears the
            // flag again.
            let (tap, observer) = observe::pair(config, observing.clone());
            let (attached, done) = oneshot::channel();
            self.commands
                .send(Command::Observe { tap, attached })
                .map_err(|_| Error::closed())?;
            done.await.map_err(|_| Error::closed())?;
            Ok(observer)
        }
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
    /// the outcome once the backend has closed and been dropped. A port on a
    /// socket of its own has released its address by then, so it can be
    /// bound again at once.
    ///
    /// Reception stops, the datagrams the application holds and every path
    /// of the port turn invalid, and new writes are refused at once. The
    /// writes already admitted get until the deadline. At the deadline the
    /// writes the backend never took fail, and those it took and never
    /// reported end with their outcomes unknown. The backend gets one more
    /// poll to close before it is dropped. Closing does not wait for
    /// registered endpoints, which see their writes end the same way. Stop
    /// them first.
    ///
    /// Another call can bring the deadline forward, even while the port is
    /// already draining or closing its backend, and never pushes it back.
    /// Every caller gets the same outcome, and a call after the close
    /// finished gets it at once.
    ///
    /// # Cancellation
    ///
    /// The close starts when this is called, not when the future is first
    /// polled, and dropping the future does not stop it.
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn close(
        &self,
        timeout: Duration,
    ) -> impl Future<Output = ShutdownOutcome> + Send + 'static {
        let deadline = Instant::now() + timeout;
        self.shared.set_phase(CLOSING);
        self.shared.request_close(deadline);
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
        let registration = crate::transport::next_id();
        let (completions, completions_rx) = mpsc::unbounded_channel();
        let withdrawal = Arc::new(Withdrawal::default());
        {
            let mut registrations =
                self.shared.lifecycle.lock().expect("not poisoned");
            if self.shared.phase() != OPEN {
                return Err(BindError::port_closed());
            }
            if *registrations >= self.shared.max_registrations {
                return Err(BindError::port_full());
            }
            let command = Command::Register {
                registration,
                completions,
                withdrawal: withdrawal.clone(),
            };
            self.commands
                .send(command)
                .map_err(|_| BindError::port_closed())?;
            *registrations += 1;
        }

        let (deliveries, deliveries_rx) =
            mpsc::channel(self.shared.delivery_queue);
        let proxy = Proxy {
            registration,
            shared: self.shared.clone(),
            commands: self.commands.clone(),
            deliveries: deliveries_rx,
            completions: completions_rx,
            withdrawal: withdrawal.clone(),
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
                withdrawal,
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
    cause: Option<ReceiveId>,
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
    let path = path.0.clone();
    commands
        .send(Command::Raw { payload, path, done, permit, cause })
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
    withdrawal: Arc<Withdrawal>,
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
        if self.withdrawal.is_withdrawn() || self.shared.closing() {
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
    completions: mpsc::UnboundedReceiver<(WriteId, WriteOutcome)>,
    /// Set as the endpoint's driver starts to close the proxy, or drops it.
    /// The port's task offers none of the endpoint's writes after that.
    withdrawal: Arc<Withdrawal>,
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
                let (payload, flow, context, stamp) =
                    datagram.into_delivered();
                let datagram = Datagram::new(payload, flow.remote, flow.local)
                    .with_context(context)
                    .with_stamp(stamp);
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
        if self.shared.closing() || self.withdrawal.is_withdrawn() {
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
    ) -> Poll<(WriteId, WriteOutcome)> {
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
    ///
    /// The first poll withdraws the endpoint before it asks the task to
    /// unregister it. A driver that stops at its deadline drops the proxy
    /// without waiting for the task, and the withdrawal is what keeps the
    /// task from offering the endpoint's writes after that. See
    /// [`Withdrawal`].
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.unregistering.is_none() {
            self.withdrawal.withdraw();
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
            self.withdrawal.withdraw();
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
    /// Ready once a close has been asked for since the task last looked.
    close_requested: Pin<Box<OwnedNotified>>,
    commands: mpsc::UnboundedReceiver<Command>,
    /// For the datagrams it hands out, which forward through it while it
    /// runs but do not keep it running.
    weak: mpsc::WeakUnboundedSender<Command>,
    ingress: Option<mpsc::UnboundedSender<ReceivedDatagram>>,
    registrations: HashMap<u64, Registered>,
    /// The observer's tap, while one is attached.
    tap: Option<Tap>,
}

/// What the port's task keeps of a registered endpoint.
struct Registered {
    /// Where the endpoint takes its writes' outcomes.
    completions: mpsc::UnboundedSender<(WriteId, WriteOutcome)>,
    /// Checked as each of its writes is offered to the backend.
    withdrawal: Arc<Withdrawal>,
}

impl PortTask {
    async fn run(mut self) {
        let deadline = poll_fn(|cx| self.poll_serve(cx)).await;
        let outcome = self.close(deadline).await;

        // A closer that sees the outcome may rebind the address at once, or
        // count on the backend's tasks having stopped. The backend's `Drop`
        // is the last thing that stops them when `poll_close` did not
        // finish, and the built-in socket closes only as it drops. So the
        // task drops everything it owns, the backend through `Port` with it,
        // before it publishes. `Port` is the backend's only owner, and the
        // handles keep only `Shared`.
        //
        // This orders the outcome after what the port owns. It does not join
        // a task the backend spawned and left running. That stays the
        // backend's to stop, as `DatagramIo::poll_close` says.
        let shared = self.shared.clone();
        drop(self);
        shared.done.send_replace(Some(outcome));
    }

    /// Serves until a close or until every handle is gone, and returns the
    /// close's deadline.
    fn poll_serve(&mut self, cx: &mut Context<'_>) -> Poll<Instant> {
        // The commands still queued are left to `close`, which takes them in
        // batches and checks the deadline before it offers any.
        if let Some(deadline) = self.poll_close_request(cx) {
            return Poll::Ready(deadline);
        }

        // A source that stopped at its batch, rather than at `Pending`, has
        // registered no waker, so the task wakes itself for it.
        let mut more = true;
        for _ in 0..BATCH {
            match self.commands.poll_recv(cx) {
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
                Poll::Ready(datagram) => {
                    self.on_datagram(datagram);
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

    /// Returns the earliest deadline asked for, once a close request has
    /// come since the task last looked, and arms the next look.
    ///
    /// `None` leaves the task's waker with the request. After `Some` it is
    /// not left yet, so a caller that goes on to wait polls again until
    /// `None`.
    fn poll_close_request(&mut self, cx: &mut Context<'_>) -> Option<Instant> {
        if self.close_requested.as_mut().poll(cx).is_pending() {
            return None;
        }
        let closer = self.shared.closer.clone();
        self.close_requested.set(closer.notified_owned());
        // The request stored its deadline before it notified, so the read
        // sees it, and any request since.
        Some(
            self.shared
                .close_deadline()
                .expect("a request stores its deadline before it notifies"),
        )
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Register { registration, completions, withdrawal } => {
                self.registrations.insert(
                    registration,
                    Registered { completions, withdrawal },
                );
            }
            Command::Unregister { registration, done } => {
                self.unregister(registration);
                let _ = done.send(());
            }
            Command::Write { registration, write, permit } => {
                // The permit of a write whose endpoint has gone returns its
                // room as it drops.
                if let Some(registered) = self.registrations.get(&registration)
                {
                    let withdrawal = registered.withdrawal.clone();
                    self.port.submit_routed(
                        write,
                        registration,
                        withdrawal,
                        permit,
                    );
                }
            }
            Command::Raw { payload, path, done, permit, cause } => {
                self.port.submit_raw(payload, path, done, permit, cause);
            }
            Command::Observe { tap, attached } => {
                self.port.observe(tap.clone());
                self.tap = Some(tap);
                let _ = attached.send(());
            }
            Command::CheckPath { path, done } => {
                let result = match self.port.check_path(&path) {
                    Ok(()) => Ok(path),
                    Err(error) => Err(Error::path_refused(error)),
                };
                let _ = done.send(result);
            }
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
            if let Some(registered) = self.registrations.get(&registration) {
                let _ = registered.completions.send((local, result));
            }
        }
    }

    fn on_datagram(&mut self, datagram: Received) {
        let Received { payload, flow, context, stamp, .. } = datagram;
        // Before the ingress limits, so that a datagram they drop is seen.
        if let Some(tap) = observe::attached(&mut self.tap) {
            tap.received(stamp, flow, [&payload[..], &[][..]], &context);
        }
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
            stamp,
            // The deadline counts from when the datagram arrived, the time
            // `Port::poll_recv` stamped it with.
            deadline: Instant::from_std(stamp.at) + self.shared.deadline,
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
    ///
    /// Each poll looks at the deadline first, then takes a batch of commands,
    /// then drains or closes the backend. The writes still queued for the
    /// task were admitted before the close, since admission refuses once it
    /// has started, and they get until the deadline like those the backend
    /// already holds. Once the deadline has passed, nothing more is offered.
    async fn close(&mut self, deadline: Instant) -> ShutdownOutcome {
        // An endpoint waiting for room in the limits is woken, tries again
        // and finds the port closing.
        self.shared.set_phase(CLOSING);
        self.ingress = None;
        let mut sleep = Box::pin(sleep_until(deadline));
        // Set once the backend has been told to close, or the deadline has
        // passed. No write is offered after that.
        let mut closing = false;
        let mut overdue = false;
        // Whether a write still in the queue failed at the deadline.
        let mut refused = false;
        // Whether the backend lost a write, once it has closed or been given
        // up on.
        let mut closed = None;
        let mut commands_open = true;

        let lost = poll_fn(|cx| {
            // A later request can only bring the deadline forward, while
            // draining or closing alike. Looking until there is none leaves
            // the waker for the next.
            while let Some(deadline) = self.poll_close_request(cx) {
                if deadline < sleep.deadline() {
                    sleep.as_mut().reset(deadline);
                }
            }
            // The timer fires on its own tick, which can come after the
            // deadline, so the clock decides too. A deadline already past
            // when the close was asked for stops the very first poll.
            if !overdue
                && (sleep.deadline() <= Instant::now()
                    || sleep.as_mut().poll(cx).is_ready())
            {
                overdue = true;
                if !closing {
                    self.port.abort();
                    self.route();
                    closing = true;
                }
            }

            // A source that stopped at its batch, rather than at `Pending`,
            // has registered no waker, so the task wakes itself for it.
            let mut more = false;
            let mut handled = 0;
            while commands_open {
                if handled == BATCH {
                    more = true;
                    break;
                }
                match self.commands.poll_recv(cx) {
                    Poll::Ready(Some(command)) => {
                        refused |= self.on_closing_command(command, !closing);
                        handled += 1;
                    }
                    Poll::Ready(None) => commands_open = false,
                    Poll::Pending => break,
                }
            }

            if closed.is_none() && !closing {
                let drained = self.port.poll_drain(cx).is_ready();
                self.route();
                // A write admitted just before the close can still be on its
                // way to the queue. It holds room in the limits until its
                // outcome is known, and its command wakes the task.
                closing = drained && self.shared.writes.is_idle();
            }
            if closed.is_none() && closing {
                if self.port.poll_close(cx).is_ready() {
                    self.route();
                    closed = Some(self.port.lost());
                } else if overdue {
                    // A backend still closing at the deadline gets this one
                    // more poll, and is dropped with the task. What it took
                    // and never reported may have gone out.
                    self.port.give_up();
                    self.route();
                    closed = Some(true);
                }
                if closed.is_some() {
                    // Commands sent from here on fail at the sender. Those
                    // already queued are refused in batches below, or an
                    // endpoint would wait for a write's outcome forever.
                    self.commands.close();
                    more |= commands_open;
                }
            }

            match closed {
                Some(lost) if !commands_open => {
                    return Poll::Ready(lost || refused);
                }
                _ => {}
            }
            if more {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await;

        if lost {
            ShutdownOutcome::DeadlineExpired
        } else {
            ShutdownOutcome::Drained
        }
    }

    /// Takes a command that reaches a closing port. A write goes to the
    /// backend only while the port still `drains` before its deadline, and
    /// fails otherwise. Returns `true` if it failed one.
    fn on_closing_command(&mut self, command: Command, drains: bool) -> bool {
        match command {
            // Its endpoint was bound before the close, and its writes queued
            // behind this were admitted before it too.
            command @ Command::Register { .. } if drains => {
                self.on_command(command);
            }
            Command::Register { .. } => {
                *self.shared.lifecycle.lock().expect("not poisoned") -= 1;
            }
            Command::Unregister { registration, done } => {
                self.unregister(registration);
                let _ = done.send(());
            }
            command @ (Command::Write { .. } | Command::Raw { .. })
                if drains =>
            {
                self.on_command(command);
            }
            Command::Write { registration, write, permit } => {
                drop(permit);
                // The write of an endpoint that has gone would have been
                // dropped in any case, and was not lost to the deadline.
                let Some(registered) = self.registrations.get(&registration)
                else {
                    return false;
                };
                let outcome = WriteOutcome::NotWritten(closing_error());
                let _ = registered.completions.send((write.id(), outcome));
                return true;
            }
            Command::Raw { done, permit, .. } => {
                drop(permit);
                let _ = done.send(WriteOutcome::NotWritten(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the port closed before the write went out",
                )));
                return true;
            }
            // Every path turned invalid as the close started.
            Command::CheckPath { done, .. } => {
                let _ = done.send(Err(Error::closed()));
            }
            // An observer still sees the drain.
            command @ Command::Observe { .. } => self.on_command(command),
        }
        false
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
    stamp: Stamp,
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

    /// The datagram's ID, which the endpoint it is delivered to keeps in
    /// the [`ReceiveInfo`] of what it makes of it.
    ///
    /// [`ReceiveInfo`]: super::ReceiveInfo
    pub fn receive_id(&self) -> ReceiveId {
        self.stamp.id
    }

    /// When the port's task took the datagram from the backend, before the
    /// application held it. The endpoint it is delivered to keeps this
    /// time too.
    pub fn received_at(&self) -> std::time::Instant {
        self.stamp.at
    }

    /// When the datagram stops being deliverable or forwardable, the
    /// decision deadline after [`ReceivedDatagram::received_at`].
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
        let payload = self.payload.clone();
        let cause = Some(self.stamp.id);
        match submit_raw(&shared, &commands, payload, path, cause) {
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
    fn into_delivered(mut self) -> (Bytes, Flow, TransportContext, Stamp) {
        self.held = None;
        let payload = mem::take(&mut self.payload);
        (payload, self.flow, mem::take(&mut self.context), self.stamp)
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
            .field("receive_id", &self.stamp.id)
            .field("received_at", &self.stamp.at)
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
/// it. [`Error::is_transport`] means it did not go out, with the backend's
/// error or the port's, which closed before offering it.
/// [`Error::is_outcome_unknown`] means it may have: the backend cannot tell,
/// or the port closed while the backend held it unreported. Dropping it does
/// not take the send back.
#[must_use = "dropping a write does not cancel it, but its outcome is lost"]
pub struct RawWrite(oneshot::Receiver<WriteOutcome>);

impl Future for RawWrite {
    type Output = Result<(), Error>;

    fn poll(
        mut self: Pin<&mut RawWrite>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(match ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(WriteOutcome::Written) => Ok(()),
            Ok(WriteOutcome::NotWritten(error)) => {
                Err(Error::transport(error))
            }
            Ok(WriteOutcome::Unknown(error)) => {
                Err(Error::outcome_unknown(error))
            }
            // The port settles every raw write it took. Its task ends without
            // doing so only when its runtime drops it.
            Err(_) => Err(Error::outcome_unknown(io::Error::new(
                io::ErrorKind::NotConnected,
                "the port stopped without reporting the write",
            ))),
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
                    let (payload, source, destination, context, _) =
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

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque, pin::pin, sync::mpsc as std_mpsc, task::Waker,
        thread,
    };

    use super::*;

    const LOCAL: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        5060,
    );
    const PEER: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20)),
        5060,
    );

    /// What the backend does with the next write it is offered.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum Mode {
        /// Takes it and reports it written at once.
        #[default]
        Take,
        /// Cannot take it now.
        Hold,
        /// Takes it and never reports it.
        Keep,
        /// Takes it, but first waits in `poll_submit` until the test lets it
        /// go, as a backend that blocked would.
        Block,
    }

    #[derive(Default)]
    struct State {
        mode: Mode,
        offered: Vec<Bytes>,
        completions: VecDeque<(WriteId, WriteOutcome)>,
        /// Told when a blocking `poll_submit` has started.
        entered: Option<std_mpsc::Sender<()>>,
        /// What a blocking `poll_submit` waits on.
        release: Option<std_mpsc::Receiver<()>>,
    }

    /// A backend the test drives through shared state. It records the
    /// payloads of the writes it took.
    #[derive(Clone, Default)]
    struct Backend(Arc<Mutex<State>>);

    impl Backend {
        fn mode(&self, mode: Mode) {
            self.0.lock().unwrap().mode = mode;
        }

        fn offered(&self) -> Vec<Bytes> {
            self.0.lock().unwrap().offered.clone()
        }
    }

    impl DatagramIo for Backend {
        fn local_addr(&self) -> SocketAddr {
            LOCAL
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::new(1472)
        }

        fn poll_recv(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Datagram, RecvError>> {
            Poll::Pending
        }

        fn poll_submit(
            &mut self,
            _cx: &mut Context<'_>,
            write: DatagramWrite,
        ) -> Submit {
            let mode = self.0.lock().unwrap().mode;
            match mode {
                Mode::Take | Mode::Keep => {}
                Mode::Hold => return Submit::Pending(write),
                Mode::Block => {
                    // The lock on the state is not held while blocked, so
                    // that the test can still read it.
                    let (entered, release) = {
                        let mut state = self.0.lock().unwrap();
                        (state.entered.take(), state.release.take())
                    };
                    entered.unwrap().send(()).unwrap();
                    let _ = release.unwrap().recv();
                }
            }
            let mut state = self.0.lock().unwrap();
            if mode != Mode::Keep {
                state
                    .completions
                    .push_back((write.id(), WriteOutcome::Written));
            }
            state.offered.push(write.payload().clone());
            Submit::Accepted
        }

        fn poll_complete(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<(WriteId, WriteOutcome)> {
            match self.0.lock().unwrap().completions.pop_front() {
                Some(completion) => Poll::Ready(completion),
                None => Poll::Pending,
            }
        }

        fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Ready(())
        }
    }

    /// A port on `backend` whose task the test polls itself, one step at a
    /// time, instead of spawning it.
    fn port(backend: &Backend) -> (DatagramPort, Ingress, PortTask) {
        PortBuilder::new().udp_io(backend.clone()).build().unwrap()
    }

    /// One turn of the port's task: the commands queued so far, a flush of
    /// the backlog, and reception.
    fn serve(task: &mut PortTask) {
        let _ = task.poll_serve(&mut Context::from_waker(Waker::noop()));
    }

    /// Offers `payload` to an endpoint's proxy, which admits it and queues
    /// it for the port's task.
    fn submit(
        registration: &mut Registration,
        id: u64,
        payload: &'static str,
    ) {
        let write = DatagramWrite::new(
            WriteId::new(id),
            Bytes::from_static(payload.as_bytes()),
            LOCAL,
            PEER,
            None,
        );
        let mut cx = Context::from_waker(Waker::noop());
        let submitted = registration.io.poll_submit(&mut cx, write);
        assert!(matches!(submitted, Submit::Accepted));
    }

    /// The task's turn that sees a close request, which hands the close its
    /// deadline.
    fn closing(task: &mut PortTask) -> Instant {
        let mut cx = Context::from_waker(Waker::noop());
        match task.poll_serve(&mut cx) {
            Poll::Ready(deadline) => deadline,
            Poll::Pending => panic!("the task saw no close request"),
        }
    }

    /// One poll of `future`, with a waker that does nothing.
    fn step<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// The outcomes the port has passed to an endpoint so far, in order.
    fn outcomes(
        registration: &mut Registration,
    ) -> Vec<(WriteId, &'static str)> {
        let mut cx = Context::from_waker(Waker::noop());
        let mut outcomes = Vec::new();
        while let Poll::Ready((id, outcome)) =
            registration.io.poll_complete(&mut cx)
        {
            let outcome = match outcome {
                WriteOutcome::Written => "written",
                WriteOutcome::NotWritten(_) => "not written",
                WriteOutcome::Unknown(_) => "unknown",
            };
            outcomes.push((id, outcome));
        }
        outcomes
    }

    /// Stops an endpoint as its driver does at the deadline: the first poll
    /// of its close withdraws it and asks the task to unregister it, and the
    /// driver drops the proxy without waiting for the answer.
    fn force_stop(mut registration: Registration) {
        let mut cx = Context::from_waker(Waker::noop());
        assert!(registration.io.poll_close(&mut cx).is_pending());
        drop(registration);
    }

    // However many times `close` is called before the task looks, and
    // whether or not its futures are dropped, the request holds one deadline
    // and one wakeup, and nothing goes into the command queue. The earliest
    // deadline wins, and the task closes by it.
    #[test]
    fn close_requests_keep_one_deadline_and_one_wakeup() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);

        for _ in 0..10_000 {
            drop(port.close(Duration::from_secs(10)));
        }
        drop(port.close(Duration::from_secs(1)));
        let by = Instant::now() + Duration::from_secs(1);
        for _ in 0..10_000 {
            drop(port.close(Duration::from_secs(5)));
        }

        assert!(task.commands.is_empty());
        let deadline = port.shared.close_deadline().unwrap();
        assert!(deadline <= by);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(task.poll_serve(&mut cx), Poll::Ready(deadline));
        assert!(task.poll_close_request(&mut cx).is_none());
    }

    // A write admitted before the close waits in the queue apart from the
    // close request, and still goes to the backend before the deadline, as
    // one the backend had already taken would drain. The turn that sees the
    // request offers nothing itself.
    #[tokio::test(start_paused = true)]
    async fn writes_queued_before_a_close_still_go() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut endpoint = port.register().unwrap();
        serve(&mut task);
        submit(&mut endpoint, 0, "queued");

        drop(port.close(Duration::from_secs(1)));
        let deadline = closing(&mut task);
        assert!(backend.offered().is_empty());
        let outcome = task.close(deadline).await;

        assert_eq!(outcome, ShutdownOutcome::Drained);
        assert_eq!(backend.offered(), ["queued"]);
        assert_eq!(outcomes(&mut endpoint), [(WriteId::new(0), "written")]);
    }

    // A close whose deadline passed well before the task looks offers
    // nothing more. A write still in the task's queue and one in the backlog
    // fail without reaching the backend, which would take them now, and one
    // it took and never reported ends unknown. The port lost them to the
    // deadline, so it has not drained.
    #[tokio::test(start_paused = true)]
    async fn an_expired_close_offers_nothing_more() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut endpoint = port.register().unwrap();
        serve(&mut task);
        backend.mode(Mode::Keep);
        submit(&mut endpoint, 0, "taken");
        serve(&mut task);
        backend.mode(Mode::Hold);
        submit(&mut endpoint, 1, "backlog");
        serve(&mut task);
        submit(&mut endpoint, 2, "queued");
        backend.mode(Mode::Take);

        drop(port.close(Duration::ZERO));
        tokio::time::advance(Duration::from_secs(1)).await;
        let deadline = closing(&mut task);
        let outcome = task.close(deadline).await;

        assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
        assert_eq!(backend.offered(), ["taken"]);
        let mut outcomes = outcomes(&mut endpoint);
        outcomes.sort();
        assert_eq!(
            outcomes,
            [
                (WriteId::new(0), "unknown"),
                (WriteId::new(1), "not written"),
                (WriteId::new(2), "not written"),
            ]
        );
    }

    // A close with no time at all offers nothing either. The clock runs, so
    // the timer, which fires on a later tick, cannot be what stops it.
    #[tokio::test]
    async fn a_close_with_no_time_offers_nothing_more() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut endpoint = port.register().unwrap();
        serve(&mut task);
        submit(&mut endpoint, 0, "queued");

        drop(port.close(Duration::ZERO));
        let deadline = closing(&mut task);
        let mut close = pin!(task.close(deadline));
        let _ = step(close.as_mut());

        assert!(backend.offered().is_empty());
        assert_eq!(close.await, ShutdownOutcome::DeadlineExpired);
        assert_eq!(
            outcomes(&mut endpoint),
            [(WriteId::new(0), "not written")]
        );
    }

    // The close takes the task's queue a batch at a time, as serving does,
    // so that however long the queue, one poll does a bounded amount.
    #[tokio::test(start_paused = true)]
    async fn a_close_takes_the_queue_a_batch_at_a_time() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut endpoint = port.register().unwrap();
        serve(&mut task);
        for id in 0..=BATCH as u64 {
            submit(&mut endpoint, id, "queued");
        }

        drop(port.close(Duration::from_secs(60)));
        let deadline = closing(&mut task);
        let mut close = pin!(task.close(deadline));

        assert!(step(close.as_mut()).is_pending());
        assert_eq!(backend.offered().len(), BATCH);
        assert_eq!(close.await, ShutdownOutcome::Drained);
        assert_eq!(backend.offered().len(), BATCH + 1);
        let outcomes = outcomes(&mut endpoint);
        assert_eq!(outcomes.len(), BATCH + 1);
        assert!(outcomes.iter().all(|&(_, outcome)| outcome == "written"));
    }

    // A deadline brought forward while the close works through the queue
    // stops it there. The writes it offered went out, and the rest fail.
    #[tokio::test(start_paused = true)]
    async fn a_sooner_deadline_stops_the_close_in_the_queue() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut endpoint = port.register().unwrap();
        serve(&mut task);
        for id in 0..=BATCH as u64 {
            submit(&mut endpoint, id, "queued");
        }
        drop(port.close(Duration::from_secs(60)));
        let deadline = closing(&mut task);
        let mut close = pin!(task.close(deadline));
        assert!(step(close.as_mut()).is_pending());

        drop(port.close(Duration::ZERO));

        assert_eq!(close.await, ShutdownOutcome::DeadlineExpired);
        assert_eq!(backend.offered().len(), BATCH);
        let outcomes = outcomes(&mut endpoint);
        let (last, written) = outcomes.split_last().unwrap();
        assert_eq!(*last, (WriteId::new(BATCH as u64), "not written"));
        assert!(written.iter().all(|&(_, outcome)| outcome == "written"));
    }

    // An endpoint admits a write, then queues it. A close in between can
    // drain everything in the queue before the write arrives. The room the
    // write holds in the limits keeps the close from finishing there, and
    // the write still goes before the deadline.
    #[tokio::test(start_paused = true)]
    async fn a_close_waits_for_a_write_on_its_way_to_the_queue() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut endpoint = port.register().unwrap();
        serve(&mut task);
        let admission =
            port.shared.writes.admit(endpoint.registration, 4, Waker::noop());
        let Admission::Admitted(permit) = admission else {
            panic!("the limits have room");
        };

        drop(port.close(Duration::from_secs(60)));
        let deadline = closing(&mut task);
        let mut close = pin!(task.close(deadline));
        assert!(step(close.as_mut()).is_pending());
        let write = DatagramWrite::new(
            WriteId::new(0),
            Bytes::from_static(b"late"),
            LOCAL,
            PEER,
            None,
        );
        let registration = endpoint.registration;
        port.commands
            .send(Command::Write { registration, write, permit })
            .unwrap_or_else(|_| panic!("the close finished without it"));

        assert_eq!(close.await, ShutdownOutcome::Drained);
        assert_eq!(backend.offered(), ["late"]);
        assert_eq!(outcomes(&mut endpoint), [(WriteId::new(0), "written")]);
    }

    // An endpoint's write that waits in the task's queue when the endpoint
    // stops at its deadline never reaches the backend, although the task
    // reads it before the unregistration that follows it. A sibling's write
    // in the same queue still goes.
    #[test]
    fn a_queued_write_does_not_reach_the_backend_after_a_forced_stop() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut stopping = port.register().unwrap();
        let mut sibling = port.register().unwrap();
        serve(&mut task);

        submit(&mut stopping, 0, "stopping");
        submit(&mut sibling, 0, "sibling");
        force_stop(stopping);
        serve(&mut task);

        assert_eq!(backend.offered(), ["sibling"]);
        assert_eq!(task.registrations.len(), 1);
        drop(sibling);
    }

    // A write the backend could not take waits in the backlog, and the task
    // can retry the backlog before it reads an unregistration queued behind
    // a full batch of commands. The retry checks the withdrawal again, so the
    // stopped endpoint's write stays back, and the sibling's writes queued
    // behind it go.
    #[test]
    fn a_write_waiting_for_the_backend_is_not_retried_after_a_forced_stop() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut stopping = port.register().unwrap();
        let mut sibling = port.register().unwrap();
        serve(&mut task);
        backend.mode(Mode::Hold);
        submit(&mut stopping, 0, "stopping");
        serve(&mut task);
        assert!(backend.offered().is_empty());

        for id in 0..BATCH as u64 {
            submit(&mut sibling, id, "sibling");
        }
        force_stop(stopping);
        backend.mode(Mode::Take);
        serve(&mut task);

        // The turn read the full batch of the sibling's writes and stopped
        // short of the unregistration, then retried the backlog.
        let only_sibling = |offered: &[Bytes]| {
            offered.iter().all(|payload| payload == "sibling")
        };
        assert!(!backend.offered().is_empty());
        assert!(only_sibling(&backend.offered()));
        assert_eq!(task.registrations.len(), 2, "unregistered in this turn");
        serve(&mut task);
        serve(&mut task);
        assert_eq!(backend.offered().len(), BATCH);
        assert!(only_sibling(&backend.offered()));
        assert_eq!(task.registrations.len(), 1);
        drop(sibling);
    }

    // A withdrawal that comes while the backend is taking one of the
    // endpoint's writes waits for `poll_submit` to return, and that write
    // counts as taken before the endpoint stopped. The task runs on a thread
    // of its own, and the backend holds its `poll_submit` until the test has
    // seen the withdrawal wait.
    #[test]
    fn a_withdrawal_waits_for_the_offer_in_progress() {
        let backend = Backend::default();
        let (port, _ingress, mut task) = port(&backend);
        let mut stopping = port.register().unwrap();
        serve(&mut task);
        let (entered, offering) = std_mpsc::channel();
        let (release, held) = std_mpsc::channel();
        {
            let mut state = backend.0.lock().unwrap();
            state.mode = Mode::Block;
            state.entered = Some(entered);
            state.release = Some(held);
        }
        submit(&mut stopping, 0, "taken first");
        let serving = thread::spawn(move || {
            serve(&mut task);
            task
        });
        offering.recv().unwrap();

        let (stopped, done) = std_mpsc::channel();
        let stop = thread::spawn(move || {
            force_stop(stopping);
            stopped.send(()).unwrap();
        });
        let waited =
            done.recv_timeout(std::time::Duration::from_millis(50)).is_err();
        // Released before any assertion, so that a failure cannot leave the
        // task's thread blocked.
        release.send(()).unwrap();

        assert!(waited, "the endpoint stopped during the backend's offer");
        let mut task = serving.join().unwrap();
        done.recv().unwrap();
        stop.join().unwrap();
        assert_eq!(backend.offered(), ["taken first"]);
        serve(&mut task);
        assert!(task.registrations.is_empty());
    }
}
