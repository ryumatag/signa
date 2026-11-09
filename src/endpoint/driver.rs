/*!
The task behind an endpoint.

One task owns the sockets, both transaction tables, and the timers, so none of
them needs a lock. It rotates through timers, internal completions, client
commands, TCP, UDP and responder abandonment. Shutdown has a separate coalesced
control wakeup. Each turn bounds write-receipt polling and UDP flush,
and the task yields after 64 events so continuously ready work also shares the
runtime with connection tasks.

The tables are slabs, see [`table`], and the timers are one heap of deadlines,
with one `Sleep` set to the earliest. An entry names its transaction by its
table id. A transaction whose deadline moves gets a new entry, and an entry
whose transaction has moved on is harmless, because a transaction fires nothing
before its time, and one whose transaction is gone finds nothing. The timer
queue also compacts stale entries and shrinks its allocation relative to live
table entries, so fast transaction churn cannot retain an unbounded history.

A shutdown is a deadline on the heap too. From the request on, the driver
answers new requests with a 503 and refuses new client transactions, while the
transactions it has go on to Terminated on their own timers. Once nothing is
left, which [`Driver::is_drained`] decides, it closes the command queue and
the TU work guards together and runs what was queued before that. The queue is
the commit point of every operation, so an operation is either run or refused
with a closed error, never dropped after its caller was told it was taken. If
it is still drained after that, the driver stops gracefully. At the deadline
it stops whatever is left. The deadline waits for the transaction timers due
at the same instant, as input does.

Stopping has two steps. The driver first drops itself apart from what the
second step needs, which drops the transactions, answers the waiting futures
with a closed error and closes the sockets. It then moves its TCP tasks to
[`tcp::Phase::Closing`], or to [`tcp::Phase::Abort`] when it was forced, and
waits for them all to end, still bounded by the deadline. Only then does it
publish the [`ShutdownOutcome`]. Waiting there is fine, since nothing else is
left for the driver to do.
*/

use std::{
    collections::HashMap,
    future::{poll_fn, Future},
    io, mem,
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::{pin, Pin},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use foldhash::fast::RandomState;
use tokio::{
    sync::{mpsc, oneshot, watch, Semaphore},
    time::{sleep_until, Sleep},
};

use crate::{
    endpoint::{
        admission::{AdmissionOwner, ClientAdmission, Permit},
        builder::{Config, Reception},
        client::{
            CancelError, CancelHandle, CancelOutcome, Delivery, Intent,
            Observation, Reserved, Starting, Target,
        },
        datagram::Datagram,
        error::Error,
        reply::{Admission, Completion, ReplyError, ReplyRoute},
        routing::{
            mark_via, reply_flow, sent_by, sent_by_is, source_toward,
            via_value, via_value_with, Branches, Link,
        },
        send::ViaMode,
        server::{
            self, IncomingEvent, ReceivedRequest, ServerRequest,
            ServerTransactionId, SubmitError,
        },
        shutdown::{self, ShutdownOutcome},
        table::{Id, Table},
        timer::{Key, TimerQueue},
    },
    message::{
        header::{
            address::has_tag, cseq::CSeq, via::Via, HeaderMap, Tag, CALL_ID,
            CSEQ, FROM, TO, VIA,
        },
        request::Request,
        response::{bare_response, reply_headers, Response},
        Message, Method, StatusCode,
    },
    transaction::{
        invite,
        key::{ClientKey, ServerKey},
        non_invite::{ClientEvent, ClientTransaction, ServerTransaction},
    },
    transport::{budget::Budget, tcp, udp, Flow, Transport, WriteLimits},
};

mod cancels;
mod invites;
mod stateless;

/// The most bytes of a request that go over UDP. RFC 3261 section 18.1.1
/// sends a larger one over a congestion-controlled transport. The limit is
/// 200 bytes under the path MTU, or 1300 bytes when the MTU is unknown, and
/// signa does not know it.
pub(super) const MAX_UDP_REQUEST: usize = 1300;

/// How many messages from TCP connections may wait for the driver. When it
/// falls behind, the readers stop and TCP flow control holds the peers back.
pub(super) const TCP_INBOUND: usize = 256;

/// One-shot replies hold a slot through command, connect, and local write.
const REPLY_OPERATIONS: usize = 64;

const BAD_REQUEST: StatusCode = status(400);
const SERVER_ERROR: StatusCode = status(500);
const SERVICE_UNAVAILABLE: StatusCode = status(503);

const fn status(code: u16) -> StatusCode {
    match StatusCode::from_u16(code) {
        Ok(status) => status,
        Err(_) => panic!("a status code"),
    }
}

/// Where a client transaction delivers its responses.
type Responder = Delivery;

/// What the driver is told, by the handles and by its own tasks.
pub(super) enum Command {
    /// A client sends a request.
    Send {
        request: Request<Bytes>,
        transport: Transport,
        next_hop: SocketAddr,
        respond: Starting,
        permit: Permit,
    },
    /// A route sends one response without a transaction.
    Reply { link: Link, bytes: Bytes, completion: Completion },
    /// A TU asks the driver to accept a response.
    Submit(server::Submission),
    /// A TU asks the driver to cancel an INVITE. One intent per INVITE
    /// reaches the driver, so these are bounded by live INVITEs.
    Cancel {
        id: Id,
        intent: Arc<Intent>,
        done: oneshot::Sender<Result<CancelOutcome, CancelError>>,
    },
    /// A TU sends a request once, without a transaction.
    Request {
        request: Request<Bytes>,
        target: Target,
        via: ViaMode,
        completion: Completion,
    },
    /// A stateless TU forwards an encoded response to the address its top
    /// Via names.
    Forward { bytes: Bytes, remote: SocketAddr, completion: Completion },
    /// A connection the driver asked for is open, or could not be opened.
    Connected {
        remote: SocketAddr,
        result: io::Result<(Flow, tcp::Writer)>,
        _attempt: crate::transport::budget::Permit,
    },
}

struct ServerEntry {
    tx: ServerMachine,
    /// Where responses go. Its remote address is the one RFC 3261 section
    /// 18.2.2 picks, which is the request's source port only with `rport`.
    link: Link,
    shared: Option<Arc<server::Shared>>,
    /// The TU's name for this transaction. It also tells a capability of a
    /// removed transaction from one of a new entry in the same slot, since
    /// the counter behind it never repeats.
    id: ServerTransactionId,
    retained: Option<crate::transport::budget::Permit>,
}

impl Drop for ServerEntry {
    fn drop(&mut self) {
        if let Some(shared) = &self.shared {
            shared.work.finish();
            shared.observation.send_modify(|state| {
                if state.end.is_none()
                    && !shared.terminated.load(Ordering::Acquire)
                {
                    state.end = Some(server::End::EndpointClosed);
                }
            });
        }
    }
}

/// The machine of a server entry. Extension methods use the non-INVITE one.
/// The INVITE state is boxed, so a non-INVITE entry, the common case, does
/// not grow by a tag or the reservation flag.
enum ServerMachine {
    NonInvite(ServerTransaction),
    Invite(Box<InviteServer>),
}

impl ServerMachine {
    fn cancel_reserved(&self) -> bool {
        matches!(self, ServerMachine::Invite(invite) if invite.cancel_reserved)
    }

    fn deadline(&self) -> Option<Instant> {
        match self {
            ServerMachine::NonInvite(tx) => tx.deadline(),
            ServerMachine::Invite(tx) => tx.deadline(),
        }
    }

    fn is_terminated(&self) -> bool {
        match self {
            ServerMachine::NonInvite(tx) => tx.is_terminated(),
            ServerMachine::Invite(tx) => tx.is_terminated(),
        }
    }

    /// Reply headers while the TU can still send a final response.
    fn headers(&self) -> Option<&HeaderMap> {
        match self {
            ServerMachine::NonInvite(tx) => tx.headers(),
            ServerMachine::Invite(tx) => tx.headers(),
        }
    }

    /// What a retransmission of the request gets.
    fn on_retransmission(&self) -> Option<Bytes> {
        match self {
            ServerMachine::NonInvite(tx) => tx.on_retransmission(),
            ServerMachine::Invite(tx) => match tx.on_retransmission() {
                invite::ServerEvent::Send(bytes) => Some(bytes),
                _ => None,
            },
        }
    }

    /// A response write failed. A non-INVITE ends. An INVITE keeps its state
    /// ([RFC 6026 section 8.8]).
    ///
    /// [RFC 6026 section 8.8]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.8
    fn on_transport_error(&mut self) {
        match self {
            ServerMachine::NonInvite(tx) => tx.on_transport_error(),
            ServerMachine::Invite(tx) => {
                tx.on_transport_error();
            }
        }
    }

    /// Ends a transaction whose abandonment 500 could not be sent. See
    /// `Driver::respond_abandoned`.
    fn abandon(&mut self) {
        match self {
            ServerMachine::NonInvite(tx) => tx.on_transport_error(),
            ServerMachine::Invite(tx) => {
                tx.abandon();
            }
        }
    }
}

/// An INVITE server transaction with what the driver adds to its machine.
struct InviteServer {
    tx: invite::ServerTransaction,
    /// The INVITE holds a table entry for the CANCEL that may target it,
    /// counted in `Driver::reserved_cancels`, until a CANCEL takes it or the
    /// INVITE is removed.
    cancel_reserved: bool,
}

impl Deref for InviteServer {
    type Target = invite::ServerTransaction;

    fn deref(&self) -> &invite::ServerTransaction {
        &self.tx
    }
}

impl DerefMut for InviteServer {
    fn deref_mut(&mut self) -> &mut invite::ServerTransaction {
        &mut self.tx
    }
}

struct ClientEntry {
    tx: ClientMachine,
    /// Where the request went. Its local address is the `sent-by` written
    /// into the `Via`, which a response has to carry back.
    link: Link,
    /// Taken when the final response, or the error, is delivered. An INVITE
    /// keeps it after a 2xx, until Timer M.
    respond: Option<Responder>,
    permit: Permit,
}

impl ClientEntry {
    /// The machine's deadline, or an INVITE's cancellation deadline if that
    /// is earlier.
    fn deadline(&self) -> Option<Instant> {
        match &self.tx {
            ClientMachine::NonInvite(tx) => tx.deadline(),
            ClientMachine::Invite(invite) => {
                match (invite.tx.deadline(), invite.cancel_deadline) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            }
        }
    }

    fn is_terminated(&self) -> bool {
        match &self.tx {
            ClientMachine::NonInvite(tx) => tx.is_terminated(),
            ClientMachine::Invite(invite) => invite.tx.is_terminated(),
        }
    }

    /// Takes a completion once, after the machine has dropped its request.
    /// The driver settles the table before delivering it. Otherwise a reliable
    /// final can wake a new call while its last slot is still charged.
    fn answer(
        &mut self,
        result: Result<Response<Bytes>, Error>,
    ) -> Option<(Responder, Result<Response<Bytes>, Error>)> {
        let respond = self.respond.take()?;
        self.permit.release_bytes();
        Some((respond, result))
    }
}

/// The machine of a client entry. The INVITE state is boxed, so a
/// non-INVITE entry, the common case, does not grow by it.
enum ClientMachine {
    NonInvite(ClientTransaction),
    Invite(Box<InviteClient>),
}

impl ClientMachine {
    /// Ends a non-INVITE whose write failed. An INVITE follows its machine,
    /// see `Driver::fail_client`.
    fn end_on_transport_error(&mut self) {
        match self {
            ClientMachine::NonInvite(tx) => tx.on_transport_error(),
            ClientMachine::Invite(invite) => {
                invite.tx.on_transport_error();
            }
        }
    }
}

/// An INVITE client transaction with what the driver adds to its machine.
struct InviteClient {
    tx: invite::ClientTransaction,
    /// Whether the first final response or an error was delivered, which
    /// ends the INVITE's place in `Driver::unanswered`.
    answered: bool,
    cancel: Cancel,
    /// Shared with `ClientControl`, so a cancel request cannot reach a
    /// later INVITE in the same slot.
    intent: Arc<Intent>,
    /// 64 T1 after the CANCEL went out ([RFC 3261 section 9.1]).
    ///
    /// [RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
    cancel_deadline: Option<Instant>,
}

impl InviteClient {
    /// Records that the first final response or an error was delivered.
    /// Returns `true` the first time, when the caller decrements
    /// `Driver::unanswered`.
    fn mark_answered(&mut self) -> bool {
        !mem::replace(&mut self.answered, true)
    }

    /// Answers a waiting request with `NotNeeded` and returns the
    /// reservation, after a final response or the end of the INVITE.
    fn cancel_not_needed(&mut self) {
        if let Cancel::Waiting(_, done) =
            mem::replace(&mut self.cancel, Cancel::Done)
        {
            let _ = done.send(Ok(CancelOutcome::NotNeeded));
        }
    }
}

/// Where an INVITE's cancellation intent stands.
enum Cancel {
    /// Not requested. The reservation waits for a request.
    Reserved(Reserved),
    /// Requested before any provisional response. The CANCEL goes out with
    /// the first one, or the request is not needed after a final.
    Waiting(Reserved, oneshot::Sender<Result<CancelOutcome, CancelError>>),
    /// Sent, not needed, or never reserved.
    Done,
}

/// What the driver knows about one next hop. Pending connects stay here
/// because their requests start transactions only after a writer is ready.
#[derive(Default)]
struct Route {
    /// The address the UDP socket sends from to this hop, found once.
    udp_source: Option<IpAddr>,
    tcp: TcpState,
}

#[derive(Default)]
enum TcpState {
    #[default]
    Closed,
    /// A connect task is running. These go out when it is done.
    Connecting(Vec<Pending>),
    Open(Flow, tcp::Writer),
}

/// Something waiting for a TCP connection to open.
enum Pending {
    /// A client's request, which starts a transaction once it can be sent.
    Request(Request<Bytes>, Starting, Permit),
    /// A non-2xx ACK whose INVITE connection had closed. It goes to the
    /// INVITE's next hop (RFC 3261 section 17.1.1.3), not to where the final
    /// response came from.
    Ack(Bytes),
    /// A CANCEL whose INVITE connection had closed.
    Cancel(CancelStart),
    /// A request sent once, which gets its Via when the connection is open.
    OneShotRequest(Request<Bytes>, ViaMode, Completion),
    /// An encoded response whose request came on a connection that has closed
    /// since. It goes to `sent-by` on a new connection
    /// (RFC 3261 section 18.2.2).
    Response(Bytes, Fallback),
    OneShot(Bytes, Completion),
    Server(Bytes, server::WriteObservation, crate::transport::budget::Permit),
}

impl Pending {
    /// Whether this is protocol work for existing transactions or replies,
    /// which may use the connection room kept for responses, rather than a
    /// new request.
    fn is_protocol_work(&self) -> bool {
        !matches!(self, Pending::Request(..) | Pending::OneShotRequest(..))
    }
}

/// A CANCEL on its way to its own client transaction.
struct CancelStart {
    /// The CANCEL, with the INVITE's top Via as its only Via.
    request: Request<Bytes>,
    /// The INVITE, whose cancellation deadline starts with the CANCEL.
    invite: Id,
    intent: Arc<Intent>,
    reserved: Reserved,
    done: Option<oneshot::Sender<Result<CancelOutcome, CancelError>>>,
}

/// Transport admission held while the driver commits a server response.
enum PreparedServerOutput {
    Tcp(tcp::PreparedWrite, Option<crate::transport::budget::Permit>),
    Udp(Bytes, Flow),
    Waiting {
        remote: SocketAddr,
        bytes: Bytes,
        fallback: crate::transport::budget::Permit,
    },
    Connect {
        remote: SocketAddr,
        bytes: Bytes,
        fallback: crate::transport::budget::Permit,
        connection: tokio::sync::OwnedSemaphorePermit,
        attempt: crate::transport::budget::Permit,
    },
}

/// Counters shared with endpoint handles. No per-message allocation.
#[derive(Default, Debug)]
pub(super) struct ConnectionCounters {
    pub(super) rejected: AtomicU64,
    pub(super) dropped: AtomicU64,
}

/// Messages the receive path discarded for want of capacity, shared with
/// endpoint handles. See `Endpoint::reception_stats`.
#[derive(Default, Debug)]
pub(super) struct ReceptionCounters {
    pub(super) acks: AtomicU64,
    pub(super) stateless_requests: AtomicU64,
    pub(super) stateless_responses: AtomicU64,
}

pub(super) fn increment(counter: &AtomicU64) {
    let mut n = counter.load(Ordering::Relaxed);
    while n != u64::MAX {
        match counter.compare_exchange_weak(
            n,
            n + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => n = actual,
        }
    }
}

// Count every admitted fallback that fails, including driver teardown. A
// completed local write disarms the counter before returning its reservation.
struct Fallback {
    _permit: crate::transport::budget::Permit,
    stats: Arc<ConnectionCounters>,
    written: bool,
}

impl Drop for Fallback {
    fn drop(&mut self) {
        if !self.written {
            increment(&self.stats.dropped);
        }
    }
}

/// What one turn of the loop acts on.
enum Event {
    Timer(Key),
    Command(Command),
    Inbound(tcp::Inbound),
    Datagram(Bytes, Flow),
    /// Every handle is gone.
    Stop,
    /// A shutdown request, or the last work guard's drop.
    Control,
    /// A shutdown has nothing left to wait for.
    Drained,
    /// A responder was dropped before an accepted final response.
    Abandon(Arc<server::Shared>, ReplyRoute),
}

/// Why [`Driver::serve`] returned.
enum End {
    /// A shutdown found nothing left.
    Drained,
    /// The shutdown deadline came first.
    Expired,
    /// Every handle is gone, so nobody waits for the outcome.
    Abandoned,
}

/// How long the TCP writers of an endpoint whose last handle dropped get to
/// write what is queued. A peer that takes longer to read a few messages is
/// not reading at all.
const ABANDONED_FLUSH: Duration = Duration::from_secs(5);

/// What is left of a stopping driver while its transport tasks end.
struct Stopping {
    tasks: tcp::Tasks,
    done: watch::Sender<Option<ShutdownOutcome>>,
    shutdown: Arc<shutdown::Control>,
    /// Another shutdown call can still bring the deadline forward. `None`
    /// once every handle that could make one is gone.
    control: Option<mpsc::Receiver<()>>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Stopping {
    /// Waits for the transport tasks to end, aborting them at the deadline.
    ///
    /// The tasks are checked before the deadline, so tasks that have ended by
    /// the poll that sees the deadline are not aborted.
    async fn join(&mut self) {
        let Stopping { tasks, shutdown, control, sleep, .. } = self;
        let mut finished = pin!(tasks.finished());
        poll_fn(|cx| loop {
            if finished.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            if let Some(receiver) = control {
                match receiver.poll_recv(cx) {
                    Poll::Ready(Some(())) => {
                        if let Some(Some(at)) = shutdown.take() {
                            let at = tokio::time::Instant::from_std(at);
                            match sleep {
                                Some(sleep) if sleep.deadline() <= at => {}
                                Some(sleep) => sleep.as_mut().reset(at),
                                None => {
                                    *sleep = Some(Box::pin(sleep_until(at)))
                                }
                            }
                        }
                        continue;
                    }
                    Poll::Ready(None) => *control = None,
                    Poll::Pending => {}
                }
            }
            if let Some(deadline) = sleep {
                if deadline.as_mut().poll(cx).is_ready() {
                    tasks.advance(tcp::Phase::Abort);
                    *sleep = None;
                    continue;
                }
            }
            return Poll::Pending;
        })
        .await;
    }
}

pub(super) struct Driver {
    /// Each queued event holds an `event_admission` permit, so the channel is
    /// bounded by that budget although it is unbounded by type.
    incoming: mpsc::UnboundedSender<server::Queued>,
    /// Application work, from admission to an accepted final or termination.
    work: Budget,
    /// Incoming events between admission and `recv`.
    event_admission: Budget,
    /// Identity values copied into responders and reply routes, held until
    /// the last route clone drops.
    routes_admission: Budget,
    /// Encoded response submissions between enqueue and driver acceptance.
    submissions: Budget,
    /// Responses that server machines cache for retransmission.
    retained: Budget,
    /// Responder drop notices. A notice carries a clone of the responder's
    /// route, which holds a `routes_admission` permit until the driver takes
    /// it, so `max_responder_handles` bounds this channel. It is separate
    /// from `commands` so that a notice is never refused while submissions
    /// wait for capacity.
    drops: mpsc::UnboundedReceiver<(Arc<server::Shared>, ReplyRoute)>,
    drop_sender: mpsc::UnboundedSender<(Arc<server::Shared>, ReplyRoute)>,
    client_admission: AdmissionOwner,
    command_sender: mpsc::WeakUnboundedSender<Command>,
    reply_admission: Admission,
    reply_bytes: Budget,
    writes: Vec<(tcp::Receipt, Completion)>,
    /// Client request writes whose failure ends their transaction. The
    /// observation keeps a late receipt away from a reused table slot.
    client_writes: Vec<(ClientReceipt, Id, Observation)>,
    client_write_cursor: usize,
    /// From the `Endpoint`, `ClientControl`, `Responder` and `ReplyRoute`
    /// handles. The driver ends when they are all gone.
    commands: mpsc::UnboundedReceiver<Command>,
    /// From the connect tasks. Kept apart from `commands`, because the driver
    /// holds the sender for them.
    internal: mpsc::UnboundedReceiver<Command>,
    internal_tx: mpsc::UnboundedSender<Command>,
    udp: Option<Datagram>,
    tcp: mpsc::Receiver<tcp::Inbound>,
    /// For the connections the driver opens.
    tcp_tx: mpsc::Sender<tcp::Inbound>,
    config: Config,
    servers: Table<ServerKey, ServerEntry>,
    clients: Table<ClientKey, ClientEntry>,
    routes: HashMap<SocketAddr, Route, RandomState>,
    /// Live client entries per TCP connection, keyed by
    /// [`tcp::Writer::connection_id`]. A closed connection without clients,
    /// such as one a server request came on, skips the client table scan.
    client_connections: HashMap<usize, usize, RandomState>,
    outbound: Arc<Semaphore>,
    response_connections: Arc<Semaphore>,
    connects: Budget,
    response_connects: Budget,
    fallback: Budget,
    fallback_writes: Vec<(tcp::Receipt, Fallback)>,
    pub(super) connection_stats: Arc<ConnectionCounters>,
    timers: TimerQueue,
    sleep: Pin<Box<Sleep>>,
    /// Client transactions without a final response or an error yet.
    unanswered: usize,
    /// Set by the first shutdown request. New requests get a 503 from then on,
    /// and the driver stops once `is_drained` says so.
    shutting_down: bool,
    /// Set once a drained shutdown has closed the command queue and the work
    /// guards. The queued commands still run.
    stopping: bool,
    /// Every shutdown waiter reads the outcome from this one value.
    pub(super) shutdown_done: watch::Sender<Option<ShutdownOutcome>>,
    /// The listener and connection tasks.
    tasks: tcp::Tasks,
    pub(super) shutdown_control: Arc<shutdown::Control>,
    next_source: usize,
    pub(super) control: mpsc::Sender<()>,
    control_rx: mpsc::Receiver<()>,
    write_cursor: usize,
    server_writes: Vec<(
        tcp::Receipt,
        server::WriteObservation,
        Option<crate::transport::budget::Permit>,
    )>,
    server_cursor: usize,
    fallback_cursor: usize,
    branches: Branches,
    /// ACK and matched CANCEL events between admission and `recv`, apart
    /// from `event_admission`.
    control_events: Budget,
    /// Matched CANCELs from admission to their final response, apart from
    /// `work`.
    control_work: Budget,
    /// The reply routes of matched CANCELs, apart from `routes_admission`.
    control_routes: Budget,
    /// INVITE server entries that hold a table entry for their CANCEL.
    reserved_cancels: usize,
    /// Stateless responses between receipt and `recv`. Stateless requests use
    /// `event_admission` and `control_events`, which a stateless endpoint has
    /// no other use for.
    stateless_responses: Budget,
    pub(super) reception_counters: Arc<ReceptionCounters>,
}

impl Driver {
    /// Must be called from within a tokio runtime, for the timer.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        incoming: mpsc::UnboundedSender<server::Queued>,
        config: Config,
        udp: Option<udp::Socket>,
        tcp: mpsc::Receiver<tcp::Inbound>,
        tcp_tx: mpsc::Sender<tcp::Inbound>,
        commands: mpsc::UnboundedReceiver<Command>,
        command_sender: mpsc::WeakUnboundedSender<Command>,
        tasks: tcp::Tasks,
    ) -> Driver {
        let (internal_tx, internal) = mpsc::unbounded_channel();
        let (control, control_rx) = mpsc::channel(32);
        let (drop_sender, drops) = mpsc::unbounded_channel();

        Driver {
            incoming,
            routes_admission: Budget::new(WriteLimits {
                messages: config.max_responder_handles,
                bytes: config.max_responder_bytes,
            }),
            event_admission: Budget::new(WriteLimits {
                messages: config.max_pending_requests,
                bytes: config.max_server_request_bytes,
            }),
            work: Budget::new(WriteLimits {
                messages: config.max_pending_requests,
                bytes: config.max_server_request_bytes,
            }),
            submissions: Budget::new(WriteLimits {
                messages: 64,
                bytes: config.max_server_response_bytes,
            }),
            retained: Budget::new(WriteLimits {
                messages: usize::MAX,
                bytes: config.max_server_response_bytes,
            }),
            drops,
            drop_sender,
            client_admission: AdmissionOwner(ClientAdmission::new(
                config.max_client_transactions,
                config.max_client_request_bytes,
            )),
            command_sender,
            reply_admission: Admission(Arc::new(Semaphore::new(
                REPLY_OPERATIONS,
            ))),
            reply_bytes: Budget::new(WriteLimits {
                messages: REPLY_OPERATIONS,
                bytes: config.max_reply_bytes,
            }),
            writes: Vec::new(),
            client_writes: Vec::new(),
            client_write_cursor: 0,
            commands,
            internal,
            internal_tx,
            udp: udp
                .map(|socket| Datagram::new(socket, config.udp_write_limits)),
            tcp,
            tcp_tx,
            config,
            servers: Table::new(),
            clients: Table::new(),
            routes: HashMap::default(),
            client_connections: HashMap::default(),
            outbound: Arc::new(Semaphore::new(
                config.max_outbound_connections.min(Semaphore::MAX_PERMITS),
            )),
            response_connections: Arc::new(Semaphore::new(REPLY_OPERATIONS)),
            connects: Budget::new(WriteLimits {
                messages: config.max_pending_connects,
                bytes: 0,
            }),
            response_connects: Budget::new(WriteLimits {
                messages: REPLY_OPERATIONS,
                bytes: 0,
            }),
            fallback: Budget::new(config.fallback_limits),
            fallback_writes: Vec::new(),
            connection_stats: Arc::default(),
            timers: TimerQueue::new(),
            sleep: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            unanswered: 0,
            shutting_down: false,
            stopping: false,
            shutdown_done: watch::channel(None).0,
            tasks,
            shutdown_control: Arc::default(),
            next_source: 0,
            control,
            control_rx,
            write_cursor: 0,
            server_writes: Vec::new(),
            server_cursor: 0,
            fallback_cursor: 0,
            branches: Branches::new(),
            control_events: Budget::new(config.control_event_limits),
            control_work: Budget::new(config.control_event_limits),
            control_routes: Budget::new(config.control_event_limits),
            reserved_cancels: 0,
            stateless_responses: Budget::new(config.client_response_budget),
            reception_counters: Arc::default(),
        }
    }

    /// The one-shot slots that reply routes and `send_request` share.
    pub(super) fn oneshot_capacity(&self) -> Arc<Semaphore> {
        self.reply_admission.0.clone()
    }

    /// The one-shot bytes that reply routes and `send_request` share.
    pub(super) fn oneshot_bytes(&self) -> Budget {
        self.reply_bytes.clone()
    }

    pub(super) fn client_admission(&self) -> ClientAdmission {
        self.client_admission.0.clone()
    }

    pub(super) async fn run(mut self) {
        let end = self.serve().await;
        self.stop(end).await;
    }

    /// Runs until the endpoint stops, and says why.
    async fn serve(&mut self) -> End {
        let mut turns = 0;
        loop {
            if turns == 64 {
                let mut yielded = false;
                poll_fn(|cx| {
                    if yielded {
                        return Poll::Ready(());
                    }
                    yielded = true;

                    cx.waker().wake_by_ref();
                    Poll::Pending
                })
                .await;
                turns = 0;
            }
            turns += 1;

            match poll_fn(|cx| self.poll_event(cx)).await {
                Event::Timer(Key::Shutdown) => return self.at_deadline(),
                Event::Timer(key) => self.on_timer(key),
                Event::Command(command) => self.on_command(command),
                Event::Inbound(inbound) => {
                    let link = Link {
                        flow: inbound.flow,
                        writer: Some(inbound.writer),
                    };
                    if let Some(message) = inbound.message {
                        self.on_message(message, link);
                    } else {
                        self.on_connection_closed(&link);
                    }
                }
                Event::Datagram(datagram, flow) => {
                    // A datagram that is not one whole message is dropped.
                    // That includes a request whose body is shorter than
                    // its `Content-Length`, which RFC 3261 section 18.3
                    // would answer with a 400, but the parse error keeps no
                    // head to answer with.
                    if let Ok(message) = Message::from_shared(datagram) {
                        self.on_message(message, Link { flow, writer: None });
                    }
                }
                Event::Abandon(shared, _route) => self.abandon(&shared),
                Event::Control => self.on_control(),
                Event::Drained => return End::Drained,
                Event::Stop => return End::Abandoned,
            }
        }
    }

    /// Handles the shutdown deadline. Timers due by then run first, so a
    /// transaction that ends at the deadline ends before it, as it would
    /// before input at the same instant. A timer due after the deadline does
    /// not count, even if the driver woke late.
    fn at_deadline(&mut self) -> End {
        let deadline = self.timers.shutdown_deadline().unwrap_or_else(now);
        while self.timers.deadline().is_some_and(|at| at <= deadline) {
            match self.timers.pop() {
                Some(Key::Shutdown) | None => {}
                Some(key) => self.on_timer(key),
            }
        }

        if !self.is_drained() || !self.shutdown_control.close_guards_if_idle()
        {
            return End::Expired;
        }
        // As in `poll_event`, closing the queue is the decision. A command
        // that got in before it was committed by its caller and runs, and a
        // later one is refused. One that leaves work behind, such as a write,
        // makes the outcome an expiry, since nothing waits for it now.
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            self.on_command(command);
        }
        if self.is_drained() {
            End::Drained
        } else {
            End::Expired
        }
    }

    /// Stops the transport tasks and publishes the outcome.
    ///
    /// See the module docs. The driver drops what it no longer needs before it
    /// waits, so observers learn that the endpoint closed without waiting for
    /// the TCP connections.
    async fn stop(self, end: End) {
        self.shutdown_control.close_guards();
        let phase = match end {
            End::Drained | End::Abandoned => tcp::Phase::Closing,
            End::Expired => tcp::Phase::Abort,
        };
        self.tasks.advance(phase);
        // The last handle's drop forces the protocol work, but writes queued
        // before it still get `ABANDONED_FLUSH`, or less if a shutdown
        // deadline comes first.
        let deadline = match end {
            End::Abandoned => {
                let flush = now().checked_add(ABANDONED_FLUSH);
                match (self.timers.shutdown_deadline(), flush) {
                    (Some(at), Some(flush)) => Some(at.min(flush)),
                    (at, flush) => at.or(flush),
                }
            }
            End::Drained | End::Expired => self.timers.shutdown_deadline(),
        };
        let mut stopping = self.into_stopping(deadline);

        stopping.join().await;

        // The deadline can stop a task that was still closing. That is still
        // a drain unless it dropped output, which only a writer has. A writer
        // aborted with reservations out records it in `discarded`.
        let drained =
            matches!(end, End::Drained) && !stopping.tasks.discarded();
        stopping.done.send_replace(Some(if drained {
            ShutdownOutcome::Drained
        } else {
            ShutdownOutcome::DeadlineExpired
        }));
    }

    /// Keeps what the transport teardown needs and drops the rest.
    fn into_stopping(self, deadline: Option<Instant>) -> Stopping {
        let Driver {
            tasks,
            shutdown_done,
            shutdown_control,
            control_rx,
            mut sleep,
            ..
        } = self;
        if let Some(at) = deadline {
            sleep.as_mut().reset(tokio::time::Instant::from_std(at));
        }

        Stopping {
            tasks,
            done: shutdown_done,
            shutdown: shutdown_control,
            control: Some(control_rx),
            sleep: deadline.map(|_| sleep),
        }
    }

    /// Polls every source in turn and returns the first event.
    ///
    /// The shutdown check comes last, once every source is pending, so that it
    /// sees the tables after everything that arrived has been handled.
    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        if let Poll::Ready(Some(())) = self.control_rx.poll_recv(cx) {
            return Poll::Ready(Event::Control);
        }

        let servers = &self.servers;
        let clients = &self.clients;
        self.timers.compact(servers.len() + clients.len(), |key| match key {
            Key::Server(id) => servers.get(id)?.tx.deadline(),
            Key::Client(id) => clients.get(id)?.deadline(),
            Key::Shutdown => {
                unreachable!("the queue owns the shutdown deadline")
            }
        });

        let mut index = self.client_write_cursor.min(self.client_writes.len());
        let mut inspected = 0;
        while index < self.client_writes.len() && inspected < 32 {
            inspected += 1;
            if let Poll::Ready(result) = self.client_writes[index].0.poll(cx) {
                let (_, id, observation) =
                    self.client_writes.swap_remove(index);
                let Err(error) = result else { continue };
                let current = self
                    .clients
                    .get(id)
                    .and_then(|entry| entry.respond.as_ref())
                    .is_some_and(|delivery| observation.matches(delivery));
                if current {
                    self.fail_client(id, error);
                }
            } else {
                index += 1;
            }
        }

        self.client_write_cursor = if index < self.client_writes.len() {
            cx.waker().wake_by_ref();
            index
        } else {
            0
        };

        let mut index = self.write_cursor.min(self.writes.len());
        let mut inspected = 0;
        while index < self.writes.len() && inspected < 32 {
            inspected += 1;
            if let Poll::Ready(result) =
                Pin::new(&mut self.writes[index].0).poll(cx)
            {
                let (_, completion) = self.writes.swap_remove(index);
                completion.finish(result.map_err(ReplyError::Transport));
            } else {
                index += 1;
            }
        }

        self.write_cursor = if index < self.writes.len() {
            cx.waker().wake_by_ref();
            index
        } else {
            0
        };

        let mut index = self.fallback_cursor.min(self.fallback_writes.len());
        let mut inspected = 0;
        while index < self.fallback_writes.len() && inspected < 32 {
            inspected += 1;
            if let Poll::Ready(result) =
                Pin::new(&mut self.fallback_writes[index].0).poll(cx)
            {
                let (_, mut fallback) =
                    self.fallback_writes.swap_remove(index);
                fallback.written = result.is_ok();
            } else {
                index += 1;
            }
        }

        self.fallback_cursor = if index < self.fallback_writes.len() {
            cx.waker().wake_by_ref();
            index
        } else {
            0
        };

        let mut index = self.server_cursor.min(self.server_writes.len());
        for _ in 0..32 {
            if index == self.server_writes.len() {
                break;
            }
            if let Poll::Ready(result) =
                Pin::new(&mut self.server_writes[index].0).poll(cx)
            {
                let (_, observation, _) =
                    self.server_writes.swap_remove(index);
                if result.is_err() {
                    self.fail_observed(observation.shared());
                }
                observation.complete(result);
            } else {
                index += 1;
            }
        }

        self.server_cursor = if index < self.server_writes.len() {
            cx.waker().wake_by_ref();
            index
        } else {
            0
        };

        for _ in 0..6 {
            let source = self.next_source;
            self.next_source = (source + 1) % 6;
            let event = match source {
                0 => self.poll_timer(cx),
                1 => self
                    .internal
                    .poll_recv(cx)
                    .map(|command| command.map(Event::Command)),
                // The queue ends either because every handle is gone or
                // because a drained shutdown closed it and ran what was left.
                2 => {
                    let stopping = self.stopping;
                    self.commands.poll_recv(cx).map(|command| match command {
                        Some(command) => Some(Event::Command(command)),
                        None if stopping => None,
                        None => Some(Event::Stop),
                    })
                }
                3 => self
                    .tcp
                    .poll_recv(cx)
                    .map(|inbound| inbound.map(Event::Inbound)),
                4 => {
                    let receive = if let Some(udp) = &mut self.udp {
                        udp.poll_flush(cx);
                        match udp.poll_recv(cx) {
                            Poll::Ready(Ok((bytes, flow))) => {
                                Poll::Ready(Some(Event::Datagram(bytes, flow)))
                            }
                            Poll::Ready(Err(_)) => {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Pending => Poll::Pending,
                        }
                    } else {
                        Poll::Pending
                    };

                    while let Some(shared) =
                        self.udp.as_mut().and_then(Datagram::take_failure)
                    {
                        self.fail_observed(&shared);
                    }

                    receive
                }
                _ => self.drops.poll_recv(cx).map(|drop| {
                    drop.map(|(id, route)| Event::Abandon(id, route))
                }),
            };
            if let Poll::Ready(Some(event)) = event {
                return Poll::Ready(event);
            }
        }

        if self.shutting_down && self.is_drained() {
            if self.stopping {
                return Poll::Ready(Event::Drained);
            }
            // A guard taken after `is_drained` looked wins, and its drop wakes
            // the driver again.
            if self.shutdown_control.close_guards_if_idle() {
                self.stopping = true;
                self.commands.close();
                cx.waker().wake_by_ref();
            }
        }

        Poll::Pending
    }

    /// Polls the next transaction or shutdown deadline.
    fn poll_timer(&mut self, cx: &mut Context<'_>) -> Poll<Option<Event>> {
        if let Some(at) = self.timers.deadline() {
            let at = tokio::time::Instant::from_std(at);
            if self.sleep.deadline() != at {
                self.sleep.as_mut().reset(at);
            }
            if self.sleep.as_mut().poll(cx).is_ready() {
                let key = self.timers.pop().expect("peeked");
                return Poll::Ready(Some(Event::Timer(key)));
            }
        }

        Poll::Pending
    }

    /// Returns whether protocol, TU and transport work has drained.
    ///
    /// A transaction counts until its machine reaches Terminated and leaves
    /// the table, whatever its handles and observers do. That includes an
    /// INVITE in Accepted until Timer L or M, and every Completed or Confirmed
    /// entry until its timer. Unread events in `Incoming` do not count, since
    /// reading them is the TU's business, and neither do reply routes and
    /// endpoint handles. A work guard is how the TU says that it has more.
    fn is_drained(&self) -> bool {
        self.servers.len() == 0
            && self.clients.len() == 0
            && self.shutdown_control.guards_idle()
            && self.client_writes.is_empty()
            && self.writes.is_empty()
            && self.server_writes.is_empty()
            && self.live_work_is_drained()
            && self.control_work.is_idle()
            && self.fallback_writes.is_empty()
            && self.unanswered == 0
            && self.udp.as_ref().map_or(true, |udp| udp.is_idle())
            && !self
                .routes
                .values()
                .any(|route| matches!(route.tcp, TcpState::Connecting(_)))
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Reply { link, bytes, completion } => {
                self.on_reply(link, bytes, completion)
            }
            Command::Send {
                request,
                transport,
                next_hop,
                respond,
                permit,
            } => {
                self.on_send(request, transport, next_hop, respond, permit);
            }
            Command::Submit(submission) => self.on_submission(submission),
            Command::Cancel { id, intent, done } => {
                self.on_cancel(id, &intent, done);
            }
            Command::Request { request, target, via, completion } => {
                self.on_oneshot_request(request, target, via, completion);
            }
            Command::Forward { bytes, remote, completion } => {
                self.on_forward(bytes, remote, completion);
            }
            Command::Connected { remote, result, _attempt } => {
                self.on_connected(remote, result);
            }
        }
    }

    /// Takes a shutdown request. A wakeup without one, such as the last work
    /// guard's drop, only makes the driver check whether it has drained.
    fn on_control(&mut self) {
        let Some(deadline) = self.shutdown_control.take() else { return };
        self.client_admission.0.close();
        self.shutting_down = true;
        if let Some(at) = deadline {
            self.timers.push(at, Key::Shutdown);
        }
    }

    fn on_timer(&mut self, key: Key) {
        let now = now();
        let timers = self.config.timers;
        match key {
            Key::Server(id) => {
                let Some(entry) = self.servers.get_mut(id) else { return };
                let before = entry.tx.deadline();
                match &mut entry.tx {
                    // The automatic 100 copies the request's Via, From, To,
                    // Call-ID and CSeq. The request's work reservation covers
                    // those bytes until a final replaces the 100, so it takes
                    // no separate `retained` reservation that could fail.
                    ServerMachine::NonInvite(tx) => {
                        if let Some(trying) = tx.on_timeout(now) {
                            let link = entry.link.clone();
                            let shared = entry
                                .shared
                                .as_ref()
                                .expect("TU transaction")
                                .clone();
                            self.send_generated(id, &link, trying, &shared);
                        }
                    }
                    ServerMachine::Invite(_) => {
                        self.on_invite_server_timer(id, now);
                    }
                }

                self.settle_server(id, before);
            }
            Key::Client(id) => {
                let Some(entry) = self.clients.get_mut(id) else { return };
                let before = entry.deadline();
                let ClientMachine::NonInvite(tx) = &mut entry.tx else {
                    self.on_invite_client_timer(id, before, now);
                    return;
                };
                let completion = match tx.on_timeout(&timers, now) {
                    ClientEvent::Retransmit(request) => {
                        match self.retransmit_client(id, &request) {
                            None => None,
                            Some(err) => {
                                let entry = self
                                    .clients
                                    .get_mut(id)
                                    .expect("a live client entry");
                                entry.tx.end_on_transport_error();
                                entry.answer(Err(Error::transport(err)))
                            }
                        }
                    }
                    ClientEvent::Timeout => {
                        entry.answer(Err(Error::timeout()))
                    }
                    ClientEvent::None
                    | ClientEvent::Provisional(_)
                    | ClientEvent::Final(_) => None,
                };

                if completion.is_some() {
                    self.unanswered -= 1;
                }

                self.settle_client(id, before);
                if let Some((respond, result)) = completion {
                    respond.send(result);
                }
            }
            Key::Shutdown => unreachable!("handled by the loop"),
        }
    }

    /// Retransmits a client request on its link. Returns the error that ends
    /// the transaction, if any.
    fn retransmit_client(
        &mut self,
        id: Id,
        request: &Bytes,
    ) -> Option<io::Error> {
        let entry = self.clients.get(id).expect("a live client entry");
        // Without room for another receipt the retransmission goes out
        // unobserved. Its failure would be one lost datagram, which the next
        // retransmission or the transaction timeout covers.
        let result = if self.client_writes.len()
            < self.config.max_client_transactions
        {
            send_client(self.udp.as_mut(), &entry.link, request, false)
        } else {
            send_on(self.udp.as_mut(), &entry.link, request, false)
                .map(|()| None)
        };
        match result {
            Ok(receipt) => {
                if let (Some(receipt), Some(delivery)) =
                    (receipt, &entry.respond)
                {
                    self.client_writes.push((
                        receipt,
                        id,
                        delivery.observation(),
                    ));
                }
                None
            }
            // A full local write queue is not a transport failure. Skip this
            // retransmission as if UDP had lost it, and keep the transaction.
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => Some(err),
        }
    }

    /// Drops a server transaction that is over, or schedules its next deadline
    /// when it moved.
    fn settle_server(&mut self, id: Id, before: Option<Instant>) {
        let Some(entry) = self.servers.get(id) else { return };
        if entry.tx.is_terminated() {
            if let Some(shared) = &entry.shared {
                shared.finish();
            }
            self.remove_server(id);
            return;
        }

        let after = entry.tx.deadline();
        if after != before {
            if let Some(at) = after {
                self.timers.push(at, Key::Server(id));
            }
        }
    }

    /// Removes a server entry and returns any CANCEL entry it reserved.
    fn remove_server(&mut self, id: Id) {
        if let Some(entry) = self.servers.remove(id) {
            if entry.tx.cancel_reserved() {
                self.reserved_cancels -= 1;
            }
        }
    }

    /// Whether the server table has `entries` free, beside those reserved for
    /// CANCELs.
    fn server_room(&self, entries: usize) -> bool {
        self.servers
            .len()
            .saturating_add(self.reserved_cancels)
            .saturating_add(entries)
            <= self.config.max_server_transactions
    }

    /// See [`Driver::settle_server`].
    fn settle_client(&mut self, id: Id, before: Option<Instant>) {
        let Some(entry) = self.clients.get(id) else { return };
        if entry.is_terminated() {
            let connection =
                entry.link.writer.as_ref().map(tcp::Writer::connection_id);
            let mut entry = self.clients.remove(id).expect("found above");
            // An INVITE that received a 2xx ends its stream at Timer M,
            // without an error. Every other end delivered its outcome first.
            if let ClientMachine::Invite(invite) = &mut entry.tx {
                invite.cancel_not_needed();
                if let Some(delivery) = entry.respond.take() {
                    delivery.end();
                }
            }
            if let Some(connection) = connection {
                let count = self
                    .client_connections
                    .get_mut(&connection)
                    .expect("a counted client connection");
                *count -= 1;
                if *count == 0 {
                    self.client_connections.remove(&connection);
                }
            }
            return;
        }

        let after = entry.deadline();
        if after != before {
            if let Some(at) = after {
                self.timers.push(at, Key::Client(id));
            }
        }
    }

    fn on_send(
        &mut self,
        request: Request<Bytes>,
        transport: Transport,
        next_hop: SocketAddr,
        respond: Starting,
        permit: Permit,
    ) {
        if self.shutting_down {
            drop(request);
            drop(permit);
            respond.send(Err(Error::closed()));
            return;
        }

        match transport {
            Transport::Udp => {
                let Some(udp) = &self.udp else {
                    let err = io::Error::new(
                        io::ErrorKind::Unsupported,
                        "the endpoint has no UDP socket",
                    );
                    drop(request);
                    drop(permit);
                    respond.send(Err(Error::transport(err)));
                    return;
                };
                let port = udp.local_addr().port();
                let source = match self.udp_source(next_hop) {
                    Ok(source) => source,
                    Err(err) => {
                        drop(request);
                        drop(permit);
                        respond.send(Err(Error::transport(err)));
                        return;
                    }
                };
                let flow = Flow {
                    transport,
                    local: SocketAddr::new(source, port),
                    remote: next_hop,
                };
                self.start_client(
                    request,
                    Link { flow, writer: None },
                    respond,
                    permit,
                );
            }
            Transport::Tcp => {
                self.send_over_tcp(
                    next_hop,
                    Pending::Request(request, respond, permit),
                );
            }
        }
    }

    /// Sends `pending` to `remote` over the connection the driver has to it,
    /// or over one it opens now.
    fn send_over_tcp(&mut self, remote: SocketAddr, pending: Pending) -> bool {
        let response = pending.is_protocol_work();
        if !self.admit_route(remote, response) {
            self.reject_pending(pending);
            return false;
        }
        let route = self.routes.entry(remote).or_default();
        match &mut route.tcp {
            TcpState::Open(flow, writer) if !writer.is_closed() => {
                let (flow, writer) = (*flow, writer.clone());
                self.deliver(pending, flow, writer);
            }
            TcpState::Connecting(waiting) => waiting.push(pending),
            TcpState::Closed | TcpState::Open(..) => {
                let (connections, attempts) = if response {
                    (&self.response_connections, &self.response_connects)
                } else {
                    (&self.outbound, &self.connects)
                };
                let connection = connections.clone().try_acquire_owned();
                let attempt = attempts.acquire(0);
                let (Ok(connection), Some(attempt)) = (connection, attempt)
                else {
                    self.reject_pending(pending);
                    return false;
                };
                route.tcp = TcpState::Connecting(vec![pending]);
                self.spawn_connect(remote, connection, attempt);
            }
        }
        true
    }

    fn spawn_connect(
        &self,
        remote: SocketAddr,
        connection: tokio::sync::OwnedSemaphorePermit,
        attempt: crate::transport::budget::Permit,
    ) {
        let config = self.config.tcp;
        let deadline = self.config.connect_timeout;
        let inbound = self.tcp_tx.clone();
        let internal = self.internal_tx.clone();
        let teardown = self.tasks.handle();
        tokio::spawn(async move {
            let connect = tcp::connect_reserved(
                remote,
                &config,
                &inbound,
                Some(connection),
                &teardown,
            );
            let result = connect_until(connect, &inbound, deadline).await;
            let _ = internal.send(Command::Connected {
                remote,
                result,
                _attempt: attempt,
            });
        });
    }

    // New client destinations cannot consume the response reserve. Cache
    // entries are only hints. Eviction never invalidates a transaction Link.
    fn admit_route(&mut self, remote: SocketAddr, response: bool) -> bool {
        if self.routes.contains_key(&remote) {
            return true;
        }
        let limit = self.config.max_routes.saturating_add(if response {
            REPLY_OPERATIONS
        } else {
            0
        });
        if limit == 0 {
            return false;
        }
        if self.routes.len() >= limit {
            let stale =
                self.routes.iter().find_map(|(key, route)| match &route.tcp {
                    TcpState::Closed => Some(*key),
                    TcpState::Open(_, writer) if writer.is_closed() => {
                        Some(*key)
                    }
                    _ => None,
                });
            if let Some(key) = stale {
                self.routes.remove(&key);
            }
        }
        self.routes.len() < limit
    }

    fn reject_pending(&mut self, pending: Pending) {
        increment(&self.connection_stats.rejected);
        match pending {
            Pending::Request(request, respond, permit) => {
                drop(request);
                drop(permit);
                respond.send(Err(Error::busy()));
            }
            Pending::Response(..) | Pending::Ack(_) => {}
            // Server output reserves its route and connection before commit
            // and never passes through `send_over_tcp`. Refusing it here
            // would be a rejection, not a transport failure.
            Pending::Server(_, observation, _) => observation.reject(),
            Pending::OneShot(bytes, completion) => {
                drop(bytes);
                completion.finish(Err(ReplyError::Busy));
            }
            Pending::OneShotRequest(request, _, completion) => {
                drop(request);
                completion.finish(Err(ReplyError::Busy));
            }
            Pending::Cancel(start) => {
                if let Some(done) = start.done {
                    let _ = done.send(Err(CancelError::Busy));
                }
            }
        }
    }

    /// Sends `pending` on an open connection.
    fn deliver(&mut self, pending: Pending, flow: Flow, writer: tcp::Writer) {
        match pending {
            Pending::Request(request, respond, permit) => {
                let link = Link { flow, writer: Some(writer) };
                self.start_client(request, link, respond, permit);
            }
            // A response that cannot be queued is lost. The connection is full
            // or gone again, and a server transaction over TCP has nothing to
            // retransmit it with.
            Pending::OneShot(bytes, completion) => {
                match writer.submit(bytes) {
                    Ok(receipt) => self.writes.push((receipt, completion)),
                    Err(error) => completion.finish(Err(match error {
                        tcp::SendError::Full => ReplyError::Busy,
                        tcp::SendError::Closed => ReplyError::Transport(
                            io::Error::new(io::ErrorKind::BrokenPipe, error),
                        ),
                    })),
                }
            }
            Pending::Server(bytes, observation, permit) => {
                match writer.submit(bytes) {
                    Ok(receipt) => self.server_writes.push((
                        receipt,
                        observation,
                        Some(permit),
                    )),
                    Err(error) => {
                        self.fail_observed(observation.shared());
                        observation.complete(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            error,
                        )));
                    }
                }
            }
            Pending::Response(bytes, permit) => {
                if let Ok(receipt) = writer.submit(bytes) {
                    self.fallback_writes.push((receipt, permit));
                }
            }
            // A lost ACK over TCP is like one lost over UDP. The server
            // retransmits its final response until Timer H.
            Pending::Ack(bytes) => {
                let _ = writer.send(bytes);
            }
            Pending::Cancel(start) => {
                self.start_cancel(start, Link { flow, writer: Some(writer) });
            }
            Pending::OneShotRequest(request, via, completion) => {
                self.send_oneshot(
                    request,
                    Link { flow, writer: Some(writer) },
                    via,
                    completion,
                );
            }
        }
    }

    // Builds a route outside `on_request`, for the benchmark hook and tests.
    // Incoming envelopes get theirs when the driver admits the request. The
    // socket tests that call it are skipped under Miri.
    #[cfg_attr(
        not(any(all(test, not(miri)), feature = "__bench")),
        allow(dead_code)
    )]
    pub(super) fn prepare_reply(
        &self,
        mut request: Request<Bytes>,
        mut link: Link,
    ) -> Result<(Request<Bytes>, ReplyRoute), ReplyError> {
        let value =
            request.headers().get(VIA).ok_or(ReplyError::Unsupported)?;
        let via = Via::top(value).ok_or(ReplyError::Unsupported)?;
        // Multicast routing needs different socket and TTL semantics.
        if via.maddr.is_some() {
            return Err(ReplyError::Unsupported);
        }

        let corrected = mark_via(value, &via, &link.flow);
        link.flow = reply_flow(&via, &link.flow);

        if let Some(value) = corrected {
            *request.headers_mut().get_mut(VIA).expect("validated top Via") =
                value;
        }

        let route = ReplyRoute::new(
            &request,
            link,
            self.command_sender.upgrade().ok_or(ReplyError::Closed)?,
            self.reply_admission.0.clone(),
            self.reply_bytes.clone(),
        );

        Ok((request, route))
    }

    fn on_reply(&mut self, link: Link, bytes: Bytes, completion: Completion) {
        if let Some(writer) = &link.writer {
            match writer.submit(bytes.clone()) {
                Ok(receipt) => self.writes.push((receipt, completion)),
                Err(tcp::SendError::Full) => {
                    drop(bytes);
                    completion.finish(Err(ReplyError::Busy))
                }
                Err(tcp::SendError::Closed) => {
                    self.send_over_tcp(
                        link.flow.remote,
                        Pending::OneShot(bytes, completion),
                    );
                }
            }
        } else if let Some(udp) = self.udp.as_mut() {
            udp.submit(bytes, link.flow, completion);
        } else {
            drop(bytes);
            completion.finish(Err(ReplyError::Transport(io::Error::new(
                io::ErrorKind::NotConnected,
                "no UDP socket",
            ))));
        }
    }

    /// Sends a TU request once, without a transaction. See
    /// `Endpoint::send_request`.
    fn on_oneshot_request(
        &mut self,
        request: Request<Bytes>,
        target: Target,
        via: ViaMode,
        completion: Completion,
    ) {
        match target.transport() {
            Transport::Udp => match self.udp_flow(target.address()) {
                Ok(flow) => self.send_oneshot(
                    request,
                    Link { flow, writer: None },
                    via,
                    completion,
                ),
                Err(error) => completion.fail(error),
            },
            Transport::Tcp => {
                self.send_over_tcp(
                    target.address(),
                    Pending::OneShotRequest(request, via, completion),
                );
            }
        }
    }

    /// Writes a forwarded response once, over UDP. See
    /// `Endpoint::forward_response`.
    fn on_forward(
        &mut self,
        bytes: Bytes,
        remote: SocketAddr,
        completion: Completion,
    ) {
        match self.udp_flow(remote) {
            Ok(flow) => self
                .udp
                .as_mut()
                .expect("`udp_flow` found a socket")
                .submit(bytes, flow, completion),
            Err(error) => completion.fail(error),
        }
    }

    /// The UDP flow from this endpoint's socket to `remote`.
    fn udp_flow(&mut self, remote: SocketAddr) -> Result<Flow, Error> {
        let Some(udp) = &self.udp else {
            return Err(Error::unsupported_routing());
        };
        let port = udp.local_addr().port();
        let source = self.udp_source(remote).map_err(Error::transport)?;

        Ok(Flow {
            transport: Transport::Udp,
            local: SocketAddr::new(source, port),
            remote,
        })
    }

    /// Adds the Via that `via` asks for on `link` and writes the request once.
    fn send_oneshot(
        &mut self,
        mut request: Request<Bytes>,
        link: Link,
        via: ViaMode,
        mut completion: Completion,
    ) {
        let sent_by = sent_by(&link.flow, self.config.tcp_listener);
        let via = match via {
            ViaMode::Fresh => {
                via_value(link.flow.transport, sent_by, &mut self.branches)
            }
            ViaMode::Branch(branch) => {
                via_value_with(link.flow.transport, sent_by, branch.as_str())
            }
        };
        request.headers_mut().prepend(VIA, via.clone());
        let bytes = request.to_bytes();
        drop(request);
        if link.writer.is_none() && bytes.len() > MAX_UDP_REQUEST {
            completion.fail(Error::too_large(bytes.len()));
            return;
        }

        completion.sent(via, link.flow);
        match &link.writer {
            Some(writer) => match writer.submit(bytes) {
                Ok(receipt) => self.writes.push((receipt, completion)),
                Err(tcp::SendError::Full) => {
                    completion.finish(Err(ReplyError::Busy));
                }
                Err(error @ tcp::SendError::Closed) => {
                    completion.finish(Err(ReplyError::Transport(
                        io::Error::new(io::ErrorKind::BrokenPipe, error),
                    )));
                }
            },
            None => self
                .udp
                .as_mut()
                .expect("a UDP link has a socket")
                .submit(bytes, link.flow, completion),
        }
    }

    /// Sends a response, or anything else that goes the way a response does,
    /// along `link`.
    ///
    /// When the request's TCP connection has closed since, the response goes
    /// to `sent-by` on a new connection, as RFC 3261 section 18.2.2 says a
    /// server SHOULD. The target is in `link` already, see [`reply_flow`].
    /// If that connection cannot be opened the response is lost. The RFC then
    /// asks for RFC 3263 to find another address, which is out of scope.
    fn send_reply(&mut self, link: &Link, bytes: &Bytes) -> io::Result<()> {
        match send_on(self.udp.as_mut(), link, bytes, false) {
            Err(err)
                if err.kind() == io::ErrorKind::BrokenPipe
                    && link.writer.is_some() =>
            {
                let target = link.flow.remote;
                let Some(permit) = self.fallback.acquire(bytes.len()) else {
                    increment(&self.connection_stats.dropped);
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "response fallback budget is full",
                    ));
                };
                if self.send_over_tcp(
                    target,
                    Pending::Response(
                        bytes.clone(),
                        Fallback {
                            _permit: permit,
                            stats: self.connection_stats.clone(),
                            written: false,
                        },
                    ),
                ) {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "connection admission is full",
                    ))
                }
            }
            result => result,
        }
    }

    /// The address the UDP socket sends to `remote` from, which goes into the
    /// `Via`. It is the socket's own unless that is a wildcard, in which case
    /// the kernel's route to `remote` says, found once per next hop.
    fn udp_source(&mut self, remote: SocketAddr) -> io::Result<IpAddr> {
        let bound = self
            .udp
            .as_ref()
            .expect("checked by the caller")
            .local_addr()
            .ip();
        if !bound.is_unspecified() {
            return Ok(bound);
        }

        if let Some(source) =
            self.routes.get(&remote).and_then(|route| route.udp_source)
        {
            return Ok(source);
        }

        let source = source_toward(remote)?;
        if self.admit_route(remote, false) {
            self.routes.entry(remote).or_default().udp_source = Some(source);
        }

        Ok(source)
    }

    /// Adds the `Via`, starts the transaction, and sends the request.
    fn start_client(
        &mut self,
        mut request: Request<Bytes>,
        link: Link,
        respond: Starting,
        permit: Permit,
    ) {
        // The command owns capacity reserved before enqueue and connect.
        debug_assert!(
            self.clients.len() < self.config.max_client_transactions
        );
        let via = via_value(
            link.flow.transport,
            sent_by(&link.flow, self.config.tcp_listener),
            &mut self.branches,
        );
        request.headers_mut().prepend(VIA, via.clone());
        let key = ClientKey::from_request(&request)
            .expect("the Via signa wrote has a branch");
        let bytes = request.to_bytes();
        if link.flow.transport == Transport::Udp
            && bytes.len() > MAX_UDP_REQUEST
        {
            let error = Error::too_large(bytes.len());
            drop(request);
            drop(bytes);
            drop(permit);
            respond.send(Err(error));
            return;
        }

        if self.client_writes.len() >= self.config.max_client_transactions {
            drop(permit);
            respond.send(Err(Error::busy()));
            return;
        }

        // The machine copies what it keeps before anything is sent. `start`
        // checked what an INVITE's machine reads, and the Via is the
        // endpoint's own.
        let reliable = link.flow.transport.is_reliable();
        let timers = self.config.timers;
        let (accepted, observing, reserved) = respond.split();
        let (tx, intent) = if request.method() == Method::INVITE {
            let tx = invite::ClientTransaction::from_encoded(
                &request,
                bytes.clone(),
                reliable,
                &timers,
                now(),
            )
            .expect("start validated the INVITE");
            let intent = Arc::<Intent>::default();
            let invite = InviteClient {
                tx,
                answered: false,
                cancel: reserved.map_or(Cancel::Done, Cancel::Reserved),
                intent: intent.clone(),
                cancel_deadline: None,
            };
            (ClientMachine::Invite(Box::new(invite)), Some(intent))
        } else {
            let tx = ClientTransaction::new(
                bytes.clone(),
                reliable,
                &timers,
                now(),
            );
            (ClientMachine::NonInvite(tx), None)
        };
        drop(request);

        let receipt = match send_client(self.udp.as_mut(), &link, &bytes, true)
        {
            Ok(receipt) => receipt,
            Err(err) => {
                drop((tx, permit));
                let _ = accepted.send(Err(
                    if err.kind() == io::ErrorKind::WouldBlock {
                        Error::busy()
                    } else {
                        Error::transport(err)
                    },
                ));
                return;
            }
        };

        let delivery = observing.delivery();
        let observation = delivery.observation();
        let flow = link.flow;
        if let Some(writer) = &link.writer {
            *self
                .client_connections
                .entry(writer.connection_id())
                .or_default() += 1;
        }
        let entry = ClientEntry { tx, link, respond: Some(delivery), permit };
        let deadline = entry.deadline();
        let id = self.clients.insert(key, entry);
        if let Some(receipt) = receipt {
            self.client_writes.push((receipt, id, observation));
        }
        if let Some(at) = deadline {
            self.timers.push(at, Key::Client(id));
        }
        self.unanswered += 1;

        let cancel = intent.map(|intent| CancelHandle::new(id, intent));
        let _ = accepted.send(Ok(observing.finish(via, flow, cancel)));
    }

    fn on_connected(
        &mut self,
        remote: SocketAddr,
        result: io::Result<(Flow, tcp::Writer)>,
    ) {
        let Some(route) = self.routes.get_mut(&remote) else { return };
        let pending = match mem::take(&mut route.tcp) {
            TcpState::Connecting(pending) => pending,
            other => {
                route.tcp = other;
                return;
            }
        };

        match result {
            Ok((flow, writer)) => {
                route.tcp = TcpState::Open(flow, writer.clone());
                for pending in pending {
                    self.deliver(pending, flow, writer.clone());
                }
            }
            Err(err) => {
                let source = Arc::new(err);

                for pending in pending {
                    match pending {
                        Pending::Request(request, respond, permit) => {
                            let err = io::Error::new(
                                source.kind(),
                                Arc::clone(&source),
                            );
                            drop(request);
                            drop(permit);
                            respond.send(Err(Error::transport(err)));
                        }
                        // See `send_reply` and `Driver::send_ack`.
                        Pending::Response(..) | Pending::Ack(_) => {}
                        Pending::Cancel(start) => {
                            if let Some(done) = start.done {
                                let _ = done.send(Err(
                                    CancelError::Transport(io::Error::new(
                                        source.kind(),
                                        Arc::clone(&source),
                                    )),
                                ));
                            }
                        }
                        Pending::OneShotRequest(_, _, completion) => {
                            completion.finish(Err(ReplyError::Transport(
                                io::Error::new(
                                    source.kind(),
                                    Arc::clone(&source),
                                ),
                            )));
                        }
                        Pending::Server(_, observation, _) => {
                            self.fail_observed(observation.shared());
                            observation.complete(Err(io::Error::new(
                                source.kind(),
                                source.clone(),
                            )));
                        }
                        Pending::OneShot(_, completion) => {
                            completion.finish(Err(ReplyError::Transport(
                                io::Error::new(
                                    source.kind(),
                                    Arc::clone(&source),
                                ),
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Fails the client transactions on a TCP connection that has closed,
    /// unless their `Via` advertises the listener.
    ///
    /// A server whose connection has closed sends the response on a new one to
    /// the `sent-by` (RFC 3261 section 18.2.2). With the listener there, the
    /// transaction keeps waiting, and Timer F ends it if nothing comes. An
    /// INVITE in Proceeding has no such timer. I leave it waiting without a
    /// notice, for its final or the TU's CANCEL, since the TU applies its own
    /// ringing limit anyway and a notice would not change what it must do.
    /// Without it nothing can come, so the transaction fails now rather than
    /// after 64*T1. Client links are always connections the driver opened, so
    /// the closed connection's flow decides for all of its transactions.
    /// Another connection to the same address keeps its transactions either
    /// way.
    fn on_connection_closed(&mut self, link: &Link) {
        if sent_by(&link.flow, self.config.tcp_listener) != link.flow.local {
            return;
        }
        let writer = link.writer.as_ref().expect("a TCP link has a writer");
        let Some(&count) =
            self.client_connections.get(&writer.connection_id())
        else {
            return;
        };
        let ids: Vec<_> = self
            .clients
            .iter()
            .filter_map(|(id, entry)| {
                entry
                    .link
                    .writer
                    .as_ref()
                    .filter(|other| writer.same_connection(other))
                    .map(|_| id)
            })
            .take(count)
            .collect();
        for id in ids {
            self.fail_client(
                id,
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TCP connection closed",
                ),
            );
        }
    }

    /// Ends a live client transaction whose request could not be written.
    ///
    /// An INVITE in Accepted keeps its state for Timer M, since a write
    /// error cannot remove what RFC 6026 retains for forked 2xx responses.
    fn fail_client(&mut self, id: Id, error: io::Error) {
        let entry = self.clients.get_mut(id).expect("a live client entry");
        let completion = match &mut entry.tx {
            ClientMachine::NonInvite(tx) => {
                tx.on_transport_error();
                let completion = entry.answer(Err(Error::transport(error)));
                if completion.is_some() {
                    self.unanswered -= 1;
                }
                completion
            }
            ClientMachine::Invite(invite) => {
                if let invite::ClientEvent::TransportError =
                    invite.tx.on_transport_error()
                {
                    invite.cancel_not_needed();
                    invite.cancel_deadline = None;
                    if invite.mark_answered() {
                        self.unanswered -= 1;
                    }
                    entry.answer(Err(Error::transport(error)))
                } else {
                    None
                }
            }
        };

        self.settle_client(id, None);
        if let Some((delivery, result)) = completion {
            delivery.send(result);
        }
    }

    fn on_message(&mut self, message: Message<Bytes>, link: Link) {
        match (self.config.reception, message) {
            (Reception::Stateful, Message::Request(request)) => {
                self.on_request(request, link)
            }
            (Reception::Stateful, Message::Response(response)) => {
                self.on_received_response(response)
            }
            (Reception::Stateless, Message::Request(request)) => {
                self.on_stateless_request(request, link)
            }
            (Reception::Stateless, Message::Response(response)) => {
                self.on_stateless_response(response, link.flow)
            }
        }
    }

    /// Returns the live client transaction under `key`, after running its
    /// timer if that is due by `now`. A timer and a message at the same
    /// instant take that order, so a response at Timer M is stray.
    fn find_client(&mut self, key: &ClientKey, now: Instant) -> Option<Id> {
        let (id, entry) = self.clients.find(key)?;
        if entry.deadline().is_some_and(|at| at <= now) {
            self.on_timer(Key::Client(id));
        }
        self.clients.get(id).map(|_| id)
    }

    /// See [`Driver::find_client`].
    fn find_server(&mut self, key: &ServerKey, now: Instant) -> Option<Id> {
        let (id, entry) = self.servers.find(key)?;
        if entry.tx.deadline().is_some_and(|at| at <= now) {
            self.on_timer(Key::Server(id));
        }
        self.servers.get(id).map(|_| id)
    }

    /// Delivers a response to its client transaction. One that matches none
    /// is stray and discarded ([RFC 6026 section 8.9]).
    ///
    /// [RFC 6026 section 8.9]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.9
    fn on_received_response(&mut self, response: Response<Bytes>) {
        let Some(key) = ClientKey::from_response(&response) else { return };
        let now = now();
        let Some(id) = self.find_client(&key, now) else { return };
        let entry = self.clients.get_mut(id).expect("found above");
        // RFC 3261 section 18.1.2 discards a response whose top `Via` names
        // a `sent-by` other than this one's. Over TCP the response may come
        // on any connection, including one the server opened to the listener.
        let ours = response.headers().get(VIA).and_then(Via::top).is_some_and(
            |via| {
                sent_by_is(
                    &via,
                    sent_by(&entry.link.flow, self.config.tcp_listener),
                )
            },
        );
        if !ours {
            return;
        }

        let before = entry.deadline();
        let ClientMachine::NonInvite(tx) = &mut entry.tx else {
            self.on_invite_response(id, response, before, now);
            return;
        };
        let completion =
            match tx.on_response(response, &self.config.timers, now) {
                ClientEvent::Final(response) => entry.answer(Ok(response)),
                ClientEvent::Provisional(response) => {
                    if let Some(delivery) = &entry.respond {
                        delivery.response(response);
                    }
                    None
                }
                ClientEvent::None
                | ClientEvent::Retransmit(_)
                | ClientEvent::Timeout => None,
            };
        if completion.is_some() {
            self.unanswered -= 1;
        }
        self.settle_client(id, before);
        if let Some((respond, result)) = completion {
            respond.send(result);
        }
    }

    fn on_request(&mut self, mut request: Request<Bytes>, link: Link) {
        // Without a readable top `Via` there is no way to answer, so there
        // is nothing to do with the request.
        let Some(value) = request.headers().get(VIA) else { return };
        let Some(via) = Via::top(value) else { return };
        // RFC 3261 section 18.2.2 sends the response to `maddr`, normally a
        // multicast group. signa does not support multicast, and answering
        // the source instead would break that rule, so the request is dropped.
        if via.maddr.is_some() {
            return;
        }
        let reply = reply_flow(&via, &link.flow);
        let marked = mark_via(value, &via, &link.flow);
        // An ACK matches the INVITE it acknowledges (RFC 3261 section
        // 17.2.3). Every other request matches its own method.
        let method = request.method().clone();
        let key = ServerKey::new(
            &via,
            if method == Method::ACK { &Method::INVITE } else { &method },
        );

        // The `Via` the request goes up with, and that every response carries,
        // has `received` and `rport` filled in (RFC 3261 section 18.2.1,
        // RFC 3581).
        if let Some(marked) = marked {
            *request.headers_mut().get_mut(VIA).expect("found above") = marked;
        }
        // The envelope describes where the request came from. The link keeps
        // where the response goes, which differs in the port without `rport`.
        let source = link.flow;
        let link = Link { flow: reply, writer: link.writer };
        let now = now();

        // No path below answers an ACK, including overload and shutdown.
        if method == Method::ACK {
            self.on_ack(request, key.as_ref(), source, now);
            return;
        }

        if let Some(key) = &key {
            if let Some(id) = self.find_server(key, now) {
                self.on_retransmission(id);
                return;
            }
        }

        // Stateful TU responses need a usable identity, not only a Via route.
        // A request without exactly one From, To, Call-ID and CSeq, or with a
        // CSeq method other than its own, stays out of transaction and
        // application work. It gets a stateless 400 so that a UDP client stops
        // retransmitting instead of waiting for Timer F. The 400 copies what
        // identity there is, and uses the same bounded reply path as the 503.
        if !has_identity(&request) {
            self.stateless(&request, &link, BAD_REQUEST);
            return;
        }

        // A CANCEL that is not a retransmission looks for its target
        // (RFC 3261 section 9.2). One without a target gets no transaction
        // and no automatic 481. That is the TU's choice, since a stateful
        // proxy may forward it instead (section 16.10).
        if method == Method::CANCEL {
            if let Some(key) = &key {
                if let Some(target) = self.find_cancel_target(key, now) {
                    let key = key.clone();
                    self.on_matched_cancel(request, key, target, source, link);
                    return;
                }
            }
        }
        let tracked = key.is_some() && method != Method::CANCEL;
        let unmatched_cancel = key.is_some() && method == Method::CANCEL;

        // Overload and shutdown answer with a stateless 503, so the peer stops
        // retransmitting and can try elsewhere. Not reading the socket instead
        // would stall every flow on a TCP connection, including the responses
        // to this endpoint's own requests on it. An INVITE needs a second
        // entry, for the CANCEL it may get.
        let entries = if method == Method::INVITE { 2 } else { 1 };
        if self.incoming.is_closed()
            || self.shutting_down
            || (tracked && !self.server_room(entries))
        {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        }

        let Some(bytes) = super::admission::request_bytes(&request) else {
            return;
        };
        let Some(event_permit) = self.event_admission.acquire(bytes) else {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        };
        let Some(permit) = self.work.acquire(bytes) else {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        };
        let Some(route_permit) = identity_bytes(&request)
            .and_then(|bytes| self.routes_admission.acquire(bytes))
        else {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        };

        let Some(commands) = self.command_sender.upgrade() else { return };

        let event = match key.filter(|_| tracked) {
            Some(key) => {
                let reliable = link.flow.transport.is_reliable();
                // The 100 goes out only after every admission check, so a
                // refused INVITE gets a 503 and nothing before it
                // (RFC 3261 section 17.2.1).
                let (tx, trying) = if method == Method::INVITE {
                    let (tx, trying) =
                        invite::ServerTransaction::new(&request, reliable);
                    let invite = InviteServer { tx, cancel_reserved: true };
                    (ServerMachine::Invite(Box::new(invite)), Some(trying))
                } else {
                    let tx = ServerTransaction::new(
                        &request,
                        reliable,
                        &self.config.timers,
                        now,
                    );
                    (ServerMachine::NonInvite(tx), None)
                };
                let (id, transaction) = self.install_server(
                    key,
                    tx,
                    link,
                    &request,
                    permit,
                    route_permit,
                    commands,
                );
                if let Some(trying) = trying {
                    let entry = self.servers.get(id).expect("new transaction");
                    let link = entry.link.clone();
                    let shared =
                        entry.shared.clone().expect("a new TU transaction");
                    self.send_generated(id, &link, trying, &shared);
                }

                IncomingEvent::Request(ServerRequest {
                    request,
                    flow: source,
                    transaction,
                })
            }
            None => {
                let route = ReplyRoute::new(
                    &request,
                    link,
                    commands,
                    self.reply_admission.0.clone(),
                    self.reply_bytes.clone(),
                )
                .with_reservations(
                    route_permit,
                    Some(server::Work::new(permit)),
                );
                let received =
                    ReceivedRequest { request, flow: source, reply: route };
                if unmatched_cancel {
                    IncomingEvent::UnmatchedCancel(received)
                } else {
                    IncomingEvent::Untracked(received)
                }
            }
        };
        let _ = self
            .incoming
            .send(server::Queued { event, _permit: event_permit });
    }

    /// Answers a request retransmission from its transaction's cache.
    fn on_retransmission(&mut self, id: Id) {
        let entry = self.servers.get(id).expect("a live server entry");
        let Some(response) = entry.tx.on_retransmission() else { return };
        let link = entry.link.clone();
        if let Some(shared) = entry.shared.clone() {
            self.send_generated(id, &link, response, &shared);
        } else {
            // An unobserved Completed entry has no observer to tell. A busy
            // budget only drops this copy, as in `send_generated`.
            match self.send_reply(&link, &response) {
                Err(error) if error.kind() != io::ErrorKind::WouldBlock => {
                    self.fail_server(id);
                }
                _ => {}
            }
        }
    }

    /// Installs a server transaction and returns its TU handles.
    #[allow(clippy::too_many_arguments)]
    fn install_server(
        &mut self,
        key: ServerKey,
        tx: ServerMachine,
        link: Link,
        request: &Request<Bytes>,
        work: crate::transport::budget::Permit,
        route: crate::transport::budget::Permit,
        commands: mpsc::UnboundedSender<Command>,
    ) -> (Id, server::ServerTransaction) {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let transaction_id =
            ServerTransactionId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let cancel_reserved = tx.cancel_reserved();
        let deadline = tx.deadline();
        let reply = ReplyRoute::new(
            request,
            link.clone(),
            commands.clone(),
            self.reply_admission.0.clone(),
            self.reply_bytes.clone(),
        );
        let id = self.servers.insert(
            key,
            ServerEntry {
                tx,
                link,
                shared: None,
                id: transaction_id,
                retained: None,
            },
        );
        if cancel_reserved {
            self.reserved_cancels += 1;
        }
        if let Some(at) = deadline {
            self.timers.push(at, Key::Server(id));
        }

        let (observation, receiver) =
            watch::channel(server::Observation::default());
        let shared = Arc::new(server::Shared {
            id: transaction_id,
            slot: id,
            work: server::Work::new(work),
            pending: AtomicUsize::new(0),
            next_operation: AtomicU64::new(1),
            final_sent: AtomicBool::new(false),
            accepted: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            observation,
            transport: AtomicUsize::new(0),
            terminated: AtomicBool::new(false),
        });
        self.servers.get_mut(id).expect("new transaction").shared =
            Some(shared.clone());
        let responder = server::Responder {
            shared,
            route: reply.with_reservations(route, None),
            method: request.method().clone(),
            commands,
            drops: self.drop_sender.clone(),
            submissions: self.submissions.clone(),
        };
        let transaction = server::ServerTransaction {
            responder,
            events: server::ServerEvents {
                id: transaction_id,
                receiver,
                seen: 0,
                ended: false,
                saw_ack_timeout: false,
                saw_termination: false,
            },
        };

        (id, transaction)
    }

    /// Sends a response the endpoint makes itself, without a transaction.
    fn stateless(
        &mut self,
        request: &Request<Bytes>,
        link: &Link,
        status: StatusCode,
    ) {
        let response =
            bare_response(&reply_headers(request.headers()), status);
        let _ = self.send_reply(link, &response);
    }

    fn prepare_server_output(
        &mut self,
        link: &Link,
        bytes: Bytes,
    ) -> Result<PreparedServerOutput, SubmitError> {
        let Some(writer) = &link.writer else {
            let udp = self.udp.as_ref().ok_or(SubmitError::Closed)?;
            udp.admit_response(bytes.len())
                .map_err(|_| SubmitError::TransportBusy)?;
            return Ok(PreparedServerOutput::Udp(bytes, link.flow));
        };
        match writer.prepare(bytes.clone()) {
            Ok(write) => return Ok(PreparedServerOutput::Tcp(write, None)),
            Err(tcp::SendError::Full) => {
                return Err(SubmitError::TransportBusy)
            }
            Err(tcp::SendError::Closed) => {}
        }

        let fallback = self
            .fallback
            .acquire(bytes.len())
            .ok_or(SubmitError::TransportBusy)?;

        let remote = link.flow.remote;
        if !self.admit_route(remote, true) {
            increment(&self.connection_stats.rejected);
            return Err(SubmitError::TransportBusy);
        }

        match &self.routes.entry(remote).or_default().tcp {
            TcpState::Open(_, writer) if !writer.is_closed() => {
                let write = writer
                    .prepare(bytes)
                    .map_err(|_| SubmitError::TransportBusy)?;

                Ok(PreparedServerOutput::Tcp(write, Some(fallback)))
            }
            TcpState::Connecting(_) => {
                Ok(PreparedServerOutput::Waiting { remote, bytes, fallback })
            }
            _ => {
                let connection = self
                    .response_connections
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        increment(&self.connection_stats.rejected);
                        SubmitError::TransportBusy
                    })?;
                let attempt =
                    self.response_connects.acquire(0).ok_or_else(|| {
                        increment(&self.connection_stats.rejected);
                        SubmitError::TransportBusy
                    })?;
                Ok(PreparedServerOutput::Connect {
                    remote,
                    bytes,
                    fallback,
                    connection,
                    attempt,
                })
            }
        }
    }

    fn commit_server_output(
        &mut self,
        output: PreparedServerOutput,
        shared: &Arc<server::Shared>,
        operation: Option<server::ResponseId>,
    ) -> bool {
        let observation = shared.write(operation);
        match output {
            PreparedServerOutput::Tcp(write, fallback) => {
                let observation = if fallback.is_some() {
                    observation.fallback(self.connection_stats.clone())
                } else {
                    observation
                };
                match write.submit() {
                    Ok(receipt) => self.server_writes.push((
                        receipt,
                        observation,
                        fallback,
                    )),
                    Err(error) => {
                        observation.complete(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            error,
                        )));
                        return false;
                    }
                }
            }
            PreparedServerOutput::Udp(bytes, flow) => {
                return self
                    .udp
                    .as_mut()
                    .expect("prepared UDP socket")
                    .send_admitted(bytes, flow, observation);
            }
            PreparedServerOutput::Waiting { remote, bytes, fallback } => {
                let TcpState::Connecting(waiting) = &mut self
                    .routes
                    .get_mut(&remote)
                    .expect("prepared route")
                    .tcp
                else {
                    unreachable!(
                        "driver does not yield between preparation and commit"
                    );
                };
                waiting.push(Pending::Server(
                    bytes,
                    observation.fallback(self.connection_stats.clone()),
                    fallback,
                ));
            }
            PreparedServerOutput::Connect {
                remote,
                bytes,
                fallback,
                connection,
                attempt,
            } => {
                self.routes.get_mut(&remote).expect("prepared route").tcp =
                    TcpState::Connecting(vec![Pending::Server(
                        bytes,
                        observation.fallback(self.connection_stats.clone()),
                        fallback,
                    )]);
                self.spawn_connect(remote, connection, attempt);
            }
        }
        true
    }

    /// Sends driver-generated server output: the automatic 100, or a cached
    /// response for a request retransmission.
    ///
    /// Local saturation only drops this attempt. The machine keeps its cached
    /// response, so the peer's next retransmission recovers it. Terminating
    /// instead would let that retransmission start a new transaction and
    /// reach the TU a second time.
    fn send_generated(
        &mut self,
        id: Id,
        link: &Link,
        bytes: Bytes,
        shared: &Arc<server::Shared>,
    ) {
        let fallback =
            link.writer.as_ref().is_some_and(tcp::Writer::is_closed);
        match self.prepare_server_output(link, bytes) {
            Ok(output) => {
                if !self.commit_server_output(output, shared, None) {
                    self.fail_server(id);
                }
            }
            Err(_) => {
                if fallback {
                    increment(&self.connection_stats.dropped);
                }
                shared.rejected();
            }
        }
    }

    fn fail_server(&mut self, id: Id) {
        if let Some(entry) = self.servers.get_mut(id) {
            entry.tx.on_transport_error();
            self.settle_server(id, None);
        }
    }

    fn live_work_is_drained(&self) -> bool {
        self.work.is_idle()
    }

    fn fail_observed(&mut self, shared: &Arc<server::Shared>) {
        if self.owns_server(shared) {
            self.fail_server(shared.slot);
        }
    }

    // A TU capability can outlive every timer, and its slot can hold a newer
    // transaction by then. The transaction id comes from a counter that does
    // not repeat, so it tells the two apart.
    fn owns_server(&self, shared: &Arc<server::Shared>) -> bool {
        self.servers
            .get(shared.slot)
            .is_some_and(|entry| entry.id == shared.id)
    }

    fn abandon(&mut self, shared: &Arc<server::Shared>) {
        if !self.owns_server(shared) {
            return;
        }
        shared.abandoned.store(true, Ordering::Release);
        if shared.pending.load(Ordering::Acquire) == 0
            && !shared.final_sent.load(Ordering::Acquire)
        {
            self.respond_abandoned(shared.slot);
        }
    }

    fn on_submission(&mut self, submission: server::Submission) {
        let server::Submission {
            shared,
            operation,
            status,
            bytes,
            done,
            _permit,
        } = submission;
        // The machine decides what follows a final response. An INVITE in
        // Accepted takes another 2xx.
        let result = if self.owns_server(&shared) {
            self.accept_response(shared.slot, status, bytes, Some(operation))
        } else {
            // The entry is gone. Accepted took a further 2xx until Timer L,
            // so L alone refuses one now (RFC 6026 section 7.3). Any other
            // response after a final was refused for its kind, and keeps that
            // answer whether the transaction ended at once, as a non-INVITE
            // does over TCP, or after a timer.
            drop(bytes);
            Err(
                if status.is_success()
                    && shared.accepted.load(Ordering::Acquire)
                {
                    SubmitError::Terminated
                } else if shared.final_sent.load(Ordering::Acquire) {
                    SubmitError::FinalAlreadySent
                } else {
                    SubmitError::Terminated
                },
            )
        };
        shared.pending.fetch_sub(1, Ordering::Release);
        // Return command capacity before acceptance can wake a new submitter.
        drop(_permit);
        let _ = done.send(result);

        if shared.abandoned.load(Ordering::Acquire) {
            self.abandon(&shared);
        }
    }

    fn accept_response(
        &mut self,
        id: Id,
        status: StatusCode,
        bytes: Bytes,
        operation: Option<server::ResponseId>,
    ) -> Result<(), SubmitError> {
        use crate::transaction::non_invite::ResponseRejection;

        let entry = self.servers.get_mut(id).ok_or(SubmitError::Terminated)?;
        match &entry.tx {
            ServerMachine::NonInvite(tx) => tx
                .check_response(status, now())
                .map_err(|error| match error {
                ResponseRejection::TooEarly => SubmitError::TooEarly,
                ResponseRejection::ProhibitedStatus => {
                    SubmitError::ProhibitedStatus
                }
                ResponseRejection::FinalAlreadySent => {
                    SubmitError::FinalAlreadySent
                }
                ResponseRejection::Terminated => SubmitError::Terminated,
            })?,
            ServerMachine::Invite(tx) => {
                tx.check_response(status).map_err(|error| match error {
                    invite::ResponseError::FinalAlreadySent => {
                        SubmitError::FinalAlreadySent
                    }
                    invite::ResponseError::Terminated => {
                        SubmitError::Terminated
                    }
                })?;
            }
        }

        let link = entry.link.clone();
        let shared = entry.shared.as_ref().expect("TU transaction").clone();
        let output = self.prepare_server_output(&link, bytes.clone())?;

        let entry = self
            .servers
            .get_mut(id)
            .expect("validated transaction remains installed");
        // Prepare transport first so rejection preserves the cached response's
        // reservation. Replacement charges only the difference, allowing a final
        // to make progress even when the provisional fills the retained budget.
        // An INVITE 2xx leaves nothing to retransmit in Accepted, so it needs
        // no retention.
        let accepting = matches!(entry.tx, ServerMachine::Invite(_))
            && status.is_success();
        if !accepting {
            match &mut entry.retained {
                Some(retained) => retained
                    .resize(bytes.len())
                    .ok_or(SubmitError::RetentionFull)?,
                None => {
                    entry.retained = Some(
                        self.retained
                            .acquire(bytes.len())
                            .ok_or(SubmitError::RetentionFull)?,
                    )
                }
            }
        }
        let before = entry.tx.deadline();
        let timers = self.config.timers;
        match &mut entry.tx {
            ServerMachine::NonInvite(tx) => {
                let sent =
                    tx.on_response(status, bytes.clone(), &timers, now());
                debug_assert!(sent);
            }
            ServerMachine::Invite(tx) => {
                let sent =
                    tx.on_response(status, bytes.clone(), &timers, now());
                debug_assert!(sent.is_ok());
                if tx.is_accepted() {
                    entry.retained = None;
                }
            }
        }

        if status.is_final() {
            shared.final_sent.store(true, Ordering::Release);
            if accepting {
                shared.accepted.store(true, Ordering::Release);
            }
            shared.work.finish();
            // An unobserved non-INVITE UDP cache needs only its response and
            // capability identity. No observer can reappear after count zero.
            // An INVITE keeps its observation for ACK timeout and further 2xx.
            if matches!(entry.tx, ServerMachine::NonInvite(_))
                && !entry.tx.is_terminated()
                && shared.observation.receiver_count() == 0
            {
                entry.shared = None;
            }
        }

        if !self.commit_server_output(output, &shared, operation) {
            if let Some(entry) = self.servers.get_mut(id) {
                entry.tx.on_transport_error();
            }
        }
        self.settle_server(id, before);
        Ok(())
    }

    fn respond_abandoned(&mut self, id: Id) {
        let Some(entry) = self.servers.get(id) else { return };
        let Some(headers) = entry.tx.headers() else { return };
        // Reuse a To tag that the TU already chose for a provisional response.
        // Otherwise the 500 needs a fresh one (RFC 3261 section 8.2.6.2). The
        // machine caches the encoded 500, so retransmissions keep this tag.
        let selected = entry
            .tx
            .on_retransmission()
            .and_then(|bytes| Response::from_shared(bytes).ok())
            .and_then(|response| response.headers().get(TO).cloned())
            .filter(|to| has_tag(to.as_str()));
        let request_tagged =
            headers.get(TO).is_some_and(|to| has_tag(to.as_str()));
        let mut builder = Response::builder().status(SERVER_ERROR);
        *builder.headers_mut().expect("new builder") = headers.clone();
        let builder = match selected {
            Some(to) => {
                builder.headers_mut().expect("new builder").insert(TO, to);
                Some(builder)
            }
            None if request_tagged => Some(builder),
            None => Tag::try_random().map(|tag| builder.to_tag(tag)),
        };
        let response = builder
            .and_then(|builder| builder.body(Bytes::new()).ok())
            .map(|response| response.to_bytes());

        // No TU is left to answer, and Proceeding has no timer, so a machine
        // whose 500 cannot be built or admitted would stay forever.
        // Terminating releases its work. A later retransmission then reaches
        // the TU as a new request, which it can answer this time.
        let accepted = response.map_or(Err(SubmitError::Busy), |response| {
            self.accept_response(id, SERVER_ERROR, response, None)
        });
        if accepted.is_err() {
            let entry =
                self.servers.get_mut(id).expect("existing transaction");
            if let Some(shared) = &entry.shared {
                shared.rejected();
            }
            entry.tx.abandon();
            self.settle_server(id, None);
        }
    }
}

/// Whether `request` has exactly one From, To, Call-ID and CSeq, and its CSeq
/// names its own method, which a stateful response needs.
fn has_identity(request: &Request<Bytes>) -> bool {
    [FROM, TO, CALL_ID, CSEQ].iter().all(|name| {
        let mut values = request.headers().get_all(name);
        values.next().is_some() && values.next().is_none()
    }) && request
        .headers()
        .get(CSEQ)
        .and_then(CSeq::parse)
        .is_some_and(|cseq| cseq.method == request.method())
}

/// The bytes of the identity values a reply route copies.
fn identity_bytes(request: &Request<Bytes>) -> Option<usize> {
    request
        .headers()
        .iter()
        .filter(|(name, _)| [VIA, FROM, TO, CALL_ID, CSEQ].contains(name))
        .try_fold(0usize, |total, (_, value)| total.checked_add(value.len()))
}

/// The current time, as the transactions and tokio's timer both see it.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Sends `bytes` along `link` without waiting.
///
/// An attempt cannot outlive endpoint teardown or its setup deadline.
async fn connect_until<T>(
    connect: impl Future<Output = io::Result<T>>,
    inbound: &mpsc::Sender<tcp::Inbound>,
    deadline: Duration,
) -> io::Result<T> {
    let mut connect = pin!(tokio::time::timeout(deadline, connect));
    let mut closed = pin!(inbound.closed());
    poll_fn(|cx| {
        if closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "endpoint stopped",
            )));
        }
        connect.as_mut().poll(cx).map(|result| {
            result.unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP connect timed out",
                ))
            })
        })
    })
    .await
}

/// The local write outcome of a client request.
enum ClientReceipt {
    Tcp(tcp::Receipt),
    Udp(oneshot::Receiver<io::Result<()>>),
}

impl ClientReceipt {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            ClientReceipt::Tcp(receipt) => Pin::new(receipt).poll(cx),
            ClientReceipt::Udp(receipt) => {
                Pin::new(receipt).poll(cx).map(|result| {
                    result.unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "UDP writer closed",
                        ))
                    })
                })
            }
        }
    }
}

/// Sends a client request and returns a receipt when its write is queued.
/// A full TCP queue is reported as `WouldBlock`.
fn send_client(
    udp: Option<&mut Datagram>,
    link: &Link,
    bytes: &Bytes,
    initial: bool,
) -> io::Result<Option<ClientReceipt>> {
    if let Some(writer) = &link.writer {
        writer
            .submit_request(bytes.clone())
            .map(|receipt| Some(ClientReceipt::Tcp(receipt)))
            .map_err(|error| {
                io::Error::new(
                    match error {
                        tcp::SendError::Full => io::ErrorKind::WouldBlock,
                        tcp::SendError::Closed => io::ErrorKind::BrokenPipe,
                    },
                    error,
                )
            })
    } else {
        udp.expect("UDP link has a socket")
            .submit_client(bytes, &link.flow, initial)
            .map(|receipt| receipt.map(ClientReceipt::Udp))
    }
}

/// Over TCP a full write queue is an error here. The connection is in trouble,
/// and a transaction that retransmits will try again.
fn send_on(
    udp: Option<&mut Datagram>,
    link: &Link,
    bytes: &Bytes,
    new_request: bool,
) -> io::Result<()> {
    match (&link.writer, udp) {
        (Some(writer), _) => (if new_request {
            writer.send_request(bytes.clone())
        } else {
            writer.send(bytes.clone())
        })
        .map_err(|err| {
            let kind = match err {
                tcp::SendError::Full => io::ErrorKind::WouldBlock,
                tcp::SendError::Closed => io::ErrorKind::BrokenPipe,
            };
            io::Error::new(kind, err)
        }),
        (None, Some(udp)) => {
            if new_request {
                udp.send_request(bytes, &link.flow)
            } else {
                udp.send(bytes, &link.flow)
            }
        }
        (None, None) => unreachable!("a UDP flow comes from the UDP socket"),
    }
}

// These private driver tests use sockets, which Miri cannot provide.
#[cfg(all(test, not(miri)))]
mod tests {
    use std::{
        sync::Mutex,
        task::{Wake, Waker},
    };

    use tokio::{
        net::UdpSocket,
        task::yield_now,
        time::{advance, sleep, timeout},
    };
    use tower_service::Service;

    use super::*;
    use crate::{
        endpoint::{
            client::{ClientControl, Responses},
            tests::{
                fixture_endpoint, invite, reply, reply_driver,
                reply_driver_with, route_request, route_response,
                udp_reply_link, DriverFixture, TestServe, REPLY_LOCAL,
            },
            Client, Endpoint,
        },
        transaction::Timers,
    };

    fn fallback(driver: &Driver, bytes: Bytes) -> Pending {
        let permit = driver.fallback.acquire(bytes.len()).unwrap();
        Pending::Response(
            bytes,
            Fallback {
                _permit: permit,
                stats: driver.connection_stats.clone(),
                written: false,
            },
        )
    }

    #[tokio::test]
    async fn connect_deadline_and_endpoint_close_drop_the_attempt() {
        let (tx, rx) = mpsc::channel(1);
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let stalled = async move {
            let _permit = permit;
            std::future::pending::<io::Result<()>>().await
        };
        let error =
            connect_until(stalled, &tx, Duration::ZERO).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(slots.available_permits(), 1);

        let permit = slots.clone().try_acquire_owned().unwrap();
        let stalled = async move {
            let _permit = permit;
            std::future::pending::<io::Result<()>>().await
        };
        drop(rx);
        let error = connect_until(stalled, &tx, Duration::from_secs(60))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn route_churn_is_bounded_and_response_entries_have_reserved_room() {
        let (mut driver, _commands, _) =
            reply_driver_with(Config { max_routes: 2, ..Config::default() });
        for port in 1..100 {
            let remote = SocketAddr::from(([127, 0, 0, 1], port));
            driver.udp_source(remote).unwrap();
            assert!(driver.routes.len() <= 2);
        }
        driver.routes.clear();
        for port in 1..=2 {
            driver.routes.insert(
                SocketAddr::from(([127, 0, 0, 1], port)),
                Route {
                    tcp: TcpState::Connecting(Vec::new()),
                    ..Route::default()
                },
            );
        }
        let remote = "127.0.0.1:3".parse().unwrap();
        assert!(!driver.admit_route(remote, false));
        assert!(driver.admit_route(remote, true));
        driver.udp_source(remote).unwrap();
        assert_eq!(driver.routes.len(), 2);
        for port in 3..=66 {
            let remote = SocketAddr::from(([127, 0, 0, 1], port));
            assert!(driver.admit_route(remote, true));
            driver.routes.insert(
                remote,
                Route {
                    tcp: TcpState::Connecting(Vec::new()),
                    ..Route::default()
                },
            );
        }
        assert!(!driver.admit_route("127.0.0.1:67".parse().unwrap(), true));
        driver.config.max_routes = 0;
        driver.routes.clear();
        driver.udp_source(remote).unwrap();
        assert!(driver.routes.is_empty());
    }

    #[tokio::test]
    async fn new_client_connect_limits_do_not_block_response_connects() {
        for (connections, attempts) in [(0, 1), (1, 0)] {
            let (mut driver, commands, _) = reply_driver_with(Config {
                max_outbound_connections: connections,
                max_pending_connects: attempts,
                ..Config::default()
            });
            let remote = "127.0.0.1:9".parse().unwrap();
            let mut client = Client::new(
                commands,
                driver.client_admission(),
                Transport::Tcp,
                remote,
            );
            let response =
                client.call(route_request("SIP/2.0/TCP example.com:9"));
            let command = driver.commands.try_recv().unwrap();
            driver.on_command(command);
            assert!(response.await.unwrap_err().is_busy());
            assert_eq!(
                driver.connection_stats.rejected.load(Ordering::Relaxed),
                1
            );

            let response = fallback(&driver, Bytes::from_static(b"response"));
            assert!(driver.send_over_tcp(remote, response));
            assert!(matches!(
                driver.routes[&remote].tcp,
                TcpState::Connecting(_)
            ));
            assert_eq!(driver.response_connections.available_permits(), 63);
        }
    }

    #[tokio::test]
    async fn connect_results_keep_attempt_capacity_until_processed() {
        let (mut driver, commands, _) = reply_driver_with(Config {
            max_pending_connects: 1,
            ..Config::default()
        });
        let listener =
            tokio::net::TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let remote = listener.local_addr().unwrap();
        let mut client = Client::new(
            commands,
            driver.client_admission(),
            Transport::Tcp,
            remote,
        );
        let response = client.call(route_request("SIP/2.0/TCP example.com:9"));
        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);
        assert!(driver.connects.acquire(0).is_none());

        let command = timeout(Duration::from_secs(1), driver.internal.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(driver.connects.acquire(0).is_none());
        driver.on_command(command);
        assert!(driver.connects.acquire(0).is_some());
        assert_eq!(driver.outbound.available_permits(), 1023);
        drop(response);
        assert_eq!(driver.outbound.available_permits(), 1023);
    }

    #[tokio::test]
    async fn fallback_count_and_bytes_survive_connect_and_write() {
        let (mut driver, _commands, _) = reply_driver_with(Config {
            fallback_limits: WriteLimits { messages: 2, bytes: 3 },
            ..Config::default()
        });
        let listener =
            tokio::net::TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let remote = listener.local_addr().unwrap();
        let response = fallback(&driver, Bytes::from_static(b"abc"));
        assert!(driver.send_over_tcp(remote, response));
        assert!(driver.fallback.acquire(1).is_none());
        let empty = fallback(&driver, Bytes::new());
        assert!(driver.send_over_tcp(remote, empty));
        assert!(driver.fallback.acquire(0).is_none());
        let command = timeout(Duration::from_secs(1), driver.internal.recv())
            .await
            .unwrap()
            .unwrap();
        driver.on_command(command);
        assert_eq!(driver.fallback_writes.len(), 2);
        assert!(driver.fallback.acquire(0).is_none());

        poll_fn(|cx| {
            let _ = driver.poll_event(cx);
            if driver.fallback_writes.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        assert!(driver.fallback.acquire(3).is_some());
        assert_eq!(driver.connection_stats.dropped.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ordinary_fallback_rejects_before_enqueue_and_returns_its_budget()
    {
        let (mut driver, _commands, _) = reply_driver_with(Config {
            fallback_limits: WriteLimits { messages: 2, bytes: 3 },
            ..Config::default()
        });
        let listener =
            tokio::net::TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let remote = listener.local_addr().unwrap();
        let (flow, writer) =
            tcp::connect(remote, &driver.config.tcp, &driver.tcp_tx)
                .await
                .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        drop(peer);
        timeout(Duration::from_secs(1), async {
            while !writer.is_closed() {
                yield_now().await;
            }
        })
        .await
        .unwrap();
        let link = Link { flow, writer: Some(writer) };
        driver.routes.insert(
            remote,
            Route {
                tcp: TcpState::Connecting(Vec::new()),
                ..Route::default()
            },
        );

        driver.send_reply(&link, &Bytes::from_static(b"abc")).unwrap();
        assert_eq!(
            driver
                .send_reply(&link, &Bytes::from_static(b"d"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        driver.send_reply(&link, &Bytes::new()).unwrap();
        assert_eq!(
            driver.send_reply(&link, &Bytes::new()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let TcpState::Connecting(waiting) = &driver.routes[&remote].tcp else {
            panic!("waiting for connection");
        };
        assert_eq!(waiting.len(), 2);
        assert_eq!(driver.connection_stats.dropped.load(Ordering::Relaxed), 2);
        driver.on_connected(
            remote,
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        );
        assert_eq!(driver.connection_stats.dropped.load(Ordering::Relaxed), 4);
        assert!(driver.fallback.acquire(3).is_some());

        let all = driver
            .response_connections
            .clone()
            .try_acquire_many_owned(REPLY_OPERATIONS as u32)
            .unwrap();
        assert_eq!(
            driver
                .send_reply(&link, &Bytes::from_static(b"abc"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(driver.fallback.acquire(3).is_some());
        assert_eq!(
            driver.connection_stats.rejected.load(Ordering::Relaxed),
            1
        );
        assert_eq!(driver.connection_stats.dropped.load(Ordering::Relaxed), 5);
        drop(all);
    }

    #[tokio::test]
    async fn fallback_failure_and_teardown_return_capacity_and_count_drops() {
        let (mut driver, _commands, _) = reply_driver_with(Config {
            fallback_limits: WriteLimits { messages: 1, bytes: 3 },
            ..Config::default()
        });
        let remote = "127.0.0.1:9".parse().unwrap();
        driver.routes.insert(
            remote,
            Route {
                tcp: TcpState::Connecting(Vec::new()),
                ..Route::default()
            },
        );
        let response = fallback(&driver, Bytes::from_static(b"abc"));
        driver.send_over_tcp(remote, response);
        driver.on_connected(
            remote,
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        );
        assert!(driver.fallback.acquire(3).is_some());
        assert_eq!(driver.connection_stats.dropped.load(Ordering::Relaxed), 1);

        driver.routes.get_mut(&remote).unwrap().tcp =
            TcpState::Connecting(Vec::new());
        let response = fallback(&driver, Bytes::from_static(b"abc"));
        driver.send_over_tcp(remote, response);
        let stats = driver.connection_stats.clone();
        let capacity = driver.fallback.clone();
        drop(driver);
        assert!(capacity.acquire(3).is_some());
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn ready_internal_commands_do_not_starve_udp() {
        let (mut driver, _commands, local) = reply_driver();
        // A connect result for a route nobody waits for is a no-op.
        let attempts = Budget::new(WriteLimits { messages: 100, bytes: 0 });
        for _ in 0..100 {
            driver
                .internal_tx
                .send(Command::Connected {
                    remote: SocketAddr::from(([127, 0, 0, 1], 9)),
                    result: Err(io::ErrorKind::ConnectionRefused.into()),
                    _attempt: attempts.acquire(0).unwrap(),
                })
                .unwrap();
        }

        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        peer.send_to(
            b"test",
            SocketAddr::from(([127, 0, 0, 1], local.port())),
        )
        .await
        .unwrap();

        sleep(Duration::from_millis(1)).await;
        let received = timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                for _ in 0..12 {
                    if let Poll::Ready(Event::Datagram(bytes, _)) =
                        driver.poll_event(cx)
                    {
                        return Poll::Ready(bytes);
                    }
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }),
        )
        .await
        .unwrap();
        assert_eq!(received.as_ref(), b"test");
        assert!(driver.internal.len() >= 98);
    }

    #[tokio::test]
    async fn shutdown_calls_coalesce_in_separate_control_capacity() {
        let (mut driver, _commands, _) = reply_driver();
        for _ in 0..10_000 {
            if driver.shutdown_control.request(Duration::from_secs(30)) {
                driver.control.try_send(()).unwrap();
            }
        }
        assert_eq!(driver.control_rx.len(), 1);
        assert!(driver.commands.is_empty());
        assert!(matches!(
            poll_fn(|cx| driver.poll_event(cx)).await,
            Event::Control
        ));

        driver.on_control();
        assert!(driver.shutting_down);
        assert!(!driver.shutdown_control.request(Duration::from_secs(60)));
        assert!(driver.shutdown_control.request(Duration::ZERO));
    }

    // A guard's drop wakes the driver through the same control queue without
    // starting a shutdown, and a full queue still wakes it once.
    #[tokio::test]
    async fn the_last_guard_wakes_the_driver_without_a_command() {
        let (mut driver, commands, _) = reply_driver();
        let guards: Vec<_> = (0..100)
            .map(|_| {
                shutdown::WorkGuard::new(
                    driver.shutdown_control.clone(),
                    driver.control.clone(),
                    commands.clone(),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(driver.control_rx.len(), 0);

        drop(guards);

        assert_eq!(driver.control_rx.len(), 1);
        assert!(driver.commands.is_empty());
        assert!(matches!(
            poll_fn(|cx| driver.poll_event(cx)).await,
            Event::Control
        ));
        driver.on_control();
        assert!(!driver.shutting_down);
        assert!(driver.shutdown_control.guards_idle());
    }

    #[tokio::test]
    async fn shared_shutdown_completion_wakes_every_caller() {
        let endpoint = crate::endpoint::Endpoint::builder()
            .serve(crate::endpoint::tests::RouteService)
            .unwrap();
        let waits: Vec<_> = (0..1000)
            .map(|_| endpoint.clone().shutdown(Duration::from_secs(1)))
            .collect();
        drop(endpoint);
        timeout(Duration::from_secs(1), async {
            for wait in waits {
                assert_eq!(wait.await, ShutdownOutcome::Drained);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_terminated_machine_does_not_release_queued_event_bytes() {
        let (mut driver, _commands, local) = reply_driver_with(Config {
            max_pending_requests: 1,
            ..Config::default()
        });
        let first = route_request(
            "SIP/2.0/UDP example.com:9;branch=z9hG4bKqueued;rport",
        );
        let key = ServerKey::from_request(&first).unwrap();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        driver.on_request(first, link.clone());
        let id = driver.servers.find(&key).unwrap().0;

        driver.fail_server(id);
        assert!(driver.work.is_idle());
        assert!(!driver.event_admission.is_idle());
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKrefused;rport",
            ),
            link.clone(),
        );
        assert_eq!(driver.incoming.receiver.len(), 1);
        assert_eq!(driver.servers.len(), 0);

        let _expired = driver.take_request();
        assert!(driver.event_admission.is_idle());
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKaccepted;rport",
            ),
            link,
        );
        assert_eq!(driver.incoming.receiver.len(), 1);
        assert_eq!(driver.servers.len(), 1);
    }

    #[tokio::test]
    async fn queued_submissions_keep_their_count_after_waiters_drop() {
        let (mut driver, _commands, local) = reply_driver();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKsubmissions;rport",
            ),
            link,
        );
        let envelope = driver.take_request();
        let (responder, _) = envelope.transaction.into_parts();
        let response = route_response(&envelope.request);
        let mut waiters = Vec::new();

        for _ in 0..64 {
            let mut submission = Box::pin(responder.respond(response.clone()));
            poll_fn(|cx| {
                assert!(submission.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            waiters.push(submission);
        }
        drop(waiters);
        assert!(driver.submissions.acquire(0).is_none());
        assert_eq!(responder.respond(response).await, Err(SubmitError::Busy));
        driver.abandon(&responder.shared);
        assert!(!responder.shared.final_sent.load(Ordering::Acquire));

        while let Ok(command) = driver.commands.try_recv() {
            driver.on_command(command);
        }

        assert!(responder.shared.final_sent.load(Ordering::Acquire));
        assert_eq!(responder.shared.pending.load(Ordering::Acquire), 0);
        assert!(driver.submissions.acquire(0).is_some());
        assert!(driver.work.is_idle());
    }

    #[tokio::test]
    async fn retained_response_bytes_are_reserved_before_machine_transition() {
        let (mut driver, _commands, local) = reply_driver();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKfirst;rport",
            ),
            link.clone(),
        );
        let first = driver.take_request();
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKother;rport",
            ),
            link,
        );
        let other = driver.take_request();
        let a = first.transaction.responder.shared.slot;
        let b = other.transaction.responder.shared.slot;
        let response_a = route_response(&first.request).to_bytes();
        let response_b = route_response(&other.request).to_bytes();
        let capacity = response_a.len() + response_b.len();
        driver.retained =
            Budget::new(WriteLimits { messages: usize::MAX, bytes: capacity });
        let blocker = driver.retained.acquire(response_b.len()).unwrap();

        driver.accept_response(a, status(200), response_a, None).unwrap();
        let before = driver.servers.get(b).unwrap().tx.deadline();
        assert_eq!(
            driver.accept_response(b, status(200), response_b.clone(), None),
            Err(SubmitError::RetentionFull)
        );
        assert_eq!(driver.servers.get(b).unwrap().tx.deadline(), before);
        assert!(driver.servers.get(b).unwrap().tx.headers().is_some());
        assert!(!other
            .transaction
            .responder
            .shared
            .final_sent
            .load(Ordering::Acquire));

        drop(blocker);
        driver.accept_response(b, status(200), response_b, None).unwrap();

        assert!(other
            .transaction
            .responder
            .shared
            .final_sent
            .load(Ordering::Acquire));
        assert!(driver.work.is_idle());
    }

    #[tokio::test]
    async fn a_reused_numeric_slot_cannot_redirect_a_tu_capability() {
        let (mut driver, _commands, local) = reply_driver();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKidentity;rport",
            ),
            link,
        );
        let envelope = driver.take_request();
        let original = &envelope.transaction.responder.shared;
        let (observation, _events) =
            watch::channel(server::Observation::default());
        let capacity = Budget::new(WriteLimits { messages: 1, bytes: 0 });
        // A capability of an earlier transaction in the same slot. Its id
        // came from the counter before this one's, which starts at 1.
        let stale = Arc::new(server::Shared {
            id: ServerTransactionId(0),
            slot: original.slot,
            work: server::Work::new(capacity.acquire(0).unwrap()),
            pending: AtomicUsize::new(1),
            next_operation: AtomicU64::new(1),
            final_sent: AtomicBool::new(false),
            accepted: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            observation,
            transport: AtomicUsize::new(0),
            terminated: AtomicBool::new(false),
        });
        let reply = route_response(&envelope.request);
        let operation =
            envelope.transaction.responder.respond(reply.clone()).id();
        let bytes = reply.to_bytes();
        let permit = driver.submissions.acquire(bytes.len()).unwrap();
        let (done, accepted) = oneshot::channel();

        driver.on_submission(server::Submission {
            shared: stale.clone(),
            operation,
            status: status(200),
            bytes,
            done,
            _permit: permit,
        });
        driver.abandon(&stale);
        driver.fail_observed(&stale);

        assert_eq!(accepted.await.unwrap(), Err(SubmitError::Terminated));
        let live = driver.servers.get(original.slot).unwrap();
        assert!(live.tx.headers().is_some());
        assert!(!original.final_sent.load(Ordering::Acquire));
        assert!(!original.abandoned.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn acceptance_returns_submission_capacity_before_waking_a_submitter()
    {
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }

        struct Next {
            responder: Arc<server::Responder>,
            response: Response<Bytes>,
            queued: AtomicBool,
        }

        impl Wake for Next {
            fn wake(self: Arc<Self>) {
                let waker = Waker::from(Arc::new(Noop));
                let mut context = Context::from_waker(&waker);
                let mut send = self.responder.respond(self.response.clone());
                self.queued.store(
                    Pin::new(&mut send).poll(&mut context).is_pending(),
                    Ordering::Relaxed,
                );
            }
        }

        let (mut driver, _commands, local) = reply_driver();
        driver.submissions =
            Budget::new(WriteLimits { messages: 1, bytes: usize::MAX });
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKwake;rport",
            ),
            link,
        );
        let envelope = driver.take_request();
        let (responder, _) = envelope.transaction.into_parts();
        let response = route_response(&envelope.request);
        let responder = Arc::new(responder);
        let next = Arc::new(Next {
            responder: responder.clone(),
            response: response.clone(),
            queued: AtomicBool::new(false),
        });
        let waker = Waker::from(next.clone());
        let mut context = Context::from_waker(&waker);
        let mut send = responder.respond(response);
        assert!(Pin::new(&mut send).poll(&mut context).is_pending());

        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);

        assert!(next.queued.load(Ordering::Relaxed));
        assert_eq!(send.await, Ok(()));
        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);
        assert!(driver.submissions.is_idle());
    }

    #[tokio::test]
    async fn dropping_the_last_command_handle_cannot_leave_a_partial_server() {
        let (mut driver, commands, local) = reply_driver();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        drop(commands);

        driver.on_request(
            route_request(
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKclosed;rport",
            ),
            link,
        );

        assert_eq!(driver.servers.len(), 0);
        assert!(driver.work.is_idle());
        assert!(driver.event_admission.is_idle());
        assert!(driver.routes_admission.is_idle());
        assert!(driver.incoming.receiver.is_empty());
    }

    #[tokio::test]
    async fn fallback_admission_is_reserved_before_server_commit() {
        let (mut driver, _commands, _) = reply_driver();
        let listener =
            tokio::net::TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let (flow, writer) = tcp::connect(
            listener.local_addr().unwrap(),
            &driver.config.tcp,
            &driver.tcp_tx,
        )
        .await
        .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        drop(peer);
        timeout(Duration::from_secs(1), async {
            while !writer.is_closed() {
                yield_now().await;
            }
        })
        .await
        .unwrap();
        driver.on_request(
            route_request("SIP/2.0/TCP example.com:9;branch=z9hG4bKfallback"),
            Link { flow, writer: Some(writer) },
        );
        let envelope = driver.take_request();
        let shared = &envelope.transaction.responder.shared;
        let response = route_response(&envelope.request);
        let all = driver
            .response_connections
            .clone()
            .try_acquire_many_owned(REPLY_OPERATIONS as u32)
            .unwrap();
        let before = driver.servers.get(shared.slot).unwrap().tx.deadline();

        assert_eq!(
            driver.accept_response(
                shared.slot,
                status(200),
                response.to_bytes(),
                None
            ),
            Err(SubmitError::TransportBusy)
        );

        assert_eq!(
            driver.servers.get(shared.slot).unwrap().tx.deadline(),
            before
        );
        assert!(!shared.final_sent.load(Ordering::Acquire));
        assert!(!driver.work.is_idle());
        assert!(driver.fallback.is_idle());
        assert!(driver.retained.is_idle());
        assert!(driver.response_connects.is_idle());
        assert_eq!(
            driver.connection_stats.rejected.load(Ordering::Relaxed),
            1
        );
        drop(all);
    }

    struct SendNext {
        client: Mutex<Client>,
        request: Request<Bytes>,
    }

    impl Wake for SendNext {
        fn wake(self: Arc<Self>) {
            // Run at the exact wakeup point, before the driver callback
            // returns, rather than relying on a scheduler race.
            drop(self.client.lock().unwrap().call(self.request.clone()));
        }
    }

    #[tokio::test]
    async fn timer_j_returns_server_capacity_and_old_ids_do_not_touch_reused_slots(
    ) {
        let (mut driver, _commands, local) = reply_driver_with(Config {
            max_server_transactions: 1,
            ..Config::default()
        });
        let request = route_request(
            "SIP/2.0/UDP example.com:9;branch=z9hG4bKfirst;rport",
        );
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());

        driver.on_request(request.clone(), link.clone());
        let received = driver.take_request();
        let old = received.transaction.responder.shared.slot;
        let response = route_response(&received.request);
        driver
            .accept_response(old, response.status(), response.to_bytes(), None)
            .unwrap();
        assert_eq!(driver.servers.len(), 1);
        let entry = driver.servers.get_mut(old).unwrap();
        let at = entry.tx.deadline().unwrap();
        let ServerMachine::NonInvite(tx) = &mut entry.tx else {
            unreachable!("an OPTIONS transaction")
        };
        tx.on_timeout(at);
        driver.settle_server(old, Some(at));
        assert_eq!(driver.servers.len(), 0);

        driver.on_request(request, link);
        driver.on_timer(Key::Server(old));

        assert_eq!(driver.servers.len(), 1);
        assert_eq!(driver.incoming.receiver.len(), 1);
        let received = driver.take_request();
        let current = received.transaction.responder.shared.slot;
        assert_ne!(current, old);
        assert!(driver.servers.get(current).is_some());
    }

    #[tokio::test]
    async fn fast_server_churn_does_not_retain_every_cancelled_trying_timer() {
        let (mut driver, _commands, local) = reply_driver_with(Config {
            max_server_transactions: 1,
            ..Config::default()
        });
        let request = route_request(
            "SIP/2.0/UDP example.com:9;branch=z9hG4bKchurn;rport",
        );
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());

        for _ in 0..1000 {
            driver.on_request(request.clone(), link.clone());
            let received = driver.take_request();
            let id = received.transaction.responder.shared.slot;
            driver.fail_server(id);
            drop(received);
            poll_fn(|cx| {
                if let Poll::Ready(Event::Timer(key)) = driver.poll_event(cx) {
                    driver.on_timer(key);
                }
                Poll::Ready(())
            })
            .await;
        }

        assert_eq!(driver.servers.len(), 0);
        let mut retained = 0;
        while driver.timers.pop().is_some() {
            retained += 1;
        }
        assert!(retained <= 64, "retained {retained} cancelled timers");
    }

    #[tokio::test]
    async fn cancellation_before_enqueue_has_no_effect_and_after_enqueue_keeps_the_write(
    ) {
        let (mut driver, commands, local) = reply_driver();
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let link = udp_reply_link(local, peer.local_addr().unwrap());
        let (request, route) = driver
            .prepare_reply(
                route_request(
                    "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
                ),
                link.clone(),
            )
            .unwrap();
        let response = route_response(&request);
        let capacity = driver.reply_admission.0.clone();
        let all = capacity.clone().acquire_many_owned(64).await.unwrap();

        {
            let mut send = pin!(route.send(response.clone()));
            poll_fn(|cx| {
                assert!(send.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert!(driver.commands.is_empty());

        drop(all);

        {
            let mut send = pin!(route.send(response.clone()));
            poll_fn(|cx| {
                assert!(send.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }

        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);

        drop(route);
        drop(commands);

        let task = tokio::spawn(driver.run());

        let mut buf = [0; 2048];
        let (n, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], &response.to_bytes());
        assert_eq!(capacity.available_permits(), 64);

        timeout(Duration::from_secs(1), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_wakes_capacity_waiters_and_fails_queued_operations() {
        let (driver, commands, local) = reply_driver();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        let (request, route) = driver
            .prepare_reply(
                route_request(
                    "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
                ),
                link,
            )
            .unwrap();
        let capacity = driver.reply_admission.0.clone();
        let all = capacity.acquire_many_owned(64).await.unwrap();

        let mut send = pin!(route.send(route_response(&request)));
        poll_fn(|cx| {
            assert!(send.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        drop(driver);
        drop(all);
        drop(commands);

        assert!(matches!(send.await, Err(ReplyError::Closed)));
    }

    #[tokio::test]
    async fn connect_waiters_hold_capacity_until_connection_failure() {
        let (mut driver, commands, _local) = reply_driver();
        let remote = "127.0.0.1:9".parse().unwrap();
        let mut client = Client::new(
            commands,
            driver.client_admission(),
            Transport::Tcp,
            remote,
        );
        driver.routes.insert(
            remote,
            Route {
                tcp: TcpState::Connecting(Vec::new()),
                ..Route::default()
            },
        );
        let mut responses = Vec::new();

        for _ in 0..8 {
            responses.push(
                client.call(route_request("SIP/2.0/UDP example.com:9;rport")),
            );
            let command = driver.commands.try_recv().unwrap();
            driver.on_command(command);
        }
        assert_eq!(driver.clients.len(), 0);
        drop(responses.pop().unwrap());
        assert!(client
            .call(route_request("SIP/2.0/UDP example.com:9;rport"))
            .await
            .unwrap_err()
            .is_busy());
        assert!(driver.commands.is_empty());
        let TcpState::Connecting(pending) = &driver.routes[&remote].tcp else {
            panic!("connect is still pending");
        };
        assert_eq!(pending.len(), 8);

        driver.on_connected(
            remote,
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connect failed",
            )),
        );

        for response in responses {
            assert!(response.await.unwrap_err().is_transport());
        }
        drop(client.call(route_request("SIP/2.0/UDP example.com:9;rport")));
        assert_eq!(driver.commands.len(), 1);
    }

    #[tokio::test]
    async fn completed_clients_keep_count_until_timer_k() {
        let (mut driver, commands, _local) = reply_driver_with(Config {
            max_client_transactions: 1,
            ..Config::default()
        });
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let mut client = Client::new(
            commands,
            driver.client_admission(),
            Transport::Udp,
            peer.local_addr().unwrap(),
        );
        let response =
            client.call(route_request("SIP/2.0/UDP example.com:9;rport"));
        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);

        timeout(
            Duration::from_secs(3),
            poll_fn(|cx| {
                let udp = driver.udp.as_mut().unwrap();
                udp.poll_flush(cx);
                if udp.is_idle() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap();

        let mut buf = [0; 2048];
        let (n, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let request = Request::from_bytes(&buf[..n]).unwrap();
        let key = ClientKey::from_request(&request).unwrap();
        let (id, _) = driver.clients.find(&key).unwrap();
        driver.on_received_response(route_response(&request));

        assert!(response.await.is_ok());
        assert_eq!(driver.clients.len(), 1);
        assert!(!driver.clients.get(id).unwrap().is_terminated());
        assert!(client
            .call(route_request("SIP/2.0/UDP example.com:9;rport"))
            .await
            .unwrap_err()
            .is_busy());
        let timers = driver.config.timers;
        let entry = driver.clients.get_mut(id).unwrap();
        let deadline = entry.deadline().unwrap();

        // Drive the machine at K directly instead of waiting on a wall clock.
        let ClientMachine::NonInvite(tx) = &mut entry.tx else {
            unreachable!("an OPTIONS transaction")
        };
        tx.on_timeout(&timers, deadline);
        driver.settle_client(id, Some(deadline));

        assert_eq!(driver.clients.len(), 0);
        drop(client.call(route_request("SIP/2.0/UDP example.com:9;rport")));
        assert_eq!(driver.commands.len(), 1);
    }

    #[tokio::test]
    async fn pre_transaction_errors_release_admission_before_waking_the_caller(
    ) {
        #[derive(Debug)]
        enum Failure {
            Connect,
            MissingUdp,
            Oversized,
        }

        for case in [Failure::Connect, Failure::MissingUdp, Failure::Oversized]
        {
            let (mut driver, commands, local) = reply_driver_with(Config {
                max_client_transactions: 1,
                ..Config::default()
            });
            let transport = if matches!(case, Failure::Connect) {
                Transport::Tcp
            } else {
                Transport::Udp
            };
            let mut client = Client::new(
                commands,
                driver.client_admission(),
                transport,
                local,
            );
            let next = route_request("SIP/2.0/UDP example.com:9;rport");
            let mut request = next.clone();
            match case {
                Failure::Connect => {
                    driver.routes.insert(
                        local,
                        Route {
                            tcp: TcpState::Connecting(Vec::new()),
                            ..Route::default()
                        },
                    );
                }
                Failure::MissingUdp => driver.udp = None,
                Failure::Oversized => {
                    *request.body_mut() =
                        Bytes::from(vec![0; MAX_UDP_REQUEST]);
                }
            }

            let mut response = Box::pin(client.call(request));
            let waker: Waker = Arc::new(SendNext {
                client: Mutex::new(client),
                request: next,
            })
            .into();
            assert!(response
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());

            let command = driver.commands.try_recv().unwrap();
            driver.on_command(command);
            if matches!(case, Failure::Connect) {
                driver.on_connected(
                    local,
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connect failed",
                    )),
                );
            }

            assert!(response.await.is_err());
            assert_eq!(driver.clients.len(), 0);
            assert_eq!(
                driver.commands.len(),
                1,
                "the error waker admitted the next request in case {case:?}"
            );
        }
    }

    #[tokio::test]
    async fn tcp_completion_retires_admission_before_waking_the_caller() {
        use tokio::{io::AsyncReadExt, net::TcpListener};

        let (mut driver, commands, _local) = reply_driver_with(Config {
            max_client_transactions: 1,
            ..Config::default()
        });
        let listener = TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let remote = listener.local_addr().unwrap();
        let (flow, writer) =
            tcp::connect(remote, &driver.config.tcp, &driver.tcp_tx)
                .await
                .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        driver.routes.insert(
            remote,
            Route { tcp: TcpState::Open(flow, writer), ..Route::default() },
        );
        let mut client = Client::new(
            commands,
            driver.client_admission(),
            Transport::Tcp,
            remote,
        );
        let request = route_request("SIP/2.0/UDP example.com:9;rport");
        let mut response = Box::pin(client.call(request.clone()));
        let waker: Waker =
            Arc::new(SendNext { client: Mutex::new(client), request }).into();
        assert!(response
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());

        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);
        let wire_request = timeout(Duration::from_secs(3), async {
            let mut bytes = Vec::new();
            loop {
                assert!(peer.read_buf(&mut bytes).await.unwrap() > 0);
                if let Ok(request) = Request::from_bytes(&bytes) {
                    break request;
                }
            }
        })
        .await
        .unwrap();
        // Start acceptance wakes separately from final-response delivery.
        assert!(response
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        driver.on_received_response(route_response(&wire_request));

        assert!(response.await.is_ok());
        assert_eq!(driver.clients.len(), 0);
        assert!(driver.client_connections.is_empty());
        assert_eq!(
            driver.commands.len(),
            1,
            "the completion waker admitted the next request"
        );
    }

    /// Lets the driver's UDP backlog drain, which `run` would do.
    async fn flush(driver: &mut Driver) {
        timeout(
            Duration::from_secs(3),
            poll_fn(|cx| {
                let udp = driver.udp.as_mut().unwrap();
                udp.poll_flush(cx);
                if udp.is_idle() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_retransmission_without_receipt_capacity_keeps_the_transaction()
    {
        let (mut driver, commands, _local) = reply_driver_with(Config {
            timers: Timers::builder()
                .t1(Duration::from_millis(10))
                .build()
                .unwrap(),
            max_client_transactions: 1,
            ..Config::default()
        });
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let mut client = Client::new(
            commands,
            driver.client_admission(),
            Transport::Udp,
            peer.local_addr().unwrap(),
        );
        let mut response = Box::pin(
            client.call(route_request("SIP/2.0/UDP example.com:9;rport")),
        );
        let command = driver.commands.try_recv().unwrap();
        driver.on_command(command);
        flush(&mut driver).await;
        let mut buffer = [0; 4096];
        let first = timeout(Duration::from_secs(1), peer.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();

        // A receipt that never resolves takes the only observation slot.
        let (id, entry) = driver.clients.iter().next().unwrap();
        let observation = entry.respond.as_ref().unwrap().observation();
        let (_never, receipt) = oneshot::channel();
        driver.client_writes.clear();
        driver.client_writes.push((
            ClientReceipt::Udp(receipt),
            id,
            observation,
        ));
        sleep(Duration::from_millis(20)).await;
        driver.on_timer(Key::Client(id));
        flush(&mut driver).await;

        let again = timeout(Duration::from_secs(1), peer.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again, first);
        assert!(driver.clients.get(id).is_some());
        assert_eq!(driver.client_writes.len(), 1);
        assert!(poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx)))
            .await
            .is_pending());
    }

    // Deterministic INVITE timers. The tests drive the driver by hand on a
    // paused clock, so a deadline fires only when a test says so, and the
    // production values, Timer D's 32 s included, stay as they are.

    const T1: Duration = Duration::from_millis(500);

    struct Noop;

    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    fn now_or_never<F: Future>(future: F) -> Option<F::Output> {
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => Some(output),
            Poll::Pending => None,
        }
    }

    /// Fires every timer due by the current, paused, time.
    fn fire_due(driver: &mut Driver) {
        let now = now();
        while driver.timers.deadline().is_some_and(|at| at <= now) {
            let key = driver.timers.pop().unwrap();
            driver.on_timer(key);
        }
    }

    struct InviteFixture {
        fixture: DriverFixture,
        endpoint: Endpoint,
        peer: UdpSocket,
    }

    impl InviteFixture {
        async fn new() -> InviteFixture {
            let (fixture, commands, local) = reply_driver_with(Config {
                max_pending_requests: 8,
                ..Config::default()
            });
            let endpoint = fixture_endpoint(&fixture, commands, local);
            let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
            InviteFixture { fixture, endpoint, peer }
        }

        /// Starts an INVITE to the peer and returns its handles and the
        /// request as sent.
        fn start(&mut self) -> (ClientControl, Responses, Request<Bytes>) {
            let target =
                Target::new(Transport::Udp, self.peer.local_addr().unwrap());
            let mut start = Box::pin(self.endpoint.start(invite(), target));
            assert!(now_or_never(start.as_mut()).is_none());
            let command = self.fixture.commands.try_recv().unwrap();
            self.fixture.on_command(command);
            let (control, responses) =
                now_or_never(start).unwrap().unwrap().into_parts();

            let mut sent = invite();
            sent.headers_mut().prepend(VIA, control.via().clone());
            (control, responses, sent)
        }

        fn deliver(&mut self, response: Response<Bytes>) {
            let link = udp_reply_link(
                self.endpoint.udp_addr().unwrap(),
                self.peer.local_addr().unwrap(),
            );
            self.fixture.on_message(Message::Response(response), link);
        }

        fn client(&self, sent: &Request<Bytes>) -> Option<Id> {
            let key = ClientKey::from_request(sent).unwrap();
            self.fixture.clients.find(&key).map(|(id, _)| id)
        }

        /// Lets the driver's UDP backlog drain, which `run` would do. A first
        /// send can wait there for the socket's readiness.
        async fn flush(&mut self) {
            let udp = self.fixture.udp.as_mut().unwrap();
            poll_fn(|cx| {
                udp.poll_flush(cx);
                if udp.is_idle() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }

        /// The next request the peer got, skipping INVITE retransmissions.
        async fn received(&mut self) -> Request<Bytes> {
            self.flush().await;
            let mut buf = vec![0; 65536];
            loop {
                let n = self.peer.recv(&mut buf).await.unwrap();
                let request = Request::from_bytes(&buf[..n]).unwrap();
                if request.method() != Method::INVITE {
                    return request;
                }
            }
        }

        /// Whether nothing but INVITE retransmissions reached the peer.
        async fn quiet(&mut self) -> bool {
            self.flush().await;
            let mut buf = vec![0; 65536];
            loop {
                match self.peer.try_recv(&mut buf) {
                    Ok(n) => {
                        let request = Request::from_bytes(&buf[..n]).unwrap();
                        if request.method() != Method::INVITE {
                            return false;
                        }
                    }
                    Err(_) => return true,
                }
            }
        }
    }

    fn observed(responses: &mut Responses) -> Option<Option<u16>> {
        now_or_never(responses.next())
            .map(|item| item.map(|r| r.unwrap().status().as_u16()))
    }

    // RFC 6026 section 8.4. M starts at the first 2xx, a later 2xx does not
    // restart it, and a 2xx at M's instant comes after the timer, so it is
    // stray (section 8.9).
    #[tokio::test(start_paused = true)]
    async fn invite_m_is_not_restarted_and_fires_before_a_2xx_at_its_instant()
    {
        let mut t = InviteFixture::new().await;
        let (_control, mut responses, sent) = t.start();
        let first = now();

        t.deliver(reply(&sent, 200, "a"));
        assert_eq!(observed(&mut responses), Some(Some(200)));
        let id = t.client(&sent).unwrap();
        let m = first + 64 * T1;
        assert_eq!(t.fixture.clients.get(id).unwrap().deadline(), Some(m));

        advance(32 * T1).await;
        t.deliver(reply(&sent, 200, "b"));
        assert_eq!(observed(&mut responses), Some(Some(200)));
        assert_eq!(t.fixture.clients.get(id).unwrap().deadline(), Some(m));

        advance(32 * T1).await;
        assert_eq!(now(), m);
        t.deliver(reply(&sent, 200, "c"));
        assert_eq!(observed(&mut responses), Some(None));
        assert!(t.client(&sent).is_none());
        assert_eq!(t.fixture.unanswered, 0);
    }

    // RFC 3261 section 17.1.1.2. B times out Calling only. Proceeding has no
    // timer, and over UDP Completed keeps the cached ACK for Timer D, at
    // least 32 s whatever T1 is.
    #[tokio::test(start_paused = true)]
    async fn invite_proceeding_has_no_timer_b_and_d_keeps_the_ack_32_seconds()
    {
        let mut t = InviteFixture::new().await;
        let (_control, mut responses, sent) = t.start();

        t.deliver(reply(&sent, 180, "a"));
        assert_eq!(observed(&mut responses), Some(Some(180)));
        advance(1000 * T1).await;
        fire_due(&mut t.fixture);
        assert_eq!(observed(&mut responses), None);
        let id = t.client(&sent).unwrap();
        assert_eq!(t.fixture.clients.get(id).unwrap().deadline(), None);

        let busy = reply(&sent, 486, "a");
        t.deliver(busy.clone());
        assert_eq!(observed(&mut responses), Some(Some(486)));
        assert_eq!(observed(&mut responses), Some(None));
        let ack = t.received().await;
        assert_eq!(ack.method(), Method::ACK);
        let d = now() + Duration::from_secs(32);
        assert_eq!(t.fixture.clients.get(id).unwrap().deadline(), Some(d));

        advance(Duration::from_secs(31)).await;
        t.deliver(busy.clone());
        assert_eq!(t.received().await.to_bytes(), ack.to_bytes());

        advance(Duration::from_secs(1)).await;
        fire_due(&mut t.fixture);
        assert!(t.client(&sent).is_none());
        t.deliver(busy);
        assert!(t.quiet().await);
    }

    // RFC 3261 section 9.1. The deadline runs 64 T1 from the CANCEL, not
    // from the INVITE, and a final at that instant comes after it.
    #[tokio::test(start_paused = true)]
    async fn the_cancel_deadline_runs_64_t1_from_the_cancel() {
        let mut t = InviteFixture::new().await;
        let (control, mut responses, sent) = t.start();
        t.deliver(reply(&sent, 180, "a"));
        assert_eq!(observed(&mut responses), Some(Some(180)));
        advance(10 * T1).await;

        let mut cancel = Box::pin(control.cancel());
        assert!(now_or_never(cancel.as_mut()).is_none());
        let command = t.fixture.commands.try_recv().unwrap();
        t.fixture.on_command(command);
        let Some(Ok(CancelOutcome::Sent(_))) = now_or_never(cancel) else {
            panic!("a CANCEL");
        };
        assert_eq!(t.received().await.method(), Method::CANCEL);
        let deadline = now() + 64 * T1;
        let id = t.client(&sent).unwrap();
        assert_eq!(
            t.fixture.clients.get(id).unwrap().deadline(),
            Some(deadline)
        );

        advance(64 * T1 - Duration::from_millis(1)).await;
        fire_due(&mut t.fixture);
        assert_eq!(observed(&mut responses), None);

        advance(Duration::from_millis(1)).await;
        t.deliver(reply(&sent, 487, "a"));
        let error =
            now_or_never(responses.next()).unwrap().unwrap().unwrap_err();
        assert!(error.is_cancel_timeout(), "{error}");
        assert!(t.client(&sent).is_none());
        assert_eq!(t.fixture.unanswered, 1, "only the CANCEL's own");
    }

    // RFC 6026 section 8.7. L starts at the first 2xx and a later 2xx does
    // not restart it. Accepted absorbs INVITE retransmissions until then. At
    // L's instant the timer runs first, so the retransmission is a new
    // request (section 8.10).
    #[tokio::test(start_paused = true)]
    async fn invite_l_is_not_restarted_and_fires_before_a_retransmission() {
        let (mut fixture, _commands, local) = reply_driver();
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let link = udp_reply_link(local, peer.local_addr().unwrap());
        let via = format!(
            "SIP/2.0/UDP {};branch=z9hG4bKaccepted",
            peer.local_addr().unwrap()
        );
        let mut request = route_request(&via);
        *request.method_mut() = Method::INVITE;
        request.headers_mut().insert(CSEQ, "1 INVITE".parse().unwrap());

        fixture.on_request(request.clone(), link.clone());
        let received = fixture.take_request();
        let slot = received.transaction.responder.shared.slot;
        let first = now();
        for tag in ["a", "b"] {
            let ok = reply(&received.request, 200, tag);
            fixture
                .accept_response(slot, ok.status(), ok.to_bytes(), None)
                .unwrap();
            assert_eq!(
                fixture.servers.get(slot).unwrap().tx.deadline(),
                Some(first + 64 * T1)
            );
            advance(32 * T1).await;
        }

        // The second advance reached L exactly, and no timer has run.
        fixture.on_request(request.clone(), link.clone());
        let fresh = fixture.take_request();
        assert_ne!(fresh.transaction.id(), received.transaction.id());
        assert!(fixture.servers.get(slot).is_none());

        advance(T1).await;
        fixture.on_request(request, link);
        assert!(fixture.incoming.receiver.try_recv().is_err());
    }

    // A cancel handle names its INVITE by table id. Once that INVITE is
    // gone, a new one in the same slot is not cancelled by the old handle.
    #[tokio::test(start_paused = true)]
    async fn a_stale_cancel_handle_cannot_reach_a_reused_slot() {
        let mut t = InviteFixture::new().await;
        let (old, _old_responses, sent) = t.start();
        t.deliver(reply(&sent, 486, "a"));
        assert_eq!(t.received().await.method(), Method::ACK);
        let old_id = t.client(&sent).unwrap();
        advance(Duration::from_secs(32)).await;
        fire_due(&mut t.fixture);
        assert!(t.client(&sent).is_none());

        let (current, mut responses, current_sent) = t.start();
        let id = t.client(&current_sent).unwrap();
        assert_eq!(
            format!("{id:?}").split(',').next(),
            format!("{old_id:?}").split(',').next()
        );
        t.deliver(reply(&current_sent, 180, "b"));
        assert_eq!(observed(&mut responses), Some(Some(180)));

        let mut stale = Box::pin(old.cancel());
        assert!(now_or_never(stale.as_mut()).is_none());
        let command = t.fixture.commands.try_recv().unwrap();
        t.fixture.on_command(command);
        assert!(matches!(
            now_or_never(stale),
            Some(Ok(CancelOutcome::NotNeeded))
        ));
        assert!(t.quiet().await);

        let mut cancel = Box::pin(current.cancel());
        assert!(now_or_never(cancel.as_mut()).is_none());
        let command = t.fixture.commands.try_recv().unwrap();
        t.fixture.on_command(command);
        assert!(matches!(
            now_or_never(cancel),
            Some(Ok(CancelOutcome::Sent(_)))
        ));
        let cancel = t.received().await;
        assert_eq!(cancel.method(), Method::CANCEL);
        assert_eq!(cancel.headers().get(TO), current_sent.headers().get(TO));
    }

    /// An INVITE answered with a 200 by a TU that then dropped its handles,
    /// with a shutdown requested at `first` that ends at `deadline`.
    async fn accepted_and_shutting_down(
        deadline: Duration,
    ) -> (DriverFixture, mpsc::UnboundedSender<Command>, Id, Instant) {
        let (mut fixture, commands, local) = reply_driver();
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let link = udp_reply_link(local, peer.local_addr().unwrap());
        let via = format!(
            "SIP/2.0/UDP {};branch=z9hG4bKdrain",
            peer.local_addr().unwrap()
        );
        let mut request = route_request(&via);
        *request.method_mut() = Method::INVITE;
        request.headers_mut().insert(CSEQ, "1 INVITE".parse().unwrap());

        fixture.on_request(request, link);
        let received = fixture.take_request();
        let slot = received.transaction.responder.shared.slot;
        let first = now();
        let ok = reply(&received.request, 200, "a");
        fixture
            .accept_response(slot, ok.status(), ok.to_bytes(), None)
            .unwrap();
        drop(received);
        flush(&mut fixture).await;
        assert!(fixture.shutdown_control.request(deadline));
        fixture.on_control();

        (fixture, commands, slot, first)
    }

    // RFC 6026 section 8.7. The server keeps an INVITE in Accepted until
    // Timer L, after its final response and with its handles dropped, and
    // the drain waits for it. A deadline at L's instant runs L first, as a
    // timer does before input at the same instant, so the outcome is a
    // drain. A deadline before L is not.
    #[tokio::test(start_paused = true)]
    async fn a_shutdown_waits_for_timer_l_and_runs_it_before_a_deadline_at_l()
    {
        let (mut fixture, commands, slot, first) =
            accepted_and_shutting_down(64 * T1).await;
        assert!(fixture.shutting_down);
        assert!(fixture.work.is_idle());
        assert!(fixture.servers.get(slot).is_some());
        assert!(!fixture.is_drained());

        advance(64 * T1 - Duration::from_millis(1)).await;
        fire_due(&mut fixture);
        assert!(!fixture.is_drained());
        advance(Duration::from_millis(1)).await;
        assert_eq!(now(), first + 64 * T1);
        assert!(matches!(fixture.at_deadline(), End::Drained));
        assert!(fixture.servers.get(slot).is_none());
        let guard = shutdown::WorkGuard::new(
            fixture.shutdown_control.clone(),
            fixture.control.clone(),
            commands,
        );
        assert!(guard.unwrap_err().is_closed());

        let (mut fixture, _commands, slot, _) =
            accepted_and_shutting_down(64 * T1 - Duration::from_millis(1))
                .await;
        advance(64 * T1 - Duration::from_millis(1)).await;
        assert!(matches!(fixture.at_deadline(), End::Expired));
        assert!(fixture.servers.get(slot).is_some());
    }

    // The outcome classifies the endpoint's work, not the instant its last
    // transport task returned. Here every machine, guard and write finished
    // before the deadline, and a transport task is still ending when the
    // deadline comes. The deadline moves it to Abort, which drops nothing
    // here, and the future still waits for the task. A task that drops
    // output records it, as in `the_deadline_aborts_a_stalled_tcp_writer`.
    #[tokio::test(start_paused = true)]
    async fn a_teardown_past_the_deadline_with_nothing_left_is_a_drain() {
        let (fixture, commands, local) = reply_driver();
        let endpoint = fixture_endpoint(&fixture, commands, local);
        let teardown = fixture.tasks.handle();
        let started = now();
        let ending = tokio::spawn(async move {
            sleep(Duration::from_secs(2)).await;
            drop(teardown);
        });
        let driver = tokio::spawn(fixture.run());

        let outcome = endpoint.shutdown(Duration::from_secs(1)).await;

        assert_eq!(outcome, ShutdownOutcome::Drained);
        assert_eq!(now(), started + Duration::from_secs(2));
        assert!(ending.is_finished());
        driver.await.unwrap();
    }

    // Once drained, the driver closes its command queue and its work guards
    // in one step. A guard taken before still holds the drain, and the last
    // guard's drop lets the driver decide.
    #[tokio::test(start_paused = true)]
    async fn the_stop_decision_closes_commands_and_guards_together() {
        let (mut fixture, commands, local) = reply_driver();
        let endpoint = fixture_endpoint(&fixture, commands, local);
        let guard = endpoint.work_guard().unwrap();
        drop(endpoint.clone().shutdown(Duration::from_secs(1)));
        assert!(matches!(
            poll_fn(|cx| fixture.poll_event(cx)).await,
            Event::Control
        ));
        fixture.on_control();
        assert!(!fixture.is_drained());

        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert!(fixture.poll_event(&mut cx).is_pending());
        assert!(!fixture.stopping);
        drop(guard);
        assert!(matches!(
            poll_fn(|cx| fixture.poll_event(cx)).await,
            Event::Control
        ));
        fixture.on_control();

        // With nothing left, the driver decides, and refuses from then on.
        assert!(fixture.poll_event(&mut cx).is_pending());
        assert!(fixture.stopping);
        assert!(endpoint.work_guard().unwrap_err().is_closed());
        let refused = now_or_never(endpoint.send_request(
            route_request("SIP/2.0/UDP example.com:9"),
            Target::new(Transport::Udp, local),
            ViaMode::Fresh,
        ));
        assert!(refused.unwrap().unwrap_err().is_closed());
    }

    // At the deadline the same decision runs a command queued before it, so
    // its caller is not told that the endpoint closed, and refuses a later
    // one.
    #[tokio::test(start_paused = true)]
    async fn the_deadline_runs_commands_queued_before_its_decision() {
        let (mut fixture, commands, local) = reply_driver();
        let endpoint = fixture_endpoint(&fixture, commands, local);
        drop(endpoint.clone().shutdown(Duration::from_secs(1)));
        assert!(matches!(
            poll_fn(|cx| fixture.poll_event(cx)).await,
            Event::Control
        ));
        fixture.on_control();
        let mut queued = Box::pin(endpoint.send_request(
            route_request("SIP/2.0/UDP example.com:9"),
            Target::new(Transport::Udp, local),
            ViaMode::Fresh,
        ));
        assert!(now_or_never(queued.as_mut()).is_none());

        advance(Duration::from_secs(1)).await;
        fixture.at_deadline();

        assert!(fixture.commands.is_empty());
        // It ran. The fixture's wildcard address makes the send itself fail.
        let ran = now_or_never(queued.as_mut());
        let closed = matches!(&ran, Some(Err(error)) if error.is_closed());
        assert!(!closed, "{ran:?}");
        let refused = now_or_never(endpoint.send_request(
            route_request("SIP/2.0/UDP example.com:9"),
            Target::new(Transport::Udp, local),
            ViaMode::Fresh,
        ));
        assert!(refused.unwrap().unwrap_err().is_closed());
    }

    // A connect in progress is accepted work, so it holds the drain, and the
    // deadline gives up on it. The attempt itself ends with the endpoint's
    // channel, see `connect_deadline_and_endpoint_close_drop_the_attempt`.
    #[tokio::test(start_paused = true)]
    async fn a_pending_connect_holds_the_drain_until_the_deadline() {
        let (mut fixture, _commands, _) = reply_driver();
        assert!(fixture.shutdown_control.request(Duration::from_secs(1)));
        fixture.on_control();
        assert!(fixture.is_drained());

        fixture.routes.insert(
            SocketAddr::from(([127, 0, 0, 1], 9)),
            Route {
                tcp: TcpState::Connecting(Vec::new()),
                ..Route::default()
            },
        );

        assert!(!fixture.is_drained());
        advance(Duration::from_secs(1)).await;
        assert!(matches!(fixture.at_deadline(), End::Expired));
    }
}
