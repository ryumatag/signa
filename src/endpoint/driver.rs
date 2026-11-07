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

A shutdown is a deadline on the heap too. From the command on, the driver
answers new requests with a 503 and refuses new sends, and it stops as soon as
nothing is open any more, or at the deadline. Stopping is dropping the driver.
That drops the transactions, answers the client futures with a closed error,
and closes the sockets. The TCP readers see their channel close and end their
connections.
*/

use std::{
    collections::HashMap,
    future::{poll_fn, Future},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use foldhash::fast::RandomState;
use tokio::{
    sync::{mpsc, oneshot, watch, Semaphore},
    time::Sleep,
};

use crate::{
    endpoint::{
        admission::{AdmissionOwner, ClientAdmission, Permit},
        builder::Config,
        datagram::Datagram,
        error::Error,
        reply::{Admission, Completion, ReplyError, ReplyRoute},
        routing::{
            mark_via, reply_flow, sent_by_is, source_toward, via_value,
            Branches, Link,
        },
        server::{
            self, IncomingEvent, ReceivedRequest, ServerRequest,
            ServerTransactionId, SubmitError,
        },
        shutdown,
        table::{Id, Table},
        timer::{Key, TimerQueue},
    },
    message::{
        header::{via::Via, VIA},
        request::Request,
        response::{bare_response, reply_headers, Response},
        Message, Method, StatusCode,
    },
    transaction::{
        key::{ClientKey, ServerKey},
        non_invite::{ClientEvent, ClientTransaction, ServerTransaction},
    },
    transport::{budget::Budget, tcp, udp, Flow, Transport, WriteLimits},
};

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
const NOT_IMPLEMENTED: StatusCode = status(501);
const SERVICE_UNAVAILABLE: StatusCode = status(503);
const TRANSACTION_DOES_NOT_EXIST: StatusCode = status(481);

const fn status(code: u16) -> StatusCode {
    match StatusCode::from_u16(code) {
        Ok(status) => status,
        Err(_) => panic!("a status code"),
    }
}

/// What a client sends.
pub(super) type Responder = oneshot::Sender<Result<Response<Bytes>, Error>>;

/// What the driver is told, by the handles and by its own tasks.
pub(super) enum Command {
    /// A client sends a request.
    Send {
        request: Request<Bytes>,
        transport: Transport,
        next_hop: SocketAddr,
        respond: Responder,
        permit: Permit,
    },
    /// A route sends one response without a transaction.
    Reply { link: Link, bytes: Bytes, completion: Completion },
    /// A TU asks the driver to accept a response.
    Submit(server::Submission),
    /// A connection the driver asked for is open, or could not be opened.
    Connected {
        remote: SocketAddr,
        result: io::Result<(Flow, tcp::Writer)>,
        _attempt: crate::transport::budget::Permit,
    },
    /// An `Endpoint` asks the driver to stop once nothing is open, or after
    /// the shared deadline. Waiters observe the shared completion channel.
    Shutdown,
}

/// Admission destination before issuing an incoming capability.
pub(super) enum Slot {
    /// A server transaction, which sends the response and answers
    /// retransmissions with it.
    Transaction(Id),
    /// No transaction, because the request had no RFC 3261 branch. The
    /// response is sent once, and a retransmission of the request reaches
    /// the TU again.
    Stateless(Link),
}

struct ServerEntry {
    tx: ServerTransaction,
    /// Where responses go. Its remote address is the one RFC 3261 section
    /// 18.2.2 picks, which is the request's source port only with `rport`.
    link: Link,
    shared: Option<Arc<server::Shared>>,
    identity: usize,
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

struct ClientEntry {
    tx: ClientTransaction,
    /// Where the request went. Its local address is the `sent-by` written
    /// into the `Via`, which a response has to carry back.
    link: Link,
    /// Taken when the final response, or the error, is delivered.
    respond: Option<Responder>,
    permit: Permit,
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
    Request(Request<Bytes>, Responder, Permit),
    /// An encoded response whose request came on a connection that has closed
    /// since. It goes to `sent-by` on a new connection
    /// (RFC 3261 section 18.2.2).
    Response(Bytes, Fallback),
    OneShot(Bytes, Completion),
    Server(Bytes, server::WriteObservation, crate::transport::budget::Permit),
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
    /// A responder was dropped before an accepted final response.
    Abandon(Arc<server::Shared>, ReplyRoute),
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
    /// From the `Endpoint`, `Client`, `Responder` and `ReplyRoute` handles.
    /// The driver ends when they are all gone.
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
    /// Set by the first shutdown command. New requests get a 503 from then on,
    /// and the driver stops once `is_drained` says so.
    shutting_down: bool,
    /// Closing this single sender wakes every caller-owned shutdown receiver.
    pub(super) shutdown_done: watch::Sender<()>,
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
}

impl Driver {
    /// Must be called from within a tokio runtime, for the timer.
    pub(super) fn new(
        incoming: mpsc::UnboundedSender<server::Queued>,
        config: Config,
        udp: Option<udp::Socket>,
        tcp: mpsc::Receiver<tcp::Inbound>,
        tcp_tx: mpsc::Sender<tcp::Inbound>,
        commands: mpsc::UnboundedReceiver<Command>,
        command_sender: mpsc::WeakUnboundedSender<Command>,
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
            shutdown_done: watch::channel(()).0,
            shutdown_control: Arc::default(),
            next_source: 0,
            control,
            control_rx,
            write_cursor: 0,
            server_writes: Vec::new(),
            server_cursor: 0,
            fallback_cursor: 0,
            branches: Branches::new(),
        }
    }

    pub(super) fn client_admission(&self) -> ClientAdmission {
        self.client_admission.0.clone()
    }

    pub(super) async fn run(mut self) {
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
                Event::Timer(Key::Shutdown) => return,
                Event::Timer(key) => self.on_timer(key),
                Event::Command(command) => self.on_command(command),
                Event::Inbound(inbound) => {
                    let link = Link {
                        flow: inbound.flow,
                        writer: Some(inbound.writer),
                    };
                    self.on_message(inbound.message, link);
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
                Event::Stop => return,
            }
        }
    }

    /// Polls every source in turn and returns the first event.
    ///
    /// The shutdown check comes last, once every source is pending, so that it
    /// sees the tables after everything that arrived has been handled.
    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        if let Poll::Ready(Some(())) = self.control_rx.poll_recv(cx) {
            return Poll::Ready(Event::Command(Command::Shutdown));
        }

        let servers = &self.servers;
        let clients = &self.clients;
        self.timers.compact(servers.len() + clients.len(), |key| match key {
            Key::Server(id) => servers.get(id)?.tx.deadline(),
            Key::Client(id) => clients.get(id)?.tx.deadline(),
            Key::Shutdown => {
                unreachable!("the queue owns the shutdown deadline")
            }
        });

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
                2 => self.commands.poll_recv(cx).map(|command| {
                    Some(command.map_or(Event::Stop, Event::Command))
                }),
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
            return Poll::Ready(Event::Stop);
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

    /// Returns whether protocol and transport work has drained.
    fn is_drained(&self) -> bool {
        self.writes.is_empty()
            && self.server_writes.is_empty()
            && self.live_work_is_drained()
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
            Command::Connected { remote, result, _attempt } => {
                self.on_connected(remote, result);
            }
            Command::Shutdown => {
                self.client_admission.0.close();
                self.shutting_down = true;
                if let Some(at) = self.shutdown_control.take() {
                    self.timers.push(at, Key::Shutdown);
                }
            }
        }
    }

    fn on_timer(&mut self, key: Key) {
        let now = now();
        let timers = self.config.timers;
        match key {
            Key::Server(id) => {
                let Some(entry) = self.servers.get_mut(id) else { return };
                let before = entry.tx.deadline();
                // The automatic 100 copies the request's Via, From, To,
                // Call-ID and CSeq. The request's work reservation covers
                // those bytes until a final replaces the 100, so it takes no
                // separate `retained` reservation that could fail.
                if let Some(trying) = entry.tx.on_timeout(now) {
                    let link = entry.link.clone();
                    let shared =
                        entry.shared.as_ref().expect("TU transaction").clone();
                    self.send_generated(id, &link, trying, &shared);
                }

                self.settle_server(id, before);
            }
            Key::Client(id) => {
                let Some(entry) = self.clients.get_mut(id) else { return };
                let before = entry.tx.deadline();
                let completion = match entry.tx.on_timeout(&timers, now) {
                    ClientEvent::Retransmit(request) => {
                        match send_on(
                            self.udp.as_mut(),
                            &entry.link,
                            &request,
                            false,
                        ) {
                            Ok(()) => None,
                            Err(err) => {
                                entry.tx.on_transport_error();
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
                    let _ = respond.send(result);
                }
            }
            Key::Shutdown => unreachable!("handled by the loop"),
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
            self.servers.remove(id);
            return;
        }

        let after = entry.tx.deadline();
        if after != before {
            if let Some(at) = after {
                self.timers.push(at, Key::Server(id));
            }
        }
    }

    /// See [`Driver::settle_server`].
    fn settle_client(&mut self, id: Id, before: Option<Instant>) {
        let Some(entry) = self.clients.get(id) else { return };
        if entry.tx.is_terminated() {
            self.clients.remove(id);
            return;
        }

        let after = entry.tx.deadline();
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
        respond: Responder,
        permit: Permit,
    ) {
        if self.shutting_down {
            drop(request);
            drop(permit);
            let _ = respond.send(Err(Error::closed()));
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
                    let _ = respond.send(Err(Error::transport(err)));
                    return;
                };
                let port = udp.local_addr().port();
                let source = match self.udp_source(next_hop) {
                    Ok(source) => source,
                    Err(err) => {
                        drop(request);
                        drop(permit);
                        let _ = respond.send(Err(Error::transport(err)));
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
        let response = !matches!(pending, Pending::Request(..));
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
        tokio::spawn(async move {
            let connect = tcp::connect_reserved(
                remote,
                &config,
                &inbound,
                Some(connection),
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
                let _ = respond.send(Err(Error::busy()));
            }
            Pending::Response(..) => {}
            // Server output reserves its route and connection before commit
            // and never passes through `send_over_tcp`. Report a rejection
            // rather than a transport failure if that ever changes.
            Pending::Server(_, observation, _) => observation.reject(),
            Pending::OneShot(bytes, completion) => {
                drop(bytes);
                completion.finish(Err(ReplyError::Busy));
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
        }
    }

    // Builds a route outside `on_request`, for the benchmark hook and tests.
    // Incoming envelopes get theirs when the driver admits the request.
    #[cfg_attr(not(any(test, feature = "__bench")), allow(dead_code))]
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
        if self.shutting_down {
            drop(bytes);
            completion.finish(Err(ReplyError::Closed));
            return;
        }

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
        respond: Responder,
        permit: Permit,
    ) {
        // The command owns capacity reserved before enqueue and connect.
        debug_assert!(
            self.clients.len() < self.config.max_client_transactions
        );
        let via = via_value(&link.flow, &mut self.branches);
        request.headers_mut().prepend(VIA, via);
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
            let _ = respond.send(Err(error));
            return;
        }

        if let Err(err) = send_on(self.udp.as_mut(), &link, &bytes, true) {
            drop(request);
            drop(bytes);
            drop(permit);
            let _ = respond.send(Err(Error::transport(err)));
            return;
        }

        let reliable = link.flow.transport.is_reliable();
        let tx = ClientTransaction::new(
            bytes,
            reliable,
            &self.config.timers,
            now(),
        );
        let deadline = tx.deadline();
        let entry = ClientEntry { tx, link, respond: Some(respond), permit };
        let id = self.clients.insert(key, entry);
        if let Some(at) = deadline {
            self.timers.push(at, Key::Client(id));
        }
        self.unanswered += 1;
    }

    fn on_connected(
        &mut self,
        remote: SocketAddr,
        result: io::Result<(Flow, tcp::Writer)>,
    ) {
        let Some(route) = self.routes.get_mut(&remote) else { return };
        let pending = match std::mem::take(&mut route.tcp) {
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
                            let _ = respond.send(Err(Error::transport(err)));
                        }
                        // See `send_reply`.
                        Pending::Response(..) => {}
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

    fn on_message(&mut self, message: Message<Bytes>, link: Link) {
        match message {
            Message::Request(request) => self.on_request(request, link),
            Message::Response(response) => self.on_received_response(response),
        }
    }

    fn on_received_response(&mut self, response: Response<Bytes>) {
        let Some(key) = ClientKey::from_response(&response) else { return };
        let Some((id, entry)) = self.clients.find_mut(&key) else { return };
        // RFC 3261 section 18.1.2 discards a response whose top `Via` names
        // a `sent-by` other than this one's.
        let ours = response
            .headers()
            .get(VIA)
            .and_then(Via::top)
            .is_some_and(|via| sent_by_is(&via, entry.link.flow.local));
        if !ours {
            return;
        }

        let before = entry.tx.deadline();
        let completion =
            match entry.tx.on_response(response, &self.config.timers, now()) {
                ClientEvent::Final(response) => entry.answer(Ok(response)),
                // A non-INVITE provisional response is not handed up.
                ClientEvent::Provisional(_)
                | ClientEvent::None
                | ClientEvent::Retransmit(_)
                | ClientEvent::Timeout => None,
            };
        if completion.is_some() {
            self.unanswered -= 1;
        }
        self.settle_client(id, before);
        if let Some((respond, result)) = completion {
            let _ = respond.send(result);
        }
    }

    fn on_request(&mut self, mut request: Request<Bytes>, link: Link) {
        // Without a readable top `Via` there is no way to answer, so there
        // is nothing to do with the request.
        let Some(value) = request.headers().get(VIA) else { return };
        let Some(via) = Via::top(value) else { return };
        // RFC 3261 section 18.2.2 sends the response to `maddr`, normally a
        // multicast group. Multicast is out of scope for 0.3.0, and answering
        // the source instead would break that rule, so the request is dropped.
        if via.maddr.is_some() {
            return;
        }
        let reply = reply_flow(&via, &link.flow);
        let marked = mark_via(value, &via, &link.flow);
        let key = ServerKey::new(&via, request.method());

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

        // INVITE transactions are not wired into the endpoint yet. An ACK
        // outside one has nothing to match and is dropped (section 17.2.3),
        // and a CANCEL with no transaction to cancel gets a 481 (section 9.2).
        let method = request.method();
        if *method == Method::INVITE {
            self.stateless(&request, &link, NOT_IMPLEMENTED);
            return;
        }
        if *method == Method::ACK {
            return;
        }
        if *method == Method::CANCEL {
            self.stateless(&request, &link, TRANSACTION_DOES_NOT_EXIST);
            return;
        }

        if let Some(key) = &key {
            if let Some((id, entry)) = self.servers.find(key) {
                if let Some(response) = entry.tx.on_retransmission() {
                    let link = entry.link.clone();
                    if let Some(shared) = entry.shared.clone() {
                        self.send_generated(id, &link, response, &shared);
                    } else {
                        // An unobserved Completed entry has no observer to
                        // tell. A busy budget only drops this copy, as in
                        // `send_generated`.
                        match self.send_reply(&link, &response) {
                            Err(error)
                                if error.kind()
                                    != io::ErrorKind::WouldBlock =>
                            {
                                self.fail_server(id);
                            }
                            _ => {}
                        }
                    }
                }
                return;
            }
        }

        // Stateful TU responses need a usable identity, not only a Via route.
        // A request without exactly one From, To, Call-ID and CSeq, or with a
        // CSeq method other than its own, stays out of transaction and
        // application work. It gets a stateless 400 so that a UDP client stops
        // retransmitting instead of waiting for Timer F. The 400 copies what
        // identity there is, and uses the same bounded reply path as the 503.
        let identity = [
            crate::message::header::FROM,
            crate::message::header::TO,
            crate::message::header::CALL_ID,
            crate::message::header::CSEQ,
        ]
        .iter()
        .all(|name| {
            let mut values = request.headers().get_all(name);
            values.next().is_some() && values.next().is_none()
        });
        if !identity
            || !request
                .headers()
                .get(crate::message::header::CSEQ)
                .and_then(crate::message::header::cseq::CSeq::parse)
                .is_some_and(|cseq| cseq.method == request.method())
        {
            self.stateless(&request, &link, BAD_REQUEST);
            return;
        }

        // Overload and shutdown answer with a stateless 503, so the peer stops
        // retransmitting and can try elsewhere. Not reading the socket instead
        // would stall every flow on a TCP connection, including the responses
        // to this endpoint's own requests on it.
        if self.incoming.is_closed()
            || self.shutting_down
            || (key.is_some()
                && self.servers.len() >= self.config.max_server_transactions)
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
        let identity_bytes = request
            .headers()
            .iter()
            .filter(|(name, _)| {
                [
                    crate::message::header::VIA,
                    crate::message::header::FROM,
                    crate::message::header::TO,
                    crate::message::header::CALL_ID,
                    crate::message::header::CSEQ,
                ]
                .contains(name)
            })
            .try_fold(0usize, |total, (_, value)| {
                total.checked_add(value.len())
            });
        let Some(route_permit) = identity_bytes
            .and_then(|bytes| self.routes_admission.acquire(bytes))
        else {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        };

        let Some(commands) = self.command_sender.upgrade() else { return };

        let slot = match key {
            Some(key) => {
                let reliable = link.flow.transport.is_reliable();
                let tx = ServerTransaction::new(
                    &request,
                    reliable,
                    &self.config.timers,
                    now(),
                );
                let deadline = tx.deadline();
                let id = self.servers.insert(
                    key,
                    ServerEntry {
                        tx,
                        link,
                        shared: None,
                        identity: 0,
                        retained: None,
                    },
                );
                if let Some(at) = deadline {
                    self.timers.push(at, Key::Server(id));
                }

                Slot::Transaction(id)
            }
            None => Slot::Stateless(link),
        };
        let route_link = match &slot {
            Slot::Transaction(id) => {
                self.servers.get(*id).expect("new transaction").link.clone()
            }
            Slot::Stateless(link) => link.clone(),
        };
        let route = ReplyRoute::new(
            &request,
            route_link,
            commands.clone(),
            self.reply_admission.0.clone(),
            self.reply_bytes.clone(),
        );
        let event = match slot {
            Slot::Transaction(id) => {
                static NEXT_ID: AtomicU64 = AtomicU64::new(1);
                let (observation, receiver) =
                    watch::channel(server::Observation::default());
                let shared = Arc::new(server::Shared {
                    id: ServerTransactionId(
                        NEXT_ID.fetch_add(1, Ordering::Relaxed),
                    ),
                    slot: id,
                    work: server::Work::new(permit),
                    pending: std::sync::atomic::AtomicUsize::new(0),
                    next_operation: AtomicU64::new(1),
                    final_sent: std::sync::atomic::AtomicBool::new(false),
                    abandoned: std::sync::atomic::AtomicBool::new(false),
                    observation,
                    transport: std::sync::atomic::AtomicUsize::new(0),
                    terminated: std::sync::atomic::AtomicBool::new(false),
                });
                let entry = self.servers.get_mut(id).expect("new transaction");
                entry.identity = Arc::as_ptr(&shared) as usize;
                entry.shared = Some(shared.clone());
                let responder = server::Responder {
                    shared,
                    route: route.with_reservations(route_permit, None),
                    method: request.method().clone(),
                    commands,
                    drops: self.drop_sender.clone(),
                    submissions: self.submissions.clone(),
                };
                let transaction_id = responder.id();
                IncomingEvent::Request(ServerRequest {
                    request,
                    flow: source,
                    transaction: server::ServerTransaction {
                        responder,
                        events: server::ServerEvents {
                            id: transaction_id,
                            receiver,
                            seen: 0,
                            ended: false,
                            saw_termination: false,
                        },
                    },
                })
            }
            Slot::Stateless(_) => IncomingEvent::Untracked(ReceivedRequest {
                request,
                flow: source,
                reply: route.with_reservations(
                    route_permit,
                    Some(server::Work::new(permit)),
                ),
            }),
        };
        let _ = self
            .incoming
            .send(server::Queued { event, _permit: event_permit });
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

    // A TU capability can outlive every timer. Its Arc keeps the allocation
    // address from being reused while this identity can still be presented.
    // The stored address is compared only, never reconstructed or dereferenced.
    fn owns_server(&self, shared: &Arc<server::Shared>) -> bool {
        self.servers.get(shared.slot).is_some_and(|entry| {
            entry.identity == Arc::as_ptr(shared) as usize
        })
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
        let result = if self.owns_server(&shared) {
            if shared.final_sent.load(Ordering::Acquire) {
                drop(bytes);
                Err(SubmitError::FinalAlreadySent)
            } else {
                self.accept_response(
                    shared.slot,
                    status,
                    bytes,
                    Some(operation),
                )
            }
        } else {
            drop(bytes);
            Err(SubmitError::Terminated)
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
        entry.tx.check_response(status, now()).map_err(
            |error| match error {
                ResponseRejection::TooEarly => SubmitError::TooEarly,
                ResponseRejection::ProhibitedStatus => {
                    SubmitError::ProhibitedStatus
                }
                ResponseRejection::FinalAlreadySent => {
                    SubmitError::FinalAlreadySent
                }
                ResponseRejection::Terminated => SubmitError::Terminated,
            },
        )?;

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
        let before = entry.tx.deadline();
        let sent = entry.tx.on_response(
            status,
            bytes.clone(),
            &self.config.timers,
            now(),
        );
        debug_assert!(sent);

        if status.is_final() {
            shared.final_sent.store(true, Ordering::Release);
            shared.work.finish();
            // An unobserved non-INVITE UDP cache needs only its response and
            // capability identity. No observer can reappear after count zero.
            if !entry.tx.is_terminated()
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
        use crate::message::header::{address::has_tag, Tag, TO};

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

        // No TU is left to answer, and a non-INVITE Proceeding state has no
        // timer, so a machine whose 500 cannot be built or admitted would stay forever.
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
            entry.tx.on_transport_error();
            self.settle_server(id, None);
        }
    }
}

impl ClientEntry {
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
    let mut connect = std::pin::pin!(tokio::time::timeout(deadline, connect));
    let mut closed = std::pin::pin!(inbound.closed());
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

    use tokio::{net::UdpSocket, time::timeout};

    use super::*;
    use crate::endpoint::tests::TestServe;
    use crate::endpoint::{
        tests::{
            reply_driver, reply_driver_with, route_request, route_response,
            udp_reply_link, REPLY_LOCAL,
        },
        Client,
    };
    use tower_service::Service;

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
                tokio::task::yield_now().await;
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
        for _ in 0..100 {
            driver.internal_tx.send(Command::Shutdown).unwrap();
        }

        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        peer.send_to(
            b"test",
            SocketAddr::from(([127, 0, 0, 1], local.port())),
        )
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;
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
            Event::Command(Command::Shutdown)
        ));

        driver.on_command(Command::Shutdown);
        assert!(driver.shutting_down);
        assert!(!driver.shutdown_control.request(Duration::from_secs(60)));
        assert!(driver.shutdown_control.request(Duration::ZERO));
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
                wait.await;
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
        let stale = Arc::new(server::Shared {
            id: original.id,
            slot: original.slot,
            work: server::Work::new(capacity.acquire(0).unwrap()),
            pending: std::sync::atomic::AtomicUsize::new(1),
            next_operation: AtomicU64::new(1),
            final_sent: std::sync::atomic::AtomicBool::new(false),
            abandoned: std::sync::atomic::AtomicBool::new(false),
            observation,
            transport: std::sync::atomic::AtomicUsize::new(0),
            terminated: std::sync::atomic::AtomicBool::new(false),
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
        use std::sync::atomic::AtomicBool;

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
                tokio::task::yield_now().await;
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
        entry.tx.on_timeout(at);
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
            let mut send = std::pin::pin!(route.send(response.clone()));
            poll_fn(|cx| {
                assert!(send.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert!(driver.commands.is_empty());

        drop(all);

        {
            let mut send = std::pin::pin!(route.send(response.clone()));
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

        let mut send = std::pin::pin!(route.send(route_response(&request)));
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
        assert!(!driver.clients.get(id).unwrap().tx.is_terminated());
        assert!(client
            .call(route_request("SIP/2.0/UDP example.com:9;rport"))
            .await
            .unwrap_err()
            .is_busy());
        let timers = driver.config.timers;
        let entry = driver.clients.get_mut(id).unwrap();
        let deadline = entry.tx.deadline().unwrap();

        // Drive the machine at K directly instead of waiting on a wall clock.
        entry.tx.on_timeout(&timers, deadline);
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
        driver.on_received_response(route_response(&wire_request));

        assert!(response.await.is_ok());
        assert_eq!(driver.clients.len(), 0);
        assert_eq!(
            driver.commands.len(),
            1,
            "the completion waker admitted the next request"
        );
    }
}
