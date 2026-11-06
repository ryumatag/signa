/*!
The task behind an endpoint.

One task owns the sockets, both transaction tables, and the timers, so none of
them needs a lock. Each turn it polls, in this order, the timer that is due
first, what the service futures and connect tasks report back, the requests
from clients, the TCP connections, the UDP socket, and, while requests wait
for the service, the service's readiness. A request the service takes runs in
a task of its own, since requests must run concurrently, and comes back as a
command with its response.

The tables are slabs, see [`table`], and the timers are one heap of deadlines,
with one `Sleep` set to the earliest. An entry names its transaction by its
table id. A transaction whose deadline moves gets a new entry, and an entry
whose transaction has moved on is harmless, because a transaction fires nothing
before its time, and one whose transaction is gone finds nothing. So nothing is
ever removed from the heap except by popping.

A shutdown is a deadline on the heap too. From the command on, the driver
answers new requests with a 503 and refuses new sends, and it stops as soon as
nothing is open any more, or at the deadline. Stopping is dropping the driver.
That drops the transactions, answers the client futures with a closed error,
and closes the sockets. The TCP readers see their channel close and end their
connections.
*/

use std::{
    cmp::Ordering,
    collections::{
        hash_map::RandomState as StdRandomState, BinaryHeap, HashMap, VecDeque,
    },
    convert::Infallible,
    fmt::Write as _,
    future::{poll_fn, Future},
    hash::{BuildHasher, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use foldhash::fast::RandomState;
use tokio::{
    sync::{mpsc, oneshot},
    time::Sleep,
};
use tower_service::Service;

use crate::{
    endpoint::{
        error::Error,
        table::{Id, Table},
    },
    header::{via::Via, HeaderValue, CSEQ, VIA},
    message::Message,
    method::Method,
    request::Request,
    response::{reply_headers, Response},
    status::StatusCode,
    transaction::{
        bare_response, ClientEvent, ClientKey, ClientTransaction, ServerKey,
        ServerTransaction, Timers,
    },
    transport::{tcp, udp, Flow, Transport},
};

/// The most bytes of a request that go over UDP. RFC 3261 section 18.1.1
/// sends a larger one over a congestion-controlled transport. The limit is
/// 200 bytes under the path MTU, or 1300 bytes when the MTU is unknown, and
/// signa does not know it.
pub(super) const MAX_UDP_REQUEST: usize = 1300;

/// How many messages from TCP connections may wait for the driver. When it
/// falls behind, the readers stop and TCP flow control holds the peers back.
pub(super) const TCP_INBOUND: usize = 256;

/// The port `sent-by` means when it names none (RFC 3261 section 18.2.2).
const DEFAULT_PORT: u16 = 5060;

/// How many datagrams may wait for the UDP socket to be writable. Beyond
/// that a send fails, and the transaction retransmits later if it does.
const UDP_BACKLOG: usize = 1024;

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

/// Settings from the builder.
#[derive(Clone, Copy, Debug)]
pub(super) struct Config {
    pub(super) timers: Timers,
    pub(super) tcp: tcp::Config,
    pub(super) max_pending_requests: usize,
    pub(super) max_client_transactions: usize,
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
    },
    /// The service answered a request, or failed on it.
    Respond { slot: Slot, response: Option<Response<Bytes>> },
    /// A connection the driver asked for is open, or could not be opened.
    Connected { remote: SocketAddr, result: io::Result<(Flow, tcp::Writer)> },
    /// An `Endpoint` asks the driver to stop once nothing is open, or after
    /// `timeout`. `done` is dropped when it has, which is all the handle waits
    /// for.
    Shutdown { timeout: Duration, done: oneshot::Sender<Infallible> },
}

/// Where the response to a request handed to the service goes.
pub(super) enum Slot {
    /// A server transaction, which sends the response and answers
    /// retransmissions with it.
    Transaction(Id),
    /// No transaction, because the request had no RFC 3261 branch. The
    /// response is sent once, and a retransmission of the request reaches
    /// the service again.
    Stateless(Link),
}

/// A way to send: the flow, and the connection when the flow is TCP.
#[derive(Clone)]
pub(super) struct Link {
    flow: Flow,
    writer: Option<tcp::Writer>,
}

struct ServerEntry {
    tx: ServerTransaction,
    /// Where responses go. Its remote address is the one RFC 3261 section
    /// 18.2.2 picks, which is the request's source port only with `rport`.
    link: Link,
}

struct ClientEntry {
    tx: ClientTransaction,
    /// Where the request went. Its local address is the `sent-by` written
    /// into the `Via`, which a response has to carry back.
    link: Link,
    /// Taken when the final response, or the error, is delivered.
    respond: Option<Responder>,
}

/// What the driver knows about one next hop.
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
    Request(Request<Bytes>, Responder),
    /// An encoded response whose request came on a connection that has closed
    /// since. It goes to `sent-by` on a new connection
    /// (RFC 3261 section 18.2.2).
    Response(Bytes),
}

/// A heap entry. Earlier deadlines come out first.
#[derive(Clone, Copy)]
struct Timer {
    at: Instant,
    key: Key,
}

#[derive(Clone, Copy)]
enum Key {
    Server(Id),
    Client(Id),
    /// The shutdown deadline. The driver stops when it fires.
    Shutdown,
}

impl PartialEq for Timer {
    fn eq(&self, other: &Timer) -> bool {
        self.at == other.at
    }
}

impl Eq for Timer {}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Timer) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timer {
    fn cmp(&self, other: &Timer) -> Ordering {
        other.at.cmp(&self.at)
    }
}

/// Makes branches. Each is the magic cookie, a random prefix taken once, and
/// a counter, so no two transactions of this endpoint share one, and no two
/// endpoints do either, in all likelihood. Neither a syscall nor a random
/// number is needed per request.
struct Branches {
    prefix: String,
    next: u64,
}

impl Branches {
    fn new() -> Branches {
        // The standard library seeds its hasher randomly. Hashing nothing with
        // a fresh one gives 64 random bits without another dependency.
        let mut seed = StdRandomState::new().build_hasher().finish();
        let mut prefix = String::from("z9hG4bK");
        for _ in 0..10 {
            let digit = (seed % 36) as u8;
            seed /= 36;
            prefix.push(char::from(if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            }));
        }

        Branches { prefix, next: 0 }
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
}

pub(super) struct Driver<S> {
    service: S,
    /// `poll_ready` failed, so the service takes nothing any more.
    service_failed: bool,
    /// From the `Endpoint` and `Client` handles. The driver ends when they
    /// are all gone.
    commands: mpsc::UnboundedReceiver<Command>,
    /// From the service futures and the connect tasks. Kept apart from
    /// `commands`, because the driver holds the sender for them.
    internal: mpsc::UnboundedReceiver<Command>,
    internal_tx: mpsc::UnboundedSender<Command>,
    udp: Option<Udp>,
    tcp: mpsc::Receiver<tcp::Inbound>,
    /// For the connections the driver opens.
    tcp_tx: mpsc::Sender<tcp::Inbound>,
    config: Config,
    servers: Table<ServerKey, ServerEntry>,
    clients: Table<ClientKey, ClientEntry>,
    routes: HashMap<SocketAddr, Route, RandomState>,
    timers: BinaryHeap<Timer>,
    sleep: Pin<Box<Sleep>>,
    /// Requests waiting for the service to be ready.
    queue: VecDeque<(Slot, Request<Bytes>)>,
    /// Requests the service has taken and not answered.
    pending: usize,
    /// Client transactions without a final response or an error yet.
    unanswered: usize,
    /// Set by the first shutdown command. New requests get a 503 from then on,
    /// and the driver stops once `is_drained` says so.
    shutting_down: bool,
    /// The handles waiting for the driver to stop, which is when these drop.
    shutdown_done: Vec<oneshot::Sender<Infallible>>,
    branches: Branches,
}

impl<S> Driver<S>
where
    S: Service<Request<Bytes>, Response = Response<Bytes>>,
    S::Future: Send + 'static,
{
    /// Must be called from within a tokio runtime, for the timer.
    pub(super) fn new(
        service: S,
        config: Config,
        udp: Option<udp::Socket>,
        tcp: mpsc::Receiver<tcp::Inbound>,
        tcp_tx: mpsc::Sender<tcp::Inbound>,
        commands: mpsc::UnboundedReceiver<Command>,
    ) -> Driver<S> {
        let (internal_tx, internal) = mpsc::unbounded_channel();

        Driver {
            service,
            service_failed: false,
            commands,
            internal,
            internal_tx,
            udp: udp.map(Udp::new),
            tcp,
            tcp_tx,
            config,
            servers: Table::new(),
            clients: Table::new(),
            routes: HashMap::default(),
            timers: BinaryHeap::new(),
            sleep: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            queue: VecDeque::new(),
            pending: 0,
            unanswered: 0,
            shutting_down: false,
            shutdown_done: Vec::new(),
            branches: Branches::new(),
        }
    }

    pub(super) async fn run(mut self) {
        loop {
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
                Event::Stop => return,
            }
        }
    }

    /// Polls every source in turn and returns the first event.
    ///
    /// The shutdown check comes last, once every source is pending, so that it
    /// sees the tables after everything that arrived has been handled.
    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        if let Some(timer) = self.timers.peek() {
            let at = tokio::time::Instant::from_std(timer.at);
            if self.sleep.deadline() != at {
                self.sleep.as_mut().reset(at);
            }
            if self.sleep.as_mut().poll(cx).is_ready() {
                let timer = self.timers.pop().expect("peeked");
                return Poll::Ready(Event::Timer(timer.key));
            }
        }

        if let Poll::Ready(Some(command)) = self.internal.poll_recv(cx) {
            return Poll::Ready(Event::Command(command));
        }

        match self.commands.poll_recv(cx) {
            Poll::Ready(Some(command)) => {
                return Poll::Ready(Event::Command(command))
            }
            Poll::Ready(None) => return Poll::Ready(Event::Stop),
            Poll::Pending => {}
        }

        // The driver holds a sender, so the channel never ends.
        if let Poll::Ready(Some(inbound)) = self.tcp.poll_recv(cx) {
            return Poll::Ready(Event::Inbound(inbound));
        }

        if let Some(udp) = &mut self.udp {
            udp.poll_flush(cx);
            match udp.socket.poll_recv(cx, &mut udp.buf) {
                Poll::Ready(Ok((datagram, flow))) => {
                    return Poll::Ready(Event::Datagram(datagram, flow))
                }
                // A receive error on an unconnected UDP socket is rare and
                // says nothing about the next datagram. Try again on the
                // next turn, without spinning on it now.
                Poll::Ready(Err(_)) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }

        self.poll_dispatch(cx);

        if self.shutting_down && self.is_drained() {
            return Poll::Ready(Event::Stop);
        }

        Poll::Pending
    }

    /// Returns `true` when nothing is left that a shutdown waits for.
    ///
    /// That is a request waiting for the service or in its hands, a client
    /// transaction waiting for its final response, a connection being opened,
    /// which carries a request or a response, and a datagram waiting for the
    /// UDP socket. A transaction that only lingers to absorb retransmissions
    /// is not waited for, since whatever it would answer goes unanswered once
    /// the endpoint is gone anyway.
    fn is_drained(&self) -> bool {
        self.queue.is_empty()
            && self.pending == 0
            && self.unanswered == 0
            && self.udp.as_ref().map_or(true, |udp| udp.backlog.is_empty())
            && !self
                .routes
                .values()
                .any(|route| matches!(route.tcp, TcpState::Connecting(_)))
    }

    /// Hands waiting requests to the service as long as it is ready.
    ///
    /// Readiness is checked and used on the same instance, and each request
    /// runs in its own task because requests run concurrently. A service that
    /// fails `poll_ready` is done for good. The requests waiting for it get a
    /// 500, and every later one gets a 503 without reaching it.
    fn poll_dispatch(&mut self, cx: &mut Context<'_>) {
        while !self.queue.is_empty() {
            match self.service.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let (slot, request) =
                        self.queue.pop_front().expect("checked above");
                    self.pending += 1;
                    let future = self.service.call(request);
                    let internal = self.internal_tx.clone();
                    tokio::spawn(async move {
                        let response = future.await.ok();
                        let _ =
                            internal.send(Command::Respond { slot, response });
                    });
                }
                Poll::Ready(Err(_)) => {
                    self.service_failed = true;
                    while let Some((slot, _)) = self.queue.pop_front() {
                        self.on_response(slot, None);
                    }
                }
                Poll::Pending => return,
            }
        }
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Send { request, transport, next_hop, respond } => {
                self.on_send(request, transport, next_hop, respond);
            }
            Command::Respond { slot, response } => {
                self.pending -= 1;
                self.on_response(slot, response);
            }
            Command::Connected { remote, result } => {
                self.on_connected(remote, result);
            }
            Command::Shutdown { timeout, done } => {
                self.shutting_down = true;
                self.shutdown_done.push(done);
                // The earliest deadline wins when several handles ask. A
                // timeout too long for the clock means no deadline.
                if let Some(at) = now().checked_add(timeout) {
                    self.timers.push(Timer { at, key: Key::Shutdown });
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
                if let Some(trying) = entry.tx.on_timeout(now) {
                    let link = entry.link.clone();
                    if self.send_reply(&link, &trying).is_err() {
                        if let Some(entry) = self.servers.get_mut(id) {
                            entry.tx.on_transport_error();
                        }
                    }
                }
                self.settle_server(id, before);
            }
            Key::Client(id) => {
                let Some(entry) = self.clients.get_mut(id) else { return };
                let before = entry.tx.deadline();
                let answered = match entry.tx.on_timeout(&timers, now) {
                    ClientEvent::Retransmit(request) => {
                        match send_on(self.udp.as_mut(), &entry.link, &request)
                        {
                            Ok(()) => false,
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
                    | ClientEvent::Final(_) => false,
                };

                if answered {
                    self.unanswered -= 1;
                }

                self.settle_client(id, before);
            }
            Key::Shutdown => unreachable!("handled by the loop"),
        }
    }

    /// Drops a server transaction that is over, or schedules its next deadline
    /// when it moved.
    fn settle_server(&mut self, id: Id, before: Option<Instant>) {
        let Some(entry) = self.servers.get(id) else { return };
        if entry.tx.is_terminated() {
            self.servers.remove(id);
            return;
        }

        let after = entry.tx.deadline();
        if after != before {
            if let Some(at) = after {
                self.timers.push(Timer { at, key: Key::Server(id) });
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
                self.timers.push(Timer { at, key: Key::Client(id) });
            }
        }
    }

    fn on_send(
        &mut self,
        request: Request<Bytes>,
        transport: Transport,
        next_hop: SocketAddr,
        respond: Responder,
    ) {
        if self.shutting_down {
            let _ = respond.send(Err(Error::closed()));
            return;
        }

        if !request.headers().contains_key(CSEQ) {
            let _ = respond.send(Err(Error::missing(CSEQ)));
            return;
        }

        match transport {
            Transport::Udp => {
                let Some(udp) = &self.udp else {
                    let err = io::Error::new(
                        io::ErrorKind::Unsupported,
                        "the endpoint has no UDP socket",
                    );
                    let _ = respond.send(Err(Error::transport(err)));
                    return;
                };
                let port = udp.socket.local_addr().port();
                let source = match self.udp_source(next_hop) {
                    Ok(source) => source,
                    Err(err) => {
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
                );
            }
            Transport::Tcp => {
                self.send_over_tcp(
                    next_hop,
                    Pending::Request(request, respond),
                );
            }
        }
    }

    /// Sends `pending` to `remote` over the connection the driver has to it,
    /// or over one it opens now.
    fn send_over_tcp(&mut self, remote: SocketAddr, pending: Pending) {
        let route = self.routes.entry(remote).or_default();
        match &mut route.tcp {
            TcpState::Open(flow, writer) if !writer.is_closed() => {
                let (flow, writer) = (*flow, writer.clone());
                self.deliver(pending, flow, writer);
            }
            TcpState::Connecting(waiting) => waiting.push(pending),
            // Closed, or open once and gone since. Open a new connection
            // and send once it is up.
            TcpState::Closed | TcpState::Open(..) => {
                route.tcp = TcpState::Connecting(vec![pending]);
                let config = self.config.tcp;
                let inbound = self.tcp_tx.clone();
                let internal = self.internal_tx.clone();
                tokio::spawn(async move {
                    let result = tcp::connect(remote, &config, &inbound).await;
                    let _ =
                        internal.send(Command::Connected { remote, result });
                });
            }
        }
    }

    /// Sends `pending` on an open connection.
    fn deliver(&mut self, pending: Pending, flow: Flow, writer: tcp::Writer) {
        match pending {
            Pending::Request(request, respond) => {
                let link = Link { flow, writer: Some(writer) };
                self.start_client(request, link, respond);
            }
            // A response that cannot be queued is lost. The connection is full
            // or gone again, and a server transaction over TCP has nothing to
            // retransmit it with.
            Pending::Response(bytes) => {
                let _ = writer.send(bytes);
            }
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
        match send_on(self.udp.as_mut(), link, bytes) {
            Err(err)
                if err.kind() == io::ErrorKind::BrokenPipe
                    && link.writer.is_some() =>
            {
                let target = link.flow.remote;
                self.send_over_tcp(target, Pending::Response(bytes.clone()));
                Ok(())
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
            .socket
            .local_addr()
            .ip();
        if !bound.is_unspecified() {
            return Ok(bound);
        }

        let route = self.routes.entry(remote).or_default();
        if let Some(source) = route.udp_source {
            return Ok(source);
        }

        let source = source_toward(remote)?;
        route.udp_source = Some(source);

        Ok(source)
    }

    /// Adds the `Via`, starts the transaction, and sends the request.
    fn start_client(
        &mut self,
        mut request: Request<Bytes>,
        link: Link,
        respond: Responder,
    ) {
        if self.clients.len() >= self.config.max_client_transactions {
            let _ = respond.send(Err(Error::busy()));
            return;
        }

        let via = via_value(&link.flow, &mut self.branches);
        request.headers_mut().prepend(VIA, via);
        let key = ClientKey::from_request(&request)
            .expect("the Via signa wrote has a branch");
        let bytes = request.to_bytes();
        if link.flow.transport == Transport::Udp
            && bytes.len() > MAX_UDP_REQUEST
        {
            let _ = respond.send(Err(Error::too_large(bytes.len())));
            return;
        }

        if let Err(err) = send_on(self.udp.as_mut(), &link, &bytes) {
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
        let entry = ClientEntry { tx, link, respond: Some(respond) };
        let id = self.clients.insert(key, entry);
        if let Some(at) = deadline {
            self.timers.push(Timer { at, key: Key::Client(id) });
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
                for pending in pending {
                    match pending {
                        Pending::Request(_, respond) => {
                            let err =
                                io::Error::new(err.kind(), err.to_string());
                            let _ = respond.send(Err(Error::transport(err)));
                        }
                        // See `send_reply`.
                        Pending::Response(_) => {}
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
        match entry.tx.on_response(response, &self.config.timers, now()) {
            ClientEvent::Final(response) => {
                if entry.answer(Ok(response)) {
                    self.unanswered -= 1;
                }
            }
            // Provisional responses are not handed up in 0.2.0. A non-INVITE
            // request gets at most a 100, which says nothing.
            ClientEvent::Provisional(_)
            | ClientEvent::None
            | ClientEvent::Retransmit(_)
            | ClientEvent::Timeout => {}
        }
        self.settle_client(id, before);
    }

    fn on_request(&mut self, mut request: Request<Bytes>, link: Link) {
        // Without a readable top `Via` there is no way to answer, so there
        // is nothing to do with the request.
        let Some(value) = request.headers().get(VIA) else { return };
        let Some(via) = Via::top(value) else { return };
        let reply = reply_flow(&via, &link.flow);
        let marked = mark_via(value, &via, &link.flow);
        let key = ServerKey::new(&via, request.method());

        // The `Via` the request goes up with, and that every response carries,
        // has `received` and `rport` filled in (RFC 3261 section 18.2.1,
        // RFC 3581).
        if let Some(marked) = marked {
            *request.headers_mut().get_mut(VIA).expect("found above") = marked;
        }
        // The service sees where the request came from. The link keeps where
        // the response goes, which differs in the port without `rport`.
        let source = link.flow;
        let link = Link { flow: reply, writer: link.writer };

        // 0.2.0 has no INVITE transactions. An ACK outside one has nothing to
        // match and is dropped (section 17.2.3), and a CANCEL with no
        // transaction to cancel gets a 481 (section 9.2).
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
            if let Some((_, entry)) = self.servers.find(key) {
                if let Some(response) = entry.tx.on_retransmission() {
                    let _ = send_on(self.udp.as_mut(), &entry.link, &response);
                }
                return;
            }
        }

        // Overload and shutdown answer with a stateless 503, so the peer stops
        // retransmitting and can try elsewhere. Not reading the socket instead
        // would stall every flow on a TCP connection, including the responses
        // to this endpoint's own requests on it.
        let waiting = self.pending + self.queue.len();
        if self.service_failed
            || self.shutting_down
            || waiting >= self.config.max_pending_requests
        {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        }

        request.extensions_mut().insert(source);
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
                let id = self.servers.insert(key, ServerEntry { tx, link });
                if let Some(at) = deadline {
                    self.timers.push(Timer { at, key: Key::Server(id) });
                }

                Slot::Transaction(id)
            }
            None => Slot::Stateless(link),
        };
        self.queue.push_back((slot, request));
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

    /// Takes what the service answered. `None` when it failed.
    ///
    /// A response has to be final and carry a `Via`, or the endpoint could
    /// not route it. Anything else becomes a 500 built from the request's
    /// headers, which a stateless slot does not keep, so there it is dropped.
    fn on_response(&mut self, slot: Slot, response: Option<Response<Bytes>>) {
        let response = response.filter(|r| {
            r.status().is_final() && r.headers().contains_key(VIA)
        });
        match slot {
            Slot::Transaction(id) => {
                let Some(entry) = self.servers.get_mut(id) else { return };
                let (status, bytes) = match &response {
                    Some(response) => (response.status(), response.to_bytes()),
                    None => match entry.tx.headers() {
                        Some(headers) => (
                            SERVER_ERROR,
                            bare_response(headers, SERVER_ERROR),
                        ),
                        // The final response is out, so nothing can be sent.
                        None => return,
                    },
                };
                let before = entry.tx.deadline();
                let timers = self.config.timers;
                let send = entry.tx.on_response(
                    status,
                    bytes.clone(),
                    &timers,
                    now(),
                );
                let link = entry.link.clone();
                if send && self.send_reply(&link, &bytes).is_err() {
                    if let Some(entry) = self.servers.get_mut(id) {
                        entry.tx.on_transport_error();
                    }
                }
                self.settle_server(id, before);
            }
            Slot::Stateless(link) => {
                if let Some(response) = response {
                    let _ = self.send_reply(&link, &response.to_bytes());
                }
            }
        }
    }
}

impl ClientEntry {
    /// Delivers the final response or the error to the client. Returns `false`
    /// when the transaction was answered before, so the caller counts each
    /// transaction once.
    fn answer(&mut self, result: Result<Response<Bytes>, Error>) -> bool {
        match self.respond.take() {
            Some(respond) => {
                let _ = respond.send(result);
                true
            }
            None => false,
        }
    }
}

/// The current time, as the transactions and tokio's timer both see it.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The UDP socket, its read buffer, and the datagrams waiting for it to be
/// writable.
struct Udp {
    socket: udp::Socket,
    buf: BytesMut,
    backlog: VecDeque<(Bytes, Flow)>,
}

impl Udp {
    fn new(socket: udp::Socket) -> Udp {
        Udp { socket, buf: BytesMut::new(), backlog: VecDeque::new() }
    }

    /// Sends `bytes` on `flow` now, or queues it when the socket is not
    /// writable at the moment.
    ///
    /// A datagram that waits and then fails is dropped. UDP loses datagrams
    /// anyway, and the transactions retransmit over it.
    fn send(&mut self, bytes: &Bytes, flow: &Flow) -> io::Result<()> {
        if self.backlog.is_empty() {
            match self.socket.try_send(bytes, flow) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
        if self.backlog.len() >= UDP_BACKLOG {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the UDP send backlog is full",
            ));
        }
        self.backlog.push_back((bytes.clone(), *flow));

        Ok(())
    }

    /// Sends what waits, as far as the socket takes it.
    fn poll_flush(&mut self, cx: &mut Context<'_>) {
        while let Some((bytes, flow)) = self.backlog.front() {
            match self.socket.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    self.backlog.pop_front();
                    continue;
                }
                Poll::Pending => return,
            }

            match self.socket.try_send(bytes, flow) {
                // Readiness is cleared, and the next poll waits for it.
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                _ => {
                    self.backlog.pop_front();
                }
            }
        }
    }
}

/// Sends `bytes` along `link` without waiting.
///
/// Over TCP a full write queue is an error here. The connection is in trouble,
/// and a transaction that retransmits will try again.
fn send_on(
    udp: Option<&mut Udp>,
    link: &Link,
    bytes: &Bytes,
) -> io::Result<()> {
    match (&link.writer, udp) {
        (Some(writer), _) => writer.send(bytes.clone()).map_err(|err| {
            let kind = match err {
                tcp::SendError::Full => io::ErrorKind::WouldBlock,
                tcp::SendError::Closed => io::ErrorKind::BrokenPipe,
            };
            io::Error::new(kind, err)
        }),
        (None, Some(udp)) => udp.send(bytes, &link.flow),
        (None, None) => unreachable!("a UDP flow comes from the UDP socket"),
    }
}

/// Asks the kernel which address it would send to `remote` from.
fn source_toward(remote: SocketAddr) -> io::Result<IpAddr> {
    let any = match remote {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let probe = std::net::UdpSocket::bind(SocketAddr::new(any, 0))?;
    probe.connect(remote)?;

    Ok(probe.local_addr()?.ip())
}

/// The `Via` this endpoint puts on a request it sends on `flow`.
///
/// `rport` asks the server to answer the port the request came from
/// (RFC 3581), which is what a NAT lets through.
fn via_value(flow: &Flow, branches: &mut Branches) -> HeaderValue {
    let mut value = String::with_capacity(80);
    let n = branches.next;
    branches.next += 1;
    let _ = write!(
        value,
        "SIP/2.0/{} {};rport;branch={}{n:x}",
        flow.transport, flow.local, branches.prefix
    );

    HeaderValue::from_built(value)
}

/// Returns `true` if the `sent-by` of `via` is `local`.
fn sent_by_is(via: &Via<'_>, local: SocketAddr) -> bool {
    via.host.parse::<IpAddr>().is_ok_and(|ip| ip == local.ip())
        && via.port.unwrap_or(DEFAULT_PORT) == local.port()
}

/// Where a response to a request received on `flow` with the top `via` goes
/// (RFC 3261 section 18.2.2, RFC 3581 section 4).
///
/// It goes to the address the request came from, which is what `received`
/// would say, since the endpoint adds that parameter whenever `sent-by` says
/// otherwise. Nothing here trusts a `received` the request came with, so a
/// request cannot have its response sent to a third party.
///
/// Over UDP the port is the source port with `rport`, and the `sent-by` port
/// without it. Over TCP the response goes back on the connection, and the
/// flow's remote address is where a new connection goes when that one has
/// closed. That is the `sent-by` port, since RFC 3581 applies `rport` to
/// unreliable transports only.
fn reply_flow(via: &Via<'_>, flow: &Flow) -> Flow {
    let port = match via.rport {
        Some(_) if !flow.transport.is_reliable() => flow.remote.port(),
        _ => via.port.unwrap_or(DEFAULT_PORT),
    };

    Flow { remote: SocketAddr::new(flow.remote.ip(), port), ..*flow }
}

/// Returns the top `Via` with `received` and `rport` filled in, or `None` when
/// neither is called for.
///
/// `received` is added at the end of the first `via-parm` when `sent-by` names
/// a host other than the source address (RFC 3261 section 18.2.1). A valueless
/// `rport` is given the source port in place (RFC 3581 section 4). An `rport`
/// that came with a value is left alone. The response goes to the source port
/// either way, see [`reply_flow`].
fn mark_via(
    value: &HeaderValue,
    via: &Via<'_>,
    flow: &Flow,
) -> Option<HeaderValue> {
    let source = flow.remote;
    let received =
        via.host.parse::<IpAddr>().map_or(true, |host| host != source.ip());
    if !received && via.rport_at.is_none() {
        return None;
    }

    let src = value.as_str();
    let mut marked = String::with_capacity(src.len() + 40);
    let mut copied = 0;
    if let Some(at) = via.rport_at {
        marked.push_str(&src[..at]);
        let _ = write!(marked, "={}", source.port());
        copied = at;
    }
    marked.push_str(&src[copied..via.end]);
    if received {
        let _ = write!(marked, ";received={}", source.ip());
    }
    marked.push_str(&src[via.end..]);

    Some(HeaderValue::from_built(marked))
}
