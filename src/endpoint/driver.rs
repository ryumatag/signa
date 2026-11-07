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
    collections::{BinaryHeap, HashMap, VecDeque},
    convert::Infallible,
    future::{poll_fn, Future},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use foldhash::fast::RandomState;
use tokio::{
    sync::{mpsc, oneshot, Semaphore},
    time::Sleep,
};
use tower_service::Service;

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
        table::{Id, Table},
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

/// One-shot replies hold a slot through command, connect, and local write.
const REPLY_OPERATIONS: usize = 64;

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
    Response(Bytes),
    OneShot(Bytes, Completion),
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
    client_admission: AdmissionOwner,
    command_sender: mpsc::WeakUnboundedSender<Command>,
    reply_admission: Admission,
    writes: Vec<(tcp::Receipt, Completion)>,
    /// `poll_ready` failed, so the service takes nothing any more.
    service_failed: bool,
    /// From the `Endpoint` and `Client` handles. The driver ends when they
    /// are all gone.
    commands: mpsc::UnboundedReceiver<Command>,
    /// From the service futures and the connect tasks. Kept apart from
    /// `commands`, because the driver holds the sender for them.
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
        command_sender: mpsc::WeakUnboundedSender<Command>,
    ) -> Driver<S> {
        let (internal_tx, internal) = mpsc::unbounded_channel();

        Driver {
            service,
            client_admission: AdmissionOwner(ClientAdmission::new(
                config.max_client_transactions,
                config.max_client_request_bytes,
            )),
            command_sender,
            reply_admission: Admission(Arc::new(Semaphore::new(
                REPLY_OPERATIONS,
            ))),
            writes: Vec::new(),
            service_failed: false,
            commands,
            internal,
            internal_tx,
            udp: udp.map(Datagram::new),
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

    pub(super) fn client_admission(&self) -> ClientAdmission {
        self.client_admission.0.clone()
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

        let mut index = 0;

        while index < self.writes.len() {
            if let Poll::Ready(result) =
                Pin::new(&mut self.writes[index].0).poll(cx)
            {
                let (_, completion) = self.writes.swap_remove(index);
                completion.finish(result.map_err(ReplyError::Transport));
            } else {
                index += 1;
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
            match udp.poll_recv(cx) {
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
        self.writes.is_empty()
            && self.queue.is_empty()
            && self.pending == 0
            && self.unanswered == 0
            && self.udp.as_ref().map_or(true, |udp| udp.is_idle())
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
            Command::Respond { slot, response } => {
                self.pending -= 1;
                self.on_response(slot, response);
            }
            Command::Connected { remote, result } => {
                self.on_connected(remote, result);
            }
            Command::Shutdown { timeout, done } => {
                self.client_admission.0.close();
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
                let completion = match entry.tx.on_timeout(&timers, now) {
                    ClientEvent::Retransmit(request) => {
                        match send_on(self.udp.as_mut(), &entry.link, &request)
                        {
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
            Pending::Response(bytes) => {
                let _ = writer.send(bytes);
            }
        }
    }

    // Issued to incoming TU envelopes once that interface replaces Service.
    #[allow(dead_code)]
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
        );

        Ok((request, route))
    }

    fn on_reply(&mut self, link: Link, bytes: Bytes, completion: Completion) {
        if self.shutting_down {
            completion.finish(Err(ReplyError::Closed));
            return;
        }

        if let Some(writer) = &link.writer {
            match writer.submit(bytes.clone()) {
                Ok(receipt) => self.writes.push((receipt, completion)),
                Err(tcp::SendError::Full) => {
                    completion.finish(Err(ReplyError::Busy))
                }
                Err(tcp::SendError::Closed) => self.send_over_tcp(
                    link.flow.remote,
                    Pending::OneShot(bytes, completion),
                ),
            }
        } else if let Some(udp) = self.udp.as_mut() {
            udp.submit(bytes, link.flow, completion);
        } else {
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

        if let Err(err) = send_on(self.udp.as_mut(), &link, &bytes) {
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
                        Pending::Response(_) => {}
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
/// Over TCP a full write queue is an error here. The connection is in trouble,
/// and a transaction that retransmits will try again.
fn send_on(
    udp: Option<&mut Datagram>,
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

// These private driver tests use sockets, which Miri cannot provide.
#[cfg(all(test, not(miri)))]
mod tests {
    use std::{
        sync::Mutex,
        task::{Wake, Waker},
    };

    use tokio::{net::UdpSocket, time::timeout};

    use super::*;
    use crate::endpoint::{
        tests::{
            reply_driver, reply_driver_with, route_request, route_response,
            udp_reply_link, REPLY_LOCAL,
        },
        Client,
    };

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
