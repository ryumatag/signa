/*!
An external Tower adapter for signa's transaction-user API.

This test crate sees only signa's public API, as tower-sip will. It builds the
pieces that `milestones/tower-sip.md` plans and runs them against real
endpoints on the loopback:

* `Exchange<R>`, the adapter's handler envelope, made by destructuring
  signa's `ServerRequest` and splitting its transaction.
* `Respond`, a local response-sender trait, implemented for signa's
  `Responder` by naming its `ResponseSubmission<'a>` future. Nothing is boxed
  and signa implements no trait for it.
* Two sender wrappers, `Observed` and `Counted`, applied by Tower layers, so a
  generic leaf handler submits through `Counted<Observed<Responder>>`.
* A bounded dispatcher with separate ordinary and control lanes. It owns one
  instance of each service, polls readiness and calls on that instance, and
  spawns a handler only after it has room for it.

Nothing here is part of signa. signa has no Tower dependency of its own, and
`tower` is only a dev-dependency.

What the tests check:

* The wrappers see every response the TU submits, 1xx and every 2xx, and keep
  watching after the first final. They do not see the 100 Trying signa sends
  or the responses its transactions retransmit.
* Readiness and call use the same service instance, which is not `Clone`.
* Handlers waiting for an ACK or blocked on readiness do not hold up ACK and
  CANCEL, which go through the control lane.
* Running handlers and buffered calls stay within their limits, and an
  ordinary request beyond them gets a 503.
* A handler's future finishing is not the end of its transaction, and a Tower
  timeout drops a handler without cancelling anything in SIP.
*/

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    fmt,
    future::{pending, poll_fn, Future},
    mem,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    task::{ready, Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use signa::{
    endpoint::{
        Endpoint, Incoming, IncomingEvent, ReceivedAck, ReceivedRequest,
        ReplyRoute, Responder, ResponseSubmission, ServerEvent, ServerEvents,
        ServerRequest, ServerTransactionId, ShutdownOutcome, SubmitError,
    },
    message::header::{Tag, CALL_ID, CSEQ},
    transaction::Timers,
    transport::Flow,
    Request, Response,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Notify},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout, Instant},
};
use tower::{layer::util::Identity, Layer, Service, ServiceBuilder};

// The adapter, as an external crate would write it.

/// The handler envelope. It is the adapter's, not signa's, and holds what the
/// dispatcher took out of signa's `ServerRequest`.
pub struct Exchange<R> {
    pub request: Request<Bytes>,
    pub flow: Flow,
    pub transaction_id: ServerTransactionId,
    pub responder: R,
    pub events: ServerEvents,
    pub reply_route: ReplyRoute,
}

impl Exchange<Responder> {
    fn new(request: ServerRequest) -> Exchange<Responder> {
        let ServerRequest { request, flow, transaction } = request;
        let transaction_id = transaction.id();
        let (responder, events) = transaction.into_parts();
        // The route is cloned before the responder is wrapped, so no wrapper
        // needs to expose it.
        let reply_route = responder.reply_route();
        Exchange {
            request,
            flow,
            transaction_id,
            responder,
            events,
            reply_route,
        }
    }
}

impl<R> Exchange<R> {
    /// Replaces the response sender and keeps every other field.
    pub fn map_responder<T>(self, f: impl FnOnce(R) -> T) -> Exchange<T> {
        Exchange {
            request: self.request,
            flow: self.flow,
            transaction_id: self.transaction_id,
            responder: f(self.responder),
            events: self.events,
            reply_route: self.reply_route,
        }
    }
}

/// Sends responses for one server transaction.
///
/// The submission future is `Unpin`, which signa's `ResponseSubmission` is,
/// so a wrapper can poll the future it wraps without pin projection.
pub trait Respond {
    type Submission<'a>: Future<Output = Result<(), SubmitError>>
        + Send
        + Unpin
    where
        Self: 'a;

    fn respond(&self, response: Response<Bytes>) -> Self::Submission<'_>;
}

impl Respond for Responder {
    type Submission<'a> = ResponseSubmission<'a>;

    fn respond(&self, response: Response<Bytes>) -> ResponseSubmission<'_> {
        Responder::respond(self, response)
    }
}

/// What an observer saw of one submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The driver accepted it. That is not delivery to the peer.
    Accepted,
    /// The driver or the responder refused it.
    Refused(SubmitError),
    /// The submission future was dropped before its result. It may still
    /// have been accepted.
    Interrupted,
}

/// The status and outcome of each observed submission, in order.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<(u16, Outcome)>>>);

impl Log {
    fn push(&self, status: u16, outcome: Outcome) {
        self.0.lock().unwrap().push((status, outcome));
    }

    fn entries(&self) -> Vec<(u16, Outcome)> {
        self.0.lock().unwrap().clone()
    }
}

/// A sender that records each submission and its outcome.
pub struct Observed<R> {
    inner: R,
    log: Log,
}

impl<R: Respond> Respond for Observed<R> {
    type Submission<'a>
        = Observing<R::Submission<'a>>
    where
        Self: 'a;

    fn respond(&self, response: Response<Bytes>) -> Self::Submission<'_> {
        let status = response.status().as_u16();
        Observing {
            inner: self.inner.respond(response),
            pending: Some((status, self.log.clone())),
        }
    }
}

/// The named future of an observed submission.
pub struct Observing<F> {
    inner: F,
    pending: Option<(u16, Log)>,
}

impl<F> Future for Observing<F>
where
    F: Future<Output = Result<(), SubmitError>> + Unpin,
{
    type Output = Result<(), SubmitError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.inner).poll(cx));
        if let Some((status, log)) = self.pending.take() {
            let outcome = match result {
                Ok(()) => Outcome::Accepted,
                Err(error) => Outcome::Refused(error),
            };
            log.push(status, outcome);
        }
        Poll::Ready(result)
    }
}

impl<F> Drop for Observing<F> {
    fn drop(&mut self) {
        if let Some((status, log)) = self.pending.take() {
            log.push(status, Outcome::Interrupted);
        }
    }
}

/// A second sender wrapper, to show that wrappers nest.
pub struct Counted<R> {
    inner: R,
    count: Arc<AtomicUsize>,
}

impl<R: Respond> Respond for Counted<R> {
    type Submission<'a>
        = R::Submission<'a>
    where
        Self: 'a;

    fn respond(&self, response: Response<Bytes>) -> Self::Submission<'_> {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.inner.respond(response)
    }
}

/// Wraps the sender of every exchange in `Observed`.
#[derive(Clone)]
pub struct ObserveLayer(Log);

impl<S> Layer<S> for ObserveLayer {
    type Service = Observe<S>;

    fn layer(&self, inner: S) -> Observe<S> {
        Observe { inner, log: self.0.clone() }
    }
}

/// The service of `ObserveLayer`.
pub struct Observe<S> {
    inner: S,
    log: Log,
}

impl<S, R> Service<Exchange<R>> for Observe<S>
where
    R: Respond,
    S: Service<Exchange<Observed<R>>, Response = ()>,
{
    type Response = ();
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, exchange: Exchange<R>) -> S::Future {
        let log = self.log.clone();
        self.inner
            .call(exchange.map_responder(|inner| Observed { inner, log }))
    }
}

/// Wraps the sender of every exchange in `Counted`.
#[derive(Clone)]
pub struct CountLayer(Arc<AtomicUsize>);

impl<S> Layer<S> for CountLayer {
    type Service = Count<S>;

    fn layer(&self, inner: S) -> Count<S> {
        Count { inner, count: self.0.clone() }
    }
}

/// The service of `CountLayer`.
pub struct Count<S> {
    inner: S,
    count: Arc<AtomicUsize>,
}

impl<S, R> Service<Exchange<R>> for Count<S>
where
    R: Respond,
    S: Service<Exchange<Counted<R>>, Response = ()>,
{
    type Response = ();
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, exchange: Exchange<R>) -> S::Future {
        let count = self.count.clone();
        self.inner
            .call(exchange.map_responder(|inner| Counted { inner, count }))
    }
}

/// What the control lane carries. Only a matched CANCEL has a responder.
pub enum Control<R> {
    Cancel { exchange: Exchange<R>, target: ServerTransactionId },
    Ack(ReceivedAck),
    UnmatchedCancel(ReceivedRequest),
    Untracked(ReceivedRequest),
}

/// The bounds `dispatch` keeps.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Ordinary handler futures running at once.
    pub handlers: usize,
    /// Ordinary requests received but not yet called.
    pub queued: usize,
    /// The same two bounds for the control lane.
    pub control_handlers: usize,
    pub control_queued: usize,
    /// 503s for ordinary overflow in flight at once.
    pub rejections: usize,
}

/// What `dispatch` saw, for the tests to check.
#[derive(Debug, Default)]
pub struct Stats {
    pub most_handlers: usize,
    pub most_queued: usize,
    pub rejected: usize,
    pub dropped_control: usize,
    pub handler_errors: usize,
}

/// Runs both lanes until `incoming` ends and every handler has finished.
///
/// One `select!` loop receives events, polls readiness and reaps finished
/// handlers, so nothing in it waits for a lane that has no room or a service
/// that is not ready. Readiness is polled only when a call is queued and the
/// lane has room, and the call follows on the same instance at once.
pub async fn dispatch<S, C>(
    mut incoming: Incoming,
    mut requests: S,
    mut control: C,
    limits: Limits,
) -> Stats
where
    S: Service<Exchange<Responder>, Response = ()>,
    S::Future: Send + 'static,
    S::Error: fmt::Debug + Send + 'static,
    C: Service<Control<Responder>, Response = ()>,
    C::Future: Send + 'static,
    C::Error: fmt::Debug + Send + 'static,
{
    let mut stats = Stats::default();
    let mut ordinary: VecDeque<Exchange<Responder>> = VecDeque::new();
    let mut controls: VecDeque<Control<Responder>> = VecDeque::new();
    let mut handlers = JoinSet::new();
    let mut control_handlers = JoinSet::new();
    let mut rejections = JoinSet::new();
    let mut open = true;

    loop {
        let idle = ordinary.is_empty()
            && controls.is_empty()
            && handlers.is_empty()
            && control_handlers.is_empty()
            && rejections.is_empty();
        if !open && idle {
            return stats;
        }

        let control_room = !controls.is_empty()
            && control_handlers.len() < limits.control_handlers;
        let ordinary_room =
            !ordinary.is_empty() && handlers.len() < limits.handlers;

        tokio::select! {
            biased;

            Some(done) = handlers.join_next(), if !handlers.is_empty() => {
                match done {
                    Ok(Ok(())) => {}
                    // The error is the handler's. signa's drop policy has
                    // already run for any responder it dropped.
                    Ok(Err(_)) | Err(_) => stats.handler_errors += 1,
                }
            }
            Some(_) = control_handlers.join_next(),
                if !control_handlers.is_empty() => {}
            Some(_) = rejections.join_next(), if !rejections.is_empty() => {}

            ready = poll_fn(|cx| control.poll_ready(cx)), if control_room => {
                ready.expect("the control service does not fail");
                let event = controls.pop_front().expect("checked above");
                control_handlers.spawn(control.call(event));
            }
            ready = poll_fn(|cx| requests.poll_ready(cx)), if ordinary_room => {
                ready.expect("the request service does not fail");
                let exchange = ordinary.pop_front().expect("checked above");
                handlers.spawn(requests.call(exchange));
                stats.most_handlers = stats.most_handlers.max(handlers.len());
            }

            event = incoming.recv(), if open => match event {
                None => open = false,
                Some(IncomingEvent::Request(request)) => {
                    let exchange = Exchange::new(request);
                    if ordinary.len() < limits.queued {
                        ordinary.push_back(exchange);
                        stats.most_queued =
                            stats.most_queued.max(ordinary.len());
                    } else {
                        stats.rejected += 1;
                        if rejections.len() < limits.rejections {
                            rejections.spawn(reject(exchange));
                        }
                        // Otherwise the responder drops here, and signa
                        // sends its 500.
                    }
                }
                Some(event) => {
                    let event = match event {
                        IncomingEvent::Cancel(cancel) => Control::Cancel {
                            target: cancel.target,
                            exchange: Exchange::new(ServerRequest {
                                request: cancel.request,
                                flow: cancel.flow,
                                transaction: cancel.transaction,
                            }),
                        },
                        IncomingEvent::Ack(ack) => Control::Ack(ack),
                        IncomingEvent::UnmatchedCancel(cancel) => {
                            Control::UnmatchedCancel(cancel)
                        }
                        IncomingEvent::Untracked(request) => {
                            Control::Untracked(request)
                        }
                        _ => {
                            stats.dropped_control += 1;
                            continue;
                        }
                    };
                    if controls.len() < limits.control_queued {
                        controls.push_back(event);
                    } else {
                        // A dropped ACK gets nothing, and a dropped CANCEL
                        // responder gets signa's 500.
                        stats.dropped_control += 1;
                    }
                }
            },
        }
    }
}

async fn reject(exchange: Exchange<Responder>) {
    let unavailable = reply(&exchange.request, 503, &Tag::random());
    let _ = exchange.responder.respond(unavailable).await;
}

// The application: a leaf handler, its control service, and their shared
// call state.

/// What the request handlers and the control service share.
#[derive(Clone, Default)]
struct Calls(Arc<Mutex<CallState>>);

impl Calls {
    fn lock(&self) -> MutexGuard<'_, CallState> {
        self.0.lock().unwrap()
    }
}

#[derive(Default)]
struct CallState {
    /// ACK waiters, by Call-ID.
    acks: HashMap<String, oneshot::Sender<()>>,
    /// CANCELs that came before their handler started.
    cancelled: HashSet<ServerTransactionId>,
    /// Handlers waiting for a CANCEL.
    cancels: HashMap<ServerTransactionId, oneshot::Sender<()>>,
}

/// Opens and closes the request service's readiness.
#[derive(Default)]
struct Gate {
    closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// Shared counters of the request service.
#[derive(Default)]
struct Usage {
    readies: AtomicUsize,
    calls: AtomicUsize,
    running: AtomicUsize,
    most_running: AtomicUsize,
}

/// The leaf handler. It is generic over the sender, so it works with whatever
/// wrappers the layers add, and it is not `Clone`.
struct Answer {
    /// Set by `poll_ready` and taken by `call`, so a call without readiness
    /// on this instance panics.
    ready: bool,
    calls: Calls,
    gate: Arc<Gate>,
    usage: Arc<Usage>,
    release: Arc<Notify>,
    /// Where a handler leaves its `ServerEvents` when it returns.
    finished: mpsc::UnboundedSender<ServerEvents>,
}

impl<R> Service<Exchange<R>> for Answer
where
    R: Respond + Send + Sync + 'static,
{
    type Response = ();
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Infallible>> {
        if self.gate.closed.load(Ordering::SeqCst) {
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            if self.gate.closed.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        if !mem::replace(&mut self.ready, true) {
            self.usage.readies.fetch_add(1, Ordering::SeqCst);
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, exchange: Exchange<R>) -> Self::Future {
        assert!(
            mem::replace(&mut self.ready, false),
            "readiness was polled on the instance that is called"
        );
        self.usage.calls.fetch_add(1, Ordering::SeqCst);
        let running = self.usage.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.usage.most_running.fetch_max(running, Ordering::SeqCst);

        let calls = self.calls.clone();
        let usage = self.usage.clone();
        let release = self.release.clone();
        let finished = self.finished.clone();
        Box::pin(async move {
            handle(exchange, &calls, &release, finished).await;
            usage.running.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

/// What a request does depends on the user part of its Request-URI:
///
/// * `answer`: 180, then a 2xx with two To tags as a forking proxy would
///   relay them, waits for the ACK, and tries a 183 that comes too late.
/// * `hold`: waits for the test to release it, then answers 200.
/// * `ring`: 180, then waits for a CANCEL and answers 487.
/// * `stall`: never answers.
async fn handle<R: Respond>(
    exchange: Exchange<R>,
    calls: &Calls,
    release: &Notify,
    finished: mpsc::UnboundedSender<ServerEvents>,
) {
    let Exchange { request, responder, events, transaction_id, .. } = exchange;
    let user = request.uri().as_str().to_owned();
    let call_id = request.headers().get(CALL_ID).unwrap().as_str().to_owned();

    if user.starts_with("sip:answer@") {
        let _ = responder.respond(reply(&request, 180, &tag("a"))).await;
        sleep(Duration::from_millis(100)).await;
        let (acked, ack) = oneshot::channel();
        calls.lock().acks.insert(call_id, acked);
        let _ = responder.respond(reply(&request, 200, &tag("a"))).await;
        let _ = responder.respond(reply(&request, 200, &tag("b"))).await;
        let _ = ack.await;
        let _ = responder.respond(reply(&request, 183, &tag("a"))).await;
    } else if user.starts_with("sip:hold@") {
        release.notified().await;
        let _ = responder.respond(reply(&request, 200, &tag("a"))).await;
    } else if user.starts_with("sip:ring@") {
        let (cancel, cancelled) = oneshot::channel();
        // A CANCEL can reach the control lane before this handler starts.
        let already = {
            let mut calls = calls.lock();
            let already = calls.cancelled.remove(&transaction_id);
            if !already {
                calls.cancels.insert(transaction_id, cancel);
            }
            already
        };
        if !already {
            let _ = responder.respond(reply(&request, 180, &tag("a"))).await;
            let _ = cancelled.await;
        }
        let _ = responder.respond(reply(&request, 487, &tag("a"))).await;
    } else {
        pending::<()>().await;
    }
    let _ = finished.send(events);
}

/// The control lane's service. It answers CANCELs and routes ACKs to the
/// handler waiting for them.
struct ControlService {
    ready: bool,
    calls: Calls,
    acks: Arc<AtomicUsize>,
}

impl Service<Control<Responder>> for ControlService {
    type Response = ();
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Infallible>> {
        self.ready = true;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, event: Control<Responder>) -> Self::Future {
        assert!(mem::replace(&mut self.ready, false));
        let calls = self.calls.clone();
        let acks = self.acks.clone();
        Box::pin(async move {
            match event {
                Control::Cancel { exchange, target } => {
                    let ok = reply(&exchange.request, 200, &Tag::random());
                    let _ = exchange.responder.respond(ok).await;
                    // The handler may not have started. It then finds the
                    // mark when it does.
                    let mut calls = calls.lock();
                    match calls.cancels.remove(&target) {
                        Some(cancel) => {
                            let _ = cancel.send(());
                        }
                        None => {
                            calls.cancelled.insert(target);
                        }
                    }
                }
                Control::Ack(ack) => {
                    acks.fetch_add(1, Ordering::SeqCst);
                    let call_id =
                        ack.request.headers().get(CALL_ID).unwrap().as_str();
                    if let Some(waiter) = calls.lock().acks.remove(call_id) {
                        let _ = waiter.send(());
                    }
                }
                Control::UnmatchedCancel(cancel) => {
                    let _ = cancel
                        .reply
                        .send(reply(&cancel.request, 481, &Tag::random()))
                        .await;
                }
                Control::Untracked(_) => {}
            }
            Ok(())
        })
    }
}

fn tag(name: &str) -> Tag {
    name.parse().unwrap()
}

fn reply(request: &Request<Bytes>, status: u16, tag: &Tag) -> Response<Bytes> {
    Response::reply_to(request)
        .status(status)
        .to_tag(tag.clone())
        .body(Bytes::new())
        .unwrap()
}

// The test harness: an endpoint, the services, and a raw UAC.

/// RFC 3261's timers with a T1 of 20 ms, so that Timer L is 1.28 s. Nothing
/// below depends on the length of a timer.
fn timers() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(160))
        .t4(Duration::from_millis(200))
        .build()
        .unwrap()
}

struct Harness {
    endpoint: Endpoint,
    calls: Calls,
    gate: Arc<Gate>,
    usage: Arc<Usage>,
    release: Arc<Notify>,
    finished: mpsc::UnboundedReceiver<ServerEvents>,
    acks: Arc<AtomicUsize>,
}

impl Harness {
    /// Binds an endpoint and dispatches its events to `layers` around the
    /// leaf handler.
    fn start<L>(limits: Limits, layers: L) -> (Harness, JoinHandle<Stats>)
    where
        L: Layer<Answer>,
        L::Service:
            Service<Exchange<Responder>, Response = ()> + Send + 'static,
        <L::Service as Service<Exchange<Responder>>>::Future: Send + 'static,
        <L::Service as Service<Exchange<Responder>>>::Error:
            fmt::Debug + Send + 'static,
    {
        let (endpoint, incoming) = Endpoint::builder()
            .udp("127.0.0.1:0".parse().unwrap())
            .timers(timers())
            .bind()
            .unwrap();
        let calls = Calls::default();
        let gate = Arc::new(Gate::default());
        let usage = Arc::new(Usage::default());
        let release = Arc::new(Notify::new());
        let (finished_tx, finished) = mpsc::unbounded_channel();
        let acks = Arc::new(AtomicUsize::new(0));
        let leaf = Answer {
            ready: false,
            calls: calls.clone(),
            gate: gate.clone(),
            usage: usage.clone(),
            release: release.clone(),
            finished: finished_tx,
        };
        let control = ControlService {
            ready: false,
            calls: calls.clone(),
            acks: acks.clone(),
        };
        let dispatching = tokio::spawn(dispatch(
            incoming,
            layers.layer(leaf),
            control,
            limits,
        ));
        let harness =
            Harness { endpoint, calls, gate, usage, release, finished, acks };
        (harness, dispatching)
    }

    async fn uac(&self) -> Uac {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Uac { socket, server: self.endpoint.udp_addr().unwrap() }
    }
}

const LIMITS: Limits = Limits {
    handlers: 8,
    queued: 8,
    control_handlers: 8,
    control_queued: 8,
    rejections: 2,
};

struct Uac {
    socket: UdpSocket,
    server: SocketAddr,
}

impl Uac {
    /// A `method` request of the call `call`, with `branch`, as text.
    fn request(
        &self,
        method: &str,
        user: &str,
        call: &str,
        branch: &str,
        to_tag: Option<&str>,
    ) -> String {
        let local = self.socket.local_addr().unwrap();
        let to = match to_tag {
            Some(tag) => format!("<sip:{user}@example.com>;tag={tag}"),
            None => format!("<sip:{user}@example.com>"),
        };
        format!(
            "{method} sip:{user}@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local};branch=z9hG4bK{branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: {to}\r\n\
             Call-ID: {call}\r\n\
             CSeq: 1 {method}\r\n\
             Content-Length: 0\r\n\r\n"
        )
    }

    async fn send(&self, message: &str) {
        self.socket.send_to(message.as_bytes(), self.server).await.unwrap();
    }

    /// The next response, or `None` after `wait` without one.
    async fn next(&self, wait: Duration) -> Option<Response<Bytes>> {
        let mut buf = vec![0; 65536];
        let (len, _) = timeout(wait, self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap();
        Some(Response::from_bytes(&buf[..len]).unwrap())
    }

    async fn status(&self) -> u16 {
        let response =
            self.next(Duration::from_secs(2)).await.expect("a response");
        response.status().as_u16()
    }

    /// Receives until a response with `status` arrives, and returns the
    /// statuses before it.
    async fn until(&self, status: u16) -> Vec<u16> {
        let mut before = Vec::new();
        loop {
            match self.status().await {
                found if found == status => return before,
                other => before.push(other),
            }
        }
    }
}

fn cseq_method(response: &Response<Bytes>) -> &str {
    response
        .headers()
        .get(CSEQ)
        .unwrap()
        .as_str()
        .split_whitespace()
        .nth(1)
        .unwrap()
}

/// Waits for the end of a transaction's observation.
async fn observe_end(mut events: ServerEvents) {
    while let Some(event) = events.next().await {
        if let ServerEvent::Terminated = event {
            return;
        }
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn wrappers_see_every_submission_and_no_protocol_output() {
    let log = Log::default();
    let count = Arc::new(AtomicUsize::new(0));
    let layers = ServiceBuilder::new()
        .layer(ObserveLayer(log.clone()))
        .layer(CountLayer(count.clone()));
    let (mut harness, dispatching) = Harness::start(LIMITS, layers);
    let uac = harness.uac().await;
    let invite = uac.request("INVITE", "answer", "observed", "-inv", None);

    uac.send(&invite).await;
    assert_eq!(uac.until(180).await, [100]);
    // A retransmission gets the 180 again, from the transaction.
    uac.send(&invite).await;
    assert_eq!(uac.status().await, 180);
    let mut tags = Vec::new();
    while tags.len() < 2 {
        let ok = uac.next(Duration::from_secs(2)).await.expect("a 2xx");
        assert_eq!(ok.status().as_u16(), 200);
        tags.push(ok.headers().get("To").unwrap().as_str().to_owned());
    }
    assert_ne!(tags[0], tags[1], "two dialogs");
    uac.send(&uac.request("ACK", "answer", "observed", "-ack", Some("a")))
        .await;
    let events = timeout(Duration::from_secs(2), harness.finished.recv())
        .await
        .unwrap()
        .unwrap();

    // The 100 and the retransmitted 180 never went through the wrappers.
    // The 183 after the 2xx was refused, and the observer saw that too.
    assert_eq!(
        log.entries(),
        [
            (180, Outcome::Accepted),
            (200, Outcome::Accepted),
            (200, Outcome::Accepted),
            (183, Outcome::Refused(SubmitError::FinalAlreadySent)),
        ]
    );
    assert_eq!(count.load(Ordering::SeqCst), 4);
    assert_eq!(harness.acks.load(Ordering::SeqCst), 1);

    // The handler has returned, and the transaction is still in Accepted
    // until Timer L.
    assert!(timeout(Duration::from_millis(200), observe_end(events))
        .await
        .is_err());
    let outcome = harness.endpoint.shutdown(Duration::from_secs(10)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    let stats = dispatching.await.unwrap();
    assert_eq!(stats.handler_errors, 0);
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn handler_end_comes_before_transaction_end() {
    let (mut harness, dispatching) = Harness::start(LIMITS, Identity::new());
    let uac = harness.uac().await;

    uac.send(&uac.request("INVITE", "answer", "lifetimes", "-l", None)).await;
    uac.until(200).await;
    uac.send(&uac.request("ACK", "answer", "lifetimes", "-l-ack", Some("a")))
        .await;
    let events = timeout(Duration::from_secs(2), harness.finished.recv())
        .await
        .unwrap()
        .unwrap();
    let returned = Instant::now();

    timeout(Duration::from_secs(5), observe_end(events)).await.unwrap();

    // Timer L is 64 T1 after the 2xx, about 1.2 s after the handler returned.
    assert!(returned.elapsed() > Duration::from_millis(500));
    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    dispatching.await.unwrap();
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn acks_progress_while_every_handler_waits_for_one() {
    let limits = Limits { handlers: 2, ..LIMITS };
    let (mut harness, dispatching) = Harness::start(limits, Identity::new());
    let uacs = [harness.uac().await, harness.uac().await, harness.uac().await];

    // Two handlers take the only two slots and wait for their ACKs. The third
    // INVITE waits in the queue.
    for (n, uac) in uacs.iter().enumerate() {
        uac.send(&uac.request(
            "INVITE",
            "answer",
            &format!("busy-{n}"),
            &format!("-b{n}"),
            None,
        ))
        .await;
    }
    for uac in &uacs[..2] {
        uac.until(200).await;
    }
    assert_eq!(uacs[2].until(100).await, Vec::<u16>::new());
    assert!(uacs[2].next(Duration::from_millis(300)).await.is_none());
    assert_eq!(harness.usage.running.load(Ordering::SeqCst), 2);

    // Their ACKs go through the control lane and free the slots.
    for (n, uac) in uacs[..2].iter().enumerate() {
        uac.send(&uac.request(
            "ACK",
            "answer",
            &format!("busy-{n}"),
            &format!("-b{n}-ack"),
            Some("a"),
        ))
        .await;
    }
    uacs[2].until(200).await;
    uacs[2]
        .send(&uacs[2].request(
            "ACK",
            "answer",
            "busy-2",
            "-b2-ack",
            Some("a"),
        ))
        .await;
    for _ in 0..3 {
        timeout(Duration::from_secs(2), harness.finished.recv())
            .await
            .unwrap();
    }

    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    let stats = dispatching.await.unwrap();
    assert_eq!(stats.most_handlers, 2);
    assert_eq!(harness.usage.most_running.load(Ordering::SeqCst), 2);
    let usage = &harness.usage;
    assert_eq!(usage.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        usage.readies.load(Ordering::SeqCst),
        3,
        "one readiness per call"
    );
    assert_eq!(harness.acks.load(Ordering::SeqCst), 3);
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn a_cancel_is_answered_while_the_request_service_is_not_ready() {
    let (mut harness, dispatching) = Harness::start(LIMITS, Identity::new());
    harness.gate.closed.store(true, Ordering::SeqCst);
    let uac = harness.uac().await;

    uac.send(&uac.request("INVITE", "ring", "gated", "-g", None)).await;
    assert_eq!(uac.status().await, 100);
    uac.send(&uac.request("CANCEL", "ring", "gated", "-g", None)).await;
    let ok = uac.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!((ok.status().as_u16(), cseq_method(&ok)), (200, "CANCEL"));
    assert_eq!(
        harness.usage.calls.load(Ordering::SeqCst),
        0,
        "the INVITE waits"
    );

    harness.gate.open();
    let terminated = uac.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!(
        (terminated.status().as_u16(), cseq_method(&terminated)),
        (487, "INVITE")
    );
    uac.send(&uac.request("ACK", "ring", "gated", "-g", Some("a"))).await;
    timeout(Duration::from_secs(2), harness.finished.recv()).await.unwrap();

    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    dispatching.await.unwrap();
    let calls = harness.calls.lock();
    assert!(calls.cancels.is_empty() && calls.cancelled.is_empty());
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn buffered_calls_are_bounded_and_overflow_gets_a_503() {
    let limits = Limits { handlers: 1, queued: 1, ..LIMITS };
    let (mut harness, dispatching) = Harness::start(limits, Identity::new());
    let uacs = [harness.uac().await, harness.uac().await, harness.uac().await];

    for (n, uac) in uacs.iter().enumerate() {
        uac.send(&uac.request(
            "INVITE",
            "hold",
            &format!("hold-{n}"),
            &format!("-h{n}"),
            None,
        ))
        .await;
        // One at a time, so the first runs and the second waits in the queue
        // before the third arrives.
        assert_eq!(uac.status().await, 100);
        sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(uacs[2].status().await, 503);
    for uac in &uacs[..2] {
        harness.release.notify_one();
        assert_eq!(uac.until(200).await, Vec::<u16>::new());
        timeout(Duration::from_secs(2), harness.finished.recv())
            .await
            .unwrap();
    }

    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    let stats = dispatching.await.unwrap();
    assert_eq!(
        (stats.most_handlers, stats.most_queued, stats.rejected),
        (1, 1, 1)
    );
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn a_tower_timeout_drops_the_handler_but_cancels_nothing() {
    // The timeout ends the handler's future. Its responder drops unanswered,
    // which is signa's 500, not a CANCEL and not the end of the transaction.
    let layers = ServiceBuilder::new().timeout(Duration::from_millis(100));
    let (harness, dispatching) = Harness::start(LIMITS, layers);
    let uac = harness.uac().await;

    uac.send(&uac.request("INVITE", "stall", "timeout", "-t", None)).await;

    assert_eq!(uac.until(500).await, [100]);
    uac.send(&uac.request("ACK", "stall", "timeout", "-t", Some("x"))).await;
    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    let stats = dispatching.await.unwrap();
    assert_eq!(stats.handler_errors, 1);
}

/// The submission futures a wrapper composes are `Send` and `Unpin`.
#[test]
fn submissions_are_send_and_unpin() {
    fn check<T: Send + Unpin>() {}
    check::<ResponseSubmission<'static>>();
    check::<Observing<ResponseSubmission<'static>>>();
}
