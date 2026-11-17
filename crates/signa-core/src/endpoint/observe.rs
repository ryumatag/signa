/*!
A lossy, bounded view of what an endpoint or a datagram port receives and
writes.

[`Endpoint::observe`] and [`DatagramPort::observe`] attach one [`Observer`].
The endpoint's driver, or the port's task, records each message it
receives, before it parses it, and the stages of each write it makes: when
it starts, when the backend or the TCP connection's writer takes it, and how
it ends. Records are copies. None of them can send, answer, deliver or hold a
transaction, and dropping the observer changes nothing on the wire.

Observation never holds up the protocol. A record that does not fit the
observer's limits is dropped and counted, and the driver goes on. The
envelopes, the client response streams and the server observations are what
a TU acts on. They do not depend on an observer, and an observer's losses say
nothing about them.

[`DatagramPort::observe`]: super::port::DatagramPort::observe
*/

use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot};

use super::{
    ClientTransactionNumber, Endpoint, Error, ResponseId, ServerTransactionId,
    driver::{Command, increment, now},
    error::Busy,
};
use crate::transport::{
    Flow, Limits, ReceiveId, Stamp, Transport,
    budget::{Budget, Permit},
    datagram::{TransportContext, WriteId, WriteOutcome},
    next_id, tcp,
};

/// What an [`Observer`] keeps and copies.
///
/// # Example
///
/// Up to 4096 records and 4 MiB, with the first 512 bytes of each message.
///
/// ```
/// use signa_core::endpoint::observe::Config;
///
/// let config = Config::new()
///     .records(4096)
///     .bytes(4 * 1024 * 1024)
///     .payload(512);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    limits: Limits,
    payload: usize,
    context: bool,
}

impl Config {
    /// Keeps up to 1024 records and 1 MiB, without payloads or contexts.
    pub fn new() -> Config {
        Config {
            limits: Limits { count: 1024, bytes: 1024 * 1024 },
            payload: 0,
            context: false,
        }
    }

    /// The most records alive at once, queued or held by the application.
    pub fn records(mut self, records: usize) -> Config {
        self.limits.count = records;
        self
    }

    /// The most bytes those records take. Each record is charged the size of
    /// a [`Record`] itself, a few hundred bytes, plus the payload and context
    /// it copied, so a record without copies still takes room.
    pub fn bytes(mut self, bytes: usize) -> Config {
        self.limits.bytes = bytes;
        self
    }

    /// Copies up to `len` bytes of each message received or written. Zero,
    /// the default, copies none. The copy is the record's own, so it does
    /// not keep a received buffer alive.
    pub fn payload(mut self, len: usize) -> Config {
        self.payload = len;
        self
    }

    /// Copies the UDP backend's context of each received message.
    pub fn context(mut self, context: bool) -> Config {
        self.context = context;
        self
    }
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

/// Receives the [`Record`]s of an endpoint, or of a
/// [`DatagramPort`](super::port::DatagramPort).
///
/// Records arrive in the order the driver made them. Each one is numbered as
/// it is made, so a record dropped for want of room leaves a gap, which the
/// next record that arrives reports in [`Record::lost_before`].
/// [`Observer::stats`] counts the losses too, whether or not another record
/// ever arrives.
///
/// A record keeps its share of the [`Config`] limits until it is
/// dropped, so records the application holds count as well as queued ones.
/// What the application copies out of them is its own.
///
/// Dropping the observer detaches it. Records already made are dropped with
/// it, and the endpoint can attach another one.
pub struct Observer {
    records: mpsc::UnboundedReceiver<Record>,
    counters: Arc<Counters>,
    /// The sequence number of the last record received.
    last: Option<u64>,
    attached: Arc<AtomicBool>,
}

impl Observer {
    /// Waits for the next record. `None` once the endpoint has stopped and
    /// every record has been received.
    ///
    /// Dropping this future consumes nothing.
    pub fn recv(
        &mut self,
    ) -> impl Future<Output = Option<Record>> + Send + '_ {
        poll_fn(|cx| self.poll_recv(cx))
    }

    /// Polls for the next record, as [`Observer::recv`].
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Record>> {
        let Some(mut record) = std::task::ready!(self.records.poll_recv(cx))
        else {
            return Poll::Ready(None);
        };
        // The tap numbers and queues a record under one lock, so records
        // arrive in the order of their numbers.
        let expected = self.last.map_or(0, |last| last + 1);
        debug_assert!(record.sequence >= expected, "records out of order");
        record.lost_before = record.sequence.saturating_sub(expected);
        self.last = Some(record.sequence);
        Poll::Ready(Some(record))
    }

    /// Returns what the observer has missed so far.
    pub fn stats(&self) -> Stats {
        let counters = &self.counters;
        Stats {
            lost: counters.lost.load(Ordering::Relaxed),
            lost_bytes: counters.lost_bytes.load(Ordering::Relaxed),
            truncated_bytes: counters.truncated_bytes.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.attached.store(false, Ordering::Release);
    }
}

impl fmt::Debug for Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observer").field("stats", &self.stats()).finish()
    }
}

/// What an [`Observer`] has missed.
///
/// Counters saturate at `u64::MAX`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Stats {
    /// Records dropped because the observer's limits were full.
    pub lost: u64,
    /// The lengths of the messages those records would have described, as
    /// [`Record::message_len`] gives them, whether or not [`Config::payload`] would
    /// have copied them. Write stages that carry no message add nothing.
    pub lost_bytes: u64,
    /// Bytes past [`Config::payload`] that delivered records did not copy,
    /// when the observer copies payloads. Lost records add nothing here.
    pub truncated_bytes: u64,
}

/// One thing an endpoint received or did with a write.
///
/// Its `Debug` shows the lengths of the payload and the context, never their
/// bytes, since SIP traffic can carry credentials.
pub struct Record {
    sequence: u64,
    lost_before: u64,
    at: Instant,
    observed: Observed,
    message_len: usize,
    payload: Option<Bytes>,
    context: Option<TransportContext>,
    _permit: Permit,
}

impl Record {
    /// The record's number. The driver numbers records from zero as it makes
    /// them, including those it drops.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// How many records were dropped between the previous one received and
    /// this one.
    pub fn lost_before(&self) -> u64 {
        self.lost_before
    }

    /// When it happened, on the endpoint's clock. For a received message
    /// that is when it arrived, see [`ReceiveInfo`].
    ///
    /// [`ReceiveInfo`]: super::ReceiveInfo
    pub fn at(&self) -> Instant {
        self.at
    }

    /// What happened.
    pub fn observed(&self) -> &Observed {
        &self.observed
    }

    /// The length of the message received or written, whether or not
    /// [`Config::payload`] copied it. Zero for a write stage that carries no
    /// message.
    pub fn message_len(&self) -> usize {
        self.message_len
    }

    /// The copy of the message's first bytes, up to the configured payload
    /// length, or `None` when the observer copies no payloads or this record
    /// carries no message.
    pub fn payload(&self) -> Option<&Bytes> {
        self.payload.as_ref()
    }

    /// The copy of the received message's context, when the observer copies
    /// contexts.
    pub fn context(&self) -> Option<&TransportContext> {
        self.context.as_ref()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("sequence", &self.sequence)
            .field("lost_before", &self.lost_before)
            .field("at", &self.at)
            .field("observed", &self.observed)
            .field("message_len", &self.message_len)
            .field("payload", &self.payload.as_ref().map(Bytes::len))
            .field(
                "context",
                &self.context.as_ref().map(TransportContext::len),
            )
            .finish()
    }
}

/// What a [`Record`] saw.
///
/// A write has up to three records, which share its [`WriteRef`]: it
/// started, it was taken, and it ended. A write that failed before it was
/// taken has no `WriteAccepted`. One started before the
/// observer was attached may show only its later stages, or none, and the
/// last stage of a write can come after its transaction has ended.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Observed {
    /// A message arrived, before the endpoint parsed it: a whole UDP
    /// datagram, or one message a TCP connection framed. A datagram that is
    /// not a SIP message is recorded too.
    #[non_exhaustive]
    Received {
        /// The message's ID, which its envelope carries in its
        /// [`ReceiveInfo`](super::ReceiveInfo).
        id: ReceiveId,
        /// The flow it arrived on.
        flow: Flow,
    },
    /// A write started, with its encoded message.
    #[non_exhaustive]
    WriteStarted {
        /// Names the write in its later records.
        write: WriteRef,
        /// The local and remote ends of the write. A TCP write that waits
        /// for a new connection starts before its local end is known, and
        /// shows the unspecified address of the remote's family, port zero.
        flow: Flow,
        /// Why the endpoint wrote it.
        origin: WriteOrigin,
        /// The received message that made the endpoint write it, such as a
        /// request its automatic 100 answers, or a retransmission its cached
        /// response answers again.
        cause: Option<ReceiveId>,
    },
    /// The write was taken to be written: by the UDP backend, or by the
    /// writer of the TCP connection, which took it from the connection's
    /// queue. On an endpoint registered on a shared port, this is the port
    /// taking it.
    #[non_exhaustive]
    WriteAccepted {
        /// The write.
        write: WriteRef,
    },
    /// The write ended.
    #[non_exhaustive]
    WriteEnded {
        /// The write.
        write: WriteRef,
        /// How it ended.
        end: WriteEnd,
        /// Whether it was taken first, so that a `WriteAccepted` was
        /// recorded for it. A write that ends before that, such as one the
        /// write limits refused or one a closing TCP connection dropped from
        /// its queue, was never offered to the network.
        accepted: bool,
    },
}

/// Names one write within an endpoint's records.
///
/// A UDP write is numbered by the endpoint's UDP backend, so
/// [`WriteRef::datagram`] is the [`WriteId`] the backend saw. The endpoint
/// numbers its TCP writes itself. Each kind has a domain of its own, which no
/// other endpoint or port in the process shares, and a number never repeats
/// within its domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WriteRef {
    domain: u64,
    number: u64,
    datagram: bool,
}

impl WriteRef {
    /// The domain the write was numbered in.
    pub fn domain(&self) -> u64 {
        self.domain
    }

    /// The write's number in its domain.
    pub fn number(&self) -> u64 {
        self.number
    }

    /// The ID the UDP backend saw for a datagram write, or `None` for a TCP
    /// write.
    pub fn datagram(&self) -> Option<WriteId> {
        self.datagram.then(|| WriteId::new(self.number))
    }
}

/// Why the endpoint wrote something.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WriteOrigin {
    /// The first write of a client transaction's request, a CANCEL included.
    #[non_exhaustive]
    Request {
        /// The client transaction, see [`ClientControl::number`].
        ///
        /// [`ClientControl::number`]: super::ClientControl::number
        transaction: ClientTransactionNumber,
    },
    /// A client transaction's request again, on Timer A or E.
    #[non_exhaustive]
    RequestRetransmission {
        /// The client transaction.
        transaction: ClientTransactionNumber,
    },
    /// The ACK an INVITE client transaction sends for a non-2xx final,
    /// or again for its retransmission.
    #[non_exhaustive]
    Ack {
        /// The client transaction.
        transaction: ClientTransactionNumber,
    },
    /// A server transaction's response: one the TU submitted, or one the
    /// endpoint made, such as the automatic 100 or the 500 for a dropped
    /// responder.
    #[non_exhaustive]
    Response {
        /// The server transaction.
        transaction: ServerTransactionId,
        /// The TU's submission, or `None` for a response the endpoint made.
        operation: Option<ResponseId>,
    },
    /// A server transaction's response again, for a retransmitted request or
    /// on Timer G.
    #[non_exhaustive]
    ResponseRetransmission {
        /// The server transaction.
        transaction: ServerTransactionId,
    },
    /// A response the endpoint made without a transaction, such as a 503
    /// for a request it could not take.
    Stateless,
    /// A response sent through a [`ReplyRoute`](super::ReplyRoute).
    Reply,
    /// A request sent with [`Endpoint::send_request`], or a response
    /// forwarded with [`Endpoint::forward_response`].
    Send,
    /// On a [`DatagramPort`], the write of an endpoint registered on it,
    /// which that endpoint's own observer names `write`. The endpoint's
    /// records say why it wrote it. This one is the same datagram reaching
    /// the backend, not a second write.
    ///
    /// [`DatagramPort`]: super::port::DatagramPort
    #[non_exhaustive]
    Endpoint {
        /// The endpoint's name for the write.
        write: WriteRef,
    },
    /// On a [`DatagramPort`], a raw send, or a datagram forwarded unchanged,
    /// whose `cause` is the datagram's own arrival.
    ///
    /// [`DatagramPort`]: super::port::DatagramPort
    Raw,
}

/// How a write ended, as the endpoint acted on it.
///
/// Over UDP these are the backend's [`WriteOutcome`]s. Over TCP a failure
/// can follow a partial write, and the endpoint treats it as not written.
///
/// The error kind is the backend's or the socket's, apart from those signa
/// reports itself:
///
/// * [`io::ErrorKind::WouldBlock`]: the write limits, or the TCP
///   connection's write queue, were full, so the write was never offered.
/// * [`io::ErrorKind::BrokenPipe`]: the TCP connection had closed, or
///   closed before it wrote the write.
/// * [`io::ErrorKind::Interrupted`]: the write was dropped before it was
///   queued, as a prepared request that was never sent is, or the endpoint
///   stopped before it went out.
/// * [`io::ErrorKind::InvalidInput`]: the datagram was larger than the UDP
///   backend sends.
/// * [`io::ErrorKind::NotConnected`]: on a [`DatagramPort`], the port
///   closed before it offered the write, or with the write unreported.
///
/// [`DatagramPort`]: super::port::DatagramPort
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteEnd {
    /// It was written whole to the local network or stream.
    Written,
    /// It did not go out, for a reason of this kind.
    NotWritten(io::ErrorKind),
    /// The backend cannot tell whether it went out.
    Unknown(io::ErrorKind),
}

impl From<&WriteOutcome> for WriteEnd {
    fn from(outcome: &WriteOutcome) -> WriteEnd {
        match outcome {
            WriteOutcome::Written => WriteEnd::Written,
            WriteOutcome::NotWritten(error) => {
                WriteEnd::NotWritten(error.kind())
            }
            WriteOutcome::Unknown(error) => WriteEnd::Unknown(error.kind()),
        }
    }
}

impl From<&io::Result<()>> for WriteEnd {
    fn from(result: &io::Result<()>) -> WriteEnd {
        match result {
            Ok(()) => WriteEnd::Written,
            Err(error) => WriteEnd::NotWritten(error.kind()),
        }
    }
}

/// Why and in answer to what a write is made, for its `WriteStarted` record.
/// It costs nothing to pass when no observer is attached.
#[derive(Clone, Copy, Debug)]
pub(super) struct Note {
    pub(super) origin: WriteOrigin,
    pub(super) cause: Option<ReceiveId>,
}

impl Note {
    pub(super) fn new(origin: WriteOrigin, cause: Option<ReceiveId>) -> Note {
        Note { origin, cause }
    }
}

/// What an observer misses, shared with it.
#[derive(Debug, Default)]
struct Counters {
    lost: AtomicU64,
    lost_bytes: AtomicU64,
    truncated_bytes: AtomicU64,
}

/// The driver's side of an observer. Clones share it, so that the driver,
/// its UDP port and the TCP writes it hooks all record into one sequence.
#[derive(Clone)]
pub(super) struct Tap(Arc<TapShared>);

struct TapShared {
    records: mpsc::UnboundedSender<Record>,
    budget: Budget,
    counters: Arc<Counters>,
    /// The next record's number. A record takes its number and goes into the
    /// queue under this lock, so the queue holds records in the order of
    /// their numbers. The driver and the writer tasks of its TCP connections
    /// record from different threads, and a number taken apart from the send
    /// could be queued after a later one. Nothing waits inside the lock.
    sequence: Mutex<u64>,
    payload: usize,
    context: bool,
    /// The domain of the endpoint's TCP writes, and the next number in it.
    tcp: u64,
    tcp_next: AtomicU64,
}

/// The bytes a record takes as the observer's byte limit counts them: its own
/// size and its copies.
fn charge(payload: usize, context: usize) -> usize {
    size_of::<Record>() + payload + context
}

impl Tap {
    /// Returns `false` once the observer has dropped, so that its holder can
    /// let the tap go.
    pub(super) fn is_attached(&self) -> bool {
        !self.0.records.is_closed()
    }

    /// Records a received message, made of `parts` in order. A TCP message
    /// comes as its head and its body.
    pub(super) fn received(
        &self,
        stamp: Stamp,
        flow: Flow,
        parts: [&[u8]; 2],
        context: &TransportContext,
    ) {
        let context = self.0.context.then(|| context.clone());
        self.record(
            stamp.at,
            Observed::Received { id: stamp.id, flow },
            parts,
            context,
        );
    }

    /// Records the start of `write` with its encoded `bytes`.
    pub(super) fn started(
        &self,
        write: WriteRef,
        flow: Flow,
        note: Note,
        bytes: &[u8],
    ) {
        let Note { origin, cause } = note;
        let observed = Observed::WriteStarted { write, flow, origin, cause };
        self.record(now(), observed, [bytes, &[]], None);
    }

    /// Records that the backend took `write`.
    pub(super) fn accepted(&self, write: WriteRef) {
        self.record(now(), Observed::WriteAccepted { write }, [&[]; 2], None);
    }

    /// Records the end of `write`.
    pub(super) fn ended(
        &self,
        write: WriteRef,
        end: WriteEnd,
        accepted: bool,
    ) {
        let observed = Observed::WriteEnded { write, end, accepted };
        self.record(now(), observed, [&[]; 2], None);
    }

    /// Numbers a TCP write on `flow` and records its start.
    pub(super) fn tcp_started(
        &self,
        flow: Flow,
        note: Note,
        bytes: &[u8],
    ) -> WriteRef {
        let number = self.0.tcp_next.fetch_add(1, Ordering::Relaxed);
        let write = WriteRef { domain: self.0.tcp, number, datagram: false };
        self.started(write, flow, note, bytes);
        write
    }

    /// Numbers a TCP write to `remote` that waits for a connection, and
    /// records its start. The connection's local end is not known yet, so
    /// the record shows the unspecified address of the remote's family.
    pub(super) fn tcp_parked(
        &self,
        remote: SocketAddr,
        note: Note,
        bytes: &[u8],
    ) -> WriteRef {
        let any = match remote {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let local = SocketAddr::new(any, 0);
        let flow = Flow { transport: Transport::Tcp, local, remote };
        self.tcp_started(flow, note, bytes)
    }

    /// The hook that records, from the connection's writer task, when it
    /// takes `write` from the queue and how the write ends, or `None` if this tap did not start it, as when another observer
    /// has replaced the one that did.
    ///
    /// The hook holds the tap weakly. A write can stay queued on a connection
    /// long after the endpoint has stopped, and a strong tap would keep the
    /// observer's channel open, so `Observer::recv` would not end.
    pub(super) fn hook(&self, write: WriteRef) -> Option<tcp::Hook> {
        if !self.started_tcp(write) {
            return None;
        }
        let tap = Arc::downgrade(&self.0);
        let mut taken = false;
        Some(tcp::Hook::new(move |stage| {
            if let tcp::Stage::Taken = stage {
                taken = true;
            }
            let Some(tap) = Weak::upgrade(&tap) else { return };
            match stage {
                tcp::Stage::Taken => Tap(tap).accepted(write),
                tcp::Stage::Ended(result) => {
                    Tap(tap).ended(write, WriteEnd::from(result), taken);
                }
            }
        }))
    }

    /// Records the end of a TCP `write` that was never queued, if this tap
    /// started it.
    pub(super) fn refused(&self, write: WriteRef, kind: io::ErrorKind) {
        if self.started_tcp(write) {
            self.ended(write, WriteEnd::NotWritten(kind), false);
        }
    }

    fn started_tcp(&self, write: WriteRef) -> bool {
        !write.datagram && write.domain == self.0.tcp
    }

    /// Makes a record and queues it, or counts it lost when the limits are
    /// full. Either way it takes the next sequence number, and the caller
    /// never waits.
    fn record(
        &self,
        at: Instant,
        observed: Observed,
        parts: [&[u8]; 2],
        context: Option<TransportContext>,
    ) {
        let shared = &*self.0;
        // An observer that has dropped takes nothing, and the tap's holders
        // let it go at their next look. Its numbers no longer matter.
        if shared.records.is_closed() {
            return;
        }
        let len = parts[0].len() + parts[1].len();
        let copied = len.min(shared.payload);
        let context_len = context.as_ref().map_or(0, TransportContext::len);

        // The permit and the copies come before the lock, which then covers
        // only the number and the send.
        let Some(permit) = shared.budget.acquire(charge(copied, context_len))
        else {
            let mut next = shared.sequence.lock().expect("not poisoned");
            *next += 1;
            increment(&shared.counters.lost);
            add(&shared.counters.lost_bytes, len);
            return;
        };
        let payload =
            (shared.payload > 0 && len > 0).then(|| copy(parts, copied));
        // A context the backend sliced out of a capture buffer would keep
        // that buffer alive with the record.
        let context = context.map(|context| context.detached());
        let mut record = Record {
            sequence: 0,
            lost_before: 0,
            at,
            observed,
            message_len: len,
            payload,
            context,
            _permit: permit,
        };

        // The counters change under the lock, before the send, so that they
        // already include what a record the observer receives reports.
        let mut next = shared.sequence.lock().expect("not poisoned");
        record.sequence = *next;
        *next += 1;
        if shared.payload > 0 {
            add(&shared.counters.truncated_bytes, len - copied);
        }
        let _ = shared.records.send(record);
    }
}

/// Copies the first `len` bytes of `parts`, taken in order.
fn copy(parts: [&[u8]; 2], len: usize) -> Bytes {
    let mut copy = BytesMut::with_capacity(len);
    let mut left = len;
    for part in parts {
        let n = part.len().min(left);
        copy.extend_from_slice(&part[..n]);
        left -= n;
    }
    copy.freeze()
}

/// Adds `n` to `counter`, saturating at `u64::MAX`.
fn add(counter: &AtomicU64, n: usize) {
    if n == 0 {
        return;
    }
    let n = n as u64;
    let mut old = counter.load(Ordering::Relaxed);
    while old != u64::MAX {
        let new = old.saturating_add(n);
        match counter.compare_exchange_weak(
            old,
            new,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => old = actual,
        }
    }
}

/// Numbers the writes of one UDP port for its records.
pub(super) fn datagram_write(domain: u64, id: WriteId) -> WriteRef {
    WriteRef { domain, number: id.get(), datagram: true }
}

/// Takes `tap` back when its observer has dropped.
pub(super) fn attached(tap: &mut Option<Tap>) -> Option<&Tap> {
    if tap.as_ref().is_some_and(|tap| !tap.is_attached()) {
        *tap = None;
    }
    tap.as_ref()
}

/// Makes the tap and the observer of `config`.
pub(super) fn pair(
    config: Config,
    attached: Arc<AtomicBool>,
) -> (Tap, Observer) {
    let (records, receiver) = mpsc::unbounded_channel();
    let counters = Arc::new(Counters::default());
    let tap = Tap(Arc::new(TapShared {
        records,
        budget: Budget::new(config.limits),
        counters: counters.clone(),
        sequence: Mutex::new(0),
        payload: config.payload,
        context: config.context,
        tcp: next_id(),
        tcp_next: AtomicU64::new(0),
    }));
    let observer =
        Observer { records: receiver, counters, last: None, attached };
    (tap, observer)
}

impl Endpoint {
    /// Attaches an observer to the endpoint, which records what it receives
    /// and writes within the limits of `config`.
    ///
    /// It resolves once the driver records. Every message the driver handles
    /// and every write it starts from then on is recorded, or counted lost.
    /// See [`Observer`] for how records are bounded and [`Observed`] for what
    /// they show.
    ///
    /// # Cancellation
    ///
    /// Dropping the future detaches the observer it would have returned.
    ///
    /// # Errors
    ///
    /// * [`Error::is_busy`] while another observer of this endpoint is alive.
    /// * [`Error::is_closed`] once the endpoint has stopped.
    ///
    /// # Example
    ///
    /// ```
    /// use signa_core::endpoint::{
    ///     Endpoint, Error,
    ///     observe::{Config, Observed},
    /// };
    ///
    /// async fn trace(endpoint: &Endpoint) -> Result<(), Error> {
    ///     let mut observer = endpoint.observe(Config::new()).await?;
    ///     while let Some(record) = observer.recv().await {
    ///         if record.lost_before() > 0 {
    ///             eprintln!("{} records lost", record.lost_before());
    ///         }
    ///         if let Observed::Received { id, flow, .. } = record.observed() {
    ///             println!("{id:?} from {}", flow.remote);
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn observe(
        &self,
        config: Config,
    ) -> impl Future<Output = Result<Observer, Error>> + Send + '_ {
        async move {
            if self.commands.is_closed() {
                return Err(Error::closed());
            }
            if self
                .observing
                .compare_exchange(
                    false,
                    true,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(Error::busy(Busy::Observer));
            }

            // From here on a failure drops the observer, which clears the
            // flag again.
            let (tap, observer) = pair(config, self.observing.clone());
            let (attached, done) = oneshot::channel();
            self.commands
                .send(Command::Observe { tap, attached })
                .map_err(|_| Error::closed())?;
            done.await.map_err(|_| Error::closed())?;
            Ok(observer)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    const PEER: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    const NOTE: Note = Note { origin: WriteOrigin::Send, cause: None };

    fn attach(config: Config) -> (Tap, Observer) {
        pair(config, Arc::new(AtomicBool::new(true)))
    }

    /// A TCP flow to the peer.
    fn flow() -> Flow {
        Flow { transport: Transport::Tcp, local: PEER, remote: PEER }
    }

    // The driver and the writer tasks of its connections record at once.
    // However their sends interleave, the observer receives the numbers in
    // order, and its gaps and stats account for every record made.
    #[tokio::test]
    async fn records_from_several_threads_arrive_in_order() {
        const THREADS: u64 = 4;
        const EACH: u64 = 5_000;
        let (tap, mut observer) = attach(Config::new().records(64));
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let tap = tap.clone();
                thread::spawn(move || {
                    for _ in 0..EACH {
                        let write = tap.tcp_started(flow(), NOTE, b"OPTIONS");
                        tap.ended(write, WriteEnd::Written, true);
                    }
                })
            })
            .collect();
        drop(tap);

        let (mut delivered, mut lost_before, mut last) = (0, 0, None);
        while let Some(record) = observer.recv().await {
            assert!(last.is_none_or(|last| record.sequence() > last));
            last = Some(record.sequence());
            delivered += 1;
            lost_before += record.lost_before();
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let total = THREADS * EACH * 2;
        assert_eq!(delivered + observer.stats().lost, total);
        assert_eq!(delivered + lost_before, last.unwrap() + 1);
    }

    // A loss counts the whole message, whether or not payloads are copied,
    // and only a delivered record counts what the capture length cut.
    #[test]
    fn stats_count_lost_messages_whole_and_truncation_once() {
        let (tap, observer) = attach(Config::new().records(1).payload(4));
        let first = tap.tcp_started(flow(), NOTE, b"first message");
        tap.tcp_started(flow(), NOTE, b"lost message");
        tap.ended(first, WriteEnd::Written, true);

        let stats = observer.stats();
        assert_eq!(stats.lost, 2);
        assert_eq!(stats.lost_bytes, 12);
        assert_eq!(stats.truncated_bytes, 9);

        let (tap, observer) = attach(Config::new().records(1));
        tap.tcp_started(flow(), NOTE, b"first message");
        tap.tcp_started(flow(), NOTE, b"lost message");
        let stats = observer.stats();
        assert_eq!((stats.lost, stats.lost_bytes), (1, 12));
        assert_eq!(stats.truncated_bytes, 0);
    }

    // A record holds its share of the limits until the application drops it.
    // Then the next one fits again, and reports the one lost meanwhile.
    #[tokio::test]
    async fn a_dropped_record_returns_its_permit() {
        let (tap, mut observer) = attach(Config::new().records(1));
        let write = tap.tcp_started(flow(), NOTE, b"OPTIONS");
        let held = observer.recv().await.unwrap();

        tap.ended(write, WriteEnd::Written, true);
        drop(held);
        tap.ended(write, WriteEnd::Written, true);

        let next = observer.recv().await.unwrap();
        assert_eq!((next.sequence(), next.lost_before()), (2, 1));
        assert_eq!(tap.0.budget.acquire(0).map(drop), None);
        drop(next);
        assert!(tap.0.budget.acquire(charge(0, 0)).is_some());
    }

    // A TCP message comes as its head and its body, and the copy runs across
    // the two up to the capture length.
    #[test]
    fn a_copy_takes_both_parts_in_order() {
        let parts: [&[u8]; 2] = [b"head", b"body"];
        assert_eq!(copy(parts, 0), "");
        assert_eq!(copy(parts, 3), "hea");
        assert_eq!(copy(parts, 6), "headbo");
        assert_eq!(copy(parts, 8), "headbody");
        assert_eq!(copy([&[], b"body"], 2), "bo");
    }

    #[test]
    fn counters_saturate() {
        let counter = AtomicU64::new(u64::MAX - 1);
        add(&counter, 5);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        add(&counter, 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        increment(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    // SIP can carry credentials, in its payload and in what a backend keeps
    // in its context, so `Debug` shows only their lengths.
    #[tokio::test]
    async fn debug_shows_no_payload_or_context() {
        let config = Config::new().payload(64).context(true);
        let (tap, mut observer) = attach(config);
        let stamp = crate::transport::Stamps::new().stamp(now());
        let context =
            TransportContext::new(Bytes::from_static(b"secret-context"))
                .unwrap();
        tap.received(
            stamp,
            flow(),
            [b"secret-head", b"secret-body"],
            &context,
        );

        let record = observer.recv().await.unwrap();
        assert_eq!(record.payload().unwrap(), "secret-headsecret-body");
        assert_eq!(record.context().unwrap().as_bytes(), "secret-context");
        let debug = format!("{record:?}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(debug.contains("payload: Some(22)"), "{debug}");
        assert!(debug.contains("context: Some(14)"), "{debug}");
    }

    // Once the observer has dropped, a record neither copies nor counts, and
    // takes no number.
    #[test]
    fn a_detached_tap_records_nothing() {
        let (tap, observer) = attach(Config::new().records(0).payload(64));
        drop(observer);

        tap.tcp_started(flow(), NOTE, b"OPTIONS");

        assert_eq!(*tap.0.sequence.lock().unwrap(), 0);
        assert_eq!(tap.0.counters.lost.load(Ordering::Relaxed), 0);
    }

    // A hook holds the tap weakly. A write still queued once the endpoint
    // has let its tap go does not keep the observer waiting, and records
    // nothing when it ends. A write another tap started gets no hook.
    #[tokio::test]
    async fn a_hook_does_not_keep_the_observer_open() {
        let (tap, mut observer) = attach(Config::new());
        let write = tap.tcp_started(flow(), NOTE, b"OPTIONS");
        let hook = tap.hook(write).unwrap();
        let (other, _observer) = attach(Config::new());
        assert!(other.hook(write).is_none());

        drop(tap);

        assert!(observer.recv().await.is_some());
        assert!(observer.recv().await.is_none());
        drop(hook);
    }

    // A parked TCP write starts before its connection exists, so its record
    // shows no local address, and one that is refused ends unqueued.
    #[tokio::test]
    async fn a_parked_write_starts_without_a_local_end() {
        let (tap, mut observer) = attach(Config::new());
        let v6: SocketAddr = "[::1]:5060".parse().unwrap();
        let write = tap.tcp_parked(v6, NOTE, b"OPTIONS");
        tap.refused(write, io::ErrorKind::ConnectionRefused);

        let started = observer.recv().await.unwrap();
        let Observed::WriteStarted { flow, .. } = started.observed() else {
            panic!("a started write, got {started:?}");
        };
        assert_eq!(flow.local, "[::]:0".parse().unwrap());
        assert_eq!(flow.remote, v6);
        let ended = observer.recv().await.unwrap();
        let Observed::WriteEnded { write: same, end, accepted } =
            *ended.observed()
        else {
            panic!("an ended write, got {ended:?}");
        };
        assert_eq!(same, write);
        assert_eq!(
            (end, accepted),
            (WriteEnd::NotWritten(io::ErrorKind::ConnectionRefused), false)
        );
    }
}
