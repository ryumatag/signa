/*!
A lossy, bounded view of what an endpoint receives and writes.

[`Endpoint::observe`] attaches one [`Observer`]. The driver records each
message it receives, before it parses it, and the stages of each write it
makes: when it starts, when the backend takes it, and how it ends. Records
are copies. None of them can send, answer, deliver or hold a transaction, and
dropping the observer changes nothing on the wire.

Observation never holds up the protocol. A record that does not fit the
observer's limits is dropped and counted, and the driver goes on. The
envelopes, the client response streams and the server observations are what
a TU acts on. They do not depend on an observer, and an observer's losses say
nothing about them.
*/

use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot};

use super::{
    Endpoint, Error, ResponseId, ServerTransactionId,
    driver::{Command, increment, now},
};
use crate::transport::{
    Flow, ReceiveId, Stamp, WriteLimits,
    budget::{Budget, Permit},
    datagram::{TransportContext, WriteId, WriteOutcome},
    next_id,
};

/// What an [`Observer`] keeps and copies.
///
/// # Example
///
/// Up to 4096 records and 4 MiB, with the first 512 bytes of each message.
///
/// ```
/// use signa_core::endpoint::ObservationConfig;
///
/// let config = ObservationConfig::new()
///     .records(4096)
///     .bytes(4 * 1024 * 1024)
///     .payload(512);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ObservationConfig {
    limits: WriteLimits,
    payload: usize,
    context: bool,
}

impl ObservationConfig {
    /// Keeps up to 1024 records and 1 MiB, without payloads or contexts.
    pub fn new() -> ObservationConfig {
        ObservationConfig {
            limits: WriteLimits { messages: 1024, bytes: 1024 * 1024 },
            payload: 0,
            context: false,
        }
    }

    /// The most records alive at once, queued or held by the application.
    pub fn records(mut self, records: usize) -> ObservationConfig {
        self.limits.messages = records;
        self
    }

    /// The most bytes those records take: each record's own size and the
    /// payload and context it copied.
    pub fn bytes(mut self, bytes: usize) -> ObservationConfig {
        self.limits.bytes = bytes;
        self
    }

    /// Copies up to `len` bytes of each message received or written. Zero,
    /// the default, copies none. The copy is the record's own, so it does
    /// not keep a received buffer alive.
    pub fn payload(mut self, len: usize) -> ObservationConfig {
        self.payload = len;
        self
    }

    /// Copies the UDP backend's context of each received message.
    pub fn context(mut self, context: bool) -> ObservationConfig {
        self.context = context;
        self
    }
}

impl Default for ObservationConfig {
    fn default() -> ObservationConfig {
        ObservationConfig::new()
    }
}

/// Receives the [`Record`]s of an endpoint, or of a
/// [`DatagramPort`](super::DatagramPort).
///
/// Records arrive in the order the driver made them. Each one is numbered as
/// it is made, so a record dropped for want of room leaves a gap, which the
/// next record that arrives reports in [`Record::lost_before`].
/// [`Observer::stats`] counts the losses too, whether or not another record
/// ever arrives.
///
/// A record keeps its share of the [`ObservationConfig`] limits until it is
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
    pub fn recv(&mut self) -> impl Future<Output = Option<Record>> + '_ {
        poll_fn(|cx| self.poll_recv(cx))
    }

    /// Polls for the next record, as [`Observer::recv`].
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Record>> {
        let Some(mut record) = std::task::ready!(self.records.poll_recv(cx))
        else {
            return Poll::Ready(None);
        };
        let expected = self.last.map_or(0, |last| last + 1);
        record.lost_before = record.sequence - expected;
        self.last = Some(record.sequence);
        Poll::Ready(Some(record))
    }

    /// Returns what the observer has missed so far.
    pub fn stats(&self) -> ObserverStats {
        let counters = &self.counters;
        ObserverStats {
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
pub struct ObserverStats {
    /// Records dropped because the observer's limits were full.
    pub lost: u64,
    /// The payload and context bytes those records would have copied.
    pub lost_bytes: u64,
    /// Bytes past [`ObservationConfig::payload`] that records did not copy,
    /// when the observer copies payloads.
    pub truncated_bytes: u64,
}

/// One thing an endpoint received or did with a write.
///
/// Its `Debug` shows the payload's length, never its bytes, since SIP
/// traffic can carry credentials.
pub struct Record {
    sequence: u64,
    lost_before: u64,
    at: Instant,
    observed: Observed,
    len: usize,
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

    /// The length of the message received or written. Zero for a write
    /// stage that carries no message.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if [`Record::len`] is zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
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
            .field("len", &self.len)
            .field("payload", &self.payload.as_ref().map(Bytes::len))
            .field("context", &self.context)
            .finish()
    }
}

/// What a [`Record`] saw.
///
/// A write has up to three records, which share its [`WriteRef`]: it
/// started, the backend took it, and it ended. A write that failed before
/// the backend took it has no `WriteAccepted`. One started before the
/// observer was attached may show only its later stages, and the last stage
/// of a write can come after its transaction has ended.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Observed {
    /// A message arrived, before the endpoint parsed it: a whole UDP
    /// datagram, or one message a TCP connection framed. A datagram that is
    /// not a SIP message is recorded too.
    Received {
        /// The message's ID, which its envelope carries in its
        /// [`ReceiveInfo`](super::ReceiveInfo).
        id: ReceiveId,
        /// The flow it arrived on.
        flow: Flow,
    },
    /// A write started, with its encoded message.
    WriteStarted {
        /// Names the write in its later records.
        write: WriteRef,
        /// The local and remote ends of the write.
        flow: Flow,
        /// Why the endpoint wrote it.
        origin: WriteOrigin,
        /// The received message that made the endpoint write it, such as a
        /// request its automatic 100 answers, or a retransmission its cached
        /// response answers again.
        cause: Option<ReceiveId>,
    },
    /// The backend, or the TCP connection's queue, took the write. On an
    /// endpoint registered on a shared port, this is the port taking it.
    WriteAccepted {
        /// The write.
        write: WriteRef,
    },
    /// The write ended.
    WriteEnded {
        /// The write.
        write: WriteRef,
        /// How it ended.
        result: WriteResult,
        /// Whether the backend had taken it. A write that ends before that,
        /// such as one the write limits refused, was never offered.
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
    Request {
        /// The client transaction, see [`ClientControl::number`].
        ///
        /// [`ClientControl::number`]: super::ClientControl::number
        transaction: u64,
    },
    /// A client transaction's request again, on Timer A or E.
    RequestRetransmission {
        /// The client transaction.
        transaction: u64,
    },
    /// The ACK an INVITE client transaction sends for a non-2xx final,
    /// or again for its retransmission.
    Ack {
        /// The client transaction.
        transaction: u64,
    },
    /// A server transaction's response: one the TU submitted, or one the
    /// endpoint made, such as the automatic 100 or the 500 for a dropped
    /// responder.
    Response {
        /// The server transaction.
        transaction: ServerTransactionId,
        /// The TU's submission, or `None` for a response the endpoint made.
        operation: Option<ResponseId>,
    },
    /// A server transaction's response again, for a retransmitted request or
    /// on Timer G.
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
    /// On a [`DatagramPort`](super::DatagramPort), the write of an endpoint
    /// registered on it, which that endpoint's own observer names `write`.
    /// The endpoint's records say why it wrote it. This one is the same
    /// datagram reaching the backend, not a second write.
    Endpoint {
        /// The endpoint's name for the write.
        write: WriteRef,
    },
    /// On a [`DatagramPort`](super::DatagramPort), a raw send, or a datagram
    /// forwarded unchanged, whose `cause` is the datagram's own arrival.
    Raw,
}

/// How a write ended, as the endpoint acted on it.
///
/// Over UDP these are the backend's [`WriteOutcome`]s. Over TCP a failure
/// can follow a partial write, and the endpoint treats it as not written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteResult {
    /// It was written whole to the local network or stream.
    Written,
    /// It did not go out, for a reason of this kind.
    NotWritten(io::ErrorKind),
    /// The backend cannot tell whether it went out.
    Unknown(io::ErrorKind),
}

impl From<&WriteOutcome> for WriteResult {
    fn from(outcome: &WriteOutcome) -> WriteResult {
        match outcome {
            WriteOutcome::Written => WriteResult::Written,
            WriteOutcome::NotWritten(error) => {
                WriteResult::NotWritten(error.kind())
            }
            WriteOutcome::Unknown(error) => WriteResult::Unknown(error.kind()),
        }
    }
}

impl From<&io::Result<()>> for WriteResult {
    fn from(result: &io::Result<()>) -> WriteResult {
        match result {
            Ok(()) => WriteResult::Written,
            Err(error) => WriteResult::NotWritten(error.kind()),
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
    /// The next record's number. Only the endpoint's tasks record, the
    /// driver and the writer tasks of its TCP connections, so this is
    /// uncontended in practice.
    sequence: AtomicU64,
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
        result: WriteResult,
        accepted: bool,
    ) {
        let observed = Observed::WriteEnded { write, result, accepted };
        self.record(now(), observed, [&[]; 2], None);
    }

    /// Numbers a TCP write.
    pub(super) fn tcp_write(&self) -> WriteRef {
        let number = self.0.tcp_next.fetch_add(1, Ordering::Relaxed);
        WriteRef { domain: self.0.tcp, number, datagram: false }
    }

    /// Makes a record and queues it, or counts it lost when the limits are
    /// full. Either way it takes the next sequence number, and the driver
    /// never waits.
    fn record(
        &self,
        at: Instant,
        observed: Observed,
        parts: [&[u8]; 2],
        context: Option<TransportContext>,
    ) {
        let shared = &*self.0;
        let sequence = shared.sequence.fetch_add(1, Ordering::Relaxed);
        let len = parts[0].len() + parts[1].len();
        let copied = len.min(shared.payload);
        let context_len = context.as_ref().map_or(0, TransportContext::len);

        let Some(permit) = shared.budget.acquire(charge(copied, context_len))
        else {
            increment(&shared.counters.lost);
            add(&shared.counters.lost_bytes, copied + context_len);
            return;
        };
        if shared.payload > 0 {
            add(&shared.counters.truncated_bytes, len - copied);
        }
        let payload = (shared.payload > 0 && len > 0).then(|| {
            let mut copy = BytesMut::with_capacity(copied);
            let mut left = copied;
            for part in parts {
                let n = part.len().min(left);
                copy.extend_from_slice(&part[..n]);
                left -= n;
            }
            copy.freeze()
        });
        // A context the backend sliced out of a capture buffer would keep
        // that buffer alive with the record.
        let context = context.map(|context| context.detached());

        let record = Record {
            sequence,
            lost_before: 0,
            at,
            observed,
            len,
            payload,
            context,
            _permit: permit,
        };
        // An observer that has dropped takes nothing, and the tap's holders
        // let it go at their next look.
        let _ = shared.records.send(record);
    }
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
    config: ObservationConfig,
    attached: Arc<AtomicBool>,
) -> (Tap, Observer) {
    let (records, receiver) = mpsc::unbounded_channel();
    let counters = Arc::new(Counters::default());
    let tap = Tap(Arc::new(TapShared {
        records,
        budget: Budget::new(config.limits),
        counters: counters.clone(),
        sequence: AtomicU64::new(0),
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
    /// use signa_core::endpoint::{Endpoint, Error, ObservationConfig, Observed};
    ///
    /// async fn trace(endpoint: &Endpoint) -> Result<(), Error> {
    ///     let mut observer = endpoint.observe(ObservationConfig::new()).await?;
    ///     while let Some(record) = observer.recv().await {
    ///         if record.lost_before() > 0 {
    ///             eprintln!("{} records lost", record.lost_before());
    ///         }
    ///         if let Observed::Received { id, flow } = record.observed() {
    ///             println!("{id:?} from {}", flow.remote);
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn observe(
        &self,
        config: ObservationConfig,
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
                return Err(Error::busy());
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
