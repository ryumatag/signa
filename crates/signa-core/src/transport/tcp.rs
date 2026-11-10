/*!
The TCP transport.

[`Listener::accept`] and `connect_reserved` each start a connection as two
tasks. The reader frames the stream with the [`Decoder`] and sends every
message into the channel the endpoint reads, with the connection's [`Flow`]
and [`Writer`], so a response goes back on the connection the request came on
(RFC 3261 section 18.2.2). The writer writes what [`Writer::send`] queues.

The channel to the endpoint is bounded. When the endpoint falls behind, the
reader stops reading and TCP flow control holds the peer back. The queue to the
writer is bounded too, but nothing waits for a slow peer. [`Writer::send`]
fails when the queue is full, and the endpoint decides what to do about it.

A connection ends at EOF, when nothing arrives for the idle timeout, on a
decode error, or when a write fails. Bytes left in the read buffer at EOF are
an unfinished message and are dropped. The listener holds at most
`max_connections` open and leaves the rest in the OS backlog.

A connection also ends when the endpoint closes the channel, which is how every
connection closes when the endpoint stops. The endpoint owns its listener and
connection tasks through a `Tasks` handle and tells them how to stop with a
`Phase`. At `Phase::Closing` the listener stops accepting and each writer
closes its queue and finishes what is in it, since the endpoint's last
responses are there. At `Phase::Abort` everything stops at once, and unwritten
messages fail their receipts. The endpoint waits for every task to end before it
reports that it has stopped, so nothing it owns writes after that.
*/

use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, tcp::OwnedReadHalf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::{
    Flow, MessageLimits, Transport, WriteLimits,
    budget::{Budget, Permit},
    framing::{Decoder, Frame, Role},
};
use crate::message::Message;

/// How much to reserve before each read. A head is a few KiB at most, so this
/// is a message or two per read without a large buffer per idle connection.
const READ_SIZE: usize = 8 * 1024;

/// How many queued messages the writer takes per write. Each one is a chunk of
/// the vectored write.
const WRITE_BATCH: usize = 64;

/// The answer to an RFC 5626 ping.
const PONG: Bytes = Bytes::from_static(b"\r\n");

/// How long the writer of a connection without an endpoint gets to finish its
/// queue once its channel closes. See [`run_connection`].
const UNOWNED_DRAIN: Duration = Duration::from_secs(5);

/// How far the endpoint that owns a set of connections has got in stopping.
///
/// The phases only move forward.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Phase {
    /// The connections serve the endpoint.
    Running,
    /// The endpoint has stopped taking work. The listener stops accepting,
    /// and each writer closes its queue and ends once the queue is written.
    Closing,
    /// Everything stops now. A writer drops what it has not written, which
    /// fails those receipts and returns their reservations.
    Abort,
}

/// The owner's side of a set of transport tasks.
///
/// Every task holds a [`Teardown`] from [`Tasks::handle`], so the tasks have
/// all ended once [`Tasks::finished`] resolves. A connection's writer is the
/// exception. Its supervisor holds the handle and waits for it. That counts
/// tasks without a lock or a registry, and a task started late, such as a
/// connection that a connect attempt opened after the owner began closing,
/// still counts until it ends. Dropping `Tasks` is [`Phase::Abort`].
#[derive(Debug)]
pub(crate) struct Tasks {
    phase: watch::Sender<Phase>,
    discarded: Arc<AtomicBool>,
}

impl Tasks {
    pub(crate) fn new() -> Tasks {
        Tasks {
            phase: watch::channel(Phase::Running).0,
            discarded: Arc::default(),
        }
    }

    /// A handle for a new task.
    pub(crate) fn handle(&self) -> Teardown {
        Teardown {
            phase: self.phase.subscribe(),
            discarded: self.discarded.clone(),
        }
    }

    /// Moves to `phase`, unless the tasks are already past it.
    pub(crate) fn advance(&self, phase: Phase) {
        self.phase.send_if_modified(|current| {
            let later = *current < phase;
            if later {
                *current = phase;
            }
            later
        });
    }

    /// Resolves once every task has ended and dropped its handle.
    pub(crate) async fn finished(&self) {
        self.phase.closed().await;
    }

    /// Whether an aborted writer dropped messages it had not written.
    pub(crate) fn discarded(&self) -> bool {
        self.discarded.load(Ordering::Acquire)
    }
}

/// A task's view of its owner's [`Phase`].
///
/// Holding one is what keeps [`Tasks::finished`] waiting.
#[derive(Clone, Debug)]
pub(crate) struct Teardown {
    phase: watch::Receiver<Phase>,
    discarded: Arc<AtomicBool>,
}

impl Teardown {
    /// A handle whose owner never stops, for connections that tests and
    /// benchmarks open without an endpoint. They end when their channels do.
    #[cfg(any(test, feature = "__bench"))]
    pub(crate) fn detached() -> Teardown {
        static DETACHED: std::sync::OnceLock<Tasks> =
            std::sync::OnceLock::new();
        DETACHED.get_or_init(Tasks::new).handle()
    }

    /// The current phase. An owner that is gone without moving the phase on,
    /// such as an endpoint whose runtime dropped its task, counts as
    /// [`Phase::Abort`].
    fn phase(&self) -> Phase {
        match self.phase.has_changed() {
            Ok(_) => *self.phase.borrow(),
            Err(_) => Phase::Abort,
        }
    }

    /// Resolves once the phase is `phase` or later.
    async fn reached(&mut self, phase: Phase) {
        let _ = self.phase.wait_for(|current| *current >= phase).await;
    }

    /// Records that a writer was aborted with output left.
    fn discard(&self) {
        self.discarded.store(true, Ordering::Release);
    }
}

/// Settings for every connection a listener accepts or `connect_reserved`
/// opens.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The decoder's limits.
    pub limits: MessageLimits,
    /// How long a connection may go without receiving anything.
    pub idle_timeout: Duration,
    /// How many connections a listener keeps open at once.
    pub max_connections: usize,
    /// Outstanding writes through local completion on one connection.
    pub write_limits: WriteLimits,
}

impl Default for Config {
    /// Default limits, a five minute idle timeout, 1024 connections, and a
    /// write queue of 64 messages.
    ///
    /// The idle timeout outlasts the 120 seconds RFC 5626 section 4.4.1 gives
    /// a client between keepalives, with room for a missed one.
    fn default() -> Config {
        Config {
            limits: MessageLimits::default(),
            idle_timeout: Duration::from_secs(300),
            max_connections: 1024,
            write_limits: WriteLimits::default(),
        }
    }
}

/// A message received on a connection, with how to answer it.
#[derive(Debug)]
pub struct Inbound {
    /// The message, or `None` once this connection has closed.
    pub message: Option<Message<Bytes>>,
    /// The connection it arrived on.
    pub flow: Flow,
    /// The way to send on that connection.
    pub writer: Writer,
}

/// Queues messages to be written on one connection.
///
/// Cheap to clone. The connection's writer task runs as long as it can
/// write, whether or not a `Writer` exists.
#[derive(Clone, Debug)]
pub struct Writer(Arc<WriteSender>);

// Every live transaction keeps a Writer in its Link. Keep that clone one
// pointer wide, with queue and quota state allocated once per connection.
// Write permits share only the quota, never this sender. Sharing the sender
// would let queued writes keep their own queue alive.
#[derive(Debug)]
struct WriteSender {
    queue: mpsc::UnboundedSender<Write>,
    capacity: Budget,
}

/// Why a message could not be queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    /// Outstanding writes have exhausted the message count or byte budget.
    Full,
    /// The connection has ended.
    Closed,
}

impl Writer {
    /// Returns `true` if both writers send on one connection.
    pub(crate) fn same_connection(&self, other: &Writer) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Identifies the connection while this writer, or a clone of it, lives.
    /// The address can be reused once every writer of the connection drops.
    pub(crate) fn connection_id(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }

    /// Returns `true` once the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.0.queue.is_closed()
    }

    /// Queues `bytes` to be written. Returns at once.
    pub fn send(&self, bytes: Bytes) -> Result<(), SendError> {
        let permit = self.reserve(bytes.len())?;
        self.enqueue(Write::reserved(bytes, permit, None))
    }

    /// Queues a new client request without consuming protocol headroom.
    pub(crate) fn send_request(&self, bytes: Bytes) -> Result<(), SendError> {
        if self.is_closed() {
            return Err(SendError::Closed);
        }
        let permit = self
            .0
            .capacity
            .acquire_request(bytes.len())
            .ok_or(SendError::Full)?;
        self.enqueue(Write::reserved(bytes, permit, None))
    }

    /// Queues a client request with reserved protocol headroom and a receipt.
    pub(crate) fn submit_request(
        &self,
        bytes: Bytes,
    ) -> Result<Receipt, SendError> {
        if self.is_closed() {
            return Err(SendError::Closed);
        }
        let permit = self
            .0
            .capacity
            .acquire_request(bytes.len())
            .ok_or(SendError::Full)?;
        let (done, result) = oneshot::channel();
        self.enqueue(Write::reserved(bytes, permit, Some(done)))?;
        Ok(Receipt(result))
    }

    /// Reserves output before the endpoint changes a server machine.
    pub(crate) fn prepare(
        &self,
        bytes: Bytes,
    ) -> Result<PreparedWrite, SendError> {
        let permit = self.reserve(bytes.len())?;
        Ok(PreparedWrite { writer: self.clone(), bytes, permit })
    }

    /// Queues a write and returns its local completion receipt.
    ///
    /// Successful enqueue commits the write. Dropping the receipt does not
    /// cancel it. The receipt succeeds once all bytes have been written to
    /// the local stream, without promising peer receipt. An error can follow
    /// a partial write. Connection teardown fails outstanding receipts.
    #[allow(dead_code)] // Used by the reply-route integration.
    pub fn submit(&self, bytes: Bytes) -> Result<Receipt, SendError> {
        let permit = self.reserve(bytes.len())?;
        let (done, result) = oneshot::channel();
        self.enqueue(Write::reserved(bytes, permit, Some(done)))?;
        Ok(Receipt(result))
    }

    fn reserve(&self, bytes: usize) -> Result<Permit, SendError> {
        if self.is_closed() {
            return Err(SendError::Closed);
        }
        self.0.capacity.acquire(bytes).ok_or_else(|| {
            if self.is_closed() { SendError::Closed } else { SendError::Full }
        })
    }

    fn enqueue(&self, write: Write) -> Result<(), SendError> {
        self.0.queue.send(write).map_err(|_| SendError::Closed)
    }
}

/// A reserved write that has not yet been committed to the socket queue.
#[derive(Debug)]
pub(crate) struct PreparedWrite {
    writer: Writer,
    bytes: Bytes,
    permit: Permit,
}

impl PreparedWrite {
    pub(crate) fn submit(self) -> Result<Receipt, SendError> {
        let (done, result) = oneshot::channel();
        self.writer.enqueue(Write::reserved(
            self.bytes,
            self.permit,
            Some(done),
        ))?;
        Ok(Receipt(result))
    }
}

/// Completion of a queued local write, not acknowledgement by the peer.
#[derive(Debug)]
#[must_use = "await the receipt to observe local write completion"]
#[allow(dead_code)] // Used by the reply-route integration.
pub struct Receipt(oneshot::Receiver<io::Result<()>>);

impl Future for Receipt {
    type Output = io::Result<()>;

    fn poll(
        mut self: std::pin::Pin<&mut Receipt>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll(cx).map(|result| {
            result.unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection ended before write completion",
                ))
            })
        })
    }
}

#[derive(Debug)]
struct Write {
    // Declaration order also governs task teardown. Release the buffer and
    // quota before dropping the sender wakes the receipt's owner.
    bytes: Bytes,
    permit: Option<Permit>,
    done: Option<oneshot::Sender<io::Result<()>>>,
    /// Marks the end of the queue. See [`run_connection`].
    close: bool,
}

impl Write {
    /// A message holding its share of the connection's write capacity.
    fn reserved(
        bytes: Bytes,
        permit: Permit,
        done: Option<oneshot::Sender<io::Result<()>>>,
    ) -> Write {
        Write { bytes, permit: Some(permit), done, close: false }
    }

    /// The marker that tells the writer to close its queue once it gets here.
    /// It carries nothing and holds no reservation, and only a connection's
    /// supervisor sends one, once.
    fn close() -> Write {
        Write { bytes: Bytes::new(), permit: None, done: None, close: true }
    }

    fn complete(&mut self, result: io::Result<()>) {
        // The caller may send again from its completion waker. Release the
        // buffer and its reservation before making that next write possible.
        self.bytes = Bytes::new();
        drop(self.permit.take());
        if let Some(done) = self.done.take() {
            let _ = done.send(result);
        }
    }
}

impl From<Bytes> for Write {
    fn from(bytes: Bytes) -> Write {
        Write { bytes, done: None, permit: None, close: false }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SendError::Full => "the connection's write capacity is exhausted",
            SendError::Closed => "the connection is closed",
        })
    }
}

impl std::error::Error for SendError {}

/// Accepts connections and starts their tasks.
#[derive(Debug)]
pub struct Listener {
    inner: TcpListener,
    local: SocketAddr,
    config: Config,
    permits: Arc<Semaphore>,
    inbound: mpsc::Sender<Inbound>,
    teardown: Teardown,
}

impl Listener {
    /// Binds a listener to `addr`. Accepted connections deliver their messages
    /// to `inbound`.
    ///
    /// Must be called from within a tokio runtime, since the listener
    /// registers with its reactor. The listener and its connections belong to
    /// no endpoint, so only the closing of `inbound` stops them.
    #[cfg(any(test, feature = "__bench"))]
    pub fn bind(
        addr: SocketAddr,
        config: Config,
        inbound: mpsc::Sender<Inbound>,
    ) -> io::Result<Listener> {
        Listener::bind_owned(addr, config, inbound, Teardown::detached())
    }

    /// Binds a listener whose task and connections belong to the owner of
    /// `teardown`.
    pub(crate) fn bind_owned(
        addr: SocketAddr,
        config: Config,
        inbound: mpsc::Sender<Inbound>,
        teardown: Teardown,
    ) -> io::Result<Listener> {
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let inner = TcpListener::from_std(listener)?;
        let permits = Arc::new(Semaphore::new(
            config.max_connections.min(Semaphore::MAX_PERMITS),
        ));

        Ok(Listener { inner, local, config, permits, inbound, teardown })
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Accepts the next connection, starts its tasks, and returns its flow.
    ///
    /// Waits for a connection to end first when `max_connections` are open.
    /// Meanwhile new connections wait in the OS backlog, which costs nothing
    /// here and lets a peer that gives up go elsewhere.
    pub async fn accept(&self) -> io::Result<Flow> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let (stream, remote) = self.inner.accept().await?;
        let local = stream.local_addr()?;
        let flow = Flow { transport: Transport::Tcp, local, remote };

        start(
            stream,
            flow,
            Role::Server,
            &self.config,
            &self.inbound,
            permit,
            &self.teardown,
        )?;

        Ok(flow)
    }

    /// Accepts connections until the receiver of `inbound` is gone or the
    /// owner reaches `Phase::Closing`, which is how the endpoint ends.
    ///
    /// An accept error is usually the process being out of descriptors. The
    /// loop waits a moment and tries again, as hyper does, rather than ending
    /// the listener over it.
    pub async fn run(self) {
        let mut teardown = self.teardown.clone();
        let mut closing = pin!(teardown.reached(Phase::Closing));
        let mut closed = pin!(self.inbound.closed());
        loop {
            let mut accept = pin!(self.accept());
            let accepted = poll_fn(|cx| {
                if closing.as_mut().poll(cx).is_ready()
                    || closed.as_mut().poll(cx).is_ready()
                {
                    return Poll::Ready(None);
                }
                accept.as_mut().poll(cx).map(Some)
            })
            .await;
            match accepted {
                None => return,
                Some(Ok(_)) => {}
                Some(Err(_)) => sleep(Duration::from_millis(100)).await,
            }
        }
    }
}

/// Opens a connection to `remote` and starts its tasks. Messages received on
/// it go to `inbound`, and the returned `Writer` sends on it.
#[cfg(any(test, feature = "__bench"))]
pub async fn connect(
    remote: SocketAddr,
    config: &Config,
    inbound: &mpsc::Sender<Inbound>,
) -> io::Result<(Flow, Writer)> {
    connect_reserved(remote, config, inbound, None, &Teardown::detached())
        .await
}

/// Opens a connection with a reservation held through reader and writer exit.
/// Its tasks belong to the owner of `teardown`.
pub(crate) async fn connect_reserved(
    remote: SocketAddr,
    config: &Config,
    inbound: &mpsc::Sender<Inbound>,
    permit: Option<OwnedSemaphorePermit>,
    teardown: &Teardown,
) -> io::Result<(Flow, Writer)> {
    let stream = TcpStream::connect(remote).await?;
    let local = stream.local_addr()?;
    let flow = Flow { transport: Transport::Tcp, local, remote };
    let writer =
        start(stream, flow, Role::Client, config, inbound, permit, teardown)?;

    Ok((flow, writer))
}

/// Starts the reader and writer tasks of one connection.
///
/// `permit` is the admission slot for the connection. It is released when the
/// reader and writer have both ended, including drain and abort completion.
/// The supervisor holds a clone of `teardown` until both have ended.
fn start(
    stream: TcpStream,
    flow: Flow,
    role: Role,
    config: &Config,
    inbound: &mpsc::Sender<Inbound>,
    permit: impl Into<Option<OwnedSemaphorePermit>>,
    teardown: &Teardown,
) -> io::Result<Writer> {
    // SIP messages are small and each one is a round trip, so coalescing only
    // adds latency.
    stream.set_nodelay(true)?;
    let (read, write) = stream.into_split();
    // The reservation bounds both this queue and the writer's active batch.
    let (queue, pending) = mpsc::unbounded_channel();
    let writer = Writer(Arc::new(WriteSender {
        queue,
        capacity: Budget::new(config.write_limits),
    }));
    let permit = Arc::new(permit.into());
    let writer_permit = permit.clone();
    // The writer holds no `Teardown` of its own, so its path from queue to
    // socket never touches the owner's phase channel. Its supervisor tells it
    // to close through the queue, waits for it, which keeps it within the
    // owner's join, and aborts it at `Phase::Abort`.
    let writing = tokio::spawn(async move {
        write_loop(write, pending).await;
        drop(writer_permit);
    });
    let reading = read_loop(
        read,
        flow,
        role,
        config.limits,
        config.idle_timeout,
        inbound.clone(),
        writer.clone(),
    );

    // After the connection ends, one message without content tells the
    // endpoint which writer closed, unless every writer is already gone.
    // The notice holds the connection permit, so connection admission bounds
    // pending notices.
    let closed_writer = Arc::downgrade(&writer.0);
    let closed_inbound = inbound.clone();
    let closed_permit = permit.clone();
    let output = writer.0.capacity.clone();
    let mut supervisor = teardown.clone();
    tokio::spawn(async move {
        let queue = closed_writer.clone();
        run_connection(
            reading,
            writing,
            permit,
            &mut supervisor,
            queue,
            output,
        )
        .await;
        if let Some(writer) = closed_writer.upgrade() {
            let _ = closed_inbound
                .send(Inbound { message: None, flow, writer: Writer(writer) })
                .await;
        }
        drop(closed_permit);
        drop(supervisor);
    });

    Ok(writer)
}

/// Owns connection teardown and keeps admission charged until both halves end.
///
/// The reader ends with [`End::Endpoint`] when the endpoint closes its channel,
/// which it does once it is stopping. The supervisor then has the writer close
/// its queue and finish it, and aborts the writer at [`Phase::Abort`]. If
/// `output` still has reservations out then, the discard is recorded.
async fn run_connection(
    reading: impl Future<Output = End>,
    mut writing: JoinHandle<()>,
    permit: Arc<Option<OwnedSemaphorePermit>>,
    teardown: &mut Teardown,
    queue: Weak<WriteSender>,
    output: Budget,
) {
    let end = {
        let mut reading = pin!(reading);
        poll_fn(|cx| {
            // A failed writer cannot serve this connection any more. Check
            // it even when the reader is blocked on a full inbound channel.
            if std::pin::Pin::new(&mut writing).poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            reading.as_mut().poll(cx).map(Some)
        })
        .await
    };
    // Drop the reader, including its socket half and pending inbound send,
    // before releasing admission or waiting for the writer to drain.
    match end {
        None => {}
        // The connection is over. A write still in flight is lost, which
        // is no worse than the peer having gone away.
        Some(End::Peer) => {
            writing.abort();
            let _ = writing.await;
        }
        // Dropping the reader above released its Writer. The marker closes
        // the queue once the writer reaches it, so no Writer the application
        // still holds keeps it open. With every Writer gone, the queue is
        // closed already.
        Some(End::Endpoint) => {
            if let Some(sender) = queue.upgrade() {
                let _ = sender.queue.send(Write::close());
            }
            let finished = if teardown.phase() == Phase::Running {
                // Only a connection opened without an endpoint sees its
                // channel close while its owner runs. Nothing will abort it,
                // so it gets a few seconds.
                timeout(UNOWNED_DRAIN, &mut writing).await.is_ok()
            } else {
                let mut abort = pin!(teardown.reached(Phase::Abort));
                poll_fn(|cx| {
                    if std::pin::Pin::new(&mut writing).poll(cx).is_ready() {
                        return Poll::Ready(true);
                    }
                    abort.as_mut().poll(cx).map(|()| false)
                })
                .await
            };
            if !finished {
                // A running writer may have nothing left, such as one that
                // has not reached the close marker yet. Every queued write
                // holds a reservation until it completes, so only a writer
                // with reservations out drops anything.
                if !output.is_idle() {
                    teardown.discard();
                }
                writing.abort();
                let _ = writing.await;
            }
        }
    }
    drop(permit);
}

/// Why the reader ended.
enum End {
    /// EOF, a read error, the idle timeout, or a bad message.
    Peer,
    /// The endpoint is gone.
    Endpoint,
}

/// Reads and frames the stream until the connection ends.
async fn read_loop(
    mut read: OwnedReadHalf,
    flow: Flow,
    role: Role,
    limits: MessageLimits,
    idle_timeout: Duration,
    inbound: mpsc::Sender<Inbound>,
    writer: Writer,
) -> End {
    let mut decoder = Decoder::new(role, limits);
    let mut buf = BytesMut::with_capacity(READ_SIZE);
    // Resolves when the endpoint drops its receiver, so an idle connection
    // closes with the endpoint instead of at the idle timeout.
    let mut closed = pin!(inbound.closed());
    loop {
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(Frame::Message(message))) => {
                    let writer = writer.clone();
                    let inbound_message =
                        Inbound { message: Some(message), flow, writer };
                    if inbound.send(inbound_message).await.is_err() {
                        return End::Endpoint;
                    }
                }
                Ok(Some(Frame::Ping)) => {
                    // A pong that does not fit in the queue is dropped. The
                    // peer pings again, and a full queue means the connection
                    // is in trouble anyway.
                    let _ = writer.send(PONG);
                }
                // TODO: Hand pongs to the client's keepalive policy, which
                // comes with RFC 5626 flows.
                Ok(Some(Frame::Pong)) => {}
                Ok(None) => break,
                // The stream has no way to find the next message after a bad
                // one, so the connection closes (RFC 3261 section 18.3).
                Err(_) => return End::Peer,
            }
        }

        buf.reserve(READ_SIZE);

        let mut read = pin!(timeout(idle_timeout, read.read_buf(&mut buf)));
        let read = poll_fn(|cx| {
            if closed.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            read.as_mut().poll(cx).map(Some)
        })
        .await;
        match read {
            None => return End::Endpoint,
            Some(Ok(Ok(n))) if n > 0 => {}
            // EOF, a read error, or the idle timeout.
            _ => return End::Peer,
        }
    }
}

/// Writes queued messages until the queue closes or a write fails.
///
/// A [`Write::close`] marker closes the queue, after which the writer ends
/// once the queue is written. Aborting the task drops what is unwritten, which
/// fails those receipts and returns their reservations.
async fn write_loop(
    mut write: impl AsyncWrite + Unpin,
    mut pending: mpsc::UnboundedReceiver<Write>,
) {
    let mut queue = Queue::default();
    while pending.recv_many(&mut queue.items, WRITE_BATCH).await > 0 {
        let mut close = false;
        queue.remaining = 0;
        for item in &queue.items {
            queue.remaining += item.bytes.len();
            close |= item.close;
        }
        if close {
            pending.close();
        }
        // An empty write at the head is already complete, including when
        // the following nonempty write fails before making progress.
        queue.advance(0);
        let written = write.write_all_buf(&mut queue).await;
        if let Err(error) = written {
            // Stop admission before draining failures. Fully written messages
            // already completed in advance(), even if this batch later fails.
            pending.close();
            let kind = error.kind();
            let source = Arc::new(error);
            for item in &mut queue.items {
                item.complete(Err(io::Error::new(kind, source.clone())));
            }
            while let Some(mut item) = pending.recv().await {
                item.complete(Err(io::Error::new(kind, source.clone())));
            }
            return;
        }
        for item in &mut queue.items {
            item.complete(Ok(()));
        }
        queue.items.clear();
        queue.next = 0;
    }
}

/// The messages of one write, as one `Buf` so that `write_all_buf` can write
/// them with one vectored call.
#[derive(Default)]
struct Queue {
    items: Vec<Write>,
    /// The first item not fully written.
    next: usize,
    /// The bytes left over all items.
    remaining: usize,
}

impl Buf for Queue {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.items.get(self.next).map_or(&[], |item| &item.bytes)
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [io::IoSlice<'a>]) -> usize {
        let items = self.items[self.next..].iter();
        let mut n = 0;
        for (slot, item) in dst.iter_mut().zip(items) {
            *slot = io::IoSlice::new(&item.bytes);
            n += 1;
        }

        n
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining, "advanced past the end of the queue");

        self.remaining -= cnt;
        while self.next < self.items.len()
            && (cnt > 0 || self.items[self.next].bytes.is_empty())
        {
            let item = &mut self.items[self.next];
            if cnt < item.bytes.len() {
                item.bytes.advance(cnt);
                return;
            }
            cnt -= item.bytes.len();
            item.complete(Ok(()));
            self.next += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::{io::sink, net::TcpStream, task::yield_now, time::sleep};

    use super::*;
    use crate::message::{Method, StatusCode};

    fn test_writer(
        messages: usize,
        bytes: usize,
    ) -> (Writer, mpsc::UnboundedReceiver<Write>) {
        let (queue, pending) = mpsc::unbounded_channel();
        (
            Writer(Arc::new(WriteSender {
                queue,
                capacity: Budget::new(WriteLimits { messages, bytes }),
            })),
            pending,
        )
    }

    struct FailsAfter(usize);

    impl AsyncWrite for FailsAfter {
        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            mut self: std::pin::Pin<&mut FailsAfter>,
            _: &mut std::task::Context<'_>,
            buffers: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            if self.0 == 0 {
                return Poll::Ready(Err(io::Error::from_raw_os_error(5)));
            }

            let n = buffers
                .iter()
                .map(|buffer| buffer.len())
                .sum::<usize>()
                .min(self.0);
            self.0 -= n;

            Poll::Ready(Ok(n))
        }

        fn poll_write(
            mut self: std::pin::Pin<&mut FailsAfter>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.0 == 0 {
                return Poll::Ready(Err(io::Error::from_raw_os_error(5)));
            }
            let n = bytes.len().min(self.0);
            self.0 -= n;

            Poll::Ready(Ok(n))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut FailsAfter>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut FailsAfter>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Takes no bytes, and tells when it was first polled.
    struct Stalled(Option<oneshot::Sender<()>>);

    impl AsyncWrite for Stalled {
        fn poll_write(
            mut self: std::pin::Pin<&mut Stalled>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(started) = self.0.take() {
                let _ = started.send(());
            }
            Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Stalled>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Stalled>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    // The async receipt tests build runtimes without an I/O driver to run
    // under Miri. #[tokio::test] initializes kqueue, which Miri does not
    // support. Channels and mock writers need no I/O driver.

    #[test]
    fn new_requests_leave_output_capacity_for_protocol_messages() {
        let (writer, mut pending) = test_writer(4, 8);
        writer.send_request(Bytes::from_static(b"123456")).unwrap();
        assert_eq!(
            writer.send_request(Bytes::from_static(b"7")),
            Err(SendError::Full)
        );
        writer.send(Bytes::from_static(b"78")).unwrap();
        assert_eq!(
            writer.send(Bytes::from_static(b"9")),
            Err(SendError::Full)
        );
        drop(pending.try_recv().unwrap());
        drop(pending.try_recv().unwrap());
        for _ in 0..3 {
            writer.send_request(Bytes::new()).unwrap();
        }
        assert_eq!(writer.send_request(Bytes::new()), Err(SendError::Full));
        writer.send(Bytes::new()).unwrap();
    }

    // An application can hold a `Writer` in a reply route for as long as it
    // likes. Closing still ends the connection once the queue is written, and
    // the connection keeps its reservation until then.
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn closing_writes_the_queue_and_ends_the_connection() {
        let tasks = Tasks::new();
        let (tx, rx) = mpsc::channel(1);
        let listener = TcpListener::bind(LOCALHOST).await.unwrap();
        let permits = Arc::new(Semaphore::new(1));
        let permit = permits.clone().try_acquire_owned().unwrap();
        let (_, writer) = connect_reserved(
            listener.local_addr().unwrap(),
            &Config::default(),
            &tx,
            Some(permit),
            &tasks.handle(),
        )
        .await
        .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();

        let receipt = writer.submit(Bytes::from_static(RESPONSE)).unwrap();
        tasks.advance(Phase::Closing);
        drop(rx);

        receipt.await.unwrap();
        assert_eq!(read_all(&mut peer).await, RESPONSE);
        timeout(Duration::from_secs(1), tasks.finished()).await.unwrap();
        assert_eq!(permits.available_permits(), 1);
        assert!(writer.is_closed());
        assert_eq!(writer.send(Bytes::new()), Err(SendError::Closed));
        assert!(!tasks.discarded());
    }

    /// A writer that stalls on its first write, under the supervisor of a
    /// connection whose endpoint has already closed its channel.
    fn stalled_connection(
        tasks: &Tasks,
        messages: usize,
        bytes: usize,
    ) -> (Writer, Receipt, oneshot::Receiver<()>, JoinHandle<()>) {
        let (writer, pending) = test_writer(messages, bytes);
        let (started, waiting) = oneshot::channel();
        let stalled = writer.submit(Bytes::from_static(b"abc")).unwrap();
        let writing =
            tokio::spawn(write_loop(Stalled(Some(started)), pending));
        let mut teardown = tasks.handle();
        let queue = Arc::downgrade(&writer.0);
        let output = writer.0.capacity.clone();
        let supervisor = tokio::spawn(async move {
            run_connection(
                std::future::ready(End::Endpoint),
                writing,
                Arc::new(None),
                &mut teardown,
                queue,
                output,
            )
            .await;
        });

        (writer, stalled, waiting, supervisor)
    }

    // The owner's deadline is the only bound on a writer the peer does not
    // read from. Closing waits for it, and aborting drops what is left.
    #[test]
    fn abort_stops_a_stalled_writer_and_fails_its_receipts() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let tasks = Tasks::new();
                tasks.advance(Phase::Closing);
                let (writer, stalled, waiting, supervisor) =
                    stalled_connection(&tasks, 2, 6);
                waiting.await.unwrap();
                yield_now().await;

                assert!(!supervisor.is_finished());
                let queued =
                    writer.submit(Bytes::from_static(b"def")).unwrap();

                tasks.advance(Phase::Abort);
                tasks.finished().await;
                supervisor.await.unwrap();

                assert!(stalled.await.is_err());
                assert!(queued.await.is_err());
                assert!(writer.is_closed());
                assert!(writer.0.capacity.acquire(6).is_some());
                assert!(tasks.discarded());
            });
    }

    // A deadline can reach a connection whose writer has nothing left but
    // has not yet run to its close marker. Aborting that writer drops
    // nothing, so it is not recorded as discarded output.
    #[test]
    fn abort_of_a_writer_with_nothing_left_discards_nothing() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let tasks = Tasks::new();
                let (writer, pending) = test_writer(4, 64);
                let writing = tokio::spawn(write_loop(sink(), pending));
                writer
                    .submit(Bytes::from_static(b"abc"))
                    .unwrap()
                    .await
                    .unwrap();
                let mut teardown = tasks.handle();
                let queue = Arc::downgrade(&writer.0);
                let output = writer.0.capacity.clone();

                tasks.advance(Phase::Abort);
                let supervisor = tokio::spawn(async move {
                    run_connection(
                        std::future::ready(End::Endpoint),
                        writing,
                        Arc::new(None),
                        &mut teardown,
                        queue,
                        output,
                    )
                    .await;
                });
                tasks.finished().await;
                supervisor.await.unwrap();

                assert!(!tasks.discarded());
                assert_eq!(writer.send(Bytes::new()), Err(SendError::Closed));
            });
    }

    // A writer whose owner is gone without a phase, such as an endpoint task
    // its runtime dropped, stops as if aborted.
    #[test]
    fn a_vanished_owner_aborts_the_writer() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let tasks = Tasks::new();
                tasks.advance(Phase::Closing);
                let (writer, stalled, waiting, supervisor) =
                    stalled_connection(&tasks, 1, 3);
                waiting.await.unwrap();

                drop(tasks);
                supervisor.await.unwrap();

                assert!(stalled.await.is_err());
                assert!(writer.0.capacity.acquire(3).is_some());
            });
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn closing_stops_a_listener_waiting_to_accept() {
        let tasks = Tasks::new();
        let (tx, _rx) = mpsc::channel(1);
        let listener =
            Listener::bind_owned(LOCALHOST, config(), tx, tasks.handle())
                .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());
        yield_now().await;

        tasks.advance(Phase::Closing);

        timeout(Duration::from_secs(1), tasks.finished()).await.unwrap();
        assert!(TcpStream::connect(addr).await.is_err());
    }

    // The reader waits for room in the endpoint's channel. Closing that
    // channel ends the wait, so a peer that keeps sending cannot hold the
    // endpoint's teardown.
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_reader_held_by_backpressure_ends_with_the_channel() {
        let tasks = Tasks::new();
        let (tx, mut rx) = mpsc::channel(1);
        let listener = Listener::bind_owned(
            LOCALHOST,
            config(),
            tx.clone(),
            tasks.handle(),
        )
        .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());
        let mut client = TcpStream::connect(addr).await.unwrap();
        for _ in 0..3 {
            client.write_all(REQUEST).await.unwrap();
        }
        assert!(rx.recv().await.unwrap().message.is_some());
        // The channel holds one message, and the reader waits to send the
        // third.
        sleep(Duration::from_millis(50)).await;

        tasks.advance(Phase::Closing);
        rx.close();

        timeout(Duration::from_secs(1), tasks.finished()).await.unwrap();
        assert!(read_all(&mut client).await.is_empty());
        drop(tx);
    }

    #[test]
    fn writer_failure_cancels_idle_and_backpressured_readers() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ReaderGuard(Arc<AtomicBool>);

        impl Drop for ReaderGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                for backpressured in [false, true] {
                    let slots = Arc::new(Semaphore::new(1));
                    let permit = Arc::new(Some(
                        slots.clone().try_acquire_owned().unwrap(),
                    ));
                    let dropped = Arc::new(AtomicBool::new(false));
                    let guard = ReaderGuard(dropped.clone());
                    let (started, ready) = oneshot::channel();
                    let (inbound, mut receiver) = mpsc::channel(1);
                    inbound.send(()).await.unwrap();
                    let reading = async move {
                        let _guard = guard;
                        started.send(()).unwrap();
                        if backpressured {
                            inbound.send(()).await.unwrap();
                        } else {
                            std::future::pending::<()>().await;
                        }
                        End::Peer
                    };
                    let (writer, pending) = test_writer(2, 6);
                    let writer_permit = permit.clone();
                    let writing = tokio::spawn(async move {
                        write_loop(FailsAfter(1), pending).await;
                        drop(writer_permit);
                    });
                    let output = writer.0.capacity.clone();
                    let connection = tokio::spawn(async move {
                        let mut teardown = Teardown::detached();
                        run_connection(
                            reading,
                            writing,
                            permit,
                            &mut teardown,
                            Weak::new(),
                            output,
                        )
                        .await;
                    });
                    ready.await.unwrap();
                    assert_eq!(slots.available_permits(), 0);
                    let partial =
                        writer.submit(Bytes::from_static(b"abc")).unwrap();
                    let queued =
                        writer.submit(Bytes::from_static(b"def")).unwrap();

                    assert!(partial.await.is_err());
                    assert!(queued.await.is_err());
                    timeout(Duration::from_secs(1), connection)
                        .await
                        .expect("writer failure must end the reader")
                        .unwrap();

                    assert!(dropped.load(Ordering::SeqCst));
                    assert!(writer.is_closed());
                    assert_eq!(slots.available_permits(), 1);
                    assert!(writer.0.capacity.acquire(6).is_some());
                    assert_eq!(receiver.recv().await, Some(()));
                    assert_eq!(receiver.recv().await, None);
                }
            });
    }

    #[test]
    fn prepared_response_writes_reserve_before_enqueue_and_return_on_abort() {
        let (writer, mut pending) = test_writer(1, 3);
        let prepared = writer.prepare(Bytes::from_static(b"abc")).unwrap();

        assert!(pending.is_empty());
        assert_eq!(writer.send(Bytes::new()), Err(SendError::Full));
        drop(prepared);
        assert!(writer.0.capacity.acquire(3).is_some());

        let prepared = writer.prepare(Bytes::from_static(b"abc")).unwrap();
        let receipt = prepared.submit().unwrap();

        assert_eq!(writer.send(Bytes::new()), Err(SendError::Full));
        drop(pending.try_recv().unwrap());
        assert!(writer.0.capacity.acquire(3).is_some());
        drop(receipt);

        let prepared = writer.prepare(Bytes::from_static(b"abc")).unwrap();
        drop(pending);

        assert_eq!(prepared.submit().unwrap_err(), SendError::Closed);
        assert!(writer.0.capacity.acquire(3).is_some());
    }

    #[test]
    fn receipts_distinguish_complete_partial_and_unwritten_messages() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (writer, pending) =
                    test_writer(WRITE_BATCH + 3, usize::MAX);
                let complete =
                    writer.submit(Bytes::from_static(b"abc")).unwrap();
                let partial =
                    writer.submit(Bytes::from_static(b"def")).unwrap();
                // Include messages outside recv_many's first batch.
                let mut failures = vec![partial];
                for _ in 0..WRITE_BATCH + 1 {
                    failures.push(
                        writer.submit(Bytes::from_static(b"ghi")).unwrap(),
                    );
                }
                write_loop(FailsAfter(5), pending).await;
                complete.await.unwrap();
                for receipt in failures {
                    let error = receipt.await.unwrap_err();
                    let source = error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<Arc<io::Error>>()
                        .unwrap();
                    assert_eq!(source.raw_os_error(), Some(5));
                }

                assert!(writer.is_closed());
            });
    }

    #[test]
    fn empty_writes_complete_before_a_later_write_failure() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (writer, pending) = test_writer(3, usize::MAX);
                let empty = writer.submit(Bytes::new()).unwrap();
                let complete =
                    writer.submit(Bytes::from_static(b"abc")).unwrap();
                let trailing = writer.submit(Bytes::new()).unwrap();

                drop(writer);

                write_loop(FailsAfter(3), pending).await;
                empty.await.unwrap();
                complete.await.unwrap();
                trailing.await.unwrap();

                let (writer, pending) = test_writer(2, usize::MAX);
                let empty = writer.submit(Bytes::new()).unwrap();
                let failure =
                    writer.submit(Bytes::from_static(b"abc")).unwrap();
                write_loop(FailsAfter(0), pending).await;
                empty.await.unwrap();

                assert!(failure.await.is_err());
            });
    }

    #[test]
    fn dropping_a_receipt_does_not_cancel_the_write() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (writer, pending) = test_writer(2, usize::MAX);

                drop(writer.submit(Bytes::from_static(b"abc")).unwrap());

                let receipt =
                    writer.submit(Bytes::from_static(b"def")).unwrap();

                drop(writer);

                let mut output = Vec::new();
                write_loop(&mut output, pending).await;
                receipt.await.unwrap();

                assert_eq!(output, b"abcdef");
            });
    }

    #[test]
    fn admission_and_connection_loss_are_distinct() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (writer, pending) = test_writer(1, usize::MAX);
                let receipt =
                    writer.submit(Bytes::from_static(b"abc")).unwrap();
                assert_eq!(
                    writer.submit(Bytes::new()).unwrap_err(),
                    SendError::Full
                );

                drop(pending);

                assert_eq!(
                    receipt.await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                assert_eq!(
                    writer.submit(Bytes::new()).unwrap_err(),
                    SendError::Closed
                );
            });
    }

    #[test]
    fn batch_and_partial_writes_keep_both_reservations() {
        let (writer, mut pending) = test_writer(2, 3);
        assert_eq!(
            writer.send(Bytes::from_static(b"long")).unwrap_err(),
            SendError::Full
        );
        drop(writer.submit(Bytes::from_static(b"abc")).unwrap());
        drop(writer.submit(Bytes::new()).unwrap());
        let mut batch = Queue {
            items: vec![
                pending.try_recv().unwrap(),
                pending.try_recv().unwrap(),
            ],
            remaining: 3,
            next: 0,
        };

        assert!(pending.is_empty());
        assert_eq!(writer.send(Bytes::new()).unwrap_err(), SendError::Full);
        batch.advance(2);
        assert_eq!(
            writer.send(Bytes::from_static(b"a")).unwrap_err(),
            SendError::Full
        );
        batch.advance(1);

        // Completion also passes the trailing empty write. Keeping the batch
        // vector alive must retain neither buffers nor reservations.
        assert!(batch.items.iter().all(|item| item.bytes.is_empty()));
        assert!(writer.send(Bytes::from_static(b"abc")).is_ok());
        assert!(writer.send(Bytes::new()).is_ok());
    }

    #[test]
    fn completion_and_teardown_return_capacity_before_waking_the_next_writer()
    {
        use std::{
            sync::atomic::{AtomicBool, Ordering},
            task::{Context, Wake, Waker},
        };

        struct SendNext(Writer, AtomicBool);

        impl Wake for SendNext {
            fn wake(self: Arc<SendNext>) {
                self.1.store(
                    self.0.send(Bytes::from_static(b"next")).is_ok(),
                    Ordering::Relaxed,
                );
            }
        }

        for complete in [true, false] {
            let (writer, mut pending) = test_writer(1, 4);
            let mut receipt =
                writer.submit(Bytes::from_static(b"done")).unwrap();
            let next = Arc::new(SendNext(writer, AtomicBool::new(false)));
            let waker: Waker = next.clone().into();
            assert!(
                std::pin::Pin::new(&mut receipt)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let mut batch = Queue {
                items: vec![pending.try_recv().unwrap()],
                remaining: 4,
                next: 0,
            };

            if complete {
                batch.advance(4);
            } else {
                drop(batch);
            }

            assert!(next.1.load(Ordering::Relaxed));
            assert_eq!(pending.try_recv().unwrap().bytes, "next");
        }
    }

    #[test]
    fn failed_and_aborted_writes_return_their_full_budget() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (writer, pending) = test_writer(1, 3);
                let failed =
                    writer.submit(Bytes::from_static(b"abc")).unwrap();
                write_loop(FailsAfter(1), pending).await;

                assert!(failed.await.is_err());
                assert!(writer.0.capacity.acquire(3).is_some());

                let (writer, pending) = test_writer(1, 3);
                let (started, waiting) = oneshot::channel();
                let aborted =
                    writer.submit(Bytes::from_static(b"abc")).unwrap();
                let task =
                    tokio::spawn(write_loop(Stalled(Some(started)), pending));
                waiting.await.unwrap();
                assert!(writer.0.capacity.acquire(0).is_none());

                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());

                assert!(aborted.await.is_err());
                assert!(writer.0.capacity.acquire(3).is_some());
            });
    }

    const LOCALHOST: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    const REQUEST: &[u8] = b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
        Via: SIP/2.0/TCP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
        Max-Forwards: 70\r\n\
        To: <sip:carol@chicago.example.com>\r\n\
        From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 63104 OPTIONS\r\n\
        Content-Length: 0\r\n\
        \r\n";

    const RESPONSE: &[u8] = b"SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/TCP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
        To: <sip:carol@chicago.example.com>;tag=93810874\r\n\
        From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 63104 OPTIONS\r\n\
        Content-Length: 0\r\n\
        \r\n";

    fn config() -> Config {
        Config {
            idle_timeout: Duration::from_millis(200),
            ..Config::default()
        }
    }

    /// A listener whose accepted connections feed the returned receiver, with
    /// a task accepting them.
    fn listen(config: Config) -> (SocketAddr, mpsc::Receiver<Inbound>) {
        let (tx, rx) = mpsc::channel(4);
        let listener = Listener::bind(LOCALHOST, config, tx).unwrap();
        let addr = listener.local_addr();

        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        (addr, rx)
    }

    async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();

        out
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_request_arrives_and_its_response_goes_back() {
        let (addr, mut rx) = listen(config());
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        let inbound = rx.recv().await.unwrap();
        let Some(Message::Request(request)) = &inbound.message else {
            panic!("expected a request");
        };
        assert_eq!(request.method(), Method::OPTIONS);
        assert_eq!(inbound.flow.transport, Transport::Tcp);
        assert_eq!(inbound.flow.local, addr);
        assert_eq!(inbound.flow.remote, client.local_addr().unwrap());

        inbound.writer.send(Bytes::from_static(RESPONSE)).unwrap();
        let mut out = vec![0; RESPONSE.len()];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(out, RESPONSE);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_fragmented_request_is_put_together() {
        let (addr, mut rx) = listen(config());
        let mut client = TcpStream::connect(addr).await.unwrap();

        let (head, rest) = REQUEST.split_at(40);
        client.write_all(head).await.unwrap();
        sleep(Duration::from_millis(20)).await;
        client.write_all(rest).await.unwrap();

        let inbound = rx.recv().await.unwrap();
        assert!(matches!(inbound.message, Some(Message::Request(_))));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn queued_messages_are_written_in_order() {
        let (addr, mut rx) = listen(config());
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        let inbound = rx.recv().await.unwrap();
        for _ in 0..3 {
            inbound.writer.send(Bytes::from_static(RESPONSE)).unwrap();
        }
        let mut out = vec![0; RESPONSE.len() * 3];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(out, [RESPONSE, RESPONSE, RESPONSE].concat());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_ping_is_answered_with_a_pong() {
        let (addr, _rx) = listen(config());
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(b"\r\n\r\n").await.unwrap();
        let mut out = [0; 2];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"\r\n");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn an_idle_connection_is_closed() {
        let (addr, _rx) = listen(config());
        let mut client = TcpStream::connect(addr).await.unwrap();

        // The server closes after the idle timeout, so the read ends.
        assert!(read_all(&mut client).await.is_empty());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_bad_message_closes_the_connection() {
        let (addr, mut rx) = listen(Config {
            idle_timeout: Duration::from_secs(10),
            ..Config::default()
        });
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(b"not sip\r\n\r\n").await.unwrap();
        assert!(read_all(&mut client).await.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn the_writer_reports_a_closed_connection() {
        let (addr, mut rx) = listen(config());
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(REQUEST).await.unwrap();
        let inbound = rx.recv().await.unwrap();

        drop(client);

        // The reader sees EOF and ends the writer. Give it a moment.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match inbound.writer.send(Bytes::from_static(RESPONSE)) {
                Err(SendError::Closed) => break,
                Ok(()) if tokio::time::Instant::now() < deadline => {
                    sleep(Duration::from_millis(10)).await;
                }
                other => panic!("unexpected result {other:?}"),
            }
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn the_connection_limit_holds_the_backlog() {
        let (addr, mut rx) = listen(Config { max_connections: 1, ..config() });
        let mut first = TcpStream::connect(addr).await.unwrap();
        first.write_all(REQUEST).await.unwrap();
        let _ = rx.recv().await.unwrap();

        // The second connection completes in the OS, but nobody reads it until
        // the first ends.
        let mut second = TcpStream::connect(addr).await.unwrap();
        second.write_all(REQUEST).await.unwrap();
        let waited = timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(waited.is_err());

        drop(first);

        let inbound =
            timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert_eq!(inbound.flow.remote, second.local_addr().unwrap());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_connected_client_sends_and_receives() {
        let (addr, mut server_rx) = listen(config());
        let (client_tx, mut client_rx) = mpsc::channel(4);
        let (flow, writer) =
            connect(addr, &config(), &client_tx).await.unwrap();
        assert_eq!(flow.remote, addr);

        writer.send(Bytes::from_static(REQUEST)).unwrap();
        let inbound = server_rx.recv().await.unwrap();
        assert_eq!(inbound.flow.remote, flow.local);
        inbound.writer.send(Bytes::from_static(RESPONSE)).unwrap();

        let inbound = client_rx.recv().await.unwrap();
        let Some(Message::Response(response)) = &inbound.message else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(inbound.flow, flow);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn a_client_takes_a_pong_in_stride() {
        let (tx, mut rx) = mpsc::channel(4);
        let listener = std::net::TcpListener::bind(LOCALHOST).unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(listener).unwrap();

        let (_, writer) = connect(addr, &config(), &tx).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        writer.send(Bytes::from_static(b"\r\n\r\n")).unwrap();
        let mut ping = [0; 4];
        server.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"\r\n\r\n");

        // A pong, then a response. Only the response reaches the channel.
        server.write_all(b"\r\n").await.unwrap();
        server.write_all(RESPONSE).await.unwrap();
        let inbound = rx.recv().await.unwrap();
        assert!(matches!(inbound.message, Some(Message::Response(_))));
    }

    #[test]
    fn the_queue_advances_across_items() {
        fn chunks(queue: &Queue) -> Vec<Vec<u8>> {
            let mut slices = [io::IoSlice::new(&[]); 4];
            let n = queue.chunks_vectored(&mut slices);
            slices[..n].iter().map(|slice| slice.to_vec()).collect()
        }

        let mut queue = Queue {
            items: vec![
                Bytes::from_static(b"ab").into(),
                Bytes::from_static(b"cde").into(),
                Bytes::from_static(b"f").into(),
            ],
            next: 0,
            remaining: 6,
        };
        assert_eq!(
            chunks(&queue),
            [b"ab".to_vec(), b"cde".to_vec(), b"f".to_vec()]
        );

        queue.advance(1);
        assert_eq!(queue.chunk(), b"b");
        queue.advance(2);
        assert_eq!(queue.chunk(), b"de");
        assert_eq!(queue.remaining(), 3);
        assert_eq!(chunks(&queue), [b"de".to_vec(), b"f".to_vec()]);
        queue.advance(3);
        assert_eq!(queue.remaining(), 0);
        assert_eq!(queue.chunk(), b"");
        assert!(chunks(&queue).is_empty());
    }
}
