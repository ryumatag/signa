/*!
The TCP transport.

[`Listener::accept`] and [`connect`] each start a connection as two tasks. The
reader frames the stream with the [`Decoder`] and sends every message into the
channel the endpoint reads, with the connection's [`Flow`] and [`Writer`], so a
response goes back on the connection the request came on
(RFC 3261 section 18.2.2). The writer writes what [`Writer::send`] queues.

The channel to the endpoint is bounded. When the endpoint falls behind, the
reader stops reading and TCP flow control holds the peer back. The queue to the
writer is bounded too, but nothing waits for a slow peer. [`Writer::send`]
fails when the queue is full, and the endpoint decides what to do about it.

A connection ends at EOF, when nothing arrives for the idle timeout, on a
decode error, or when a write fails. Bytes left in the read buffer at EOF are
an unfinished message and are dropped. The listener holds at most
`max_connections` open and leaves the rest in the OS backlog.

A connection also ends when the endpoint is gone, which the reader sees as the
channel closing. That is how every connection closes when the endpoint stops.
The writer then finishes what is queued before the stream is dropped, since the
endpoint's last responses are in that queue.
*/

use std::{
    fmt,
    future::{poll_fn, Future},
    io,
    net::SocketAddr,
    pin::pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, TcpListener, TcpStream},
    sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
    time::{sleep, timeout},
};

use super::{
    budget::{Budget, Permit},
    framing::{Decoder, Frame, Role},
    Flow, MessageLimits, Transport, WriteLimits,
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

/// How long the writer gets to finish its queue once the endpoint is gone. A
/// peer that takes longer to read a few messages is not reading at all.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Settings for every connection a listener accepts or [`connect`] opens.
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
    /// The message.
    pub message: Message<Bytes>,
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
    /// Returns `true` once the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.0.queue.is_closed()
    }

    /// Queues `bytes` to be written. Returns at once.
    pub fn send(&self, bytes: Bytes) -> Result<(), SendError> {
        let permit = self.reserve(bytes.len())?;
        self.enqueue(Write { bytes, done: None, permit: Some(permit) })
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
        self.enqueue(Write { bytes, done: Some(done), permit: Some(permit) })?;
        Ok(Receipt(result))
    }

    fn reserve(&self, bytes: usize) -> Result<Permit, SendError> {
        if self.is_closed() {
            return Err(SendError::Closed);
        }
        self.0.capacity.acquire(bytes).ok_or_else(|| {
            if self.is_closed() {
                SendError::Closed
            } else {
                SendError::Full
            }
        })
    }

    fn enqueue(&self, write: Write) -> Result<(), SendError> {
        self.0.queue.send(write).map_err(|_| SendError::Closed)
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
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Self::Output> {
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
}

impl Write {
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
    fn from(bytes: Bytes) -> Self {
        Write { bytes, done: None, permit: None }
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
}

impl Listener {
    /// Binds a listener to `addr`. Accepted connections deliver their messages
    /// to `inbound`.
    ///
    /// Must be called from within a tokio runtime, since the listener
    /// registers with its reactor.
    pub fn bind(
        addr: SocketAddr,
        config: Config,
        inbound: mpsc::Sender<Inbound>,
    ) -> io::Result<Listener> {
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let inner = TcpListener::from_std(listener)?;
        let permits = Arc::new(Semaphore::new(config.max_connections));

        Ok(Listener { inner, local, config, permits, inbound })
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
        )?;

        Ok(flow)
    }

    /// Accepts connections until the receiver of `inbound` is gone, which is
    /// how the endpoint ends.
    ///
    /// An accept error is usually the process being out of descriptors. The
    /// loop waits a moment and tries again, as hyper does, rather than ending
    /// the listener over it.
    pub async fn run(self) {
        let mut closed = pin!(self.inbound.closed());
        loop {
            let mut accept = pin!(self.accept());
            let accepted = poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
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
pub async fn connect(
    remote: SocketAddr,
    config: &Config,
    inbound: &mpsc::Sender<Inbound>,
) -> io::Result<(Flow, Writer)> {
    let stream = TcpStream::connect(remote).await?;
    let local = stream.local_addr()?;
    let flow = Flow { transport: Transport::Tcp, local, remote };
    // The permit limits accepted connections. Opened ones are limited by
    // whoever opens them.
    let permit = None;
    let writer = start(stream, flow, Role::Client, config, inbound, permit)?;

    Ok((flow, writer))
}

/// Starts the reader and writer tasks of one connection.
///
/// `permit` is the listener's slot for the connection. It is released when the
/// reader ends, which is when the connection is over.
fn start(
    stream: TcpStream,
    flow: Flow,
    role: Role,
    config: &Config,
    inbound: &mpsc::Sender<Inbound>,
    permit: impl Into<Option<OwnedSemaphorePermit>>,
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
    let mut writing = tokio::spawn(write_loop(write, pending));
    let reading = read_loop(
        read,
        flow,
        role,
        config.limits,
        config.idle_timeout,
        inbound.clone(),
        writer.clone(),
    );
    let permit = permit.into();

    tokio::spawn(async move {
        match reading.await {
            // The connection is over. A write still in flight is lost, which
            // is no worse than the peer having gone away.
            End::Peer => writing.abort(),
            // The endpoint stopped. What it queued last, such as the final
            // responses before a shutdown, still goes out. The queue closes
            // with the endpoint's last `Writer`, and the writer ends with it.
            End::Endpoint => {
                if timeout(DRAIN_TIMEOUT, &mut writing).await.is_err() {
                    writing.abort();
                }
            }
        }
        drop(permit);
    });

    Ok(writer)
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
                    let inbound_message = Inbound { message, flow, writer };
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
async fn write_loop(
    mut write: impl AsyncWrite + Unpin,
    mut pending: mpsc::UnboundedReceiver<Write>,
) {
    let mut queue = Queue::default();
    while pending.recv_many(&mut queue.items, WRITE_BATCH).await > 0 {
        queue.remaining =
            queue.items.iter().map(|item| item.bytes.len()).sum();
        // An empty write at the head is already complete, including when
        // the following nonempty write fails before making progress.
        queue.advance(0);
        if let Err(error) = write.write_all_buf(&mut queue).await {
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

    use tokio::{net::TcpStream, time::sleep};

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
            mut self: std::pin::Pin<&mut Self>,
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
            mut self: std::pin::Pin<&mut Self>,
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
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // The async receipt tests build runtimes without an I/O driver to run
    // under Miri. #[tokio::test] initializes kqueue, which Miri does not
    // support. Channels and mock writers need no I/O driver.

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
            fn wake(self: Arc<Self>) {
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
            assert!(std::pin::Pin::new(&mut receipt)
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
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
        struct Stalled(Option<oneshot::Sender<()>>);

        impl AsyncWrite for Stalled {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                if let Some(started) = self.0.take() {
                    let _ = started.send(());
                }
                Poll::Pending
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

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
        let Message::Request(request) = &inbound.message else {
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
        assert!(matches!(inbound.message, Message::Request(_)));
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
        let Message::Response(response) = &inbound.message else {
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
        assert!(matches!(inbound.message, Message::Response(_)));
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
