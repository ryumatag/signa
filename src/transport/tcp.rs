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

TODO: Close connections from the outside for shutdown. That comes with the
endpoint, which knows when it is shutting down.
*/

use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{
        mpsc::{self, error::TrySendError},
        OwnedSemaphorePermit, Semaphore,
    },
    time::timeout,
};

use crate::{
    frame::{Decoder, Frame, Limits, Role},
    message::Message,
    transport::{Flow, Transport}
};

/// How much to reserve before each read. A head is a few KiB at most, so this
/// is a message or two per read without a large buffer per idle connection.
const READ_SIZE: usize = 8 * 1024;

/// How many queued messages the writer takes per write. Each one is a chunk of
/// the vectored write.
const WRITE_BATCH: usize = 64;

/// The answer to an RFC 5626 ping.
const PONG: Bytes = Bytes::from_static(b"\r\n");

/// Settings for every connection a listener accepts or [`connect`] opens.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The decoder's limits.
    pub limits: Limits,
    /// How long a connection may go without receiving anything.
    pub idle_timeout: Duration,
    /// How many connections a listener keeps open at once.
    pub max_connections: usize,
    /// How many messages may wait to be written on one connection.
    pub write_queue: usize,
}

impl Default for Config {
    /// Default limits, a five minute idle timeout, 1024 connections, and a
    /// write queue of 64 messages.
    ///
    /// The idle timeout outlasts the 120 seconds RFC 5626 section 4.4.1 gives
    /// a client between keepalives, with room for a missed one.
    fn default() -> Config {
        Config {
            limits: Limits::default(),
            idle_timeout: Duration::from_secs(300),
            max_connections: 1024,
            write_queue: 64,
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
pub struct Writer {
    queue: mpsc::Sender<Bytes>,
}

/// Why a message could not be queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    /// The write queue is full. The peer is not reading fast enough.
    Full,
    /// The connection has ended.
    Closed,
}

impl Writer {
    /// Queues `bytes` to be written. Returns at once.
    pub fn send(&self, bytes: Bytes) -> Result<(), SendError> {
        self.queue.try_send(bytes).map_err(|err| match err {
            TrySendError::Full(_) => SendError::Full,
            TrySendError::Closed(_) => SendError::Closed,
        })
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SendError::Full => "the write queue of the connection is full",
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
    let (queue, pending) = mpsc::channel(config.write_queue);
    let writer = Writer { queue };
    let writing = tokio::spawn(write_loop(write, pending));
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
        reading.await;
        // The connection is over. A write still in flight is lost, which is no
        // worse than the peer having gone away.
        writing.abort();
        drop(permit);
    });

    Ok(writer)
}

/// Reads and frames the stream until the connection ends.
async fn read_loop(
    mut read: OwnedReadHalf,
    flow: Flow,
    role: Role,
    limits: Limits,
    idle_timeout: Duration,
    inbound: mpsc::Sender<Inbound>,
    writer: Writer,
) {
    let mut decoder = Decoder::new(role, limits);
    let mut buf = BytesMut::with_capacity(READ_SIZE);
    loop {
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(Frame::Message(message))) => {
                    let writer = writer.clone();
                    let inbound_message = Inbound { message, flow, writer };
                    if inbound.send(inbound_message).await.is_err() {
                        // The endpoint is gone.
                        return;
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
                Err(_) => return,
            }
        }

        buf.reserve(READ_SIZE);

        match timeout(idle_timeout, read.read_buf(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            // EOF, a read error, or the idle timeout.
            _ => return,
        }
    }
}

/// Writes queued messages until the queue closes or a write fails.
async fn write_loop(
    mut write: OwnedWriteHalf,
    mut pending: mpsc::Receiver<Bytes>,
) {
    let mut queue = Queue::default();
    while pending.recv_many(&mut queue.items, WRITE_BATCH).await > 0 {
        queue.remaining = queue.items.iter().map(Bytes::len).sum();
        if write.write_all_buf(&mut queue).await.is_err() {
            return;
        }
        queue.items.clear();
        queue.next = 0;
    }
}

/// The messages of one write, as one `Buf` so that `write_all_buf` can write
/// them with one vectored call.
#[derive(Default)]
struct Queue {
    items: Vec<Bytes>,
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
        self.items.get(self.next).map_or(&[], |item| item)
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [io::IoSlice<'a>]) -> usize {
        let items = self.items[self.next..].iter();
        let mut n = 0;
        for (slot, item) in dst.iter_mut().zip(items) {
            *slot = io::IoSlice::new(item);
            n += 1;
        }

        n
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining, "advanced past the end of the queue");
        self.remaining -= cnt;
        while cnt > 0 {
            let item = &mut self.items[self.next];
            if cnt < item.len() {
                item.advance(cnt);
                return;
            }
            cnt -= item.len();
            self.next += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::{net::TcpStream, time::sleep};

    use super::*;
    use crate::{method::Method, status::StatusCode};

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
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"cde"),
                Bytes::from_static(b"f"),
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
