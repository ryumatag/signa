/*!
The endpoint, which runs the transports and the transactions and connects
them to application code through Tower.

An [`Endpoint`] owns a UDP socket, a TCP listener, or both, and the
non-INVITE transactions on them. SIP sends and receives requests on the same
socket, so one endpoint is both the server and the client side, where hyper
has one type for each. [`Endpoint::builder`] binds the sockets and takes the
[`Service`] that answers requests. [`Endpoint::client`] makes a [`Client`]
that sends requests to one next hop.

# Serving

Every request that arrives and matches no transaction goes to the service as
a `Request<Bytes>`, with the [`Flow`](crate::transport::Flow) it arrived on
in its extensions. The service answers with the final response, built with
[`Response::reply_to`]
so that it carries the `Via` the endpoint routes it by. RFC 4320 leaves a
non-INVITE request no provisional response worth sending, and the endpoint
sends the one 100 the RFC asks for itself when the service is slow, so the
service never deals with provisional responses.

The service is polled for readiness before each request and called on the
same instance, and each call runs in its own task. Requests wait for the
service up to a limit, and a request beyond it is answered with a stateless
503. A service error, a response that is not final, or one without a `Via`
turns into a 500, since the endpoint has nothing else to send.

0.2.0 has no INVITE transactions. An INVITE gets a 501, an ACK is dropped,
and a CANCEL gets a 481, none of which reach the service.

# Sending

A [`Client`] implements [`Service`] for one next hop. The endpoint adds the
topmost `Via`, runs the client transaction with its retransmissions and
Timer F, and resolves the future with the final response or an [`Error`].
Over TCP the endpoint opens a connection to the next hop on the first
request and keeps it for the next ones.

# Shutdown

[`Endpoint::shutdown`] stops the endpoint once what it has in hand is done, or
at a deadline. From the call on, a new request gets a stateless 503 and a new
request through a [`Client`] fails with [`Error::is_closed`]. The endpoint goes
on answering the requests the service has, sending the final responses, and
waiting for the responses to its own requests. Once none of that is left, or at
the deadline, it stops. Stopping closes the sockets and every TCP connection,
drops the transactions that only linger to absorb retransmissions, and fails
whatever was still waiting with [`Error::is_closed`].

Dropping the last `Endpoint` and `Client` stops the endpoint at once, without
the grace.

# Example

```no_run
use std::time::Duration;

use bytes::Bytes;
use signa::{
    endpoint::Endpoint, transport::Transport, Request, Response, StatusCode,
};
use tower_service::Service;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = Endpoint::builder()
    .udp("0.0.0.0:5060".parse()?)
    .tcp("0.0.0.0:5060".parse()?)
    .serve(tower::service_fn(|request: Request<Bytes>| async move {
        let response = Response::reply_to(&request)
            .status(StatusCode::OK)
            .body(Bytes::new())?;
        Ok::<_, signa::message::BuildError>(response)
    }))?;

let mut client = endpoint.client(Transport::Udp, "192.0.2.4:5060".parse()?);
let request = Request::builder()
    .method("OPTIONS")
    .uri("sip:bob@192.0.2.4")
    .header("From", "<sip:alice@192.0.2.1>;tag=1928301774")
    .header("To", "<sip:bob@192.0.2.4>")
    .header("Call-ID", "a84b4c76e66710")
    .header("CSeq", "1 OPTIONS")
    .header("Max-Forwards", "70")
    .body(Bytes::new())?;
let response = client.call(request).await?;
assert_eq!(response.status(), StatusCode::OK);

// Stop taking requests, and give the ones in hand up to ten seconds.
endpoint.shutdown(Duration::from_secs(10)).await;
# Ok(())
# }
```

[`Service`]: tower_service::Service

Transaction timer configuration is owned by [`crate::transaction`], and
transport metadata by [`crate::transport`]. They are not public members of
this module. The following cannot compile because this import is private:

```compile_fail
use signa::endpoint::Timers;
```
*/

use std::{fmt, io, net::SocketAddr, time::Duration};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tower_service::Service;

use self::driver::{Command, Config, Driver, TCP_INBOUND};
use crate::{
    message::{request::Request, response::Response},
    transaction::Timers,
    transport::{tcp, udp, MessageLimits, Transport},
};

pub use self::{
    client::{Client, ResponseFuture},
    error::Error,
    reply::{ReplyError, ReplyRoute},
    shutdown::Shutdown,
};

mod client;
mod driver;
mod error;
mod reply;
mod shutdown;
mod table;

/// A handle to a running endpoint.
///
/// The endpoint runs in a task of its own as long as an `Endpoint`, a
/// [`Client`] of it, or a [`Shutdown`] exists. When the last one is dropped it
/// stops at once, closes its sockets and connections, and drops its
/// transactions. [`Endpoint::shutdown`] stops it with a grace period instead.
///
/// See the [module docs](self) for what it does.
#[derive(Clone)]
pub struct Endpoint {
    commands: mpsc::UnboundedSender<Command>,
    udp: Option<SocketAddr>,
    tcp: Option<SocketAddr>,
}

impl Endpoint {
    /// Starts building an endpoint.
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// The address of the UDP socket, if one was bound.
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp
    }

    /// The address of the TCP listener, if one was bound.
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp
    }

    /// Makes a client that sends to `next_hop` over `transport`.
    ///
    /// A UDP client needs the endpoint to have a UDP socket, and fails each
    /// request with a transport error otherwise. A TCP client opens its own
    /// connection, with or without a listener.
    pub fn client(
        &self,
        transport: Transport,
        next_hop: SocketAddr,
    ) -> Client {
        Client::new(self.commands.clone(), transport, next_hop)
    }

    /// Stops the endpoint once what it has in hand is done, or after
    /// `timeout`, and returns a future that resolves when it has stopped.
    ///
    /// From this call on, the endpoint answers a new request with a 503 and
    /// fails a new request through a [`Client`] with [`Error::is_closed`].
    /// It waits for the requests the service has, the responses to its own
    /// requests, and the connections it is opening, then stops. At `timeout`
    /// it stops regardless, and whatever still waits fails with
    /// [`Error::is_closed`]. See the [module docs](self#shutdown).
    ///
    /// Other handles to the endpoint go on working until it stops, and calling
    /// this on more than one of them is fine. The earliest deadline wins.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// # use signa::endpoint::Endpoint;
    /// # async fn run(endpoint: Endpoint) {
    /// // Say on SIGTERM. Nothing waits past 30 seconds, which is just
    /// // short of Timer F with the default T1.
    /// endpoint.shutdown(Duration::from_secs(30)).await;
    /// # }
    /// ```
    pub fn shutdown(self, timeout: Duration) -> Shutdown {
        let (done, wait) = oneshot::channel();
        // A send that fails means the endpoint has stopped already, and the
        // dropped `done` resolves the future at once.
        let _ = self.commands.send(Command::Shutdown { timeout, done });

        Shutdown::new(self.commands, wait)
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("udp", &self.udp)
            .field("tcp", &self.tcp)
            .finish()
    }
}

/// Builds an [`Endpoint`].
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use signa::{endpoint::Endpoint, transaction::Timers};
/// # use bytes::Bytes;
/// # use signa::{Request, Response};
///
/// # fn service() -> impl tower_service::Service<
/// #     Request<Bytes>,
/// #     Response = Response<Bytes>,
/// #     Future = std::future::Ready<
/// #         Result<Response<Bytes>, std::convert::Infallible>,
/// #     >,
/// # > + Send
/// #        + 'static {
/// #     tower::service_fn(|_| unreachable!())
/// # }
/// # fn main() -> std::io::Result<()> {
/// # let rt = tokio::runtime::Runtime::new()?;
/// # let _guard = rt.enter();
/// let endpoint = Endpoint::builder()
///     .udp("0.0.0.0:5060".parse().unwrap())
///     .timers(Timers::builder().t1(Duration::from_millis(200)).build().unwrap())
///     .max_pending_requests(256)
///     .serve(service())?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Builder {
    udp: Option<SocketAddr>,
    tcp: Option<SocketAddr>,
    config: Config,
}

impl Default for Builder {
    fn default() -> Builder {
        Builder::new()
    }
}

impl Builder {
    /// Creates a builder with no sockets and the defaults below.
    pub fn new() -> Builder {
        Builder {
            udp: None,
            tcp: None,
            config: Config {
                timers: Timers::default(),
                tcp: tcp::Config::default(),
                max_pending_requests: 1024,
                max_client_transactions: 4096,
            },
        }
    }

    /// Binds a UDP socket to `addr`.
    ///
    /// On Linux, Android, and Apple platforms a socket bound to a wildcard
    /// address answers each request from the address it came to. Elsewhere the
    /// kernel picks the source address, so bind to one address there when the
    /// host has several.
    pub fn udp(mut self, addr: SocketAddr) -> Builder {
        self.udp = Some(addr);
        self
    }

    /// Binds a TCP listener to `addr`.
    pub fn tcp(mut self, addr: SocketAddr) -> Builder {
        self.tcp = Some(addr);
        self
    }

    /// Sets the transaction timers. The default is RFC 3261's, with T1 at
    /// 500 ms.
    pub fn timers(mut self, timers: Timers) -> Builder {
        self.config.timers = timers;
        self
    }

    /// Sets how large the head and the body of a message received over TCP may
    /// be.
    ///
    /// A larger one closes the connection. The default allows 64 KiB and
    /// 1 MiB.
    pub fn limits(mut self, limits: MessageLimits) -> Builder {
        self.config.tcp.limits = limits;
        self
    }

    /// Sets how long a TCP connection may go without receiving anything before
    /// it is closed. The default is five minutes, which outlasts the RFC 5626
    /// keepalive interval.
    pub fn idle_timeout(mut self, timeout: Duration) -> Builder {
        self.config.tcp.idle_timeout = timeout;
        self
    }

    /// Sets how many TCP connections the listener keeps open at once. More
    /// wait in the OS backlog. The default is 1024.
    pub fn max_connections(mut self, limit: usize) -> Builder {
        self.config.tcp.max_connections = limit;
        self
    }

    /// Sets how many requests may wait for the service or be in its hands at
    /// once. A request beyond that gets a stateless 503. The default is 1024.
    pub fn max_pending_requests(mut self, limit: usize) -> Builder {
        self.config.max_pending_requests = limit;
        self
    }

    /// Sets how many client transactions may be open at once. A request
    /// beyond that fails with [`Error::is_busy`]. The default is 4096.
    ///
    /// Over UDP a transaction stays open for Timer K, which is T4 or 5 s,
    /// after its final response, to absorb retransmissions of it. So the limit
    /// bounds the requests of the last five seconds, not the ones still
    /// waiting for an answer.
    pub fn max_client_transactions(mut self, limit: usize) -> Builder {
        self.config.max_client_transactions = limit;
        self
    }

    /// Binds the sockets, starts the endpoint with `service` answering its
    /// requests, and returns a handle to it.
    ///
    /// Must be called from within a tokio runtime, since the endpoint runs as
    /// a task on it.
    ///
    /// # Errors
    ///
    /// Returns the error of binding a socket.
    pub fn serve<S>(self, service: S) -> io::Result<Endpoint>
    where
        S: Service<Request<Bytes>, Response = Response<Bytes>>
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        let udp = self.udp.map(udp::Socket::bind).transpose()?;
        let (tcp_tx, tcp_rx) = mpsc::channel(TCP_INBOUND);
        let listener = self
            .tcp
            .map(|addr| {
                tcp::Listener::bind(addr, self.config.tcp, tcp_tx.clone())
            })
            .transpose()?;
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let endpoint = Endpoint {
            commands,
            udp: udp.as_ref().map(udp::Socket::local_addr),
            tcp: listener.as_ref().map(tcp::Listener::local_addr),
        };

        if let Some(listener) = listener {
            tokio::spawn(listener.run());
        }
        let driver = Driver::new(
            service,
            self.config,
            udp,
            tcp_rx,
            tcp_tx,
            commands_rx,
            endpoint.commands.downgrade(),
        );
        tokio::spawn(driver.run());

        Ok(endpoint)
    }
}

/// Connects a benchmark-supplied request and transports to the real driver.
///
/// Called inside a tokio runtime. Fixture messages, services, sockets and
/// task ownership belong to the external benchmark crate.
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub fn reply_driver<S>(
    service: S,
    request: Request<Bytes>,
    flow: crate::transport::Flow,
    writer: Option<tcp::Writer>,
    udp: Option<udp::Socket>,
    tcp: mpsc::Receiver<tcp::Inbound>,
    tcp_tx: mpsc::Sender<tcp::Inbound>,
) -> Result<
    (Request<Bytes>, ReplyRoute, impl std::future::Future<Output = ()> + Send),
    ReplyError,
>
where
    S: Service<Request<Bytes>, Response = Response<Bytes>> + Send + 'static,
    S::Future: Send + 'static,
{
    use self::driver::Link;

    let (commands, rx) = mpsc::unbounded_channel();
    let driver = Driver::new(
        service,
        Builder::new().config,
        udp,
        tcp,
        tcp_tx,
        rx,
        commands.downgrade(),
    );
    let (request, route) =
        driver.prepare_reply(request, Link { flow, writer })?;

    Ok((request, route, driver.run()))
}

// These integration tests use sockets, which Miri cannot provide.
#[cfg(all(test, not(miri)))]
mod tests {
    use std::{
        convert::Infallible,
        future::{self, Future, Ready},
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        sync::{mpsc, Notify},
        time::{sleep, timeout},
    };
    use tower::{limit::ConcurrencyLimit, service_fn, ServiceExt};
    use tower_service::Service;

    use crate::{
        endpoint::{
            driver::{Command, Config, Driver, Link, TCP_INBOUND},
            error::Error,
            Endpoint, ReplyError,
        },
        message::{
            header::{HeaderValue, CSEQ, TO, VIA},
            request::Request,
            response::Response,
            StatusCode,
        },
        transaction::Timers,
        transport::{tcp, udp, Flow, Transport},
    };

    const LOCALHOST: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// Timers that make a test wait milliseconds instead of seconds. Timer F is
    /// 640 ms, and the 100 goes out after 70 ms.
    fn short_timers() -> Timers {
        Timers::builder()
            .t1(Duration::from_millis(10))
            .t2(Duration::from_millis(40))
            .t4(Duration::from_millis(50))
            .build()
            .unwrap()
    }

    fn request(method: &str) -> Request<Bytes> {
        Request::builder()
            .method(method)
            .uri("sip:bob@example.com")
            .header("From", "<sip:alice@example.com>;tag=1928301774")
            .header("To", "<sip:bob@example.com>")
            .header("Call-ID", "a84b4c76e66710")
            .header("CSeq", format!("1 {method}").as_str())
            .header("Max-Forwards", "70")
            .body(Bytes::new())
            .unwrap()
    }

    fn ok(request: &Request<Bytes>) -> Response<Bytes> {
        Response::reply_to(request)
            .status(StatusCode::OK)
            .body(Bytes::new())
            .unwrap()
    }

    /// A service that answers 200 and counts what it saw.
    #[derive(Clone, Default)]
    struct Counting {
        requests: Arc<AtomicUsize>,
        flows: Arc<std::sync::Mutex<Vec<Flow>>>,
    }

    impl Service<Request<Bytes>> for Counting {
        type Response = Response<Bytes>;
        type Error = Infallible;
        type Future = future::Ready<Result<Response<Bytes>, Infallible>>;

        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Bytes>) -> Self::Future {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let flow = *request.extensions().get::<Flow>().expect("a flow");
            self.flows.lock().unwrap().push(flow);
            future::ready(Ok(ok(&request)))
        }
    }

    /// Serves `service` on UDP and TCP, on ports the OS picks.
    fn serve<S>(service: S) -> Endpoint
    where
        S: Service<Request<Bytes>, Response = Response<Bytes>>
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        Endpoint::builder()
            .udp(LOCALHOST)
            .tcp(LOCALHOST)
            .timers(short_timers())
            .serve(service)
            .unwrap()
    }

    /// A raw UDP peer for tests that watch the wire.
    struct Peer {
        socket: UdpSocket,
        buf: Vec<u8>,
    }

    impl Peer {
        async fn new() -> Peer {
            Peer {
                socket: UdpSocket::bind(LOCALHOST).await.unwrap(),
                buf: vec![0; 65536],
            }
        }

        fn port(&self) -> u16 {
            self.socket.local_addr().unwrap().port()
        }

        async fn send(&self, to: SocketAddr, message: &str) {
            self.socket.send_to(message.as_bytes(), to).await.unwrap();
        }

        /// Receives one datagram, or `None` after 200 ms without one.
        async fn recv(&mut self) -> Option<String> {
            let received = timeout(
                Duration::from_millis(200),
                self.socket.recv_from(&mut self.buf),
            )
            .await
            .ok()?;
            let (len, _) = received.unwrap();

            Some(String::from_utf8(self.buf[..len].to_vec()).unwrap())
        }

        /// A request from this peer, with `via` as its top `Via` value.
        fn request(&self, method: &str, via: &str) -> String {
            format!(
                "{method} sip:bob@example.com SIP/2.0\r\n\
                 Via: {via}\r\n\
                 From: <sip:alice@example.com>;tag=1\r\n\
                 To: <sip:bob@example.com>\r\n\
                 Call-ID: raw-{}\r\n\
                 CSeq: 1 {method}\r\n\
                 Content-Length: 0\r\n\
                 \r\n",
                self.port()
            )
        }
    }

    pub(super) const REPLY_LOCAL: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    pub(super) struct RouteService;

    impl Service<Request<Bytes>> for RouteService {
        type Response = Response<Bytes>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _: Request<Bytes>) -> Self::Future {
            future::ready(Ok(Response::builder()
                .status(500)
                .body(Bytes::new())
                .unwrap()))
        }
    }

    pub(super) fn reply_driver(
    ) -> (Driver<RouteService>, mpsc::UnboundedSender<Command>, SocketAddr)
    {
        let (commands, rx) = mpsc::unbounded_channel();
        let (tx, tcp) = mpsc::channel(TCP_INBOUND);
        let socket = udp::Socket::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let local = socket.local_addr();
        let config = Config {
            timers: Timers::default(),
            tcp: tcp::Config::default(),
            max_pending_requests: 8,
            max_client_transactions: 8,
        };

        (
            Driver::new(
                RouteService,
                config,
                Some(socket),
                tcp,
                tx,
                rx,
                commands.downgrade(),
            ),
            commands,
            local,
        )
    }

    pub(super) fn route_request(via: &str) -> Request<Bytes> {
        Request::builder()
            .method("OPTIONS")
            .uri("sip:bob@example.com")
            .header("Via", via)
            .header("From", "<sip:alice@example.com>;tag=alice")
            .header("To", "<sip:bob@example.com>")
            .header("Call-ID", "route-test")
            .header("CSeq", "1 OPTIONS")
            .body(Bytes::new())
            .unwrap()
    }

    pub(super) fn route_response(request: &Request<Bytes>) -> Response<Bytes> {
        let mut response = Response::reply_to(request)
            .status(200)
            .body(Bytes::new())
            .unwrap();
        let to = response.headers().get(TO).unwrap().as_str().to_owned()
            + ";tag=bob";
        response
            .headers_mut()
            .insert(TO, HeaderValue::from_bytes(to.as_bytes()).unwrap());

        response
    }

    pub(super) fn udp_reply_link(local: SocketAddr, peer: SocketAddr) -> Link {
        Link {
            flow: Flow {
                transport: Transport::Udp,
                local: SocketAddr::new(REPLY_LOCAL.ip(), local.port()),
                remote: peer,
            },
            writer: None,
        }
    }

    #[tokio::test]
    async fn udp_round_trip() {
        let service = Counting::default();
        let server = serve(service.clone());
        let client_end = serve(Counting::default());
        let mut client =
            client_end.client(Transport::Udp, server.udp_addr().unwrap());

        let response = client.call(request("OPTIONS")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(CSEQ).unwrap(), "1 OPTIONS");

        // The endpoint wrote the Via, and the server filled in rport.
        let via = response.headers().get(VIA).unwrap().as_str();
        let client_port = client_end.udp_addr().unwrap().port();
        assert!(
            via.starts_with(&format!(
                "SIP/2.0/UDP 127.0.0.1:{client_port};rport="
            )),
            "{via}"
        );
        assert!(via.contains(";branch=z9hG4bK"), "{via}");
        assert!(!via.contains("received"), "{via}");

        // The service saw the flow.
        assert_eq!(service.requests.load(Ordering::SeqCst), 1);
        let flows = service.flows.lock().unwrap();
        assert_eq!(flows[0].transport, Transport::Udp);
        assert_eq!(flows[0].local, server.udp_addr().unwrap());
        assert_eq!(flows[0].remote, client_end.udp_addr().unwrap());
    }

    #[tokio::test]
    async fn tcp_round_trip_reuses_the_connection() {
        let service = Counting::default();
        let server = serve(service.clone());
        let client_end =
            Endpoint::builder().serve(Counting::default()).unwrap();
        let mut client =
            client_end.client(Transport::Tcp, server.tcp_addr().unwrap());

        for _ in 0..2 {
            let response = client.call(request("OPTIONS")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let via = response.headers().get(VIA).unwrap().as_str();
            assert!(via.starts_with("SIP/2.0/TCP 127.0.0.1:"), "{via}");
        }

        let flows = service.flows.lock().unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].transport, Transport::Tcp);
        assert_eq!(flows[0], flows[1], "both requests on one connection");
    }

    /// Reads one message without a body from a connection.
    async fn read_head(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let n = timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("a message within a second")
                .unwrap();
            assert!(n > 0, "closed before the message ended");
            buf.push(byte[0]);
        }

        String::from_utf8(buf).unwrap()
    }

    /// Reads messages from a connection until a final response.
    async fn read_final(stream: &mut TcpStream) -> String {
        loop {
            let message = read_head(stream).await;
            if !message.starts_with("SIP/2.0 1") {
                return message;
            }
        }
    }

    #[tokio::test]
    async fn a_response_opens_a_new_connection_when_the_request_s_has_closed()
    {
        let gate = Arc::new(Notify::new());
        let service = {
            let gate = gate.clone();
            service_fn(move |request: Request<Bytes>| {
                let gate = gate.clone();
                async move {
                    gate.notified().await;
                    Ok::<_, Infallible>(ok(&request))
                }
            })
        };
        let server = serve(service);
        let peer = Peer::new().await;

        // The peer listens on its `sent-by` port, sends a request on one
        // connection, and closes it before the response.
        let listener = TcpListener::bind(LOCALHOST).await.unwrap();
        let sent_by = listener.local_addr().unwrap();
        let mut stream =
            TcpStream::connect(server.tcp_addr().unwrap()).await.unwrap();
        let request = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/TCP 127.0.0.1:{};rport;branch=z9hG4bK1",
                sent_by.port()
            ),
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        drop(stream);
        // Let the endpoint see the close.
        sleep(Duration::from_millis(50)).await;
        gate.notify_one();

        // The response arrives on a new connection to `sent-by`, and not to
        // the source port, since `rport` means nothing over TCP (RFC 3581).
        let (mut conn, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("a connection within a second")
            .unwrap();
        // With the short timers a 100 may come first, on that connection too.
        let response = read_final(&mut conn).await;
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        assert!(response.contains("branch=z9hG4bK1"), "{response}");

        // A second response to the same `sent-by` reuses that connection.
        let mut stream =
            TcpStream::connect(server.tcp_addr().unwrap()).await.unwrap();
        let request = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/TCP 127.0.0.1:{};branch=z9hG4bK2",
                sent_by.port()
            ),
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        drop(stream);
        sleep(Duration::from_millis(50)).await;
        gate.notify_one();
        let response = read_final(&mut conn).await;
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        assert!(response.contains("branch=z9hG4bK2"), "{response}");
    }

    #[tokio::test]
    async fn a_response_nobody_listens_for_is_dropped() {
        let service = Counting::default();
        let server = serve(service.clone());
        let peer = Peer::new().await;

        // Nothing listens on port 1, so the new connection fails.
        let mut stream =
            TcpStream::connect(server.tcp_addr().unwrap()).await.unwrap();
        let request =
            peer.request("OPTIONS", "SIP/2.0/TCP 127.0.0.1:1;branch=z9hG4bK1");
        stream.write_all(request.as_bytes()).await.unwrap();
        // The service answers at once, so the response may go on this
        // connection or on the failed one. Either way the endpoint goes on.
        drop(stream);
        sleep(Duration::from_millis(50)).await;

        let mut client = serve(Counting::default())
            .client(Transport::Udp, server.udp_addr().unwrap());
        let response = client.call(self::request("OPTIONS")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(service.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn two_endpoints_talk_both_ways() {
        let a_service = Counting::default();
        let b_service = Counting::default();
        let a = serve(a_service.clone());
        let b = serve(b_service.clone());
        let mut a_to_b = a.client(Transport::Udp, b.udp_addr().unwrap());
        let mut b_to_a = b.client(Transport::Udp, a.udp_addr().unwrap());

        let (x, y) = tokio::join!(
            a_to_b.call(request("OPTIONS")),
            b_to_a.call(request("OPTIONS"))
        );
        assert_eq!(x.unwrap().status(), StatusCode::OK);
        assert_eq!(y.unwrap().status(), StatusCode::OK);
        assert_eq!(a_service.requests.load(Ordering::SeqCst), 1);
        assert_eq!(b_service.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retransmissions_are_absorbed_by_the_server_transaction() {
        let service = Counting::default();
        let server = serve(service.clone());
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let request = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bKabc",
                peer.port()
            ),
        );

        for _ in 0..3 {
            peer.send(to, &request).await;
            let response = peer.recv().await.unwrap();
            assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        }
        assert_eq!(service.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn requests_without_a_cookie_are_handed_up_each_time() {
        let service = Counting::default();
        let server = serve(service.clone());
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let request = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=1", peer.port()),
        );

        for _ in 0..2 {
            peer.send(to, &request).await;
            let response = peer.recv().await.unwrap();
            assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        }
        assert_eq!(service.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn received_and_rport_are_filled_in() {
        let service = Counting::default();
        let server = serve(service.clone());
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;

        // The host is not the source address, so `received` is added. The port
        // is this peer's, so the response comes here without `rport`.
        let request = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/UDP pc33.example.com:{};branch=z9hG4bK1",
                peer.port()
            ),
        );
        peer.send(to, &request).await;
        let response = peer.recv().await.unwrap();
        let expected = format!(
            "Via: SIP/2.0/UDP pc33.example.com:{};branch=z9hG4bK1;received=127.0.0.1\r\n",
            peer.port()
        );
        assert!(response.contains(&expected), "{response}");

        // With `rport` and a port that is not the source port, the response
        // comes to the source port anyway, and says so in place.
        let request = peer.request(
            "OPTIONS",
            "SIP/2.0/UDP 127.0.0.1:1;rport;branch=z9hG4bK2,SIP/2.0/UDP x;branch=z9hG4bK3",
        );
        peer.send(to, &request).await;
        let response = peer.recv().await.unwrap();
        let expected = format!(
            "Via: SIP/2.0/UDP 127.0.0.1:1;rport={};branch=z9hG4bK2,SIP/2.0/UDP x;branch=z9hG4bK3\r\n",
            peer.port()
        );
        assert!(response.contains(&expected), "{response}");

        // Both at once, with a host that is not an address.
        let request = peer.request(
            "OPTIONS",
            "SIP/2.0/UDP pc33.example.com;branch=z9hG4bK5;rport",
        );
        peer.send(to, &request).await;
        let response = peer.recv().await.unwrap();
        let expected = format!(
            "Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK5;rport={};received=127.0.0.1\r\n",
            peer.port()
        );
        assert!(response.contains(&expected), "{response}");

        // A spoofed `received` does not redirect the response.
        let request = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/UDP 127.0.0.1:{};received=192.0.2.1;branch=z9hG4bK4",
                peer.port()
            ),
        );
        peer.send(to, &request).await;
        assert!(peer.recv().await.unwrap().starts_with("SIP/2.0 200 OK\r\n"));

        // Without `rport`, the response goes to the `sent-by` port, which is
        // not this peer's (RFC 3261 section 18.2.2). The service still sees
        // where the request came from.
        let request =
            peer.request("OPTIONS", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bK6");
        peer.send(to, &request).await;
        assert!(peer.recv().await.is_none());
        let flows = service.flows.lock().unwrap();
        let peer_addr = peer.socket.local_addr().unwrap();
        assert_eq!(flows.len(), 5);
        assert!(
            flows.iter().all(|flow| flow.remote == peer_addr),
            "{flows:?}"
        );
    }

    #[tokio::test]
    async fn a_slow_service_gets_a_100_sent_for_it() {
        let service = service_fn(|request: Request<Bytes>| async move {
            sleep(Duration::from_millis(150)).await;
            Ok::<_, Infallible>(ok(&request))
        });
        let server = serve(service);
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let request = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK1", peer.port()),
        );

        peer.send(to, &request).await;
        let trying = peer.recv().await.unwrap();
        assert!(trying.starts_with("SIP/2.0 100 Trying\r\n"), "{trying}");
        assert!(trying.contains("branch=z9hG4bK1"), "{trying}");
        let response = peer.recv().await.unwrap();
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
    }

    #[tokio::test]
    async fn invite_ack_and_cancel_do_not_reach_the_service() {
        let service = Counting::default();
        let server = serve(service.clone());
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let via =
            format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK1", peer.port());

        peer.send(to, &peer.request("INVITE", &via)).await;
        let response = peer.recv().await.unwrap();
        assert!(
            response.starts_with("SIP/2.0 501 Not Implemented\r\n"),
            "{response}"
        );

        peer.send(to, &peer.request("CANCEL", &via)).await;
        let response = peer.recv().await.unwrap();
        assert!(response.starts_with("SIP/2.0 481 "), "{response}");

        peer.send(to, &peer.request("ACK", &via)).await;
        assert!(peer.recv().await.is_none());

        assert_eq!(service.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn overload_gets_a_stateless_503() {
        let gate = Arc::new(Notify::new());
        let service = {
            let gate = gate.clone();
            service_fn(move |request: Request<Bytes>| {
                let gate = gate.clone();
                async move {
                    gate.notified().await;
                    Ok::<_, Infallible>(ok(&request))
                }
            })
        };
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_pending_requests(1)
            .serve(service)
            .unwrap();
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let first = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK1", peer.port()),
        );
        let second = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK2", peer.port()),
        );

        peer.send(to, &first).await;
        peer.send(to, &second).await;
        let response = peer.recv().await.unwrap();
        assert!(
            response.starts_with("SIP/2.0 503 Service Unavailable\r\n"),
            "{response}"
        );
        assert!(response.contains("branch=z9hG4bK2"), "{response}");

        // The 503 was stateless, so the retransmission gets another.
        peer.send(to, &second).await;
        let response = peer.recv().await.unwrap();
        assert!(response.starts_with("SIP/2.0 503 "), "{response}");

        // The first request is still in the service's hands, and the second
        // has room once the first is answered.
        gate.notify_one();
        let response = peer.recv().await.unwrap();
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        assert!(response.contains("branch=z9hG4bK1"), "{response}");
        peer.send(to, &second).await;
        gate.notify_one();
        let response = peer.recv().await.unwrap();
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        assert!(response.contains("branch=z9hG4bK2"), "{response}");
    }

    #[tokio::test]
    async fn unusable_answers_become_a_500() {
        // An error, a provisional response, and a response without a Via.
        let service = service_fn(|request: Request<Bytes>| async move {
            let cseq = request.headers().get(CSEQ).unwrap().as_str();
            match cseq.as_bytes()[0] {
                b'1' => Err(crate::message::BuildError::missing("anything")),
                b'2' => Ok(Response::reply_to(&request)
                    .status(StatusCode::TRYING)
                    .body(Bytes::new())
                    .unwrap()),
                _ => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Bytes::new())
                    .unwrap()),
            }
        });
        let server = serve(service);
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;

        for cseq in 1..=3 {
            let request = peer
                .request(
                    "OPTIONS",
                    &format!(
                        "SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK{cseq}",
                        peer.port()
                    ),
                )
                .replace("CSeq: 1 OPTIONS", &format!("CSeq: {cseq} OPTIONS"));
            peer.send(to, &request).await;
            let response = peer.recv().await.unwrap();
            assert!(
                response.starts_with("SIP/2.0 500 Server Internal Error\r\n"),
                "{response}"
            );
            assert!(
                response.contains(&format!("branch=z9hG4bK{cseq}")),
                "{response}"
            );
            assert!(
                response.contains(&format!("CSeq: {cseq} OPTIONS")),
                "{response}"
            );
        }
    }

    #[tokio::test]
    async fn readiness_and_layers_are_respected() {
        // A concurrency limit of one makes the service unready while a request
        // is in flight. The requests still all get answered, one at a time.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let service = {
            let (in_flight, most) = (in_flight.clone(), most.clone());
            service_fn(move |request: Request<Bytes>| {
                let (in_flight, most) = (in_flight.clone(), most.clone());
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    sleep(Duration::from_millis(20)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(ok(&request))
                }
            })
        };
        let server = serve(ConcurrencyLimit::new(service, 1));
        let client_end = serve(Counting::default());
        let client =
            client_end.client(Transport::Udp, server.udp_addr().unwrap());

        let mut calls = Vec::new();
        for i in 0..3 {
            let mut request = request("OPTIONS");
            request.headers_mut().insert(
                crate::message::header::CALL_ID,
                crate::HeaderValue::from_bytes(format!("call-{i}").as_bytes())
                    .unwrap(),
            );
            calls.push(client.clone().oneshot(request));
        }
        for call in calls {
            assert_eq!(call.await.unwrap().status(), StatusCode::OK);
        }
        assert_eq!(most.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timer_f_ends_a_request_nobody_answers() {
        let mut peer = Peer::new().await;
        let client_end = serve(Counting::default());
        let mut client = client_end
            .client(Transport::Udp, peer.socket.local_addr().unwrap());

        let started = tokio::time::Instant::now();
        let err = client.call(request("OPTIONS")).await.unwrap_err();
        assert!(err.is_timeout(), "{err}");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(600), "{elapsed:?}");

        // T1, 2 T1, 4 T1, then every T2 until F: the request arrived more than
        // once.
        let mut copies = 0;
        while peer.recv().await.is_some() {
            copies += 1;
        }
        assert!(copies >= 5, "{copies}");
    }

    #[tokio::test]
    async fn a_response_from_another_sent_by_is_discarded() {
        let mut peer = Peer::new().await;
        let client_end = serve(Counting::default());
        let mut client = client_end
            .client(Transport::Udp, peer.socket.local_addr().unwrap());

        let call =
            tokio::spawn(async move { client.call(request("OPTIONS")).await });
        let received = peer.recv().await.unwrap();
        let (head, _) = received.split_once("\r\n").unwrap();
        assert_eq!(head, "OPTIONS sip:bob@example.com SIP/2.0");
        let via_line =
            received.lines().find(|l| l.starts_with("Via:")).unwrap();
        let forged = via_line.replace("127.0.0.1", "192.0.2.1");
        let response = received
            .replacen(head, "SIP/2.0 200 OK", 1)
            .replacen(via_line, &forged, 1);
        let from = received.lines().find(|l| l.starts_with("Via:")).is_some();
        assert!(from);
        peer.send(client_end.udp_addr().unwrap(), &response).await;

        let err = call.await.unwrap().unwrap_err();
        assert!(err.is_timeout(), "{err}");
    }

    #[tokio::test]
    async fn large_requests_do_not_go_over_udp() {
        let server = serve(Counting::default());
        let client_end = serve(Counting::default());
        let mut request = request("OPTIONS");
        *request.body_mut() = Bytes::from(vec![b'x'; 1300]);

        let mut udp =
            client_end.client(Transport::Udp, server.udp_addr().unwrap());
        let err = udp.call(request.clone()).await.unwrap_err();
        assert!(err.is_too_large(), "{err}");

        let mut tcp =
            client_end.client(Transport::Tcp, server.tcp_addr().unwrap());
        let response = tcp.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn refused_requests_and_connections_are_errors() {
        let client_end = serve(Counting::default());

        let mut request = request("OPTIONS");
        request.headers_mut().remove(CSEQ);
        let mut client = client_end.client(Transport::Udp, LOCALHOST);
        let err = client.call(request).await.unwrap_err();
        assert_eq!(err.to_string(), "the request has no CSeq");

        // A port nobody listens on.
        let listener = TcpListener::bind(LOCALHOST).await.unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        let mut client = client_end.client(Transport::Tcp, closed);
        let err = client.call(self::request("OPTIONS")).await.unwrap_err();
        assert!(err.is_transport(), "{err}");
        assert!(std::error::Error::source(&err).is_some());

        // No UDP socket to send from.
        let tcp_only = Endpoint::builder().serve(Counting::default()).unwrap();
        let mut client = tcp_only.client(Transport::Udp, LOCALHOST);
        let err = client.call(self::request("OPTIONS")).await.unwrap_err();
        assert!(err.is_transport(), "{err}");

        // Too many transactions.
        let peer = Peer::new().await;
        let limited = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1)
            .serve(Counting::default())
            .unwrap();
        let mut client =
            limited.client(Transport::Udp, peer.socket.local_addr().unwrap());
        let first = client.call(self::request("OPTIONS"));
        let err = client.call(self::request("OPTIONS")).await.unwrap_err();
        assert!(err.is_busy(), "{err}");
        assert!(first.await.unwrap_err().is_timeout());
    }

    #[tokio::test]
    async fn dropping_the_future_does_not_end_the_transaction() {
        let mut peer = Peer::new().await;
        let client_end = serve(Counting::default());
        let mut client = client_end
            .client(Transport::Udp, peer.socket.local_addr().unwrap());

        let call = client.call(request("OPTIONS"));
        assert!(peer.recv().await.is_some());
        drop(call);
        // Retransmissions go on without anyone waiting.
        assert!(peer.recv().await.is_some());
        assert!(peer.recv().await.is_some());
    }

    #[tokio::test]
    async fn the_endpoint_stops_with_its_last_handle() {
        let client_end = serve(Counting::default());
        let server = serve(Counting::default());
        let addr = client_end.udp_addr().unwrap();
        let mut client =
            client_end.client(Transport::Udp, server.udp_addr().unwrap());

        // A client keeps the endpoint running after the handle is gone.
        drop(client_end);
        assert_eq!(
            client.call(request("OPTIONS")).await.unwrap().status(),
            StatusCode::OK
        );

        drop(client);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(UdpSocket::bind(addr).await.is_ok(), "the socket was closed");
    }

    #[tokio::test]
    async fn a_stopped_endpoint_fails_requests() {
        // Dropping the runtime's tasks is what stops an endpoint from under a
        // client. A future polled after that reports it.
        let peer = Peer::new().await;
        let client_end = serve(Counting::default());
        let mut client = client_end
            .client(Transport::Udp, peer.socket.local_addr().unwrap());
        let mut pending: Pin<
            Box<dyn Future<Output = Result<Response<Bytes>, Error>>>,
        > = Box::pin(client.call(request("OPTIONS")));
        // The peer never answers. Stop the driver by closing its command channel,
        // which drops the transaction that waits.
        drop(client);
        drop(client_end);
        let err = (&mut pending).await.unwrap_err();
        assert!(err.is_closed(), "{err}");
    }

    /// A service that answers 200 once `gate` is notified, once per request.
    #[derive(Clone)]
    struct Gated {
        gate: Arc<Notify>,
    }

    impl Service<Request<Bytes>> for Gated {
        type Response = Response<Bytes>;
        type Error = Infallible;
        type Future = Pin<
            Box<
                dyn Future<Output = Result<Response<Bytes>, Infallible>>
                    + Send,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Bytes>) -> Self::Future {
            let gate = self.gate.clone();
            Box::pin(async move {
                gate.notified().await;
                Ok(ok(&request))
            })
        }
    }

    impl Peer {
        /// Receives datagrams until a final response, or `None` when none comes.
        async fn recv_final(&mut self) -> Option<String> {
            loop {
                let message = self.recv().await?;
                if !message.starts_with("SIP/2.0 1") {
                    return Some(message);
                }
            }
        }
    }

    /// Answers a request received by a raw peer with a 200, on the same `Via`.
    fn answer(received: &str) -> String {
        let (head, _) = received.split_once("\r\n").unwrap();

        received.replacen(head, "SIP/2.0 200 OK", 1)
    }

    #[tokio::test]
    async fn shutdown_waits_for_the_service_and_refuses_the_rest() {
        let gate = Arc::new(Notify::new());
        let server = serve(Gated { gate: gate.clone() });
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let first = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK1", peer.port()),
        );
        let second = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK2", peer.port()),
        );

        peer.send(to, &first).await;
        // The 100 shows the service has the request.
        let trying = peer.recv().await.unwrap();
        assert!(trying.starts_with("SIP/2.0 100 "), "{trying}");

        let mut shutdown = Box::pin(server.shutdown(Duration::from_secs(5)));
        assert!(timeout(Duration::from_millis(50), &mut shutdown)
            .await
            .is_err());

        // A new request is refused, and a retransmission of the first is still
        // absorbed by its transaction.
        peer.send(to, &second).await;
        let response = peer.recv().await.unwrap();
        assert!(response.starts_with("SIP/2.0 503 "), "{response}");
        assert!(response.contains("branch=z9hG4bK2"), "{response}");
        peer.send(to, &first).await;
        let trying = peer.recv().await.unwrap();
        assert!(trying.starts_with("SIP/2.0 100 "), "{trying}");

        // The service's answer goes out, and then the endpoint stops.
        gate.notify_one();
        let response = peer.recv_final().await.unwrap();
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        assert!(response.contains("branch=z9hG4bK1"), "{response}");
        timeout(Duration::from_secs(1), shutdown).await.unwrap();
        assert!(UdpSocket::bind(to).await.is_ok(), "the socket was closed");
    }

    #[tokio::test]
    async fn shutdown_waits_for_the_response_to_its_own_request() {
        let mut peer = Peer::new().await;
        let client_end = serve(Counting::default());
        let mut client = client_end
            .client(Transport::Udp, peer.socket.local_addr().unwrap());

        let call =
            tokio::spawn(async move { client.call(request("OPTIONS")).await });
        let received = peer.recv().await.unwrap();

        let other = client_end.clone();
        let mut shutdown =
            Box::pin(client_end.shutdown(Duration::from_secs(5)));
        assert!(timeout(Duration::from_millis(50), &mut shutdown)
            .await
            .is_err());

        // A request after the call is refused. The one in flight is waited for.
        let mut late =
            other.client(Transport::Udp, peer.socket.local_addr().unwrap());
        let err = late.call(request("OPTIONS")).await.unwrap_err();
        assert!(err.is_closed(), "{err}");

        peer.send(other.udp_addr().unwrap(), &answer(&received)).await;
        let response = call.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The second handle asking too makes no difference.
        let again = other.shutdown(Duration::from_secs(5));
        timeout(Duration::from_secs(1), shutdown).await.unwrap();
        timeout(Duration::from_secs(1), again).await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_gives_up_at_the_deadline() {
        let gate = Arc::new(Notify::new());
        let server = serve(Gated { gate });
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let request = peer.request(
            "OPTIONS",
            &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK1", peer.port()),
        );
        let mut client =
            server.client(Transport::Udp, peer.socket.local_addr().unwrap());
        let call = tokio::spawn(async move {
            client.call(self::request("OPTIONS")).await
        });

        // The service never answers, and neither does the peer.
        peer.send(to, &request).await;
        assert!(peer.recv().await.is_some());

        let started = tokio::time::Instant::now();
        timeout(
            Duration::from_secs(1),
            server.shutdown(Duration::from_millis(100)),
        )
        .await
        .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(100));
        let err = call.await.unwrap().unwrap_err();
        assert!(err.is_closed(), "{err}");
        assert!(UdpSocket::bind(to).await.is_ok(), "the socket was closed");
    }

    #[tokio::test]
    async fn stopping_closes_the_connections() {
        let server = serve(Counting::default());
        let mut stream =
            TcpStream::connect(server.tcp_addr().unwrap()).await.unwrap();
        let request = format!(
            "OPTIONS sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TCP 127.0.0.1:{};branch=z9hG4bK1\r\n\
             From: <sip:alice@example.com>;tag=1\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: tcp-1\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n",
            stream.local_addr().unwrap().port()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let response = read_final(&mut stream).await;
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");

        // The endpoint is gone, so the connection ends at once rather than at the
        // idle timeout.
        drop(server);
        let mut buf = [0; 1];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("closed within a second")
            .unwrap();
        assert_eq!(n, 0, "EOF");
    }

    #[tokio::test]
    async fn the_last_responses_go_out_before_the_connections_close() {
        let gate = Arc::new(Notify::new());
        let server = serve(Gated { gate: gate.clone() });
        let mut stream =
            TcpStream::connect(server.tcp_addr().unwrap()).await.unwrap();
        let request = format!(
            "OPTIONS sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TCP 127.0.0.1:{};branch=z9hG4bK1\r\n\
             From: <sip:alice@example.com>;tag=1\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: tcp-1\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n",
            stream.local_addr().unwrap().port()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let trying = read_head(&mut stream).await;
        assert!(trying.starts_with("SIP/2.0 100 "), "{trying}");

        // The endpoint stops right after it queues the 200, and the connection
        // still carries it before closing.
        let shutdown = server.shutdown(Duration::from_secs(5));
        gate.notify_one();
        let response = read_final(&mut stream).await;
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        timeout(Duration::from_secs(1), shutdown).await.unwrap();
        let mut buf = [0; 1];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("closed within a second")
            .unwrap();
        assert_eq!(n, 0, "EOF");
    }

    #[tokio::test]
    async fn udp_route_preserves_local_address_and_rport_and_can_outlive_other_handles(
    ) {
        let (driver, commands, local) = reply_driver();
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let link = udp_reply_link(local, peer.local_addr().unwrap());
        let local = link.flow.local;
        let (request, route) = driver
            .prepare_reply(
                route_request(
                    "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
                ),
                link,
            )
            .unwrap();

        assert!(request.headers().get(VIA).unwrap().as_str().contains(
            &format!("rport={}", peer.local_addr().unwrap().port())
        ));
        let response = route_response(&request);

        let task = tokio::spawn(driver.run());
        drop(commands);
        route.clone().send(response.clone()).await.unwrap();

        let mut buf = [0; 2048];
        let (n, source) =
            timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, local);
        assert_eq!(&buf[..n], &response.to_bytes());

        drop(route);
        timeout(Duration::from_secs(1), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_without_rport_uses_sent_by_port() {
        let (driver, _commands, local) = reply_driver();
        let target = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let source = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let link = udp_reply_link(local, source.local_addr().unwrap());
        let via = format!(
            "SIP/2.0/UDP example.com:{};branch=z9hG4bKroute",
            target.local_addr().unwrap().port()
        );
        let (request, route) =
            driver.prepare_reply(route_request(&via), link).unwrap();

        let task = tokio::spawn(driver.run());
        route.send(route_response(&request)).await.unwrap();

        let mut buf = [0; 2048];
        timeout(Duration::from_secs(1), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        task.abort();
    }

    #[tokio::test]
    async fn tcp_uses_original_writer_then_falls_back_after_closure() {
        let (driver, commands, _local) = reply_driver();
        let (incoming, mut rx) = mpsc::channel(4);
        let listener =
            tcp::Listener::bind(REPLY_LOCAL, tcp::Config::default(), incoming)
                .unwrap();
        let addr = listener.local_addr();
        let mut peer = TcpStream::connect(addr).await.unwrap();
        listener.accept().await.unwrap();

        let fallback =
            tokio::net::TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let via = format!(
            "SIP/2.0/TCP example.com:{};branch=z9hG4bKroute",
            fallback.local_addr().unwrap().port()
        );

        let original = route_request(&via);
        peer.write_all(&original.to_bytes()).await.unwrap();
        let inbound = rx.recv().await.unwrap();
        let (request, route) = driver
            .prepare_reply(
                original,
                Link {
                    flow: inbound.flow,
                    writer: Some(inbound.writer.clone()),
                },
            )
            .unwrap();
        let response = route_response(&request);
        let expected = response.to_bytes();

        let task = tokio::spawn(driver.run());
        route.send(response.clone()).await.unwrap();

        let mut buf = vec![0; expected.len()];
        timeout(Duration::from_secs(1), peer.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, expected);

        drop(peer);
        timeout(Duration::from_secs(1), async {
            while !inbound.writer.is_closed() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        let send = route.send(response);
        let receive = async {
            let (mut stream, _) = fallback.accept().await.unwrap();
            let mut buf = vec![0; expected.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, expected);
        };
        let (sent, ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(send, receive)
        })
        .await
        .unwrap();
        sent.unwrap();

        drop(route);
        drop(commands);
        timeout(Duration::from_secs(1), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fallback_connect_errors_retain_the_io_source() {
        let (driver, _commands, _local) = reply_driver();
        let target = tokio::net::TcpListener::bind(REPLY_LOCAL).await.unwrap();
        let address = target.local_addr().unwrap();
        drop(target);

        let (tx, mut rx) = mpsc::channel(1);
        let listener =
            tcp::Listener::bind(REPLY_LOCAL, tcp::Config::default(), tx)
                .unwrap();
        let mut peer =
            TcpStream::connect(listener.local_addr()).await.unwrap();
        listener.accept().await.unwrap();

        let request = route_request(&format!(
            "SIP/2.0/TCP example.com:{};branch=z9hG4bKroute",
            address.port()
        ));
        peer.write_all(&request.to_bytes()).await.unwrap();
        let inbound = rx.recv().await.unwrap();
        let (request, route) = driver
            .prepare_reply(
                request,
                Link {
                    flow: inbound.flow,
                    writer: Some(inbound.writer.clone()),
                },
            )
            .unwrap();

        drop(peer);
        timeout(Duration::from_secs(1), async {
            while !inbound.writer.is_closed() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        let task = tokio::spawn(async move {
            driver.run().await;
        });

        // Windows may retry SYNs before reporting connection refusal, even
        // on loopback. Allow time for the OS to finish those retries.
        let result = timeout(
            Duration::from_secs(10),
            route.send(route_response(&request)),
        )
        .await
        .expect("fallback connection error was not delivered");
        let Err(ReplyError::Transport(error)) = result else {
            panic!("expected connect error");
        };

        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        let source =
            error.get_ref().unwrap().downcast_ref::<Arc<io::Error>>().unwrap();
        assert!(source.raw_os_error().is_some());

        task.abort();
    }
}
