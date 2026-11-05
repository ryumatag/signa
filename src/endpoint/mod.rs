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
a `Request<Bytes>`, with the [`Flow`] it arrived on in its extensions. The
service answers with the final response, built with [`Response::reply_to`]
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
    endpoint::{Endpoint, Transport},
    Request, Response, StatusCode,
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
        Ok::<_, signa::Error>(response)
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
*/

use std::{fmt, io, net::SocketAddr, time::Duration};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tower_service::Service;

use self::driver::{Command, Config, Driver, TCP_INBOUND};
use crate::{
    request::Request,
    response::Response,
    transport::{tcp, udp},
};

pub use self::{
    client::{Client, ResponseFuture},
    error::Error,
    shutdown::Shutdown,
};
pub use crate::{
    frame::Limits,
    transaction::Timers,
    transport::{Flow, Transport},
};

mod client;
mod driver;
mod error;
mod shutdown;
#[cfg(test)]
mod tests;

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
/// use signa::endpoint::{Endpoint, Timers};
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
///     .timers(Timers { t1: Duration::from_millis(200), ..Timers::default() })
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
    pub fn limits(mut self, limits: Limits) -> Builder {
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
        );
        tokio::spawn(driver.run());

        Ok(endpoint)
    }
}
