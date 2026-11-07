/*!
Endpoint configuration, socket binding and task startup.
*/

use std::{io, net::SocketAddr, time::Duration};

use bytes::Bytes;
use tokio::sync::mpsc;
use tower_service::Service;

use super::{
    driver::{Driver, TCP_INBOUND},
    Endpoint,
};
use crate::{
    message::{request::Request, response::Response},
    transaction::Timers,
    transport::{tcp, udp, MessageLimits, WriteLimits},
};

/// Settings shared by endpoint startup and the protocol driver.
#[derive(Clone, Copy, Debug)]
pub(super) struct Config {
    pub(super) timers: Timers,
    pub(super) tcp: tcp::Config,
    pub(super) max_pending_requests: usize,
    pub(super) max_server_transactions: usize,
    pub(super) max_client_transactions: usize,
    pub(super) max_client_request_bytes: usize,
    pub(super) udp_write_limits: WriteLimits,
    pub(super) max_reply_bytes: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            timers: Timers::default(),
            tcp: tcp::Config::default(),
            max_pending_requests: 1024,
            max_server_transactions: 4096,
            max_client_transactions: 4096,
            max_client_request_bytes: 64 * 1024 * 1024,
            udp_write_limits: WriteLimits {
                messages: 1024,
                ..WriteLimits::default()
            },
            max_reply_bytes: 64 * 1024 * 1024,
        }
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
        Builder { udp: None, tcp: None, config: Config::default() }
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

    /// Sets outstanding write limits for each TCP connection.
    ///
    /// The defaults are 64 messages and 8 MiB. Counts and encoded bytes stay
    /// charged while queued, batched and partially written, until local
    /// completion or teardown. A saturated connection refuses new writes
    /// without waiting. Client sends report a transport error and one-shot
    /// replies report [`super::ReplyError::Busy`].
    ///
    /// ```
    /// use signa::{endpoint::Endpoint, transport::WriteLimits};
    /// let builder = Endpoint::builder().tcp_write_limits(WriteLimits {
    ///     messages: 128,
    ///     bytes: 16 * 1024 * 1024,
    /// });
    /// # drop(builder);
    /// ```
    pub fn tcp_write_limits(mut self, limits: WriteLimits) -> Builder {
        self.config.tcp.write_limits = limits;
        self
    }

    /// Sets outstanding write limits for the endpoint's UDP socket.
    ///
    /// The defaults are 1024 datagrams and 8 MiB of encoded bytes. A saturated
    /// socket refuses new writes without waiting. Capacity is returned after
    /// the local send attempt, including failures. These limits also apply
    /// to immediately writable sends, so a single datagram cannot exceed
    /// the byte budget. They do not promise delivery to a peer.
    ///
    /// ```
    /// use signa::{endpoint::Endpoint, transport::WriteLimits};
    /// let builder = Endpoint::builder().udp_write_limits(WriteLimits {
    ///     messages: 512,
    ///     bytes: 4 * 1024 * 1024,
    /// });
    /// # drop(builder);
    /// ```
    pub fn udp_write_limits(mut self, limits: WriteLimits) -> Builder {
        self.config.udp_write_limits = limits;
        self
    }

    /// Sets the aggregate encoded bytes of admitted one-shot replies.
    ///
    /// The default is 64 MiB. Reservation precedes encoding and command
    /// enqueue and lasts through connect setup and local write completion.
    /// Saturation returns [`super::ReplyError::Busy`] without enqueue.
    /// The existing limit of 64 outstanding one-shot replies also applies.
    /// A dropped completion future does not return either reservation.
    ///
    /// ```
    /// use signa::endpoint::Endpoint;
    /// let builder = Endpoint::builder().max_reply_bytes(16 * 1024 * 1024);
    /// # drop(builder);
    /// ```
    pub fn max_reply_bytes(mut self, limit: usize) -> Builder {
        self.config.max_reply_bytes = limit;
        self
    }

    /// Sets how many requests may wait for the service or be in its hands at
    /// once. A request beyond that gets a stateless 503. The default is 1024.
    pub fn max_pending_requests(mut self, limit: usize) -> Builder {
        self.config.max_pending_requests = limit;
        self
    }

    /// Sets how many server transactions may be retained at once.
    ///
    /// The default is 4096. The limit includes requests waiting for the
    /// service, requests in its hands and Completed entries. Over UDP a
    /// non-INVITE final response stays in the table for Timer J (64 T1,
    /// normally 32 seconds) to answer retransmissions, as required by
    /// [RFC 3261 section 17.2.2]. A full table refuses new transactions with
    /// a stateless 503. Existing retransmissions still match their transaction.
    ///
    /// Zero refuses all new stateful requests. Requests without an RFC 3261
    /// transaction key still use only [`Builder::max_pending_requests`].
    /// Neither limit caps response sizes or application-owned allocations.
    ///
    /// ```
    /// use signa::endpoint::Endpoint;
    ///
    /// let builder = Endpoint::builder()
    ///     .max_server_transactions(8192)
    ///     .max_pending_requests(512);
    /// # drop(builder);
    /// ```
    ///
    /// [RFC 3261 section 17.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.2
    pub fn max_server_transactions(mut self, limit: usize) -> Builder {
        self.config.max_server_transactions = limit;
        self
    }

    /// Sets how many client requests may be admitted at once, including
    /// queued commands, pending connects and live transactions. A request
    /// beyond that fails before enqueue with [`super::Error::is_busy`].
    /// The default is 4096. Zero refuses all client requests.
    ///
    /// Over UDP a transaction stays open for Timer K, which is T4 or 5 s,
    /// after its final response, to absorb retransmissions of it. So the limit
    /// bounds the requests of the last five seconds, not the ones still
    /// waiting for an answer.
    pub fn max_client_transactions(mut self, limit: usize) -> Builder {
        self.config.max_client_transactions = limit;
        self
    }

    /// Sets the aggregate logical bytes of admitted client requests.
    ///
    /// The default is 64 MiB. Zero refuses all client requests. The budget
    /// counts the input method, URI, version, header names/values and body.
    /// Capacity is reserved before command enqueue,
    /// held through connection setup and retransmissions, and released when
    /// the transaction drops its request. Saturation returns Busy.
    ///
    /// This measures content lengths, not application Extensions, shared
    /// backing allocations, generated Via metadata or allocator overhead.
    /// The transaction count separately bounds per-entry metadata. It is
    /// not a process memory ceiling.
    ///
    /// ```
    /// use signa::endpoint::Endpoint;
    ///
    /// let builder = Endpoint::builder()
    ///     .max_client_transactions(1024)
    ///     .max_client_request_bytes(16 * 1024 * 1024);
    /// # drop(builder);
    /// ```
    pub fn max_client_request_bytes(mut self, limit: usize) -> Builder {
        self.config.max_client_request_bytes = limit;
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
        let udp_addr = udp.as_ref().map(udp::Socket::local_addr);
        let tcp_addr = listener.as_ref().map(tcp::Listener::local_addr);

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
            commands.downgrade(),
        );
        let endpoint = Endpoint {
            client_admission: driver.client_admission(),
            commands,
            udp: udp_addr,
            tcp: tcp_addr,
        };
        tokio::spawn(driver.run());

        Ok(endpoint)
    }
}
