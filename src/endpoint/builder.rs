/*!
Endpoint configuration, socket binding and task startup.
*/

use std::{net::SocketAddr, time::Duration};

use tokio::sync::mpsc;

use super::{
    driver::{Driver, TCP_INBOUND},
    BindError, Endpoint, Incoming,
};
use crate::{
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
    pub(super) max_server_request_bytes: usize,
    pub(super) max_server_response_bytes: usize,
    pub(super) max_responder_bytes: usize,
    pub(super) max_responder_handles: usize,
    pub(super) max_outbound_connections: usize,
    pub(super) max_pending_connects: usize,
    pub(super) max_routes: usize,
    pub(super) fallback_limits: WriteLimits,
    pub(super) connect_timeout: Duration,
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
            max_server_request_bytes: 64 * 1024 * 1024,
            max_server_response_bytes: 64 * 1024 * 1024,
            max_responder_bytes: 64 * 1024 * 1024,
            max_responder_handles: 4096,
            max_outbound_connections: 1024,
            max_pending_connects: 64,
            max_routes: 4096,
            fallback_limits: WriteLimits {
                messages: 64,
                bytes: 8 * 1024 * 1024,
            },
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Configures and binds an [`Endpoint`] with one incoming event receiver.
///
/// # Example
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let (_endpoint, mut incoming) = signa::endpoint::Endpoint::builder()
///     .udp("127.0.0.1:5060".parse()?)
///     .max_pending_requests(256)
///     .bind()?;
/// let _event = incoming.recv().await;
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
    /// it is closed.
    ///
    /// The default is five minutes, which outlasts the RFC 5626 keepalive
    /// interval.
    pub fn idle_timeout(mut self, timeout: Duration) -> Builder {
        self.config.tcp.idle_timeout = timeout;
        self
    }

    /// Sets how many TCP connections the listener keeps open at once. More
    /// wait in the OS backlog.
    ///
    /// The default is 1024. The slot lasts through reader exit, writer drain
    /// and acknowledgement of writer abort.
    ///
    /// Outbound connections use [`Builder::max_outbound_connections`].
    pub fn max_connections(mut self, limit: usize) -> Builder {
        self.config.tcp.max_connections = limit;
        self
    }

    /// Sets the maximum connections opened for new client requests.
    ///
    /// The default is 1024. Connecting, reading, writing and draining all hold
    /// a slot. Exhaustion reports [`Error::is_busy`]. Accepted
    /// connections have the independent [`Builder::max_connections`] limit.
    /// Another 64 outbound slots are reserved for response fallback, so new
    /// client traffic cannot consume them. Zero disables new client connects.
    ///
    /// [`Error::is_busy`]: super::Error::is_busy
    pub fn max_outbound_connections(mut self, limit: usize) -> Builder {
        self.config.max_outbound_connections = limit;
        self
    }

    /// Sets concurrent client connection attempts, including unprocessed
    /// results.
    ///
    /// The default is 64. Responses have 64 separate attempt slots. A request
    /// joining an existing attempt needs no additional slot.
    pub fn max_pending_connects(mut self, limit: usize) -> Builder {
        self.config.max_pending_connects = limit;
        self
    }

    /// Sets the next-hop cache size available to new client requests.
    ///
    /// The default is 4096. Another 64 entries are reserved for response
    /// fallback. At capacity, unused UDP or closed TCP entries are evicted.
    /// Live or connecting entries are never evicted. A UDP source can be
    /// computed without caching when full. New TCP destinations report Busy.
    pub fn max_routes(mut self, limit: usize) -> Builder {
        self.config.max_routes = limit;
        self
    }

    /// Sets ordinary response fallback counts and encoded bytes.
    ///
    /// The defaults are 64 responses and 8 MiB, held from reconnect admission
    /// through local write completion or failure. This is independent of
    /// client request and one-shot reply admission. Saturated responses are
    /// dropped and counted by [`Endpoint::connection_stats`].
    ///
    /// [`Endpoint::connection_stats`]: super::Endpoint::connection_stats
    pub fn fallback_limits(mut self, limits: WriteLimits) -> Builder {
        self.config.fallback_limits = limits;
        self
    }

    /// Sets how long an outbound TCP connection attempt may take.
    ///
    /// The default is ten seconds. Endpoint teardown also cancels attempts.
    pub fn connect_timeout(mut self, timeout: Duration) -> Builder {
        self.config.connect_timeout = timeout;
        self
    }

    /// Sets outstanding write limits for each TCP connection.
    ///
    /// The defaults are 64 messages and 8 MiB. Counts and encoded bytes stay
    /// charged while queued, batched and partially written, until local
    /// completion or teardown. A saturated connection refuses new writes
    /// without waiting. New client requests leave one quarter of both limits
    /// (rounded down) for existing transaction output and responses. Client
    /// sends report a transport error and one-shot replies report
    /// [`ReplyError::Busy`].
    ///
    /// [`ReplyError::Busy`]: super::ReplyError::Busy
    ///
    /// # Example
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
    /// the byte budget. New client requests leave one quarter of both limits
    /// (rounded down) for existing transaction output and responses. These
    /// limits do not promise delivery to a peer.
    ///
    /// # Example
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
    /// Saturation returns [`ReplyError::Busy`] without enqueue.
    /// The existing limit of 64 outstanding one-shot replies also applies.
    /// A dropped completion future does not return either reservation.
    ///
    /// [`ReplyError::Busy`]: super::ReplyError::Busy
    ///
    /// # Example
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

    /// Sets how many received requests the application may have unanswered.
    ///
    /// The default is 1024, and it must be positive. A request counts from
    /// admission until its responder's final response is accepted or its
    /// transaction ends. An untracked request counts until its reply route
    /// sends a final response or every clone of the route is dropped. Taking
    /// the event with [`Incoming::recv`] does not end the count, so slow
    /// handlers hold capacity. A request still waiting in [`Incoming`] counts
    /// even after its transaction ends. A new request beyond the limit gets a
    /// stateless 503.
    pub fn max_pending_requests(mut self, limit: usize) -> Builder {
        self.config.max_pending_requests = limit;
        self
    }

    /// Sets how many server transactions may be retained at once.
    ///
    /// The default is 4096. Each tracked request holds an entry until its
    /// transaction ends. Over TCP that is the final response. Over UDP a
    /// non-INVITE final response stays in the table for Timer J (64 T1,
    /// normally 32 seconds) to answer retransmissions, as required by
    /// [RFC 3261 section 17.2.2]. A full table refuses new transactions with
    /// a stateless 503. Existing retransmissions still match their
    /// transaction.
    ///
    /// Zero refuses all new stateful requests. Requests without an RFC 3261
    /// transaction key do not count against this limit.
    ///
    /// # Example
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
    /// beyond that fails before enqueue with [`Error::is_busy`].
    /// The default is 4096. Zero refuses all client requests.
    ///
    /// Over UDP a transaction stays open for Timer K, which is T4 or 5 s,
    /// after its final response, to absorb retransmissions of it. So the limit
    /// bounds the requests of the last five seconds, not the ones still
    /// waiting for an answer.
    ///
    /// [`Error::is_busy`]: super::Error::is_busy
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
    /// # Example
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

    /// Sets how many bytes of request content the unanswered requests of
    /// [`Builder::max_pending_requests`] may hold.
    ///
    /// The default is 64 MiB, and it must be positive. It counts the request
    /// line, header names and values, and body of each request, not the
    /// allocations behind them. A request still waiting in [`Incoming`] counts
    /// even after its transaction ends. A new request beyond the limit gets a
    /// stateless 503.
    pub fn max_server_request_bytes(mut self, bytes: usize) -> Builder {
        self.config.max_server_request_bytes = bytes;
        self
    }

    /// Sets how many responders and reply routes the application may hold.
    ///
    /// The default is 4096, and it must be positive. Each admitted request
    /// creates one route, which its responder holds. Clones of a route share
    /// it, and it counts until the last clone drops, even after the request
    /// is answered. Keep routes only as long as needed, for example for UAS
    /// 2xx retransmission. A new request beyond the limit gets a stateless 503.
    pub fn max_responder_handles(mut self, limit: usize) -> Builder {
        self.config.max_responder_handles = limit;
        self
    }

    /// Sets how many bytes the routes of [`Builder::max_responder_handles`]
    /// may hold.
    ///
    /// The default is 64 MiB, and it must be positive. A route copies the
    /// request's Via, From, To, Call-ID and CSeq values to validate responses
    /// against them, without keeping the rest of the request. A new request
    /// beyond the limit gets a stateless 503.
    pub fn max_responder_bytes(mut self, bytes: usize) -> Builder {
        self.config.max_responder_bytes = bytes;
        self
    }

    /// Sets two separate byte limits on server responses.
    ///
    /// The default is 64 MiB, and it must be positive. One limit covers
    /// submitted responses waiting for the driver, together with a fixed
    /// count of 64. Beyond it, `respond` returns [`SubmitError::Busy`]. The
    /// other covers responses that server transactions keep for
    /// retransmission, which a Completed UDP transaction holds until Timer J.
    /// Beyond it, `respond` returns [`SubmitError::RetentionFull`].
    ///
    /// Neither changes the transaction. `Busy` clears as the driver takes
    /// queued responses, and `RetentionFull` as other transactions end, up to
    /// Timer J later. A single response larger than the limit always gets
    /// `Busy`. The 500 sent after a responder drop also needs retention, and
    /// without it the abandoned transaction ends unanswered.
    ///
    /// [`SubmitError::Busy`]: super::SubmitError::Busy
    /// [`SubmitError::RetentionFull`]: super::SubmitError::RetentionFull
    pub fn max_server_response_bytes(mut self, bytes: usize) -> Builder {
        self.config.max_server_response_bytes = bytes;
        self
    }

    /// Binds sockets and starts the protocol driver, returning its command
    /// handle and incoming event receiver. The endpoint spawns no handler
    /// tasks.
    ///
    /// Dropping the returned [`Incoming`] starts an immediate shutdown, so
    /// keep it for as long as the endpoint runs.
    ///
    /// # Panics
    ///
    /// Panics outside a tokio runtime, since the endpoint runs as a task on
    /// it.
    ///
    /// # Errors
    ///
    /// Returns a [`BindError`] for a socket that fails to bind, or an invalid
    /// configuration: a zero `max_pending_requests`,
    /// `max_server_request_bytes`, `max_responder_handles`,
    /// `max_responder_bytes` or `max_server_response_bytes`. Zero client,
    /// table and transport limits are valid and refuse that work instead.
    pub fn bind(self) -> Result<(Endpoint, Incoming), BindError> {
        for (reason, value) in [
            (
                "max_pending_requests must be positive",
                self.config.max_pending_requests,
            ),
            (
                "max_server_request_bytes must be positive",
                self.config.max_server_request_bytes,
            ),
            (
                "max_responder_handles must be positive",
                self.config.max_responder_handles,
            ),
            (
                "max_responder_bytes must be positive",
                self.config.max_responder_bytes,
            ),
            (
                "max_server_response_bytes must be positive",
                self.config.max_server_response_bytes,
            ),
        ] {
            if value == 0 {
                return Err(BindError::invalid_config(reason));
            }
        }

        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let udp = self
            .udp
            .map(udp::Socket::bind)
            .transpose()
            .map_err(BindError::io)?;
        let (tcp_tx, tcp_rx) = mpsc::channel(TCP_INBOUND);
        let listener = self
            .tcp
            .map(|addr| {
                tcp::Listener::bind(addr, self.config.tcp, tcp_tx.clone())
            })
            .transpose()
            .map_err(BindError::io)?;
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let udp_addr = udp.as_ref().map(udp::Socket::local_addr);
        let tcp_addr = listener.as_ref().map(tcp::Listener::local_addr);

        if let Some(listener) = listener {
            tokio::spawn(listener.run());
        }
        let driver = Driver::new(
            incoming_tx,
            self.config,
            udp,
            tcp_rx,
            tcp_tx,
            commands_rx,
            commands.downgrade(),
        );
        let endpoint = Endpoint {
            client_admission: driver.client_admission(),
            shutdown_control: driver.shutdown_control.clone(),
            control: driver.control.clone(),
            shutdown_wait: driver.shutdown_done.subscribe(),
            connection_stats: driver.connection_stats.clone(),
            commands,
            udp: udp_addr,
            tcp: tcp_addr,
        };
        let incoming = Incoming::new(
            incoming_rx,
            driver.shutdown_control.clone(),
            driver.control.clone(),
        );
        tokio::spawn(driver.run());

        Ok((endpoint, incoming))
    }
}
