/*!
The endpoint's transaction-user (TU) interface.

Binding returns a cloneable [`Endpoint`] and one cancellation-safe [`Incoming`]
receiver. The driver runs transport and transaction work. Application code owns
its receive loop and handler tasks. Incoming requests carry their
[`Flow`](crate::transport::Flow) in the envelope, and `Extensions` stays for
application data.

# Non-INVITE reception

[`IncomingEvent::Request`] owns a request and its [`ServerTransaction`]. Split
the transaction into a non-cloneable [`Responder`] and independent
[`ServerEvents`]. `respond` returns once the driver accepts the response, not
when the peer gets it. A final response may leave a UDP transaction in
Completed until Timer J. Every response other than 100 needs a To tag, which
[`response::Builder::to_tag`](crate::message::response::Builder::to_tag) adds.

Dropping an unanswered responder makes the driver send a 500. It reuses a To
tag already sent in a provisional response, or adds a random one. If the 500
cannot be admitted, the transaction ends, and a retransmission arrives as a new
request. This is signa's abandonment policy, not an RFC rule.

[`IncomingEvent::Untracked`] carries a one-shot [`ReplyRoute`] instead, for a
request without an RFC 3261 branch. Each retransmission of it arrives as a new
event.

The driver absorbs retransmissions and sends RFC 4320's automatic 100. INVITE
gets 501, CANCEL gets 481 and ACK is discarded until INVITE support lands. A
request without exactly one From, To, Call-ID and CSeq, or whose CSeq method
differs from its own, gets a stateless 400 and never reaches the application. A
request whose top Via has `maddr` is dropped, since its response would go to a
multicast group, which signa does not support.

Dropping [`Incoming`] starts an immediate shutdown. An application that only
sends requests keeps it anyway, because peers can still send it requests, such
as a BYE within a dialog.

# Admission and completion

Each limit below refuses a new request with a stateless 503 while existing
transactions go on:

* [`Builder::max_pending_requests`] and [`Builder::max_server_request_bytes`]
  bound unanswered requests and their content. A request counts until it has a
  final response or its transaction ends, not merely until `recv`.
* [`Builder::max_responder_handles`] and [`Builder::max_responder_bytes`] bound
  reply routes. A responder holds its request's route, and a route counts until
  its last clone drops.
* [`Builder::max_server_transactions`] bounds the transaction table, including
  Completed UDP entries kept for Timer J.

[`Builder::max_server_response_bytes`] bounds submitted and retained responses.
`respond` reports a full submission queue as [`SubmitError::Busy`], full
retention as [`SubmitError::RetentionFull`] and full transport output as
[`SubmitError::TransportBusy`], without changing the transaction. These limits
count message content, not allocations or memory the application keeps.

[`ServerEvents`] reports write failures, including those after a reliable final
response ends the transaction, and driver-generated output that local capacity
refused. A refused automatic 100 or retransmitted response leaves the
transaction live, so the peer's next retransmission can recover it. Missed
events are counted, and termination is never lost to them.
[`ServerEvent::Terminated`] marks the end of the transaction, and the stream
ends once its accepted writes finish. Dropping the observer has no protocol
effect. A responder drop is ordered after the submissions it already queued,
and a queued submission may still run after its waiting future is dropped.

# Client operations and shutdown

[`Endpoint::start`] accepts an explicit [`Target`] and returns split control
and response observation. All accepted provisional responses are delivered.
Client admission bounds commands, connects and live transactions. Initial sends
leave a quarter of output capacity for transaction output and responses. See
[`Builder::tcp_write_limits`], [`Builder::udp_write_limits`] and
[`Builder::fallback_limits`].

[`Endpoint::shutdown`] closes new admission and drains current work until the
earliest requested deadline. Once shutdown starts, new requests get a 503 and
existing reply routes and responders keep working while admitted work drains.

Transaction timers remain under [`crate::transaction`], without an endpoint
alias:

```compile_fail
use signa::endpoint::Timers;
```

# Example

This UAS answers each request with a 200. `to_tag` adds a fresh To tag to an
initial request's response and keeps the tag of a request within a dialog. It
ignores untracked requests, which then get no answer. A failed submission is
logged rather than returned, since leaving the loop would drop `incoming` and
shut the endpoint down.

```no_run
use bytes::Bytes;
use signa::{endpoint::{Endpoint, IncomingEvent}, message::header::Tag, Response};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let (_endpoint, mut incoming) = Endpoint::builder()
    .udp("127.0.0.1:5060".parse()?)
    .bind()?;

while let Some(event) = incoming.recv().await {
    if let IncomingEvent::Request(envelope) = event {
        let (responder, _) = envelope.transaction.into_parts();
        let response = Response::reply_to(&envelope.request)
            .status(200)
            .to_tag(Tag::random())
            .body(Bytes::new())?;

        if let Err(error) = responder.respond(response).await {
            eprintln!("response not accepted: {error}");
        }
    }
}
# Ok(())
# }
```
*/

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

#[cfg(feature = "__bench")]
use bytes::Bytes;
use tokio::sync::{mpsc, watch};

#[cfg(all(test, not(miri)))]
use self::client::compatibility::Client;
use self::{admission::ClientAdmission, driver::Command};
#[cfg(feature = "__bench")]
use self::{builder::Config, driver::Driver};
#[cfg(all(test, not(miri)))]
use crate::transport::Transport;
use crate::transport::{budget::Budget, WriteLimits};
#[cfg(feature = "__bench")]
use crate::{
    message::Request,
    transport::{tcp, udp},
};

pub use self::{
    builder::Builder,
    client::{
        ClientControl, ClientTransaction, ClientTransactionId, Responses,
        Target,
    },
    error::{BindError, Error},
    reply::{ReplyError, ReplyRoute},
    server::{
        Incoming, IncomingEvent, ReceivedRequest, Responder, ResponseId,
        ResponseSubmission, ServerEvent, ServerEvents, ServerRequest,
        ServerTransaction, ServerTransactionId, SubmitError,
    },
    shutdown::Shutdown,
};

mod admission;
mod builder;
mod client;
mod datagram;
mod driver;
mod error;
mod reply;
mod routing;
mod server;
mod shutdown;
mod table;
mod timer;

/// A handle to a running endpoint.
///
/// The endpoint runs while an `Endpoint`, [`ClientControl`], [`Responder`],
/// [`ReplyRoute`] or [`Shutdown`] exists, and while a one-shot reply is in
/// flight. [`ServerEvents`] and [`Incoming`] do not keep it running, and
/// dropping `Incoming` starts an immediate shutdown. When the last of those
/// handles drops, the driver stops, closes its sockets and drops its
/// transactions. [`Endpoint::shutdown`] stops it with a grace period instead.
///
/// See the [module docs](self) for what it does.
#[derive(Clone)]
pub struct Endpoint {
    commands: mpsc::UnboundedSender<Command>,
    client_admission: ClientAdmission,
    client_response_budget: Budget,
    client_handles: Budget,
    client_response_limits: WriteLimits,
    shutdown_control: Arc<shutdown::Control>,
    control: mpsc::Sender<()>,
    shutdown_wait: watch::Receiver<()>,
    connection_stats: Arc<driver::ConnectionCounters>,
    udp: Option<SocketAddr>,
    tcp: Option<SocketAddr>,
}

/// Cumulative connection-admission and ordinary fallback outcomes.
///
/// Counters saturate at `u64::MAX`. Snapshots can include concurrent updates
/// independently. They count local outcomes, not delivery to the SIP peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ConnectionStats {
    /// TCP submissions refused by route, connection or connect-attempt limits.
    pub rejected: u64,
    /// Ordinary fallback responses lost to admission, connect or write
    /// failure.
    ///
    /// Includes unfinished fallbacks discarded when the driver stops. One-shot
    /// replies report their own error and are not included.
    pub dropped: u64,
}

impl Endpoint {
    /// Returns connection-admission and ordinary fallback counters.
    ///
    /// ```no_run
    /// # fn inspect(endpoint: &signa::endpoint::Endpoint) {
    /// let stats = endpoint.connection_stats();
    /// println!("{} refusals, {} fallback drops", stats.rejected, stats.dropped);
    /// # }
    /// ```
    pub fn connection_stats(&self) -> ConnectionStats {
        use std::sync::atomic::Ordering;
        ConnectionStats {
            rejected: self.connection_stats.rejected.load(Ordering::Relaxed),
            dropped: self.connection_stats.dropped.load(Ordering::Relaxed),
        }
    }

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

    // See `client::compatibility`.
    #[cfg(all(test, not(miri)))]
    fn client(&self, transport: Transport, next_hop: SocketAddr) -> Client {
        Client::new(
            self.commands.clone(),
            self.client_admission.clone(),
            transport,
            next_hop,
        )
    }

    /// Stops the endpoint once what it has in hand is done, or after
    /// `timeout`, and returns a future that resolves when it has stopped.
    ///
    /// From this call on, the endpoint answers a new request with a 503 and
    /// rejects [`Endpoint::start`] with [`Error::is_closed`].
    /// It waits until every admitted request has a final response, its own
    /// requests have theirs, and pending writes and connects finish, then
    /// stops. It does not wait out Timer J. At `timeout` it stops regardless,
    /// and whatever still waits fails with [`Error::is_closed`]. See the
    /// [module docs](self#client-operations-and-shutdown).
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
        self.client_admission.close();
        if self.shutdown_control.request(timeout) {
            let _ = self.control.try_send(());
        }
        Shutdown::new(self.commands, self.shutdown_wait)
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

/// Connects a benchmark-supplied request and transports to the real driver.
///
/// Called inside a tokio runtime. Fixture messages, services, sockets and task
/// ownership belong to the external benchmark crate.
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub fn reply_driver(
    request: Request<Bytes>,
    flow: crate::transport::Flow,
    writer: Option<tcp::Writer>,
    udp: Option<udp::Socket>,
    tcp: mpsc::Receiver<tcp::Inbound>,
    tcp_tx: mpsc::Sender<tcp::Inbound>,
) -> Result<
    (Request<Bytes>, ReplyRoute, impl std::future::Future<Output = ()> + Send),
    ReplyError,
> {
    use self::routing::Link;

    let (commands, rx) = mpsc::unbounded_channel();
    let (incoming, _receiver) = mpsc::unbounded_channel();
    let driver = Driver::new(
        incoming,
        Config::default(),
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
        pin::{self, Pin},
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
            builder::Config,
            driver::{Command, Driver, TCP_INBOUND},
            error::Error,
            routing::Link,
            Builder, Endpoint, Incoming, IncomingEvent, ReplyError,
            ServerRequest, Target,
        },
        message::{
            header::{HeaderValue, Tag, CSEQ, TO, VIA},
            request::Request,
            response::Response,
            StatusCode,
        },
        transaction::Timers,
        transport::{tcp, udp, Flow, Transport, WriteLimits},
    };

    const LOCALHOST: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// Timers that make a test wait milliseconds instead of seconds. Timer F
    /// is 640 ms, and the 100 goes out after 70 ms.
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

    // RFC 3261 section 17.1.2 delivers provisional responses and the first
    // final. Timer K remains independent of response observation.
    #[tokio::test]
    async fn client_tu_reports_flow_via_provisionals_and_final_on_both_transports(
    ) {
        for transport in [Transport::Udp, Transport::Tcp] {
            let (server, mut incoming) = Endpoint::builder()
                .udp(LOCALHOST)
                .tcp(LOCALHOST)
                .bind()
                .unwrap();
            let target = Target::new(
                transport,
                if transport == Transport::Udp {
                    server.udp_addr().unwrap()
                } else {
                    server.tcp_addr().unwrap()
                },
            );
            let (endpoint, _incoming) =
                Endpoint::builder().udp(LOCALHOST).bind().unwrap();

            let transaction =
                endpoint.start(request("OPTIONS"), target).await.unwrap();
            let (control, mut responses) = transaction.into_parts();
            assert_eq!(control.flow().remote, target.address());
            assert_eq!(control.flow().transport, transport);
            assert_ne!(control.flow().local.port(), 0);

            let IncomingEvent::Request(envelope) =
                incoming.recv().await.unwrap()
            else {
                panic!("request")
            };
            assert!(envelope
                .request
                .headers()
                .get(VIA)
                .unwrap()
                .as_str()
                .contains(
                    control.via().as_str().split("branch=").nth(1).unwrap()
                ));

            let (responder, _) = envelope.transaction.into_parts();
            // Reliable non-INVITE transactions allow an immediate 100.
            if transport == Transport::Tcp {
                responder
                    .respond(
                        Response::reply_to(&envelope.request)
                            .status(100)
                            .body(Bytes::new())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    responses.next().await.unwrap().unwrap().status().as_u16(),
                    100
                );
            }
            responder
                .respond(
                    Response::reply_to(&envelope.request)
                        .status(200)
                        .to_tag(Tag::random())
                        .body(Bytes::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                responses.next().await.unwrap().unwrap().status(),
                StatusCode::OK
            );
            assert!(responses.next().await.is_none());
            assert!(responses.next().await.is_none());

            endpoint.shutdown(Duration::ZERO).await;
            server.shutdown(Duration::ZERO).await;
        }
    }

    #[tokio::test]
    async fn client_tu_overflow_does_not_end_the_machine_or_free_its_slot() {
        let mut peer = Peer::new().await;
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1)
            .client_response_limits(WriteLimits { messages: 1, bytes: 4096 })
            .bind()
            .unwrap();
        let target =
            Target::new(Transport::Udp, peer.socket.local_addr().unwrap());

        let (control, mut responses) = endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap()
            .into_parts();
        let wire = peer.recv().await.unwrap();
        let original = Request::from_bytes(wire.as_bytes()).unwrap();
        for _ in 0..2 {
            let provisional = Response::reply_to(&original)
                .status(100)
                .body(Bytes::new())
                .unwrap();
            peer.send(
                endpoint.udp_addr().unwrap(),
                std::str::from_utf8(&provisional.to_bytes()).unwrap(),
            )
            .await;
        }

        // Wait for another request retransmission so the driver has processed
        // the queued responses without requiring an application read.
        assert!(peer.recv().await.is_some());
        assert_eq!(
            responses.next().await.unwrap().unwrap().status().as_u16(),
            100
        );
        assert!(responses
            .next()
            .await
            .unwrap()
            .unwrap_err()
            .is_delivery_overflow());
        assert!(responses.next().await.is_none());

        drop(control);
        assert!(endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap_err()
            .is_busy());

        peer.send(
            endpoint.udp_addr().unwrap(),
            std::str::from_utf8(&ok(&original).to_bytes()).unwrap(),
        )
        .await;
        endpoint.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn client_tu_start_and_receive_cancellation_preserve_committed_work()
    {
        let mut peer = Peer::new().await;
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1)
            .bind()
            .unwrap();
        let target =
            Target::new(Transport::Udp, peer.socket.local_addr().unwrap());

        drop(endpoint.start(request("OPTIONS"), target));
        {
            let mut starting =
                pin::pin!(endpoint.start(request("OPTIONS"), target));
            future::poll_fn(|cx| {
                assert!(starting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }

        assert!(peer.recv().await.is_some());
        assert!(endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap_err()
            .is_busy());
        assert!(
            peer.recv().await.is_some(),
            "dropping start must not stop retransmission"
        );

        endpoint.shutdown(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn client_tu_observes_timeout_shutdown_and_held_handle_capacity() {
        let peer = Peer::new().await;
        let target =
            Target::new(Transport::Udp, peer.socket.local_addr().unwrap());
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_handles(1)
            .bind()
            .unwrap();

        let (control, mut responses) = endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap()
            .into_parts();
        assert!(responses.next().await.unwrap().unwrap_err().is_timeout());
        assert!(responses.next().await.is_none());

        drop(responses);
        assert!(endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap_err()
            .is_busy());

        drop(control);
        let (control, mut responses) = endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap()
            .into_parts();
        endpoint.shutdown(Duration::ZERO).await;
        assert!(responses.next().await.unwrap().unwrap_err().is_closed());
        assert!(responses.next().await.is_none());
        drop(control);
    }

    #[tokio::test]
    async fn client_tu_rejects_multicast_before_admission() {
        let (endpoint, _incoming) =
            Endpoint::builder().max_client_transactions(0).bind().unwrap();

        for address in ["224.0.0.1:5060", "[ff02::1]:5060"] {
            let error = endpoint
                .start(
                    request("OPTIONS"),
                    Target::new(Transport::Udp, address.parse().unwrap()),
                )
                .await
                .unwrap_err();
            assert!(error.is_unsupported_routing());
        }

        endpoint.shutdown(Duration::ZERO).await;
    }

    // RFC 3261 section 8.1.2 requires TLS for a SIPS Request-URI. Zero
    // client capacity makes any admitted request busy, so an unsupported
    // routing error shows the refusal came first, with nothing connected or
    // sent on either transport.
    #[tokio::test]
    async fn client_tu_refuses_a_sips_request_uri_before_admission() {
        let mut peer = Peer::new().await;
        let listener = TcpListener::bind(LOCALHOST).await.unwrap();
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .tcp(LOCALHOST)
            .max_client_transactions(0)
            .bind()
            .unwrap();
        let targets = [
            Target::new(Transport::Udp, peer.socket.local_addr().unwrap()),
            Target::new(Transport::Tcp, listener.local_addr().unwrap()),
        ];

        for target in targets {
            for uri in ["sips:bob@example.com", "SiPs:bob@example.com"] {
                for route in [None, Some("<sip:proxy.example.net;lr>")] {
                    let mut request = request("OPTIONS");
                    *request.uri_mut() = uri.parse().unwrap();
                    if let Some(route) = route {
                        request.headers_mut().append(
                            "Route".parse().unwrap(),
                            route.parse().unwrap(),
                        );
                    }

                    let error =
                        endpoint.start(request, target).await.unwrap_err();
                    assert!(error.is_unsupported_routing(), "{uri} {error}");
                }
            }
            let error =
                endpoint.start(request("OPTIONS"), target).await.unwrap_err();
            assert!(error.is_busy(), "{error}");
        }

        assert!(peer.recv().await.is_none());
        assert!(timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err());

        endpoint.shutdown(Duration::ZERO).await;
    }

    // signa's boundary. `start` sends to the explicit target, which is none
    // of the URIs in the request, and leaves the Request-URI and every Route
    // row as the caller built them. The request has the strict-routing form
    // of RFC 3261 section 12.2.1.1, where the top Route has `lr` but is not
    // the next hop. The hosts are never resolved.
    #[tokio::test]
    async fn client_tu_sends_to_the_target_with_request_uri_and_route_as_given(
    ) {
        const ROUTES: [&str; 2] = [
            "<sip:loose.example.net;lr>, <sip:edge.example.net;lr>",
            "<sip:bob@example.com>",
        ];
        let mut peer = Peer::new().await;
        let listener = TcpListener::bind(LOCALHOST).await.unwrap();
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .bind()
            .unwrap();

        for transport in [Transport::Udp, Transport::Tcp] {
            let target = Target::new(
                transport,
                if transport == Transport::Udp {
                    peer.socket.local_addr().unwrap()
                } else {
                    listener.local_addr().unwrap()
                },
            );
            let mut request = request("OPTIONS");
            *request.uri_mut() = "sip:strict.example.net".parse().unwrap();
            for route in ROUTES {
                request
                    .headers_mut()
                    .append("Route".parse().unwrap(), route.parse().unwrap());
            }

            let control = endpoint.start(request, target).await.unwrap();
            let (control, _responses) = control.into_parts();

            assert_eq!(control.flow().remote, target.address());
            let sent = if transport == Transport::Udp {
                Request::from_bytes(peer.recv().await.unwrap().as_bytes())
                    .unwrap()
            } else {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await
            };
            assert_eq!(sent.uri().as_str(), "sip:strict.example.net");
            let routes = sent
                .headers()
                .get_all("Route")
                .map(HeaderValue::as_str)
                .collect::<Vec<_>>();
            assert_eq!(routes, ROUTES);
        }

        endpoint.shutdown(Duration::ZERO).await;
    }

    // Without a TCP listener the Via names the connection's own port, so no
    // response can come once that connection closes.
    #[tokio::test]
    async fn client_tu_reports_tcp_eof_after_a_successful_request_write() {
        let listener = TcpListener::bind(LOCALHOST).await.unwrap();
        let (endpoint, _incoming) = Endpoint::builder().bind().unwrap();
        let target =
            Target::new(Transport::Tcp, listener.local_addr().unwrap());
        let (control, mut responses) = endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap()
            .into_parts();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 4096];
        assert!(peer.read(&mut buffer).await.unwrap() > 0);

        drop(peer);

        let error = timeout(Duration::from_secs(1), responses.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is_transport());
        assert!(responses.next().await.is_none());

        drop(control);
        endpoint.shutdown(Duration::ZERO).await;
    }

    // RFC 3261 sections 18.1.1 and 18.2.2. The client advertises its listener,
    // so a server whose connection closed answers on a new one.
    #[tokio::test]
    async fn client_tu_takes_a_tcp_response_on_a_connection_to_its_listener() {
        let server = TcpListener::bind(LOCALHOST).await.unwrap();
        let (endpoint, _incoming) = Endpoint::builder()
            .tcp(LOCALHOST)
            .timers(short_timers())
            .bind()
            .unwrap();
        let listener = endpoint.tcp_addr().unwrap();
        let target = Target::new(Transport::Tcp, server.local_addr().unwrap());
        let (control, mut responses) = endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap()
            .into_parts();
        let (mut peer, _) = server.accept().await.unwrap();
        let request = read_request(&mut peer).await;

        let via = control.via().as_str();
        assert!(
            via.starts_with(&format!(
                "SIP/2.0/TCP 127.0.0.1:{};",
                listener.port()
            )),
            "{via}"
        );
        assert_ne!(control.flow().local.port(), listener.port());
        assert_eq!(request.headers().get(VIA).unwrap(), control.via());

        drop(peer);
        sleep(Duration::from_millis(50)).await;
        let mut callback = TcpStream::connect(listener).await.unwrap();
        callback.write_all(&ok(&request).to_bytes()).await.unwrap();

        let response = timeout(Duration::from_secs(1), responses.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(responses.next().await.is_none());

        drop(control);
        endpoint.shutdown(Duration::ZERO).await;
    }

    // With a listener advertised, a closed connection is not the end of the
    // transaction. Timer F is, when no response comes another way.
    #[tokio::test]
    async fn client_tu_waits_for_timer_f_after_eof_when_it_has_a_listener() {
        let server = TcpListener::bind(LOCALHOST).await.unwrap();
        let (endpoint, _incoming) = Endpoint::builder()
            .tcp(LOCALHOST)
            .timers(short_timers())
            .bind()
            .unwrap();
        let target = Target::new(Transport::Tcp, server.local_addr().unwrap());
        let (control, mut responses) = endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap()
            .into_parts();
        let (mut peer, _) = server.accept().await.unwrap();
        read_request(&mut peer).await;

        drop(peer);

        let error = timeout(Duration::from_secs(2), responses.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is_timeout(), "{error}");
        assert!(responses.next().await.is_none());

        drop(control);
        endpoint.shutdown(Duration::ZERO).await;
    }

    /// Reads one request from a raw TCP peer.
    async fn read_request(stream: &mut TcpStream) -> Request<Bytes> {
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(1), async {
            loop {
                assert!(stream.read_buf(&mut bytes).await.unwrap() > 0);
                if let Ok(request) = Request::from_bytes(&bytes) {
                    break request;
                }
            }
        })
        .await
        .expect("a request within a second")
    }

    #[tokio::test]
    async fn reply_routes_keep_sending_while_existing_work_drains() {
        let mut peer = Peer::new().await;
        let (endpoint, mut incoming) =
            Endpoint::builder().udp(LOCALHOST).bind().unwrap();
        let to = endpoint.udp_addr().unwrap();
        peer.send(
            to,
            &peer.request(
                "OPTIONS",
                &format!(
                    "SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bKdrain;rport",
                    peer.port()
                ),
            ),
        )
        .await;
        let IncomingEvent::Request(envelope) = incoming.recv().await.unwrap()
        else {
            panic!("request")
        };
        let (responder, _) = envelope.transaction.into_parts();
        let route = responder.reply_route();

        let shutdown = endpoint.shutdown(Duration::from_secs(1));
        tokio::task::yield_now().await;

        let response = Response::reply_to(&envelope.request)
            .status(200)
            .to_tag(Tag::random())
            .body(Bytes::new())
            .unwrap();
        route.send(response.clone()).await.unwrap();
        assert!(peer.recv().await.unwrap().starts_with("SIP/2.0 200"));

        responder.respond(response).await.unwrap();
        shutdown.await;
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

    /// Application-side compatibility fixture for transport and client tests.
    pub(super) trait TestServe {
        fn serve<S>(self, service: S) -> std::io::Result<Endpoint>
        where
            S: Service<Request<Bytes>, Response = Response<Bytes>>
                + Send
                + 'static,
            S::Future: Send + 'static;
    }

    impl TestServe for Builder {
        fn serve<S>(self, mut service: S) -> std::io::Result<Endpoint>
        where
            S: Service<Request<Bytes>, Response = Response<Bytes>>
                + Send
                + 'static,
            S::Future: Send + 'static,
        {
            let (endpoint, mut incoming) = self.bind()?;
            tokio::spawn(async move {
                while let Some(event) = incoming.recv().await {
                    let (mut request, flow, responder, route) = match event {
                        IncomingEvent::Request(envelope) => {
                            let (responder, _) =
                                envelope.transaction.into_parts();
                            (
                                envelope.request,
                                envelope.flow,
                                Some(responder),
                                None,
                            )
                        }
                        IncomingEvent::Untracked(envelope) => (
                            envelope.request,
                            envelope.flow,
                            None,
                            Some(envelope.reply),
                        ),
                    };
                    request.extensions_mut().insert(flow);
                    if std::future::poll_fn(|cx| service.poll_ready(cx))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let future = service.call(request);

                    tokio::spawn(async move {
                        let response = future.await.ok();
                        if let Some(mut response) = response {
                            if let Some(to) = response.headers().get(TO) {
                                if !crate::message::header::address::has_tag(
                                    to.as_str(),
                                ) {
                                    let value =
                                        format!("{};tag=test", to.as_str());
                                    response.headers_mut().insert(
                                        TO,
                                        HeaderValue::from_bytes(
                                            value.as_bytes(),
                                        )
                                        .unwrap(),
                                    );
                                }
                            }
                            if let Some(responder) = responder {
                                let _ = responder.respond(response).await;
                            } else if let Some(route) = route {
                                let _ = route.send(response).await;
                            }
                        }
                    });
                }
            });

            Ok(endpoint)
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

    pub(super) struct DriverFixture {
        pub(super) driver: Driver,
        pub(super) incoming: Incoming,
    }

    impl std::ops::Deref for DriverFixture {
        type Target = Driver;

        fn deref(&self) -> &Driver {
            &self.driver
        }
    }

    impl std::ops::DerefMut for DriverFixture {
        fn deref_mut(&mut self) -> &mut Driver {
            &mut self.driver
        }
    }

    impl DriverFixture {
        pub(super) async fn run(self) {
            let Self { driver, incoming } = self;
            let _incoming = incoming;
            driver.run().await;
        }

        pub(super) fn take_request(&mut self) -> ServerRequest {
            let IncomingEvent::Request(request) =
                self.incoming.receiver.try_recv().unwrap().event
            else {
                panic!("tracked request");
            };
            request
        }
    }

    pub(super) fn reply_driver(
    ) -> (DriverFixture, mpsc::UnboundedSender<Command>, SocketAddr) {
        reply_driver_with(Config {
            timers: Timers::default(),
            tcp: tcp::Config::default(),
            max_pending_requests: 8,
            max_client_transactions: 8,
            ..Config::default()
        })
    }

    pub(super) fn reply_driver_with(
        config: Config,
    ) -> (DriverFixture, mpsc::UnboundedSender<Command>, SocketAddr) {
        let (commands, rx) = mpsc::unbounded_channel();
        let (tx, tcp) = mpsc::channel(TCP_INBOUND);
        let socket = udp::Socket::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let local = socket.local_addr();

        let (incoming, events) = mpsc::unbounded_channel();
        let driver = Driver::new(
            incoming,
            config,
            Some(socket),
            tcp,
            tx,
            rx,
            commands.downgrade(),
        );
        let incoming = Incoming::new(
            events,
            driver.shutdown_control.clone(),
            driver.control.clone(),
        );
        (DriverFixture { driver, incoming }, commands, local)
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
        Response::reply_to(request)
            .status(200)
            .to_tag("bob")
            .body(Bytes::new())
            .unwrap()
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
    async fn completed_servers_refuse_new_transactions_but_answer_retransmissions(
    ) {
        let service = Counting::default();
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .max_server_transactions(1)
            .serve(service.clone())
            .unwrap();
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let first = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bKfirst",
                peer.port(),
            ),
        );
        let second = first.replace("z9hG4bKfirst", "z9hG4bKsecond");

        peer.send(to, &first).await;
        let final_response = peer.recv().await.unwrap();
        assert!(final_response.starts_with("SIP/2.0 200 OK\r\n"));

        peer.send(to, &second).await;
        assert!(peer.recv().await.unwrap().starts_with("SIP/2.0 503 "));
        peer.send(to, &second).await;
        assert!(peer.recv().await.unwrap().starts_with("SIP/2.0 503 "));
        peer.send(to, &first).await;

        assert_eq!(peer.recv().await.unwrap(), final_response);
        assert_eq!(service.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reliable_server_finals_return_the_only_table_slot() {
        let service = Counting::default();
        let server = Endpoint::builder()
            .tcp(LOCALHOST)
            .max_server_transactions(1)
            .max_pending_requests(1)
            .serve(service.clone())
            .unwrap();
        let endpoint = Endpoint::builder().serve(Counting::default()).unwrap();
        let mut client =
            endpoint.client(Transport::Tcp, server.tcp_addr().unwrap());

        for _ in 0..40 {
            let response = timeout(
                Duration::from_secs(3),
                client.call(request("OPTIONS")),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        assert_eq!(service.requests.load(Ordering::SeqCst), 40);
    }

    #[tokio::test]
    async fn zero_server_capacity_still_allows_legacy_stateless_dispatch() {
        let service = Counting::default();
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .max_server_transactions(0)
            .serve(service.clone())
            .unwrap();
        let to = server.udp_addr().unwrap();
        let mut peer = Peer::new().await;
        let stateful = peer.request(
            "OPTIONS",
            &format!(
                "SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bKfirst",
                peer.port(),
            ),
        );
        let stateless = stateful.replace(";branch=z9hG4bKfirst", "");

        peer.send(to, &stateful).await;
        assert!(peer.recv().await.unwrap().starts_with("SIP/2.0 503 "));
        peer.send(to, &stateless).await;

        assert!(peer.recv().await.unwrap().starts_with("SIP/2.0 200 OK\r\n"));
        assert_eq!(service.requests.load(Ordering::SeqCst), 1);
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

        // No UDP socket to send from. The endpoint refuses before admission.
        let tcp_only = Endpoint::builder().serve(Counting::default()).unwrap();
        let err = tcp_only
            .start(
                self::request("OPTIONS"),
                Target::new(Transport::Udp, LOCALHOST),
            )
            .await
            .unwrap_err();
        assert!(err.is_unsupported_routing(), "{err}");

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
        // The peer never answers. Stop the driver by closing its command
        // channel, which drops the transaction that waits.
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
        /// Receives datagrams until a final response, or `None` when none
        /// comes.
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

        // A request after the call is refused. The one in flight is waited
        // for.
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

        // The endpoint is gone, so the connection ends at once rather than at
        // the idle timeout.
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

    #[tokio::test]
    async fn route_identity_is_owned_and_all_via_rows_are_preserved() {
        let (driver, _commands, local) = reply_driver();
        let link = udp_reply_link(local, "127.0.0.1:9".parse().unwrap());
        let mut original = route_request(
            "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
        );
        original.headers_mut().append(
            VIA,
            HeaderValue::from_static(
                "SIP/2.0/UDP older.example.com;branch=z9hG4bKolder",
            ),
        );

        let input = original.to_bytes();
        let original = Request::from_shared(input.clone()).unwrap();
        let (corrected, route) = driver.prepare_reply(original, link).unwrap();

        assert_eq!(corrected.headers().get_all(VIA).count(), 2);
        let encoded = route_response(&corrected).to_bytes();
        drop(corrected);

        assert!(input.is_unique());

        // The route remains usable after dropping the received message.
        let task = tokio::spawn(driver.run());
        route.send(Response::from_shared(encoded).unwrap()).await.unwrap();

        task.abort();
    }

    #[tokio::test]
    async fn final_responses_release_bytes_while_completed_entries_keep_count()
    {
        let timers =
            Timers::builder().t4(Duration::from_secs(60)).build().unwrap();
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .serve(Counting::default())
            .unwrap();
        let request = Request::builder()
            .method("OPTIONS")
            .uri("sip:example.com")
            .header("CSeq", "1 OPTIONS")
            .header("From", "<sip:alice@example.com>;tag=alice")
            .header("To", "<sip:bob@example.com>")
            .header("Call-ID", "bytes-lifetime")
            .body(Bytes::from_static(b"request"))
            .unwrap();
        let content_bytes =
            crate::endpoint::admission::request_bytes(&request).unwrap();

        let endpoint = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(timers)
            .max_client_transactions(2)
            .max_client_request_bytes(content_bytes)
            .serve(Counting::default())
            .unwrap();
        let mut client =
            endpoint.client(Transport::Udp, server.udp_addr().unwrap());

        for _ in 0..2 {
            let response =
                timeout(Duration::from_secs(3), client.call(request.clone()))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // Only one request fits the content budget, so the second response
        // proves bytes were released. Both Completed slots remain occupied.
        assert!(client.call(request).await.unwrap_err().is_busy());
    }

    #[tokio::test]
    async fn exhausted_write_bytes_report_busy_without_leaking_client_admission(
    ) {
        let service = Counting::default();
        let server = serve(service.clone());
        let limits = WriteLimits { messages: 1, bytes: 1 };
        let endpoint = Endpoint::builder()
            .udp(LOCALHOST)
            .max_client_transactions(1)
            .tcp_write_limits(limits)
            .udp_write_limits(limits)
            .serve(Counting::default())
            .unwrap();

        for (transport, remote) in [
            (Transport::Tcp, server.tcp_addr().unwrap()),
            (Transport::Udp, server.udp_addr().unwrap()),
        ] {
            let mut client = endpoint.client(transport, remote);
            for _ in 0..2 {
                let error = timeout(
                    Duration::from_secs(3),
                    client.call(request("OPTIONS")),
                )
                .await
                .unwrap()
                .unwrap_err();
                assert!(error.is_busy());
                assert!(std::error::Error::source(&error).is_none());
            }
        }

        assert_eq!(service.requests.load(Ordering::SeqCst), 0);
    }
}
