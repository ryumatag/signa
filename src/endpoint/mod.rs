/*!
The endpoint's transaction-user (TU) interface.

Binding returns a cloneable [`Endpoint`] and one cancellation-safe [`Incoming`]
receiver. The driver runs transport and transaction work. Application code owns
its receive loop and handler tasks. Incoming requests carry their
[`Flow`](crate::transport::Flow) in the envelope, and `Extensions` stays for
application data.

# Reception

[`IncomingEvent::Request`] owns a request and its [`ServerTransaction`]. Split
the transaction into a non-cloneable [`Responder`] and independent
[`ServerEvents`]. `respond` returns once the driver accepts the response, not
when the peer gets it. A final response may leave a UDP transaction in
Completed until Timer J. Every response other than 100 needs a To tag, which
[`response::Builder::to_tag`](crate::message::response::Builder::to_tag) adds.

An INVITE gets a 100 Trying from the driver as soon as it is admitted, and a
refused one gets a 503 without it. The TU sends provisional responses and a
final one. After a non-2xx the transaction retransmits it over UDP, absorbs its
ACK, and reports [`ServerEvent::AckTimeout`] if none comes. After a 2xx it
stays in Accepted for Timer L, takes further 2xx, including other forks', and
absorbs INVITE retransmissions without sending anything
([RFC 6026 section 8.7]). It does not retransmit a 2xx. A UAS does that through
[`Responder::reply_route`] until its ACK arrives
([RFC 3261 section 13.3.1.4]).

An ACK never gets a response. One for a non-2xx is the transaction's. One
for a 2xx, which matches an INVITE in Accepted or no transaction at all,
arrives as [`IncomingEvent::Ack`].

A CANCEL that matches a transaction, by branch and `sent-by`, arrives as
[`IncomingEvent::Cancel`] with its own transaction and its target's
[`ServerTransactionId`] ([RFC 3261 section 9.2]). The target may be a
non-INVITE request. The TU decides what the CANCEL means. A UAS answers it with
a 200 and a pending INVITE with a 487. A proxy cancels its branches. A CANCEL
without a target arrives as [`IncomingEvent::UnmatchedCancel`], with a reply
route and no automatic 481, since a stateful proxy may have to forward it
instead (section 16.10).

Dropping an unanswered responder makes the driver send a 500. It reuses a To
tag already sent in a provisional response, or adds a random one. If the 500
cannot be admitted, the transaction ends, and a retransmission arrives as a new
request. This is signa's abandonment policy, not an RFC rule.

[`IncomingEvent::Untracked`] carries a one-shot [`ReplyRoute`] instead, for a
request without an RFC 3261 branch. Each retransmission of it arrives as a new
event.

The driver absorbs retransmissions and sends RFC 4320's automatic 100 for a
non-INVITE. A request without exactly one From, To, Call-ID and CSeq, or whose
CSeq method differs from its own, gets a stateless 400, or nothing if it is an
ACK, and never reaches the application. A request whose top Via has `maddr` is
dropped, since its response would go to a multicast group, which signa does not
support.

[RFC 6026 section 8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
[RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
[RFC 3261 section 9.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2

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
  Completed UDP entries kept for Timer J and INVITEs kept for Timers I, H and
  L. An INVITE also holds the entry its CANCEL would take.

ACK and matched CANCEL events have their own count and byte limit,
[`Builder::control_event_limits`], so handlers that hold every ordinary slot
while they wait for an ACK or CANCEL do not stop it.

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
An INVITE also delivers every 2xx until Timer M, acknowledges a non-2xx itself,
and is cancelled with [`ClientControl::cancel`]. The TU acknowledges a 2xx
with [`Endpoint::send_request`]. Client admission bounds commands, connects and
live transactions, and reserves a CANCEL with each INVITE. Initial sends leave a
quarter of output capacity for transaction output and responses. See
[`Builder::tcp_write_limits`], [`Builder::udp_write_limits`] and
[`Builder::fallback_limits`].

[`Endpoint::shutdown`] closes new admission and drains current work until the
earliest requested deadline. Once shutdown starts, new requests get a 503 and
existing reply routes and responders keep working while admitted work drains.
Matched CANCELs, ACKs and `send_request` still work then. The drain does not
wait for INVITEs in Accepted or for their 2xx and ACKs yet.

Transaction timers remain under [`crate::transaction`], without an endpoint
alias:

```compile_fail
use signa::endpoint::Timers;
```

# Example

This UAS answers each non-INVITE request with a 200 and refuses INVITE.

`to_tag` adds a fresh To tag to an initial request's response and keeps the tag
of a request within a dialog. It ignores untracked requests, which then get no
answer. A failed submission is logged rather than returned, since leaving the
loop would drop `incoming` and shut the endpoint down.

```no_run
use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent},
    message::header::Tag,
    Method, Response,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let (_endpoint, mut incoming) = Endpoint::builder()
    .udp("127.0.0.1:5060".parse()?)
    .bind()?;

while let Some(event) = incoming.recv().await {
    if let IncomingEvent::Request(envelope) = event {
        // A 2xx to an INVITE starts a dialog, whose 2xx retransmissions and
        // ACK this loop does not handle.
        let status = if envelope.request.method() == Method::INVITE {
            501
        } else {
            200
        };
        let (responder, _) = envelope.transaction.into_parts();
        let response = Response::reply_to(&envelope.request)
            .status(status)
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
use tokio::sync::{mpsc, watch, Semaphore};

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
        CancelError, CancelOutcome, ClientControl, ClientTransaction,
        ClientTransactionId, Responses, Target,
    },
    error::{BindError, Error},
    reply::{ReplyError, ReplyRoute},
    send::{SentRequest, ViaMode},
    server::{
        Incoming, IncomingCancel, IncomingEvent, ReceivedAck, ReceivedRequest,
        Responder, ResponseId, ResponseSubmission, ServerEvent, ServerEvents,
        ServerRequest, ServerTransaction, ServerTransactionId, SubmitError,
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
mod send;
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
    /// The one-shot slots and bytes that reply routes share, for
    /// [`Endpoint::send_request`].
    oneshot_capacity: Arc<Semaphore>,
    oneshot_bytes: Budget,
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
    /// stops. It does not wait out Timer J, or Timer L or M of an INVITE that
    /// got a 2xx, so a 2xx retransmission or ACK after that finds the endpoint
    /// gone. At `timeout` it stops regardless,
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
        future::{self, poll_fn, Future, Ready},
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::{self, Pin},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
        time::{Duration, Instant},
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
            Builder, CancelError, CancelOutcome, Endpoint, Incoming,
            IncomingEvent, ReplyError, Responses, ServerEvent, ServerEvents,
            ServerRequest, SubmitError, Target, ViaMode,
        },
        message::{
            header::{HeaderValue, Tag, CALL_ID, CSEQ, FROM, ROUTE, TO, VIA},
            request::Request,
            response::Response,
            Message, Method, StatusCode,
        },
        transaction::Timers,
        transport::{budget::Budget, tcp, udp, Flow, Transport, WriteLimits},
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
                        // The final-only adapter has no use for ACK or
                        // CANCEL. A dropped CANCEL responder sends a 500.
                        _ => continue,
                    };
                    request.extensions_mut().insert(flow);
                    if poll_fn(|cx| service.poll_ready(cx)).await.is_err() {
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

        /// Receives one message, or `None` after 200 ms without one.
        async fn message(&mut self) -> Option<Message<Bytes>> {
            let received = self.recv().await?;
            Some(Message::from_bytes(received.as_bytes()).unwrap())
        }

        async fn send_message(&self, to: SocketAddr, message: &impl ToWire) {
            self.socket.send_to(&message.wire(), to).await.unwrap();
        }

        fn addr(&self) -> SocketAddr {
            self.socket.local_addr().unwrap()
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

    trait ToWire {
        fn wire(&self) -> Bytes;
    }

    impl ToWire for Request<Bytes> {
        fn wire(&self) -> Bytes {
            self.to_bytes()
        }
    }

    impl ToWire for Response<Bytes> {
        fn wire(&self) -> Bytes {
            self.to_bytes()
        }
    }

    impl ToWire for String {
        fn wire(&self) -> Bytes {
            Bytes::copy_from_slice(self.as_bytes())
        }
    }

    /// A raw TCP peer that takes one framed message at a time.
    struct Stream {
        stream: TcpStream,
        buf: Vec<u8>,
    }

    impl Stream {
        fn new(stream: TcpStream) -> Stream {
            Stream { stream, buf: Vec::new() }
        }

        async fn send(&mut self, message: &impl ToWire) {
            self.stream.write_all(&message.wire()).await.unwrap();
        }

        /// The next message, or `None` after `wait` without one or at EOF.
        async fn within(&mut self, wait: Duration) -> Option<Message<Bytes>> {
            timeout(wait, async {
                loop {
                    if let Some(message) = self.take() {
                        return message;
                    }
                    if self.stream.read_buf(&mut self.buf).await.unwrap() == 0
                    {
                        future::pending::<()>().await;
                    }
                }
            })
            .await
            .ok()
        }

        async fn next(&mut self) -> Message<Bytes> {
            self.within(Duration::from_secs(1)).await.expect("a message")
        }

        fn take(&mut self) -> Option<Message<Bytes>> {
            let head = self.buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
            let text = std::str::from_utf8(&self.buf[..head]).unwrap();
            let body = text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if self.buf.len() < head + body {
                return None;
            }
            let bytes: Vec<u8> = self.buf.drain(..head + body).collect();
            Some(Message::from_bytes(&bytes).unwrap())
        }
    }

    fn into_request(message: Message<Bytes>) -> Request<Bytes> {
        match message {
            Message::Request(request) => request,
            Message::Response(response) => {
                panic!("a request, got {response:?}")
            }
        }
    }

    fn into_response(message: Message<Bytes>) -> Response<Bytes> {
        match message {
            Message::Response(response) => response,
            Message::Request(request) => panic!("a response, got {request:?}"),
        }
    }

    /// An INVITE with a body and a route set, which its ACK and CANCEL must
    /// not copy and must copy respectively.
    pub(super) fn invite() -> Request<Bytes> {
        Request::builder()
            .method("INVITE")
            .uri("sip:bob@example.com")
            .header("From", "Alice <sip:alice@example.com>;tag=1928301774")
            .header("To", "Bob <sip:bob@example.com>")
            .header("Call-ID", "a84b4c76e66710@pc33.example.com")
            .header("CSeq", "314159 INVITE")
            .header("Max-Forwards", "70")
            .header(
                "Route",
                "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>",
            )
            .header("Content-Type", "application/sdp")
            .body(Bytes::from_static(b"v=0\r\n"))
            .unwrap()
    }

    /// A response to `request`, with a To tag unless it is a 100.
    pub(super) fn reply(
        request: &Request<Bytes>,
        code: u16,
        tag: &str,
    ) -> Response<Bytes> {
        let builder = Response::reply_to(request).status(code);
        let builder = if code == 100 { builder } else { builder.to_tag(tag) };
        builder.body(Bytes::new()).unwrap()
    }

    /// The ACK a UAC core builds for a 2xx, with the To of the 2xx.
    fn ack_for(
        invite: &Request<Bytes>,
        ok: &Response<Bytes>,
    ) -> Request<Bytes> {
        let mut builder = Request::builder()
            .method("ACK")
            .uri(invite.uri().as_str())
            .header("Max-Forwards", "70");
        for name in [FROM, CALL_ID] {
            builder = builder.header(
                name.as_str(),
                invite.headers().get(&name).unwrap().as_str(),
            );
        }
        let number = invite
            .headers()
            .get(CSEQ)
            .unwrap()
            .as_str()
            .split(' ')
            .next()
            .unwrap();
        builder
            .header("To", ok.headers().get(TO).unwrap().as_str())
            .header("CSeq", format!("{number} ACK").as_str())
            .body(Bytes::new())
            .unwrap()
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

    /// An endpoint handle on a driver that a test runs by hand.
    pub(super) fn fixture_endpoint(
        fixture: &DriverFixture,
        commands: mpsc::UnboundedSender<Command>,
        udp: SocketAddr,
    ) -> Endpoint {
        Endpoint {
            commands,
            client_admission: fixture.client_admission(),
            client_response_budget: Budget::new(WriteLimits {
                messages: 64,
                bytes: 1 << 20,
            }),
            client_handles: Budget::new(WriteLimits {
                messages: 64,
                bytes: usize::MAX,
            }),
            client_response_limits: WriteLimits {
                messages: 16,
                bytes: 1 << 16,
            },
            shutdown_control: fixture.shutdown_control.clone(),
            control: fixture.control.clone(),
            shutdown_wait: fixture.shutdown_done.subscribe(),
            connection_stats: fixture.connection_stats.clone(),
            oneshot_capacity: fixture.oneshot_capacity(),
            oneshot_bytes: fixture.oneshot_bytes(),
            udp: Some(udp),
            tcp: None,
        }
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

    /// The far side of a transaction, over either transport.
    enum Remote {
        Udp(Peer, SocketAddr),
        Tcp(Stream),
    }

    impl Remote {
        async fn send(&mut self, message: &impl ToWire) {
            match self {
                Remote::Udp(peer, to) => peer.send_message(*to, message).await,
                Remote::Tcp(stream) => stream.send(message).await,
            }
        }

        /// The next message, or `None` after 200 ms without one.
        async fn next(&mut self) -> Option<Message<Bytes>> {
            match self {
                Remote::Udp(peer, _) => peer.message().await,
                Remote::Tcp(stream) => {
                    stream.within(Duration::from_millis(200)).await
                }
            }
        }

        /// As `next`, skipping retransmissions of `method`.
        async fn next_except(
            &mut self,
            method: &str,
        ) -> Option<Message<Bytes>> {
            loop {
                let message = self.next().await?;
                let skipped = matches!(
                    &message,
                    Message::Request(request) if request.method() == method
                );
                if !skipped {
                    return Some(message);
                }
            }
        }
    }

    /// A UAS for client tests, listening on UDP and TCP.
    struct Far {
        udp: Peer,
        tcp: TcpListener,
    }

    impl Far {
        async fn new() -> Far {
            Far {
                udp: Peer::new().await,
                tcp: TcpListener::bind(LOCALHOST).await.unwrap(),
            }
        }

        fn target(&self, transport: Transport) -> Target {
            Target::new(
                transport,
                match transport {
                    Transport::Udp => self.udp.addr(),
                    Transport::Tcp => self.tcp.local_addr().unwrap(),
                },
            )
        }

        /// The side of the connection the endpoint opened, or of its socket.
        async fn remote(
            self,
            transport: Transport,
            endpoint: &Endpoint,
        ) -> Remote {
            match transport {
                Transport::Udp => {
                    Remote::Udp(self.udp, endpoint.udp_addr().unwrap())
                }
                Transport::Tcp => {
                    let (stream, _) = self.tcp.accept().await.unwrap();
                    Remote::Tcp(Stream::new(stream))
                }
            }
        }
    }

    /// The next response, which must come within a second.
    async fn next(responses: &mut Responses) -> Response<Bytes> {
        timeout(Duration::from_secs(1), responses.next())
            .await
            .expect("a response within a second")
            .expect("an open stream")
            .unwrap()
    }

    fn invite_endpoint(timers: Timers) -> (Endpoint, Incoming) {
        Endpoint::builder()
            .udp(LOCALHOST)
            .tcp(LOCALHOST)
            .timers(timers)
            .bind()
            .unwrap()
    }

    // RFC 3261 sections 17.1.1.2 and 17.1.1.3. The TU sees each provisional
    // response and the first non-2xx final. The transaction acknowledges that
    // final and each retransmission of it, with the INVITE's routing and the
    // final's To, and delivers it once.
    #[tokio::test]
    async fn invite_client_acknowledges_a_non_2xx_on_both_transports() {
        for transport in [Transport::Udp, Transport::Tcp] {
            let (endpoint, _incoming) = invite_endpoint(Timers::default());
            let far = Far::new().await;
            let target = far.target(transport);

            let (control, mut responses) =
                endpoint.start(invite(), target).await.unwrap().into_parts();
            let mut remote = far.remote(transport, &endpoint).await;
            let sent = into_request(remote.next().await.unwrap());
            assert_eq!(sent.headers().get(VIA), Some(control.via()));
            assert_eq!(sent.body().as_ref(), b"v=0\r\n");

            for code in [100, 180, 183] {
                remote.send(&reply(&sent, code, "early")).await;
                assert_eq!(next(&mut responses).await.status().as_u16(), code);
            }
            let busy = reply(&sent, 486, "busy");
            remote.send(&busy).await;
            assert_eq!(next(&mut responses).await.status().as_u16(), 486);
            assert!(responses.next().await.is_none());

            let ack = into_request(remote.next().await.unwrap());
            assert_eq!(ack.method(), Method::ACK);
            assert_eq!(ack.uri().as_str(), sent.uri().as_str());
            assert_eq!(
                ack.headers().get_all(VIA).collect::<Vec<_>>(),
                [control.via()]
            );
            assert_eq!(ack.headers().get(CSEQ).unwrap(), "314159 ACK");
            assert_eq!(ack.headers().get(TO), busy.headers().get(TO));
            for name in [FROM, CALL_ID] {
                assert_eq!(
                    ack.headers().get(&name),
                    sent.headers().get(&name)
                );
            }
            assert_eq!(
                ack.headers().get_all(ROUTE).collect::<Vec<_>>(),
                sent.headers().get_all(ROUTE).collect::<Vec<_>>()
            );
            assert!(ack.body().is_empty());

            if transport == Transport::Udp {
                remote.send(&busy).await;
                let again = into_request(remote.next().await.unwrap());
                assert_eq!(again.to_bytes(), ack.to_bytes());
            }
            assert!(responses.next().await.is_none());
            assert!(matches!(
                control.cancel().await,
                Ok(CancelOutcome::NotNeeded)
            ));

            endpoint.shutdown(Duration::ZERO).await;
        }
    }

    // RFC 6026 section 8.4 and RFC 3261 section 13.2.2.4. Every 2xx reaches
    // the TU until Timer M, including retransmissions and other forks, and
    // the TU acknowledges each with an ACK of its own. signa sends none.
    #[tokio::test]
    async fn invite_client_delivers_forked_2xx_until_timer_m_for_the_tu_to_ack(
    ) {
        for transport in [Transport::Udp, Transport::Tcp] {
            let (endpoint, _incoming) = invite_endpoint(short_timers());
            let far = Far::new().await;
            let target = far.target(transport);

            let (control, mut responses) =
                endpoint.start(invite(), target).await.unwrap().into_parts();
            let mut remote = far.remote(transport, &endpoint).await;
            let sent = into_request(remote.next().await.unwrap());

            remote.send(&reply(&sent, 180, "a")).await;
            assert_eq!(next(&mut responses).await.status().as_u16(), 180);
            let first = reply(&sent, 200, "a");
            let second = reply(&sent, 200, "b");
            for ok in [&first, &second, &first] {
                remote.send(ok).await;
                let response = next(&mut responses).await;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers().get(TO), ok.headers().get(TO));
            }
            assert!(remote.next_except("INVITE").await.is_none());

            for ok in [&first, &second] {
                let sent_ack = endpoint
                    .send_request(ack_for(&sent, ok), target, ViaMode::Fresh)
                    .await
                    .unwrap();
                let ack =
                    into_request(remote.next_except("INVITE").await.unwrap());
                assert_eq!(ack.method(), Method::ACK);
                assert_eq!(ack.headers().get(VIA), Some(sent_ack.via()));
                assert_ne!(sent_ack.via(), control.via());
                assert_eq!(sent_ack.flow().remote, target.address());
                assert_eq!(ack.headers().get(TO), ok.headers().get(TO));
            }

            // Timer M ends observation without an error.
            let end = timeout(Duration::from_secs(2), responses.next()).await;
            assert!(end.unwrap().is_none());

            endpoint.shutdown(Duration::ZERO).await;
        }
    }

    // A full response stream stops observation, not the machine. The non-2xx
    // is still acknowledged.
    #[tokio::test]
    async fn invite_client_overflow_keeps_acknowledging() {
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .client_response_limits(WriteLimits { messages: 1, bytes: 4096 })
            .bind()
            .unwrap();
        let far = Far::new().await;
        let target = far.target(Transport::Udp);
        let (_control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());

        remote.send(&reply(&sent, 180, "a")).await;
        remote.send(&reply(&sent, 183, "a")).await;
        sleep(Duration::from_millis(50)).await;
        remote.send(&reply(&sent, 486, "a")).await;

        assert_eq!(next(&mut responses).await.status().as_u16(), 180);
        let error = responses.next().await.unwrap().unwrap_err();
        assert!(error.is_delivery_overflow(), "{error}");
        assert!(responses.next().await.is_none());
        let ack = into_request(remote.next().await.unwrap());
        assert_eq!(ack.method(), Method::ACK);
    }

    // An INVITE reserves its CANCEL, so new requests cannot take what a
    // cancellation needs.
    #[tokio::test]
    async fn invite_admission_reserves_a_cancel() {
        let (endpoint, _incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .max_client_transactions(2)
            .bind()
            .unwrap();
        let far = Far::new().await;
        let target = far.target(Transport::Udp);

        let (control, _responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        assert!(endpoint.start(invite(), target).await.unwrap_err().is_busy());
        assert!(endpoint
            .start(request("OPTIONS"), target)
            .await
            .unwrap_err()
            .is_busy());

        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());
        remote.send(&reply(&sent, 180, "a")).await;
        sleep(Duration::from_millis(50)).await;
        let Ok(CancelOutcome::Sent(_)) = control.cancel().await else {
            panic!("a CANCEL within the reservation");
        };
        let cancel = into_request(remote.next().await.unwrap());
        assert_eq!(cancel.method(), Method::CANCEL);
    }

    /// A request from a raw UAC, with `via` and the To tag of the response
    /// an ACK acknowledges.
    fn raw(method: &str, via: &str, to_tag: Option<&str>) -> String {
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@example.com>;tag={tag}"),
            None => "<sip:bob@example.com>".to_owned(),
        };
        format!(
            "{method} sip:bob@example.com SIP/2.0\r\n\
             Via: {via}\r\n\
             From: <sip:alice@example.com>;tag=uac\r\n\
             To: {to}\r\n\
             Call-ID: raw-call\r\n\
             CSeq: 1 {method}\r\n\
             Max-Forwards: 70\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// A raw UAC of `endpoint` and the Via of its requests with `branch`.
    async fn uac(
        transport: Transport,
        endpoint: &Endpoint,
        branch: &str,
    ) -> (Remote, String) {
        match transport {
            Transport::Udp => {
                let peer = Peer::new().await;
                let via = format!(
                    "SIP/2.0/UDP {};branch=z9hG4bK{branch};rport",
                    peer.addr()
                );
                (Remote::Udp(peer, endpoint.udp_addr().unwrap()), via)
            }
            Transport::Tcp => {
                let stream = TcpStream::connect(endpoint.tcp_addr().unwrap())
                    .await
                    .unwrap();
                let via = format!(
                    "SIP/2.0/TCP {};branch=z9hG4bK{branch}",
                    stream.local_addr().unwrap()
                );
                (Remote::Tcp(Stream::new(stream)), via)
            }
        }
    }

    async fn event(incoming: &mut Incoming) -> IncomingEvent {
        timeout(Duration::from_secs(1), incoming.recv())
            .await
            .expect("an event within a second")
            .expect("an open endpoint")
    }

    async fn server_request(incoming: &mut Incoming) -> ServerRequest {
        match event(incoming).await {
            IncomingEvent::Request(request) => request,
            other => panic!("a request, got {other:?}"),
        }
    }

    async fn server_event(events: &mut ServerEvents) -> ServerEvent {
        timeout(Duration::from_secs(2), events.next())
            .await
            .expect("an event within two seconds")
            .expect("an open observation")
    }

    fn status_of(message: Option<Message<Bytes>>) -> u16 {
        into_response(message.expect("a response")).status().as_u16()
    }

    // RFC 3261 section 17.2.1. An admitted INVITE gets a 100 at once, takes
    // provisional responses, and absorbs the ACK of its non-2xx final.
    #[tokio::test]
    async fn invite_server_sends_100_and_absorbs_the_non_2xx_ack() {
        for transport in [Transport::Udp, Transport::Tcp] {
            let (endpoint, mut incoming) = invite_endpoint(short_timers());
            let (mut remote, via) = uac(transport, &endpoint, "invite").await;
            let invite = raw("INVITE", &via, None);

            remote.send(&invite).await;
            assert_eq!(status_of(remote.next().await), 100);
            let ServerRequest { request, transaction, .. } =
                server_request(&mut incoming).await;
            assert_eq!(request.method(), Method::INVITE);
            let (responder, mut events) = transaction.into_parts();

            for code in [180, 183] {
                responder.respond(reply(&request, code, "uas")).await.unwrap();
                assert_eq!(status_of(remote.next().await), code);
            }
            if transport == Transport::Udp {
                remote.send(&invite).await;
                assert_eq!(status_of(remote.next().await), 183);
            }
            responder.respond(reply(&request, 486, "uas")).await.unwrap();
            assert_eq!(status_of(remote.next().await), 486);
            for code in [180, 200, 486] {
                assert_eq!(
                    responder.respond(reply(&request, code, "uas")).await,
                    Err(SubmitError::FinalAlreadySent)
                );
            }

            remote.send(&raw("ACK", &via, Some("uas"))).await;
            assert!(matches!(
                server_event(&mut events).await,
                ServerEvent::Terminated
            ));
            assert!(timeout(Duration::from_millis(50), incoming.recv())
                .await
                .is_err());

            endpoint.shutdown(Duration::ZERO).await;
        }
    }

    // RFC 6026 section 8.7. Accepted takes further 2xx, including another
    // fork's, absorbs INVITE retransmissions without sending anything, and
    // hands every ACK to the TU. Timer L ends it, not the ACK.
    #[tokio::test]
    async fn invite_server_takes_forked_2xx_and_hands_acks_to_the_tu() {
        for transport in [Transport::Udp, Transport::Tcp] {
            let (endpoint, mut incoming) = invite_endpoint(short_timers());
            let (mut remote, via) = uac(transport, &endpoint, "forked").await;
            let invite = raw("INVITE", &via, None);
            remote.send(&invite).await;
            assert_eq!(status_of(remote.next().await), 100);
            let ServerRequest { request, transaction, .. } =
                server_request(&mut incoming).await;
            let (responder, mut events) = transaction.into_parts();

            let accepted = Instant::now();
            for tag in ["a", "b"] {
                responder.respond(reply(&request, 200, tag)).await.unwrap();
                let ok = into_response(remote.next().await.unwrap());
                assert_eq!(
                    ok.headers().get(TO).unwrap().as_str(),
                    format!("<sip:bob@example.com>;tag={tag}")
                );
            }
            for code in [180, 486] {
                assert_eq!(
                    responder.respond(reply(&request, code, "a")).await,
                    Err(SubmitError::FinalAlreadySent)
                );
            }
            if transport == Transport::Udp {
                remote.send(&invite).await;
                assert!(remote.next().await.is_none());
            }

            // An ACK with the INVITE's branch matches Accepted. One with its
            // own branch, as RFC 3261 sends, matches nothing.
            let fresh =
                via.replace("branch=z9hG4bKforked", "branch=z9hG4bKack");
            for via in [&via, &fresh] {
                remote.send(&raw("ACK", via, Some("a"))).await;
                let IncomingEvent::Ack(ack) = event(&mut incoming).await
                else {
                    panic!("an ACK for the TU");
                };
                assert_eq!(ack.request.method(), Method::ACK);
            }
            drop(responder);
            assert!(remote.next().await.is_none());

            // The machine-level and driver tests pin L exactly. Here it is
            // enough that neither the ACK nor the second 2xx ended it.
            assert!(matches!(
                server_event(&mut events).await,
                ServerEvent::Terminated
            ));
            assert!(accepted.elapsed() >= 64 * short_timers().t1());

            endpoint.shutdown(Duration::ZERO).await;
        }
    }

    // RFC 3261 section 17.2.1. Timer G retransmits the non-2xx over UDP, and
    // Timer H reports the missing ACK before the transaction ends.
    #[tokio::test]
    async fn invite_server_reports_a_missing_ack_at_timer_h() {
        let (endpoint, mut incoming) = invite_endpoint(short_timers());
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "h").await;
        remote.send(&raw("INVITE", &via, None)).await;
        assert_eq!(status_of(remote.next().await), 100);
        let ServerRequest { request, transaction, .. } =
            server_request(&mut incoming).await;
        let (responder, mut events) = transaction.into_parts();

        responder.respond(reply(&request, 486, "uas")).await.unwrap();
        for _ in 0..3 {
            assert_eq!(status_of(remote.next().await), 486);
        }

        assert!(matches!(
            server_event(&mut events).await,
            ServerEvent::AckTimeout
        ));
        assert!(matches!(
            server_event(&mut events).await,
            ServerEvent::Terminated
        ));
        assert!(events.next().await.is_none());
    }

    // signa's abandonment policy applies to an INVITE too. The 500 keeps the
    // To tag of the provisional response, and the ACK of the 500 is absorbed.
    #[tokio::test]
    async fn a_dropped_invite_responder_sends_a_500_with_the_provisional_tag()
    {
        let (endpoint, mut incoming) = invite_endpoint(Timers::default());
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "drop").await;
        remote.send(&raw("INVITE", &via, None)).await;
        assert_eq!(status_of(remote.next().await), 100);
        let ServerRequest { request, transaction, .. } =
            server_request(&mut incoming).await;
        let (responder, _events) = transaction.into_parts();
        responder.respond(reply(&request, 180, "ringing")).await.unwrap();
        assert_eq!(status_of(remote.next().await), 180);

        drop(responder);

        let error = into_response(remote.next().await.unwrap());
        assert_eq!(error.status().as_u16(), 500);
        assert_eq!(
            error.headers().get(TO).unwrap(),
            "<sip:bob@example.com>;tag=ringing"
        );
        remote.send(&raw("ACK", &via, Some("ringing"))).await;
        assert!(remote.next().await.is_none());
        assert!(timeout(Duration::from_millis(50), incoming.recv())
            .await
            .is_err());
    }

    // RFC 6026 section 8.8. A response transport failure is reported, and
    // the INVITE stays in Accepted for further 2xx.
    #[tokio::test]
    async fn invite_server_keeps_accepted_after_a_transport_failure() {
        let (endpoint, mut incoming) = invite_endpoint(Timers::default());
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "error").await;
        remote.send(&raw("INVITE", &via, None)).await;
        assert_eq!(status_of(remote.next().await), 100);
        let ServerRequest { request, transaction, .. } =
            server_request(&mut incoming).await;
        let (responder, mut events) = transaction.into_parts();

        // This fits the byte quotas but exceeds the UDP payload maximum.
        let mut large = reply(&request, 200, "a");
        *large.body_mut() = Bytes::from(vec![0; 80 * 1024]);
        let submission = responder.respond(large);
        let operation = submission.id();
        submission.await.unwrap();
        let ServerEvent::TransportFailure { operation: failed, .. } =
            server_event(&mut events).await
        else {
            panic!("a transport failure");
        };
        assert_eq!(failed, Some(operation));

        responder.respond(reply(&request, 200, "b")).await.unwrap();
        assert_eq!(status_of(remote.next().await), 200);
        assert!(timeout(Duration::from_millis(50), events.next())
            .await
            .is_err());
    }

    // RFC 3261 section 17. No ACK gets a response. One that matches no
    // transaction, even without an RFC 3261 branch, goes to the TU. One
    // without a usable identity is discarded.
    #[tokio::test]
    async fn acks_never_get_a_response() {
        let (endpoint, mut incoming) = invite_endpoint(Timers::default());
        let (mut remote, via) =
            uac(Transport::Udp, &endpoint, "unmatched").await;
        let untracked = via.replace("branch=z9hG4bKunmatched", "branch=1");

        for via in [&via, &untracked] {
            remote.send(&raw("ACK", via, Some("x"))).await;
            let IncomingEvent::Ack(ack) = event(&mut incoming).await else {
                panic!("an ACK for the TU");
            };
            assert_eq!(ack.flow.transport, Transport::Udp);
        }
        let broken =
            raw("ACK", &via, Some("x")).replace("Call-ID: raw-call\r\n", "");
        remote.send(&broken).await;
        assert!(timeout(Duration::from_millis(50), incoming.recv())
            .await
            .is_err());
        assert!(remote.next().await.is_none());
    }

    // Ordinary admission is full and the TU holds an INVITE, waiting for its
    // ACK or CANCEL. Both still reach the TU, through their own capacity.
    #[tokio::test]
    async fn ack_and_cancel_progress_while_ordinary_admission_is_full() {
        let (endpoint, mut incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .max_pending_requests(1)
            .bind()
            .unwrap();
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "held").await;
        remote.send(&raw("INVITE", &via, None)).await;
        assert_eq!(status_of(remote.next().await), 100);
        let held = server_request(&mut incoming).await;
        let target = held.transaction.id();

        let (mut other, other_via) =
            uac(Transport::Udp, &endpoint, "new").await;
        other.send(&raw("OPTIONS", &other_via, None)).await;
        assert_eq!(status_of(other.next().await), 503);

        other.send(&raw("ACK", &other_via, Some("x"))).await;
        assert!(matches!(event(&mut incoming).await, IncomingEvent::Ack(_)));
        assert!(other.next().await.is_none());

        remote.send(&raw("CANCEL", &via, None)).await;
        let IncomingEvent::Cancel(cancel) = event(&mut incoming).await else {
            panic!("a matched CANCEL");
        };
        assert_eq!(cancel.target, target);
        let (responder, _) = cancel.transaction.into_parts();
        responder.respond(reply(&cancel.request, 200, "uas")).await.unwrap();
        assert_eq!(status_of(remote.next().await), 200);
        drop(held);
    }

    // Control capacity is finite as well. An ACK beyond it is discarded
    // without a response, and capacity returns once the TU takes the event.
    #[tokio::test]
    async fn control_capacity_discards_acks_beyond_it() {
        let (endpoint, mut incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .control_event_limits(WriteLimits { messages: 1, bytes: 4096 })
            .bind()
            .unwrap();
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "full").await;
        for tag in ["first", "second"] {
            remote.send(&raw("ACK", &via, Some(tag))).await;
        }
        sleep(Duration::from_millis(50)).await;

        let IncomingEvent::Ack(ack) = event(&mut incoming).await else {
            panic!("the first ACK");
        };
        assert!(ack
            .request
            .headers()
            .get(TO)
            .unwrap()
            .as_str()
            .ends_with("first"));
        assert!(timeout(Duration::from_millis(50), incoming.recv())
            .await
            .is_err());
        assert!(remote.next().await.is_none());

        remote.send(&raw("ACK", &via, Some("third"))).await;
        assert!(matches!(event(&mut incoming).await, IncomingEvent::Ack(_)));
    }

    // A shutdown refuses new requests with a 503 but still hands the TU an
    // ACK, and never answers it. The unanswered INVITE keeps the endpoint
    // draining. Draining Accepted transactions themselves is later work.
    #[tokio::test]
    async fn acks_reach_the_tu_during_shutdown_without_a_response() {
        let (endpoint, mut incoming) = invite_endpoint(Timers::default());
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "drain").await;
        remote.send(&raw("INVITE", &via, None)).await;
        assert_eq!(status_of(remote.next().await), 100);
        let ServerRequest { transaction, .. } =
            server_request(&mut incoming).await;
        let (responder, _events) = transaction.into_parts();

        let shutdown = endpoint.clone().shutdown(Duration::from_secs(10));
        sleep(Duration::from_millis(20)).await;
        let (mut late, late_via) =
            uac(Transport::Udp, &endpoint, "late").await;
        late.send(&raw("INVITE", &late_via, None)).await;
        assert_eq!(status_of(late.next().await), 503);

        let fresh =
            via.replace("branch=z9hG4bKdrain", "branch=z9hG4bKdrainack");
        remote.send(&raw("ACK", &fresh, Some("a"))).await;
        assert!(matches!(event(&mut incoming).await, IncomingEvent::Ack(_)));
        assert!(remote.next().await.is_none());
        drop((shutdown, responder));
    }

    // RFC 3261 section 9.2. A CANCEL matches by branch and sent-by, so two
    // peers with the same branch have different targets. The CANCEL has its
    // own transaction, which answers its retransmissions after the target
    // has ended.
    #[tokio::test]
    async fn a_cancel_reaches_the_tu_with_its_target_and_transaction() {
        let (endpoint, mut incoming) = invite_endpoint(short_timers());
        let (mut first, first_via) =
            uac(Transport::Udp, &endpoint, "same").await;
        let (mut second, second_via) =
            uac(Transport::Udp, &endpoint, "same").await;
        first.send(&raw("INVITE", &first_via, None)).await;
        assert_eq!(status_of(first.next().await), 100);
        let one = server_request(&mut incoming).await;
        second.send(&raw("INVITE", &second_via, None)).await;
        assert_eq!(status_of(second.next().await), 100);
        let two = server_request(&mut incoming).await;
        assert_ne!(one.transaction.id(), two.transaction.id());

        let cancel = raw("CANCEL", &second_via, None);
        second.send(&cancel).await;
        let IncomingEvent::Cancel(matched) = event(&mut incoming).await else {
            panic!("a matched CANCEL");
        };
        assert_eq!(matched.target, two.transaction.id());
        assert_eq!(matched.request.method(), Method::CANCEL);

        // The UAS answers the CANCEL and then its INVITE with a 487.
        let (cancel_responder, _) = matched.transaction.into_parts();
        cancel_responder
            .respond(reply(&matched.request, 200, "uas"))
            .await
            .unwrap();
        assert_eq!(status_of(second.next().await), 200);
        let (responder, mut events) = two.transaction.into_parts();
        responder.respond(reply(&two.request, 487, "uas")).await.unwrap();
        assert_eq!(status_of(second.next().await), 487);
        second.send(&raw("ACK", &second_via, Some("uas"))).await;
        assert!(matches!(
            server_event(&mut events).await,
            ServerEvent::Terminated
        ));

        second.send(&cancel).await;
        assert_eq!(status_of(second.next_except("INVITE").await), 200);
        assert!(timeout(Duration::from_millis(50), incoming.recv())
            .await
            .is_err());
        drop(one);
    }

    // RFC 3261 section 9.2. A CANCEL can target a non-INVITE request, which
    // it does not affect. The TU answers both as usual.
    #[tokio::test]
    async fn a_cancel_of_a_non_invite_is_not_an_invite_cancellation() {
        let (endpoint, mut incoming) = invite_endpoint(Timers::default());
        let (mut remote, via) =
            uac(Transport::Udp, &endpoint, "options").await;
        remote.send(&raw("OPTIONS", &via, None)).await;
        let options = server_request(&mut incoming).await;

        remote.send(&raw("CANCEL", &via, None)).await;
        let IncomingEvent::Cancel(cancel) = event(&mut incoming).await else {
            panic!("a matched CANCEL");
        };
        assert_eq!(cancel.target, options.transaction.id());
        assert!(remote.next().await.is_none());

        let (responder, _) = options.transaction.into_parts();
        responder.respond(reply(&options.request, 200, "uas")).await.unwrap();
        assert_eq!(status_of(remote.next().await), 200);
        drop(cancel);
    }

    // A CANCEL without a target gets no transaction and no automatic 481.
    // The TU answers through its reply route.
    #[tokio::test]
    async fn an_unmatched_cancel_waits_for_the_tu() {
        let (endpoint, mut incoming) = invite_endpoint(Timers::default());
        let (mut remote, via) = uac(Transport::Udp, &endpoint, "none").await;
        let cancel = raw("CANCEL", &via, None);

        remote.send(&cancel).await;
        let IncomingEvent::UnmatchedCancel(unmatched) =
            event(&mut incoming).await
        else {
            panic!("an unmatched CANCEL");
        };
        assert!(remote.next().await.is_none());
        unmatched
            .reply
            .send(reply(&unmatched.request, 481, "uas"))
            .await
            .unwrap();
        assert_eq!(status_of(remote.next().await), 481);

        remote.send(&cancel).await;
        assert!(matches!(
            event(&mut incoming).await,
            IncomingEvent::UnmatchedCancel(_)
        ));
    }

    /// Polls `future` once, which commits a `cancel` or `start`.
    async fn poll_once<F: Future + Unpin>(future: &mut F) {
        poll_fn(|cx| {
            assert!(Pin::new(&mut *future).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    // RFC 3261 section 9.1. One intent per INVITE, no CANCEL before a
    // provisional response, and a CANCEL that copies the INVITE's identity,
    // routing and top Via into a transaction and observation of its own.
    #[tokio::test]
    async fn cancel_waits_for_a_provisional_and_runs_its_own_transaction() {
        let (endpoint, _incoming) = invite_endpoint(Timers::default());
        let far = Far::new().await;
        let target = far.target(Transport::Udp);
        let (control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());

        let mut first = Box::pin(control.cancel());
        poll_once(&mut first).await;
        assert!(matches!(
            control.cancel().await,
            Err(CancelError::AlreadyRequested)
        ));
        assert!(remote.next_except("INVITE").await.is_none());

        remote.send(&reply(&sent, 180, "early")).await;
        let Ok(CancelOutcome::Sent(cancelling)) =
            timeout(Duration::from_secs(1), first).await.unwrap()
        else {
            panic!("a CANCEL after the provisional response");
        };
        let cancel = into_request(remote.next_except("INVITE").await.unwrap());
        assert_eq!(cancel.method(), Method::CANCEL);
        assert_eq!(cancel.uri().as_str(), sent.uri().as_str());
        assert_eq!(
            cancel.headers().get_all(VIA).collect::<Vec<_>>(),
            [control.via()]
        );
        assert_eq!(cancel.headers().get(CSEQ).unwrap(), "314159 CANCEL");
        for name in [FROM, TO, CALL_ID] {
            assert_eq!(cancel.headers().get(&name), sent.headers().get(&name));
        }
        assert_eq!(
            cancel.headers().get_all(ROUTE).collect::<Vec<_>>(),
            sent.headers().get_all(ROUTE).collect::<Vec<_>>()
        );
        for name in ["Require", "Proxy-Require", "Content-Type"] {
            assert!(!cancel.headers().contains_key(name), "{name}");
        }
        assert!(cancel.body().is_empty());

        let (cancel_control, mut cancel_responses) = cancelling.into_parts();
        assert_eq!(cancel_control.via(), control.via());
        assert!(matches!(
            cancel_control.cancel().await,
            Err(CancelError::NotInvite)
        ));
        assert_eq!(next(&mut responses).await.status().as_u16(), 180);
        remote.send(&reply(&cancel, 200, "early")).await;
        assert_eq!(next(&mut cancel_responses).await.status(), StatusCode::OK);
        assert!(cancel_responses.next().await.is_none());

        // The CANCEL's outcome does not end the INVITE. Its 487 does.
        remote.send(&reply(&sent, 487, "early")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 487);
        assert!(responses.next().await.is_none());
        let ack = into_request(remote.next().await.unwrap());
        assert_eq!(ack.method(), Method::ACK);
    }

    // A dropped cancel future does not withdraw a committed intent.
    #[tokio::test]
    async fn a_dropped_cancel_future_still_cancels_once() {
        let (endpoint, _incoming) = invite_endpoint(Timers::default());
        let far = Far::new().await;
        let target = far.target(Transport::Udp);
        let (control, _responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());

        let mut cancel = Box::pin(control.cancel());
        poll_once(&mut cancel).await;
        drop(cancel);
        remote.send(&reply(&sent, 183, "early")).await;

        let cancel = into_request(remote.next_except("INVITE").await.unwrap());
        assert_eq!(cancel.method(), Method::CANCEL);
        assert!(matches!(
            control.cancel().await,
            Err(CancelError::AlreadyRequested)
        ));
        assert!(remote.next_except("CANCEL").await.is_none());
    }

    // RFC 3261 section 9.1. A 2xx that wins the race with the CANCEL reaches
    // the TU, which acknowledges it. The cancellation deadline does not apply
    // once a final response has arrived.
    #[tokio::test]
    async fn a_2xx_racing_a_cancel_still_reaches_the_tu() {
        let (endpoint, _incoming) = invite_endpoint(short_timers());
        let far = Far::new().await;
        let target = far.target(Transport::Udp);
        let (control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());
        remote.send(&reply(&sent, 180, "a")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 180);
        let Ok(CancelOutcome::Sent(_)) = control.cancel().await else {
            panic!("a CANCEL");
        };
        let cancel = into_request(remote.next_except("INVITE").await.unwrap());

        let ok = reply(&sent, 200, "a");
        remote.send(&ok).await;
        remote.send(&reply(&cancel, 200, "a")).await;
        assert_eq!(next(&mut responses).await.status(), StatusCode::OK);
        assert!(remote.next_except("CANCEL").await.is_none());
        endpoint
            .send_request(ack_for(&sent, &ok), target, ViaMode::Fresh)
            .await
            .unwrap();
        let ack = into_request(remote.next_except("CANCEL").await.unwrap());
        assert_eq!(ack.method(), Method::ACK);

        let end = timeout(Duration::from_secs(2), responses.next()).await;
        assert!(end.unwrap().is_none(), "Timer M, not the cancel deadline");
    }

    // RFC 3261 section 9.1. Without a final response 64 T1 after the CANCEL,
    // the INVITE ends with an explicit error. A later final is stray.
    #[tokio::test]
    async fn the_cancel_deadline_ends_an_unanswered_invite() {
        let (endpoint, _incoming) = invite_endpoint(short_timers());
        let far = Far::new().await;
        let target = far.target(Transport::Udp);
        let (control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());
        remote.send(&reply(&sent, 180, "a")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 180);
        let Ok(CancelOutcome::Sent(_)) = control.cancel().await else {
            panic!("a CANCEL");
        };
        let cancel = into_request(remote.next_except("INVITE").await.unwrap());
        remote.send(&reply(&cancel, 200, "a")).await;
        let cancelled = Instant::now();

        let error = timeout(Duration::from_secs(2), responses.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is_cancel_timeout(), "{error}");
        assert!(cancelled.elapsed() >= 63 * short_timers().t1());
        assert!(responses.next().await.is_none());

        remote.send(&reply(&sent, 487, "a")).await;
        assert!(remote.next_except("CANCEL").await.is_none());
    }

    // The decision for a TCP INVITE in Proceeding whose connection closes,
    // with an advertised listener. Nothing is reported and no timer runs,
    // since the final may come on a new connection (RFC 3261 section 18.2.2).
    // When it does, the ACK goes to the INVITE's own target, on a new
    // connection if needed (section 17.1.1.3), never back to where the final
    // came from.
    #[tokio::test]
    async fn a_tcp_invite_acks_a_final_from_a_new_connection_at_its_target() {
        let (endpoint, _incoming) = invite_endpoint(short_timers());
        let far = Far::new().await;
        let target = far.target(Transport::Tcp);
        let (control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let (connection, _) = far.tcp.accept().await.unwrap();
        let mut first = Stream::new(connection);
        let sent = into_request(first.next().await);
        first.send(&reply(&sent, 180, "a")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 180);

        drop(first);
        let quiet = 3 * 64 * short_timers().t1();
        assert!(timeout(quiet, responses.next()).await.is_err());

        let listener = endpoint.tcp_addr().unwrap();
        let mut callback =
            Stream::new(TcpStream::connect(listener).await.unwrap());
        let busy = reply(&sent, 486, "a");
        callback.send(&busy).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 486);

        let (connection, _) =
            timeout(Duration::from_secs(1), far.tcp.accept())
                .await
                .unwrap()
                .unwrap();
        let mut second = Stream::new(connection);
        let ack = into_request(second.next().await);
        assert_eq!(ack.method(), Method::ACK);
        assert_eq!(ack.headers().get(VIA), Some(control.via()));
        assert_eq!(ack.headers().get(TO), busy.headers().get(TO));
        assert!(callback.within(Duration::from_millis(100)).await.is_none());
    }

    // A CANCEL whose INVITE connection has closed goes to the INVITE's
    // target on a new connection, with the INVITE's Via.
    #[tokio::test]
    async fn a_tcp_cancel_after_the_connection_closed_goes_to_the_target() {
        let (endpoint, _incoming) = invite_endpoint(short_timers());
        let far = Far::new().await;
        let target = far.target(Transport::Tcp);
        let (control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let (connection, _) = far.tcp.accept().await.unwrap();
        let mut first = Stream::new(connection);
        let sent = into_request(first.next().await);
        first.send(&reply(&sent, 180, "a")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 180);
        drop(first);
        sleep(Duration::from_millis(50)).await;

        let Ok(CancelOutcome::Sent(cancelling)) = control.cancel().await
        else {
            panic!("a CANCEL on a new connection");
        };
        let (_, mut cancel_responses) = cancelling.into_parts();
        let (connection, _) =
            timeout(Duration::from_secs(1), far.tcp.accept())
                .await
                .unwrap()
                .unwrap();
        let mut second = Stream::new(connection);
        let cancel = into_request(second.next().await);
        assert_eq!(cancel.method(), Method::CANCEL);
        assert_eq!(cancel.headers().get(VIA), Some(control.via()));

        second.send(&reply(&cancel, 200, "a")).await;
        assert_eq!(next(&mut cancel_responses).await.status(), StatusCode::OK);
        second.send(&reply(&sent, 487, "a")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 487);
        assert_eq!(into_request(second.next().await).method(), Method::ACK);
    }

    // Without a listener, no response can reach a TCP INVITE once its
    // connection closes, so it fails at once, as any client transaction does.
    #[tokio::test]
    async fn a_tcp_invite_without_a_listener_fails_when_its_connection_closes()
    {
        let (endpoint, _incoming) =
            Endpoint::builder().udp(LOCALHOST).bind().unwrap();
        let far = Far::new().await;
        let target = far.target(Transport::Tcp);
        let (_control, mut responses) =
            endpoint.start(invite(), target).await.unwrap().into_parts();
        let (connection, _) = far.tcp.accept().await.unwrap();
        let mut first = Stream::new(connection);
        let sent = into_request(first.next().await);
        first.send(&reply(&sent, 180, "a")).await;
        assert_eq!(next(&mut responses).await.status().as_u16(), 180);

        drop(first);
        let error = timeout(Duration::from_secs(1), responses.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is_transport(), "{error}");
    }

    // Dropping both client handles is neither a CANCEL nor the end of the
    // machine, which still acknowledges the non-2xx.
    #[tokio::test]
    async fn dropped_invite_handles_neither_cancel_nor_stop_the_machine() {
        let (endpoint, _incoming) = invite_endpoint(Timers::default());
        let far = Far::new().await;
        let target = far.target(Transport::Udp);
        let transaction = endpoint.start(invite(), target).await.unwrap();
        let mut remote = far.remote(Transport::Udp, &endpoint).await;
        let sent = into_request(remote.next().await.unwrap());

        drop(transaction);
        remote.send(&reply(&sent, 180, "a")).await;
        assert!(remote.next_except("INVITE").await.is_none());
        remote.send(&reply(&sent, 603, "a")).await;
        let ack = into_request(remote.next_except("INVITE").await.unwrap());
        assert_eq!(ack.method(), Method::ACK);
    }
}
