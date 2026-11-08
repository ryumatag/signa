use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    convert::Infallible,
    future,
    hash::{Hash, Hasher},
    hint::black_box as bb,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use criterion::Criterion;
use signa::{
    bench::{reply_driver, tcp, udp, Flow},
    endpoint::{
        Branch, Builder, CancelOutcome, Endpoint, Error, Incoming,
        IncomingEvent, Reception, ReplyRoute, Responder, Target, ViaMode,
    },
    message::header::{HeaderValue, CSEQ, VIA},
    transaction::Timers,
    transport::Transport,
    Request, Response, StatusCode,
};
use tokio::runtime;
use tower_service::Service;

use crate::benchmark;

const LOCALHOST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

// With RFC 3261's timers a server transaction over UDP lingers for 32 s
// (Timer J) and a client one for 5 s (Timer K) after the response, so at the
// rate of this benchmark the tables and the timer heap would grow for its
// whole run and the numbers would depend on how long it ran. Short timers keep
// them at a steady size. The round trip itself does not wait on any timer.
fn short_timers() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(10))
        .t2(Duration::from_millis(40))
        .t4(Duration::from_millis(50))
        .build()
        .unwrap()
}

/// Answers every request with a 200 at once.
#[derive(Clone)]
struct Ok200;

impl Service<Request<Bytes>> for Ok200 {
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
        let response = Response::reply_to(&request)
            .status(StatusCode::OK)
            .body(Bytes::new())
            .unwrap();
        future::ready(Ok(response))
    }
}

fn runtime() -> runtime::Runtime {
    runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

// A request and its response between two endpoints over the loopback. This is
// everything on the path: the client transaction, the Via, encoding, the
// transport both ways, parsing, the server transaction, the service, and the
// response back. The transport benchmarks measure the syscalls alone.
pub(super) fn round_trip(c: &mut Criterion) {
    let rt = runtime();
    let (server, client_end) = {
        let _guard = rt.enter();
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .tcp(LOCALHOST)
            .timers(short_timers())
            .max_server_transactions(1 << 20)
            .serve(Ok200)
            .unwrap();
        // Even with Timer K at 50 ms, more than the default 4096 client
        // transactions are open at once.
        let client_end = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1 << 20)
            .serve(Ok200)
            .unwrap();
        (server, client_end)
    };
    // An OPTIONS, since 0.2.0 answers an INVITE with a 501 before the service.
    // The endpoint adds the Via.
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@biloxi.example.com")
        .header("From", "Alice <sip:alice@atlanta.example.com>;tag=1928301774")
        .header("To", "Bob <sip:bob@biloxi.example.com>")
        .header("Call-ID", "a84b4c76e66710@pc33.atlanta.example.com")
        .header("CSeq", "314159 OPTIONS")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap();
    let len = request.to_bytes().len() as u64;

    let mut udp =
        client_end.client(Transport::Udp, server.udp_addr().unwrap());
    benchmark(c, "endpoint/udp/round_trip", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                let response = udp.call(bb(request.clone())).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            });
        });
    });

    let mut tcp =
        client_end.client(Transport::Tcp, server.tcp_addr().unwrap());
    benchmark(c, "endpoint/tcp/round_trip", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                let response = tcp.call(bb(request.clone())).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            });
        });
    });
}

// The round trip of `round_trip` over UDP with a stateless proxy between the
// endpoints, so the difference is the proxy hop: a receive, an event, the TU's
// branch and Via work, and a send, each way. The proxy's TU runs on the same
// runtime and does what a stateless proxy must at the least. It hashes the
// received top Via into a branch, and checks and removes its own Via from a
// response before forwarding it.
pub(super) fn stateless_forward(c: &mut Criterion) {
    let rt = runtime();
    let (server, client_end, proxy_addr) = {
        let _guard = rt.enter();
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_server_transactions(1 << 20)
            .serve(Ok200)
            .unwrap();
        let client_end = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1 << 20)
            .serve(Ok200)
            .unwrap();
        let (proxy, incoming) = Builder::new()
            .udp(LOCALHOST)
            .reception(Reception::Stateless)
            .bind()
            .unwrap();
        let proxy_addr = proxy.udp_addr().unwrap();
        tokio::spawn(stateless_proxy(
            proxy,
            incoming,
            server.udp_addr().unwrap(),
        ));
        (server, client_end, proxy_addr)
    };
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@biloxi.example.com")
        .header("From", "Alice <sip:alice@atlanta.example.com>;tag=1928301774")
        .header("To", "Bob <sip:bob@biloxi.example.com>")
        .header("Call-ID", "a84b4c76e66710@pc33.atlanta.example.com")
        .header("CSeq", "314159 OPTIONS")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap();
    let len = request.to_bytes().len() as u64;

    let mut udp = client_end.client(Transport::Udp, proxy_addr);
    benchmark(c, "endpoint/udp/stateless_forward", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                let response = udp.call(bb(request.clone())).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            });
        });
    });
    drop(server);
}

/// The proxy of `stateless_forward`.
async fn stateless_proxy(
    proxy: Endpoint,
    mut incoming: Incoming,
    downstream: SocketAddr,
) {
    let target = Target::new(Transport::Udp, downstream);
    let own = format!("SIP/2.0/UDP {};", proxy.udp_addr().unwrap());
    while let Some(event) = incoming.recv().await {
        match event {
            IncomingEvent::StatelessRequest(received) => {
                let request = received.request;
                let mut hasher = DefaultHasher::new();
                request.headers().get(VIA).unwrap().as_str().hash(&mut hasher);
                let branch: Branch =
                    format!("z9hG4bK-sl-{:016x}", hasher.finish())
                        .parse()
                        .unwrap();
                proxy
                    .send_request(request, target, ViaMode::Branch(branch))
                    .await
                    .unwrap();
            }
            IncomingEvent::StatelessResponse(received) => {
                let mut response = received.response;
                let headers = response.headers_mut();
                // The endpoint prepends its Via as a row of its own.
                assert!(headers.get(VIA).unwrap().as_str().starts_with(&own));
                let rest: Vec<HeaderValue> =
                    headers.get_all(VIA).skip(1).cloned().collect();
                headers.remove(VIA);
                for value in rest {
                    headers.append(VIA, value);
                }
                proxy.forward_response(response).await.unwrap();
            }
            _ => unreachable!("a stateless endpoint"),
        }
    }
}

/// A UAS for the INVITE benchmarks. The Request-URI user says what it does:
/// `accept` answers 200, `reject` answers 486, and `ring` answers 180 and
/// waits for the CANCEL, which it answers with 200 and the INVITE with 487.
/// It does not retransmit its 2xx. The UAC acknowledges each 2xx at once,
/// within the benchmark, so the UAS core never needs to.
fn invite_uas(mut incoming: Incoming) {
    tokio::spawn(async move {
        let mut ringing: HashMap<_, (Responder, Request<Bytes>)> =
            HashMap::new();
        while let Some(event) = incoming.recv().await {
            match event {
                IncomingEvent::Request(envelope) => {
                    let (responder, _) = envelope.transaction.into_parts();
                    let user = envelope.request.uri().as_str();
                    let status = if user.starts_with("sip:accept@") {
                        200
                    } else if user.starts_with("sip:reject@") {
                        486
                    } else {
                        180
                    };
                    let response = tagged(&envelope.request, status);
                    responder.respond(response).await.unwrap();
                    if status == 180 {
                        ringing.insert(
                            responder.id(),
                            (responder, envelope.request),
                        );
                    }
                }
                IncomingEvent::Cancel(cancel) => {
                    let (responder, _) = cancel.transaction.into_parts();
                    responder
                        .respond(tagged(&cancel.request, 200))
                        .await
                        .unwrap();
                    let (invite, request) = ringing
                        .remove(&cancel.target)
                        .expect("a ringing INVITE");
                    invite.respond(tagged(&request, 487)).await.unwrap();
                }
                _ => {}
            }
        }
    });
}

fn tagged(request: &Request<Bytes>, status: u16) -> Response<Bytes> {
    Response::reply_to(request)
        .status(status)
        .to_tag("bench")
        .body(Bytes::new())
        .unwrap()
}

fn invite_request(user: &str) -> Request<Bytes> {
    Request::builder()
        .method("INVITE")
        .uri(format!("sip:{user}@biloxi.example.com").as_str())
        .header("From", "Alice <sip:alice@atlanta.example.com>;tag=1928301774")
        .header("To", "Bob <sip:bob@biloxi.example.com>")
        .header("Call-ID", "a84b4c76e66710@pc33.atlanta.example.com")
        .header("CSeq", "314159 INVITE")
        .header("Max-Forwards", "70")
        .header("Contact", "<sip:alice@pc33.atlanta.example.com>")
        .header("Content-Type", "application/sdp")
        .body(Bytes::from_static(
            b"v=0\r\n\
              o=alice 2890844526 2890844526 IN IP4 \
              pc33.atlanta.example.com\r\n",
        ))
        .unwrap()
}

/// The ACK a UAC core sends for `ok`, which the benchmark builds as a UA would.
fn ack_for(invite: &Request<Bytes>, ok: &Response<Bytes>) -> Request<Bytes> {
    Request::builder()
        .method("ACK")
        .uri(invite.uri().as_str())
        .header("From", invite.headers().get("From").unwrap().as_str())
        .header("To", ok.headers().get("To").unwrap().as_str())
        .header("Call-ID", invite.headers().get("Call-ID").unwrap().as_str())
        .header("CSeq", "314159 ACK")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap()
}

// INVITE transactions between two endpoints over the loopback, with the TU
// API and no final-only adapter. Each benchmark says where its measurement
// ends. None of them is the time to the end of a transaction, which comes at
// Timer L or M, or at Timer H or the ACK on the server.
//
// T1 is 10 ms, so L and M are their 64 T1 of 640 ms, and the tables hold a
// steady number of Accepted entries instead of growing for the whole run.
// Over UDP a non-2xx leaves the client in Completed for Timer D, which is at
// least 32 s whatever T1 is. At this rate that grows the table for the whole
// measurement, so the non-2xx and CANCEL paths run over TCP only, where D is
// zero. Retained state belongs to `scripts/tables`.
pub(super) fn invite(c: &mut Criterion) {
    let rt = runtime();
    let (server, uac) = {
        let _guard = rt.enter();
        let (server, incoming) = Endpoint::builder()
            .udp(LOCALHOST)
            .tcp(LOCALHOST)
            .timers(short_timers())
            .max_server_transactions(1 << 20)
            .bind()
            .unwrap();
        invite_uas(incoming);
        let uac = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1 << 20)
            .max_client_handles(1 << 20)
            .bind()
            .unwrap();
        (server, uac)
    };
    let (uac, _incoming) = uac;

    // From `start` to the first 2xx in `Responses` and the TU's ACK written
    // locally by `send_request`. The 100 Trying and the 2xx come from the
    // UAS endpoint.
    for (transport, address) in [
        (Transport::Udp, server.udp_addr().unwrap()),
        (Transport::Tcp, server.tcp_addr().unwrap()),
    ] {
        let target = Target::new(transport, address);
        let request = invite_request("accept");
        let len = request.to_bytes().len() as u64;
        let id =
            format!("endpoint/invite/{}/accepted", transport_name(transport));
        benchmark(c, id, len, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (_control, mut responses) = uac
                        .start(bb(request.clone()), target)
                        .await
                        .unwrap()
                        .into_parts();
                    let ok = loop {
                        let response =
                            responses.next().await.unwrap().unwrap();
                        if response.status() == StatusCode::OK {
                            break response;
                        }
                    };
                    uac.send_request(
                        ack_for(&request, &ok),
                        target,
                        ViaMode::Fresh,
                    )
                    .await
                    .unwrap();
                });
            });
        });
    }

    // From `start` to the 486 in `Responses`. The driver writes the ACK
    // before it delivers the final.
    let target = Target::new(Transport::Tcp, server.tcp_addr().unwrap());
    let request = invite_request("reject");
    let len = request.to_bytes().len() as u64;
    benchmark(c, "endpoint/invite/tcp/rejected", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                let (_control, mut responses) = uac
                    .start(bb(request.clone()), target)
                    .await
                    .unwrap()
                    .into_parts();
                let busy = loop {
                    let response = responses.next().await.unwrap().unwrap();
                    if response.status().is_final() {
                        break response;
                    }
                };
                assert_eq!(busy.status().as_u16(), 486);
            });
        });
    });

    // From `start` to the 487 in the INVITE's `Responses`, through the 180,
    // `cancel`, and the CANCEL's own 200 in its separate stream.
    let request = invite_request("ring");
    let len = request.to_bytes().len() as u64;
    benchmark(c, "endpoint/cancel/tcp/ringing", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                let (control, mut responses) = uac
                    .start(bb(request.clone()), target)
                    .await
                    .unwrap()
                    .into_parts();
                loop {
                    let response = responses.next().await.unwrap().unwrap();
                    if response.status().as_u16() == 180 {
                        break;
                    }
                }
                let CancelOutcome::Sent(cancel) =
                    control.cancel().await.unwrap()
                else {
                    panic!("a CANCEL after the 180");
                };
                let (_, mut cancel_responses) = cancel.into_parts();
                let terminated = loop {
                    let response = responses.next().await.unwrap().unwrap();
                    if response.status().is_final() {
                        break response;
                    }
                };
                assert_eq!(terminated.status().as_u16(), 487);
                let ok = cancel_responses.next().await.unwrap().unwrap();
                assert_eq!(ok.status(), StatusCode::OK);
            });
        });
    });
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    }
}

pub(super) fn reply_route(c: &mut Criterion) {
    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, UdpSocket},
    };

    let rt =
        runtime::Builder::new_current_thread().enable_all().build().unwrap();

    let peer = rt.block_on(UdpSocket::bind(LOCALHOST)).unwrap();
    let (route, response) = rt
        .block_on(reply_route_fixture(
            Transport::Udp,
            peer.local_addr().unwrap(),
        ))
        .unwrap();
    let expected = response.to_bytes();
    let len = expected.len();
    let mut buffer = vec![0; len];

    benchmark(c, "endpoint/udp/reply_route", len as u64, |b| {
        b.iter(|| {
            rt.block_on(async {
                route.send(bb(response.clone())).await.unwrap();

                let (n, _) = peer.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], expected.as_ref());
            })
        })
    });

    drop(route);

    let listener = rt.block_on(TcpListener::bind(LOCALHOST)).unwrap();
    let ((route, response), (mut peer, _)) = rt.block_on(async {
        let (route, peer) = tokio::join!(
            reply_route_fixture(
                Transport::Tcp,
                listener.local_addr().unwrap()
            ),
            listener.accept()
        );

        (route.unwrap(), peer.unwrap())
    });
    let expected = response.to_bytes();
    let len = expected.len();
    let mut buffer = vec![0; len];

    benchmark(c, "endpoint/tcp/reply_route", len as u64, |b| {
        b.iter(|| {
            rt.block_on(async {
                route.send(bb(response.clone())).await.unwrap();

                peer.read_exact(&mut buffer).await.unwrap();
                assert_eq!(buffer, expected);
            })
        })
    });
}

struct NoDispatch;

impl Service<Request<Bytes>> for NoDispatch {
    type Response = Response<Bytes>;
    type Error = Infallible;
    type Future = future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn call(&mut self, _: Request<Bytes>) -> Self::Future {
        unreachable!("fixture sends responses only")
    }
}

/// Creates a running driver and a route to the benchmark peer.
async fn reply_route_fixture(
    transport: Transport,
    peer: SocketAddr,
) -> io::Result<(ReplyRoute, Response<Bytes>)> {
    let (tx, tcp_rx) = tokio::sync::mpsc::channel(256);
    let config = tcp::Config::default();

    let udp = if transport == Transport::Udp {
        Some(udp::Socket::bind(
            "127.0.0.1:0".parse().expect("literal address"),
        )?)
    } else {
        None
    };

    let (flow, writer) = if transport == Transport::Tcp {
        let (flow, writer) = tcp::connect(peer, &config, &tx).await?;

        (flow, Some(writer))
    } else {
        (
            Flow {
                transport,
                local: udp.as_ref().expect("bound UDP socket").local_addr(),
                remote: peer,
            },
            None,
        )
    };

    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@example.com")
        .header(
            "Via",
            format!("SIP/2.0/{transport} {peer};branch=z9hG4bKbench;rport")
                .as_str(),
        )
        .header("From", "<sip:alice@example.com>;tag=alice")
        .header("To", "<sip:bob@example.com>;tag=bob")
        .header("Call-ID", "reply-bench")
        .header("CSeq", "1 OPTIONS")
        .body(Bytes::new())
        .expect("valid fixture request");

    let (request, route, driver) = reply_driver(
        request, flow, writer, udp, tcp_rx, tx,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let response = Response::reply_to(&request)
        .status(200)
        .body(Bytes::new())
        .expect("valid fixture response");

    tokio::spawn(driver);

    Ok((route, response))
}

pub(super) fn client_admission(c: &mut Criterion) {
    use std::{
        future::Future,
        pin::{pin, Pin},
        task::Waker,
    };

    let rt = runtime();
    let _guard = rt.enter();
    let endpoint = Endpoint::builder()
        .max_client_transactions(1)
        .serve(NoDispatch)
        .unwrap();
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:example.com")
        .header("CSeq", "1 OPTIONS")
        .header("From", "<sip:alice@example.com>;tag=alice")
        .header("To", "<sip:bob@example.com>")
        .header("Call-ID", "admission-bench")
        .body(Bytes::new())
        .unwrap();
    let target = Target::new(Transport::Tcp, LOCALHOST);
    let mut pending = pin!(endpoint.start(request.clone(), target));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    let len = request.to_bytes().len() as u64;

    // Enter the runtime without driving it. The first command stays queued,
    // so each subsequent call must reject without depending on connect timing.
    benchmark(c, "reject/endpoint/client_admission", len, |b| {
        b.iter(|| {
            let mut response =
                pin!(endpoint.start(bb(request.clone()), target));
            let Poll::Ready(Err(error)) =
                Pin::new(&mut response).poll(&mut cx)
            else {
                panic!("admission must reject before enqueue");
            };
            assert!(error.is_busy());
        });
    });

    let mut invalid = request.clone();
    invalid.headers_mut().insert(CSEQ, "1 BYE".parse().unwrap());
    benchmark(c, "reject/endpoint/client_cseq", len, |b| {
        b.iter(|| {
            let mut response =
                pin!(endpoint.start(bb(invalid.clone()), target));
            let Poll::Ready(Err(error)) =
                Pin::new(&mut response).poll(&mut cx)
            else {
                panic!("invalid CSeq must reject before enqueue");
            };
            assert!(error.is_invalid_cseq());
        });
    });
}

pub(super) fn server_admission(c: &mut Criterion) {
    let rt = runtime();
    let (server, endpoint) = {
        let _guard = rt.enter();
        // Keep the first Completed entry for the whole measurement, including
        // longer CI runs. No rejected request may create another entry.
        let timers = Timers::builder()
            .t1(Duration::from_secs(60))
            .t2(Duration::from_secs(240))
            .build()
            .unwrap();
        let server = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(timers)
            .max_server_transactions(1)
            .serve(Ok200)
            .unwrap();
        let endpoint = Endpoint::builder()
            .udp(LOCALHOST)
            .timers(short_timers())
            .max_client_transactions(1 << 20)
            .serve(NoDispatch)
            .unwrap();
        (server, endpoint)
    };
    let mut client =
        endpoint.client(Transport::Udp, server.udp_addr().unwrap());
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:example.com")
        .header("CSeq", "1 OPTIONS")
        .header("From", "<sip:alice@example.com>;tag=alice")
        .header("To", "<sip:bob@example.com>")
        .header("Call-ID", "admission-bench")
        .body(Bytes::new())
        .unwrap();
    let len = request.to_bytes().len() as u64;

    let first = rt.block_on(client.call(request.clone())).unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    benchmark(c, "reject/endpoint/server_table", len, |b| {
        b.iter(|| {
            let response =
                rt.block_on(client.call(bb(request.clone()))).unwrap();
            assert_eq!(response.status().as_u16(), 503);
        });
    });
}

/// Exercise driver-side refusal without starting a socket or a transaction.
pub(super) fn connection_admission(c: &mut Criterion) {
    let rt = runtime();
    let endpoint = {
        let _guard = rt.enter();
        Endpoint::builder()
            .max_outbound_connections(0)
            .serve(NoDispatch)
            .unwrap()
    };
    let mut client = endpoint.client(Transport::Tcp, LOCALHOST);
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:example.com")
        .header("CSeq", "1 OPTIONS")
        .header("From", "<sip:alice@example.com>;tag=alice")
        .header("To", "<sip:bob@example.com>")
        .header("Call-ID", "admission-bench")
        .body(Bytes::new())
        .unwrap();
    benchmark(
        c,
        "endpoint/tcp/connection_rejection",
        request.to_bytes().len() as u64,
        |b| {
            b.iter(|| {
                let error =
                    rt.block_on(client.call(request.clone())).unwrap_err();
                assert!(error.is_busy());
            });
        },
    );
}

/// Shutdown waiters remain caller-owned while one control wakeup is queued.
pub(super) fn shutdown_coalescing(c: &mut Criterion) {
    use std::{future::Future, pin::Pin, task::Waker, time::Duration};
    let rt = runtime();
    let _guard = rt.enter();
    let endpoint = Endpoint::builder().serve(NoDispatch).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    drop(endpoint.clone().shutdown(Duration::MAX));
    benchmark(c, "control/endpoint/shutdown_coalesced", 1, |b| {
        b.iter(|| {
            let mut wait = endpoint.clone().shutdown(Duration::MAX);
            assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
        });
    });
}

trait Serve {
    fn serve<S>(self, service: S) -> io::Result<Endpoint>
    where
        S: Service<Request<Bytes>, Response = Response<Bytes>>
            + Send
            + 'static,
        S::Future: Send + 'static;
}

impl Serve for Builder {
    fn serve<S>(self, mut service: S) -> io::Result<Endpoint>
    where
        S: Service<Request<Bytes>, Response = Response<Bytes>>
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        let (endpoint, mut incoming) = self.bind()?;
        tokio::spawn(async move {
            while let Some(event) = incoming.recv().await {
                let (request, responder, route) = match event {
                    IncomingEvent::Request(envelope) => {
                        let (responder, _) = envelope.transaction.into_parts();
                        (envelope.request, Some(responder), None)
                    }
                    IncomingEvent::Untracked(envelope) => {
                        (envelope.request, None, Some(envelope.reply))
                    }
                    _ => continue,
                };
                if std::future::poll_fn(|cx| service.poll_ready(cx))
                    .await
                    .is_err()
                {
                    break;
                }
                let response = service.call(request).await.ok();

                if let Some(mut response) = response {
                    let to = response
                        .headers()
                        .get("To")
                        .expect("fixture To")
                        .as_str();
                    let tagged = format!("{to};tag=bench");
                    response.headers_mut().insert(
                        signa::message::header::TO,
                        signa::HeaderValue::from_bytes(tagged.as_bytes())
                            .unwrap(),
                    );
                    if let Some(responder) = responder {
                        responder.respond(response).await.unwrap();
                    } else if let Some(route) = route {
                        route.send(response).await.unwrap();
                    }
                }
            }
        });

        Ok(endpoint)
    }
}

// A benchmark-local client that waits for the final response. signa exposes
// every response through `Endpoint::start` and implements no `Service`.
struct Client {
    endpoint: Endpoint,
    target: Target,
}

trait ClientFixture {
    fn client(&self, transport: Transport, address: SocketAddr) -> Client;
}

impl ClientFixture for Endpoint {
    fn client(&self, transport: Transport, address: SocketAddr) -> Client {
        Client {
            endpoint: self.clone(),
            target: Target::new(transport, address),
        }
    }
}

impl Client {
    async fn call(
        &mut self,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, Error> {
        let (_control, mut responses) =
            self.endpoint.start(request, self.target).await?.into_parts();
        loop {
            let response =
                responses.next().await.expect("transaction outcome")?;
            if response.status().as_u16() >= 200 {
                return Ok(response);
            }
        }
    }
}
