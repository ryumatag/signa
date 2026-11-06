use std::{
    convert::Infallible,
    future,
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
    endpoint::ReplyRoute,
    endpoint::{Endpoint, Timers, Transport},
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

    let (request, route, driver) =
        reply_driver(NoDispatch, request, flow, writer, udp, tcp_rx, tx)
            .map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, error)
            })?;
    let response = Response::reply_to(&request)
        .status(200)
        .body(Bytes::new())
        .expect("valid fixture response");

    tokio::spawn(driver);

    Ok((route, response))
}
