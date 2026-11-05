// Every test here opens sockets, which Miri does not have.
#![cfg(not(miri))]

use std::{
    convert::Infallible,
    future::{self, Future},
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
    sync::Notify,
    time::{sleep, timeout},
};
use tower::{limit::ConcurrencyLimit, service_fn, ServiceExt};
use tower_service::Service;

use crate::{
    endpoint::{error::Error, Endpoint},
    header::{CSEQ, VIA},
    request::Request,
    response::Response,
    status::StatusCode,
    transaction::Timers,
    transport::{Flow, Transport},
};

const LOCALHOST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Timers that make a test wait milliseconds instead of seconds. Timer F is
/// 640 ms, and the 100 goes out after 70 ms.
const FAST: Timers = Timers {
    t1: Duration::from_millis(10),
    t2: Duration::from_millis(40),
    t4: Duration::from_millis(50),
};

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
    S: Service<Request<Bytes>, Response = Response<Bytes>> + Send + 'static,
    S::Future: Send + 'static,
{
    Endpoint::builder()
        .udp(LOCALHOST)
        .tcp(LOCALHOST)
        .timers(FAST)
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
    let client_end = Endpoint::builder().serve(Counting::default()).unwrap();
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
async fn a_response_opens_a_new_connection_when_the_request_s_has_closed() {
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
        &format!("SIP/2.0/TCP 127.0.0.1:{};branch=z9hG4bK2", sent_by.port()),
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
        &format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bKabc", peer.port()),
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
    assert!(flows.iter().all(|flow| flow.remote == peer_addr), "{flows:?}");
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
    let via = format!("SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK1", peer.port());

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
        .timers(FAST)
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
            b'1' => Err(crate::Error::missing("anything")),
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
    let client = client_end.client(Transport::Udp, server.udp_addr().unwrap());

    let mut calls = Vec::new();
    for i in 0..3 {
        let mut request = request("OPTIONS");
        request.headers_mut().insert(
            crate::header::CALL_ID,
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
    let mut client =
        client_end.client(Transport::Udp, peer.socket.local_addr().unwrap());

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
    let mut client =
        client_end.client(Transport::Udp, peer.socket.local_addr().unwrap());

    let call =
        tokio::spawn(async move { client.call(request("OPTIONS")).await });
    let received = peer.recv().await.unwrap();
    let (head, _) = received.split_once("\r\n").unwrap();
    assert_eq!(head, "OPTIONS sip:bob@example.com SIP/2.0");
    let via_line = received.lines().find(|l| l.starts_with("Via:")).unwrap();
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
        .timers(FAST)
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
    let mut client =
        client_end.client(Transport::Udp, peer.socket.local_addr().unwrap());

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
    let mut client =
        client_end.client(Transport::Udp, peer.socket.local_addr().unwrap());
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
