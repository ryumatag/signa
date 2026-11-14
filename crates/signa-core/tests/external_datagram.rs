/*!
An endpoint whose UDP datagrams travel over a backend of the application's
own, through the public API only.

The backend here is an in-memory packet wire, standing in for an adapter that
reads and writes frames on a NIC. The test decides when each write completes,
fails or waits, which a socket cannot be made to do on demand. Its contexts
are text such as `nic0 vlan 100`, which the endpoint never reads, and two
wires with the same addresses stand for two network domains.
*/

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    pin::pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{
        Endpoint, Incoming, IncomingEvent, PathSelection, Reception,
        ServerRequest, ShutdownOutcome, Target, ViaMode,
    },
    message::header::{Tag, VIA},
    transaction::Timers,
    transport::{
        Flow, Transport, WriteLimits,
        datagram::{
            Capabilities, Datagram, DatagramIo, DatagramWrite,
            MAX_CONTEXT_LEN, RecvError, Submit, TransportContext, WriteId,
            WritePath,
        },
    },
};
use tokio::{sync::Notify, time::timeout};

/// The address the endpoint owns on the wire. Nothing binds it on this host.
const LOCAL: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
    5060,
);
const PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20)),
    5070,
);
/// A second address the wire may send from, as on a second VLAN.
const ALTERNATE: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10)),
    5060,
);
/// A public address that a static NAT maps onto `ALTERNATE`.
const PUBLIC: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)),
    5060,
);

/// What the wire does with the next write.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Writes {
    /// Takes it and reports it written at once.
    #[default]
    Complete,
    /// Takes it and reports it only when the test finishes it.
    Delay,
    /// Takes it and reports that writing it failed.
    Fail,
    /// Cannot take it now.
    Hold,
}

/// One write the wire accepted.
#[derive(Clone, Debug)]
struct Sent {
    payload: Bytes,
    source: SocketAddr,
    destination: SocketAddr,
    path: Way,
}

/// What [`WritePath`] a write came with, with its context's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Way {
    Default,
    Reply(Bytes),
    Prepared(Bytes),
}

impl Way {
    fn reply(context: &'static str) -> Way {
        Way::Reply(Bytes::from_static(context.as_bytes()))
    }

    fn prepared(context: &'static str) -> Way {
        Way::Prepared(Bytes::from_static(context.as_bytes()))
    }
}

#[derive(Default)]
struct State {
    inbound: VecDeque<Result<Datagram, RecvError>>,
    recv: Option<Waker>,
    writes: Writes,
    sent: Vec<Sent>,
    submit: Option<Waker>,
    completions: VecDeque<(WriteId, io::Result<()>)>,
    complete: Option<Waker>,
    delayed: VecDeque<WriteId>,
    closed: bool,
    /// Makes the close never finish, as a backend with a stuck writer task.
    stuck: bool,
    /// Path contexts the wire refuses to send on any more, as for a PPPoE
    /// session that has ended.
    stale: Vec<Bytes>,
}

#[derive(Clone, Default)]
struct Wire {
    state: Arc<Mutex<State>>,
    sent: Arc<Notify>,
}

impl Wire {
    fn deliver(&self, datagram: Result<Datagram, RecvError>) {
        let mut state = self.state.lock().unwrap();
        state.inbound.push_back(datagram);
        if let Some(waker) = state.recv.take() {
            waker.wake();
        }
    }

    fn writes(&self, writes: Writes) {
        let mut state = self.state.lock().unwrap();
        state.writes = writes;
        if let Some(waker) = state.submit.take() {
            waker.wake();
        }
    }

    /// Reports the oldest delayed write.
    fn finish(&self, result: io::Result<()>) {
        let mut state = self.state.lock().unwrap();
        let id = state.delayed.pop_front().expect("a delayed write");
        state.completions.push_back((id, result));
        if let Some(waker) = state.complete.take() {
            waker.wake();
        }
    }

    /// Waits until the wire has accepted `n` writes, and returns them.
    async fn sent(&self, n: usize) -> Vec<Sent> {
        timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.sent.notified();
                {
                    let state = self.state.lock().unwrap();
                    if state.sent.len() >= n {
                        return state.sent.clone();
                    }
                }
                notified.await;
            }
        })
        .await
        .expect("the writes within two seconds")
    }

    fn closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    fn stale(&self, context: &'static str) {
        let context = Bytes::from_static(context.as_bytes());
        self.state.lock().unwrap().stale.push(context);
    }

    /// The number of writes the wire has accepted so far.
    fn count(&self) -> usize {
        self.state.lock().unwrap().sent.len()
    }
}

impl DatagramIo for Wire {
    fn local_addr(&self) -> SocketAddr {
        LOCAL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::new(1472)
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        let mut state = self.state.lock().unwrap();
        match state.inbound.pop_front() {
            Some(datagram) => Poll::Ready(datagram),
            None => {
                state.recv = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        let mut state = self.state.lock().unwrap();
        let id = write.id();
        let path = match write.path() {
            WritePath::Default => Way::Default,
            WritePath::Reply(context) => {
                Way::Reply(context.as_bytes().clone())
            }
            WritePath::Prepared(context) => {
                Way::Prepared(context.as_bytes().clone())
            }
            _ => unreachable!("no other paths"),
        };
        if let Way::Prepared(context) = &path {
            if state.stale.contains(context) {
                return Submit::Rejected(
                    write,
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "session ended",
                    ),
                );
            }
        }
        match state.writes {
            Writes::Complete => state.completions.push_back((id, Ok(()))),
            Writes::Delay => state.delayed.push_back(id),
            Writes::Fail => state.completions.push_back((
                id,
                Err(io::Error::new(io::ErrorKind::NotConnected, "link down")),
            )),
            Writes::Hold => {
                state.submit = Some(cx.waker().clone());
                return Submit::Pending(write);
            }
        }
        state.sent.push(Sent {
            source: write.source(),
            destination: write.destination(),
            path,
            payload: write.into_payload(),
        });
        self.sent.notify_waiters();

        Submit::Accepted
    }

    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, io::Result<()>)> {
        let mut state = self.state.lock().unwrap();
        match state.completions.pop_front() {
            Some(completion) => Poll::Ready(completion),
            None => {
                state.complete = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    // The wire may send from its own address or the alternate one, with any
    // context. Another source is not this host's to use.
    fn check_path(
        &mut self,
        source: SocketAddr,
        _destination: SocketAddr,
        _context: &TransportContext,
    ) -> io::Result<()> {
        if source == LOCAL || source == ALTERNATE {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "not ours"))
        }
    }

    // A delayed write that is still on the wire when it closes is failed, as
    // an adapter fails the frames its NIC queue still holds.
    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        if state.stuck {
            return Poll::Pending;
        }
        while let Some(id) = state.delayed.pop_front() {
            state.completions.push_back((
                id,
                Err(io::Error::new(io::ErrorKind::Interrupted, "closed")),
            ));
        }
        Poll::Ready(())
    }
}

fn bind(wire: &Wire) -> (Endpoint, Incoming) {
    Endpoint::builder().udp_io(wire.clone()).bind().unwrap()
}

fn options(branch: &str) -> String {
    format!(
        "OPTIONS sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@192.0.2.20>;tag=alice\r\n\
         To: <sip:bob@192.0.2.10>\r\n\
         Call-ID: {branch}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

fn outgoing(call: &str) -> Request<Bytes> {
    Request::builder()
        .method("OPTIONS")
        .uri("sip:alice@192.0.2.20")
        .header("From", "<sip:bob@192.0.2.10>;tag=bob")
        .header("To", "<sip:alice@192.0.2.20>")
        .header("Call-ID", call)
        .header("CSeq", "1 OPTIONS")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap()
}

fn datagram(text: String) -> Result<Datagram, RecvError> {
    Ok(Datagram::new(Bytes::from(text), PEER, LOCAL))
}

fn context(text: &'static str) -> TransportContext {
    TransportContext::new(Bytes::from_static(text.as_bytes())).unwrap()
}

/// A datagram from `PEER` with `text` and the context `on`.
fn arriving(text: String, on: &'static str) -> Result<Datagram, RecvError> {
    datagram(text).map(|datagram| datagram.with_context(context(on)))
}

async fn request(incoming: &mut Incoming) -> ServerRequest {
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    match event.unwrap().unwrap() {
        IncomingEvent::Request(request) => request,
        other => panic!("expected a request, got {other:?}"),
    }
}

fn ok(request: &Request<Bytes>) -> Response<Bytes> {
    Response::reply_to(request)
        .status(200)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap()
}

// A request that arrives on the wire comes up with the addresses the wire
// reported, and its response goes back down from the address it came to. The
// Via names port 5060 and `rport` asks for the port it came from, which is
// where the response goes (RFC 3581 section 4).
#[tokio::test]
async fn a_request_and_its_response_cross_the_wire() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    assert_eq!(endpoint.udp_addr(), Some(LOCAL));

    let context = TransportContext::new(Bytes::from_static(b"nic0 vlan 100"));
    wire.deliver(
        datagram(options("uas"))
            .map(|datagram| datagram.with_context(context.unwrap())),
    );
    let request = request(&mut incoming).await;
    assert_eq!(
        request.received.flow(),
        Flow { transport: Transport::Udp, local: LOCAL, remote: PEER }
    );
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, PEER));
    let response = Response::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(sent[0].path, Way::reply("nic0 vlan 100"));
}

// A client transaction sends from the backend's address and names it in its
// Via. Its response arrives through the backend too.
#[tokio::test]
async fn a_client_transaction_runs_over_the_wire() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);

    let target = Target::new(Transport::Udp, PEER);
    let (control, mut responses) = endpoint
        .start(outgoing("uac"), target.clone())
        .await
        .unwrap()
        .into_parts();
    assert_eq!(control.flow().local, LOCAL);

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, PEER));
    assert_eq!(sent[0].path, Way::Default);
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    let via = request.headers().get(VIA).unwrap().as_str();
    assert!(via.starts_with("SIP/2.0/UDP 192.0.2.10:5060;rport;branch="));

    wire.deliver(Ok(Datagram::new(ok(&request).to_bytes(), PEER, LOCAL)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

// A one-shot send resolves when the wire reports the datagram written, not
// when it takes it.
#[tokio::test]
async fn a_send_waits_for_its_completion() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    wire.writes(Writes::Delay);
    let target = Target::new(Transport::Udp, PEER);

    let mut send = pin!(endpoint.send_request(
        outgoing("delay"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut send => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }
    assert!(
        timeout(Duration::from_millis(50), &mut send).await.is_err(),
        "the write has not completed"
    );
    wire.finish(Ok(()));

    let sent = timeout(Duration::from_secs(2), send).await.unwrap().unwrap();
    assert_eq!(sent.flow().local, LOCAL);
}

// A write the wire takes and then fails is a transport error, for a one-shot
// send and for a client transaction's request alike. A transaction whose
// request fails at once is never started, and one whose request fails later
// ends with the error.
#[tokio::test]
async fn a_failed_write_is_reported() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    wire.writes(Writes::Fail);
    let target = Target::new(Transport::Udp, PEER);

    let error = endpoint
        .send_request(outgoing("fail"), target.clone(), ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_transport());
    let error = endpoint
        .start(outgoing("fail-at-once"), target.clone())
        .await
        .unwrap_err();
    assert!(error.is_transport());

    wire.writes(Writes::Delay);
    let (_control, mut responses) = endpoint
        .start(outgoing("fail-later"), target.clone())
        .await
        .unwrap()
        .into_parts();
    wire.sent(3).await;
    wire.finish(Err(io::Error::new(io::ErrorKind::NotConnected, "link down")));
    let error = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is_transport());
}

// Writes the wire cannot take wait in the endpoint, within its UDP write
// limits, and go out in order once the wire can take them.
#[tokio::test]
async fn a_held_wire_fills_the_write_limits() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .udp_write_limits(WriteLimits { messages: 2, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    wire.writes(Writes::Hold);
    let target = Target::new(Transport::Udp, PEER);

    let first =
        endpoint.send_request(outgoing("1"), target.clone(), ViaMode::Fresh);
    let second =
        endpoint.send_request(outgoing("2"), target.clone(), ViaMode::Fresh);
    let mut both = pin!(async { tokio::join!(first, second) });
    assert!(timeout(Duration::from_millis(50), &mut both).await.is_err());
    let error = endpoint
        .send_request(outgoing("3"), target.clone(), ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_busy());

    wire.writes(Writes::Complete);
    let (first, second) = timeout(Duration::from_secs(2), both).await.unwrap();
    first.unwrap();
    second.unwrap();
    let sent = wire.sent(2).await;
    let calls: Vec<_> = sent
        .iter()
        .map(|sent| {
            let request = Request::from_bytes(&sent.payload).unwrap();
            request.headers().get("Call-ID").unwrap().as_str().to_owned()
        })
        .collect();
    assert_eq!(calls, ["1", "2"]);
}

// What the wire cannot deliver whole is counted and never parsed.
#[tokio::test]
async fn undeliverable_datagrams_are_counted_and_dropped() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);

    wire.deliver(Err(RecvError::Truncated));
    wire.deliver(Err(RecvError::Io(io::Error::other("nic reset"))));
    wire.deliver(datagram(options("after")));

    let request = request(&mut incoming).await;
    assert_eq!(request.request.headers().get("Call-ID").unwrap(), "after");
    let stats = endpoint.reception_stats();
    assert_eq!(stats.truncated_datagrams, 1);
    assert_eq!(stats.receive_errors, 1);
}

#[test]
fn a_context_is_bounded_when_it_is_made() {
    let longest = Bytes::from(vec![0; MAX_CONTEXT_LEN]);
    let longer = Bytes::from(vec![0; MAX_CONTEXT_LEN + 1]);

    assert_eq!(TransportContext::new(longest).unwrap().len(), MAX_CONTEXT_LEN);
    assert_eq!(
        TransportContext::new(longer).unwrap_err().context_len(),
        MAX_CONTEXT_LEN + 1
    );
}

// A graceful shutdown waits for the writes on the wire to complete, then
// closes the backend.
#[tokio::test]
async fn shutdown_drains_the_wire_then_closes_it() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    wire.writes(Writes::Delay);
    let target = Target::new(Transport::Udp, PEER);
    let mut send = pin!(endpoint.send_request(
        outgoing("drain"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut send => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }

    let mut shutdown = pin!(endpoint.clone().shutdown(Duration::from_secs(5)));
    assert!(timeout(Duration::from_millis(50), &mut shutdown).await.is_err());
    assert!(!wire.closed());
    wire.finish(Ok(()));

    let outcome = timeout(Duration::from_secs(2), shutdown).await.unwrap();
    assert_eq!(outcome, ShutdownOutcome::Drained);
    assert!(wire.closed());
    send.await.unwrap();
}

// At the deadline, a write the wire never took fails as closed, and one it
// took fails as the backend reports it on close.
#[tokio::test]
async fn the_deadline_fails_what_is_left_and_closes_the_wire() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);
    wire.writes(Writes::Delay);
    let mut taken = pin!(endpoint.send_request(
        outgoing("taken"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut taken => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }
    wire.writes(Writes::Hold);
    let held = endpoint.send_request(
        outgoing("held"),
        target.clone(),
        ViaMode::Fresh,
    );
    let mut held = pin!(held);
    assert!(timeout(Duration::from_millis(50), &mut held).await.is_err());

    let outcome = timeout(
        Duration::from_secs(2),
        endpoint.clone().shutdown(Duration::from_millis(100)),
    )
    .await
    .unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(wire.closed());
    assert!(held.await.unwrap_err().is_closed());
    assert!(taken.await.unwrap_err().is_transport());
}

// A backend that never finishes closing cannot hold the shutdown past its
// deadline. The endpoint drops it, and the write it held fails as closed.
#[tokio::test]
async fn a_stuck_close_is_dropped_at_the_deadline() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);
    wire.writes(Writes::Delay);
    wire.state.lock().unwrap().stuck = true;
    let mut send = pin!(endpoint.send_request(
        outgoing("stuck"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut send => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }

    let outcome = timeout(
        Duration::from_secs(2),
        endpoint.clone().shutdown(Duration::from_millis(100)),
    )
    .await
    .unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(wire.closed());
    assert_eq!(Arc::strong_count(&wire.state), 1, "the backend is dropped");
    assert!(send.await.unwrap_err().is_closed());
}

#[test]
fn a_backend_must_name_its_address_and_send_something() {
    struct Misnamed {
        local: &'static str,
        max_payload: usize,
        wire: Wire,
    }

    impl DatagramIo for Misnamed {
        fn local_addr(&self) -> SocketAddr {
            self.local.parse().unwrap()
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::new(self.max_payload)
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Datagram, RecvError>> {
            self.wire.poll_recv(cx)
        }

        fn poll_submit(
            &mut self,
            cx: &mut Context<'_>,
            write: DatagramWrite,
        ) -> Submit {
            self.wire.poll_submit(cx, write)
        }

        fn poll_complete(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<(WriteId, io::Result<()>)> {
            self.wire.poll_complete(cx)
        }

        fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            self.wire.poll_close(cx)
        }
    }

    for (local, max_payload) in [
        ("0.0.0.0:5060", 1472),
        ("192.0.2.10:0", 1472),
        ("192.0.2.10:5060", 0),
    ] {
        let backend = Misnamed { local, max_payload, wire: Wire::default() };

        let error = Endpoint::builder().udp_io(backend).bind().unwrap_err();

        assert!(error.is_invalid_config(), "{local} {max_payload}");
    }
}

fn invite(branch: &str) -> String {
    format!(
        "INVITE sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@192.0.2.20>;tag=alice\r\n\
         To: <sip:bob@192.0.2.10>\r\n\
         Call-ID: {branch}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@192.0.2.20:5070>\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

/// An ACK that matches no transaction, which goes to the TU.
fn stray_ack() -> String {
    "ACK sip:bob@192.0.2.10 SIP/2.0\r\n\
     Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bKstray;rport\r\n\
     Max-Forwards: 70\r\n\
     From: <sip:alice@192.0.2.20>;tag=alice\r\n\
     To: <sip:bob@192.0.2.10>;tag=bob\r\n\
     Call-ID: stray\r\n\
     CSeq: 1 ACK\r\n\
     Content-Length: 0\r\n\r\n"
        .to_owned()
}

fn outgoing_invite(call: &str) -> Request<Bytes> {
    Request::builder()
        .method("INVITE")
        .uri("sip:alice@192.0.2.20")
        .header("From", "<sip:bob@203.0.113.5>;tag=bob")
        .header("To", "<sip:alice@192.0.2.20>")
        .header("Call-ID", call)
        .header("CSeq", "1 INVITE")
        .header("Max-Forwards", "70")
        .header("Contact", "<sip:bob@203.0.113.5>")
        .body(Bytes::new())
        .unwrap()
}

fn status(sent: &Sent) -> u16 {
    Response::from_bytes(&sent.payload).unwrap().status().as_u16()
}

fn method(sent: &Sent) -> Option<String> {
    let request = Request::from_bytes(&sent.payload).ok()?;
    Some(request.method().as_str().to_owned())
}

// Each response of a server transaction goes back with the context its
// request arrived with: the automatic 100, the final, and the final again
// for a retransmission. A request that came without context is answered
// without one. An ACK the TU gets comes up with its own context.
#[tokio::test]
async fn server_output_goes_back_with_the_request_s_context() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);

    wire.deliver(arriving(invite("busy"), "nic0"));
    let busy_invite = request(&mut incoming).await;
    assert_eq!(busy_invite.received.context().as_bytes(), "nic0");
    assert_eq!(busy_invite.received.source(), PEER);
    assert_eq!(busy_invite.received.destination(), LOCAL);
    let (responder, _) = busy_invite.transaction.into_parts();
    let busy = Response::reply_to(&busy_invite.request)
        .status(486)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap();
    responder.respond(busy).await.unwrap();
    wire.deliver(arriving(invite("busy"), "nic0"));

    let sent = wire.sent(3).await;
    assert_eq!(sent.iter().map(status).collect::<Vec<_>>(), [100, 486, 486]);
    for sent in &sent {
        assert_eq!((sent.source, sent.destination), (LOCAL, PEER));
        assert_eq!(sent.path, Way::reply("nic0"));
    }

    wire.deliver(datagram(options("bare")));
    let bare = request(&mut incoming).await;
    assert!(bare.received.context().is_empty());
    let (responder, _) = bare.transaction.into_parts();
    responder.respond(ok(&bare.request)).await.unwrap();
    assert_eq!(wire.sent(4).await[3].path, Way::Default);

    wire.deliver(arriving(stray_ack(), "nic2"));
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::Ack(ack)) = event.unwrap() else {
        panic!("expected the ACK");
    };
    assert_eq!(ack.received.context().as_bytes(), "nic2");
}

// Without `rport` a response goes to the port of the Via, not to the one its
// request came from (RFC 3261 section 18.2.2). The backend gets that
// destination with the request's context, and works out the way back from
// both. It does not swap the request's addresses.
#[tokio::test]
async fn a_response_without_rport_goes_to_the_via_port_with_the_context() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);
    let text = options("plain").replace(";rport", "");

    wire.deliver(arriving(text, "nic0"));
    let request = request(&mut incoming).await;
    assert_eq!(request.received.source(), PEER);
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    let via_port = SocketAddr::new(PEER.ip(), 5060);
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, via_port));
    assert_eq!(sent[0].path, Way::reply("nic0"));
}

// Two endpoints on two wires with the same addresses stand for two network
// domains. The same request, branch and addresses in both makes a
// transaction in each, and each answers on its own wire with its own
// context. Within one domain the same request over another NIC is a
// retransmission: the NIC is no part of the matching key of RFC 3261 section
// 17.2.3, and the cached response goes back the way the first copy came.
#[tokio::test]
async fn identical_tuples_in_separate_domains_stay_apart() {
    let (a_wire, b_wire) = (Wire::default(), Wire::default());
    let (_a, mut a_incoming) = bind(&a_wire);
    let (_b, mut b_incoming) = bind(&b_wire);

    a_wire.deliver(arriving(options("same"), "domain a"));
    b_wire.deliver(arriving(options("same"), "domain b"));
    for (incoming, domain) in
        [(&mut a_incoming, "domain a"), (&mut b_incoming, "domain b")]
    {
        let request = request(incoming).await;
        assert_eq!(request.received.context().as_bytes(), domain);
        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request)).await.unwrap();
    }
    assert_eq!(a_wire.sent(1).await[0].path, Way::reply("domain a"));
    assert_eq!(b_wire.sent(1).await[0].path, Way::reply("domain b"));

    a_wire.deliver(arriving(options("same"), "domain a nic1"));
    let sent = a_wire.sent(2).await;
    assert_eq!(sent[1].payload, sent[0].payload);
    assert_eq!(sent[1].path, Way::reply("domain a"));
    let again = timeout(Duration::from_millis(50), a_incoming.recv()).await;
    assert!(again.is_err(), "a retransmission reaches no TU");
    assert_eq!(b_wire.count(), 1);
}

// The 503 a request gets when the endpoint is full goes back with the
// request's context, though nothing keeps that context afterwards.
#[tokio::test]
async fn a_stateless_refusal_goes_back_with_the_context() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .max_pending_requests(1)
        .bind()
        .unwrap();

    wire.deliver(arriving(options("held"), "nic0"));
    let _held = request(&mut incoming).await;
    wire.deliver(arriving(options("refused"), "nic1"));

    let sent = wire.sent(1).await;
    assert_eq!(status(&sent[0]), 503);
    assert_eq!(sent[0].path, Way::reply("nic1"));
}

// The endpoint counts the contexts it keeps for as long as anything holds
// them, which for a server transaction lasts until Timer J. New requests get
// three quarters of the limits and a 503 past them. A request without
// context takes nothing.
#[tokio::test]
async fn kept_contexts_are_bounded_for_their_lifetime() {
    let wire = Wire::default();
    let timers =
        Timers::builder().t1(Duration::from_millis(5)).build().unwrap();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(timers)
        .context_limits(WriteLimits { messages: 4, bytes: 64 * 1024 })
        .bind()
        .unwrap();

    let mut held = Vec::new();
    for call in ["one", "two", "three"] {
        wire.deliver(arriving(options(call), "nic0"));
        held.push(request(&mut incoming).await);
    }
    wire.deliver(arriving(options("four"), "nic0"));
    let sent = wire.sent(1).await;
    assert_eq!(status(&sent[0]), 503);
    wire.deliver(datagram(options("bare")));
    let bare = request(&mut incoming).await;
    assert!(bare.received.context().is_empty());

    // Their 500s go out when the responders drop, and Timer J of 64 T1 ends
    // the transactions that kept the contexts. Until then a request with
    // context gets a 503.
    drop(held);
    wire.sent(4).await;
    let admitted = timeout(Duration::from_secs(5), async {
        for attempt in 0.. {
            wire.deliver(arriving(options(&format!("late{attempt}")), "nic0"));
            let event = timeout(Duration::from_millis(50), incoming.recv());
            if let Ok(Some(IncomingEvent::Request(request))) = event.await {
                return request;
            }
        }
        unreachable!()
    })
    .await
    .expect("Timer J frees the contexts");
    assert_eq!(admitted.received.context().as_bytes(), "nic0");
}

// A request on a prepared path goes from the path's source with its
// context, names the path's `sent-by` in its Via, and keeps the path for its
// retransmissions and its CANCEL. A response must name that `sent-by`,
// as RFC 3261 section 18.1.2 checks, not the source address.
#[tokio::test]
async fn a_prepared_path_carries_a_whole_transaction() {
    let wire = Wire::default();
    let timers =
        Timers::builder().t1(Duration::from_millis(20)).build().unwrap();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(timers)
        .bind()
        .unwrap();
    assert_eq!(endpoint.timers(), timers);

    let selection = PathSelection::new(ALTERNATE, PEER)
        .context(context("vlan 200"))
        .sent_by(PUBLIC);
    let path = endpoint.prepare_path(selection).await.unwrap();
    assert_eq!(
        (path.source(), path.destination(), path.sent_by()),
        (ALTERNATE, PEER, PUBLIC)
    );
    assert_eq!(path.context().as_bytes(), "vlan 200");
    let (control, mut responses) = endpoint
        .start(outgoing_invite("path"), Target::path(path))
        .await
        .unwrap()
        .into_parts();
    assert_eq!(control.flow().local, ALTERNATE);

    // The INVITE and at least one retransmission after T1.
    let sent = wire.sent(2).await;
    let invite = Request::from_bytes(&sent[0].payload).unwrap();
    let via = invite.headers().get(VIA).unwrap().clone();
    assert!(via.as_str().starts_with("SIP/2.0/UDP 203.0.113.5:5060;rport;"));

    let ringing = Response::reply_to(&invite)
        .status(180)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    let mut misnamed = ringing.clone();
    let source_via = via.as_str().replace("203.0.113.5", "198.51.100.10");
    misnamed.headers_mut().insert(VIA, source_via.parse().unwrap());
    wire.deliver(Ok(Datagram::new(misnamed.to_bytes(), PEER, ALTERNATE)));
    wire.deliver(Ok(Datagram::new(ringing.to_bytes(), PEER, ALTERNATE)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status().as_u16(), 180);
    assert_eq!(response.headers().get(VIA), Some(&via));

    let outcome = control.cancel().await.unwrap();
    assert!(matches!(outcome, signa_core::endpoint::CancelOutcome::Sent(_)));
    let cancel = timeout(Duration::from_secs(2), async {
        loop {
            let sent = wire.sent(wire.count() + 1).await;
            if let Some(cancel) = sent
                .into_iter()
                .find(|sent| method(sent).as_deref() == Some("CANCEL"))
            {
                return cancel;
            }
        }
    })
    .await
    .unwrap();

    // The 487 is acknowledged by the transaction, on the INVITE's path
    // (RFC 3261 section 17.1.1.3).
    let terminated = Response::reply_to(&invite)
        .status(487)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    wire.deliver(Ok(Datagram::new(terminated.to_bytes(), PEER, ALTERNATE)));
    timeout(Duration::from_secs(2), async {
        while !wire
            .sent(wire.count())
            .await
            .iter()
            .any(|sent| method(sent).as_deref() == Some("ACK"))
        {
            wire.sent(wire.count() + 1).await;
        }
    })
    .await
    .unwrap();

    let sent = wire.sent(wire.count()).await;
    for sent in sent.iter().filter(|sent| method(sent).is_some()) {
        assert_eq!((sent.source, sent.destination), (ALTERNATE, PEER));
        assert_eq!(sent.path, Way::prepared("vlan 200"));
    }
    let cancel = Request::from_bytes(&cancel.payload).unwrap();
    assert_eq!(cancel.headers().get(VIA), Some(&via));
}

// A path belongs to the endpoint that prepared it, and so does a prepared
// request. Another endpoint refuses both before anything is sent. The
// backend refuses a source it may not send from when the path is prepared,
// and a path that has turned stale since when a request is sent on it.
#[tokio::test]
async fn paths_are_checked_before_anything_is_sent() {
    let (a_wire, b_wire) = (Wire::default(), Wire::default());
    let (a, _a_incoming) = bind(&a_wire);
    let (b, _b_incoming) = bind(&b_wire);
    let path = a.prepare_path(PathSelection::new(LOCAL, PEER)).await.unwrap();

    let on_path = || Target::path(path.clone());
    assert!(
        b.start(outgoing("1"), on_path()).await.unwrap_err().is_stale_path()
    );
    let error = b
        .send_request(outgoing("2"), on_path(), ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_stale_path());
    assert!(
        b.prepare(outgoing("3"), on_path()).await.unwrap_err().is_stale_path()
    );
    let prepared = a
        .prepare(outgoing("4"), Target::new(Transport::Udp, PEER))
        .await
        .unwrap();
    assert!(b.start_prepared(prepared).await.unwrap_err().is_stale_path());
    assert_eq!((a_wire.count(), b_wire.count()), (0, 0));

    let multicast: SocketAddr = "224.0.1.75:5060".parse().unwrap();
    let no_port = SocketAddr::new(PEER.ip(), 0);
    let unspecified: SocketAddr = "0.0.0.0:5060".parse().unwrap();
    for selection in [
        PathSelection::new(LOCAL, multicast),
        PathSelection::new(LOCAL, no_port),
        PathSelection::new(LOCAL, PEER).sent_by(unspecified),
        PathSelection::new(unspecified, PEER),
    ] {
        let error = a.prepare_path(selection).await.unwrap_err();
        assert!(error.is_path_refused(), "{error}");
    }

    let error =
        a.prepare_path(PathSelection::new(PUBLIC, PEER)).await.unwrap_err();
    assert!(error.is_path_refused());
    assert_eq!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::AddrNotAvailable)
    );

    let selection =
        PathSelection::new(ALTERNATE, PEER).context(context("pppoe 7"));
    let path = a.prepare_path(selection).await.unwrap();
    a_wire.stale("pppoe 7");
    let error = a.start(outgoing("5"), Target::path(path)).await.unwrap_err();
    assert!(error.is_transport());
}

// `prepare` measures a request with the Via it will go out with, and
// `start_prepared` sends exactly those bytes. A UDP request over 1300 bytes
// is refused when started, not when measured, so the caller can take it to
// TCP instead (RFC 3261 section 18.1.1). That limit is for requests the
// endpoint generates. A response goes up to what the backend sends.
#[tokio::test]
async fn prepared_sizes_are_exact_and_only_requests_have_the_udp_limit() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);

    let prepared =
        endpoint.prepare(outgoing("size"), target.clone()).await.unwrap();
    let (len, via) = (prepared.encoded_len(), prepared.via().clone());
    assert_eq!(prepared.request().headers().get(VIA), Some(&via));
    assert_eq!(prepared.flow().local, LOCAL);
    endpoint.start_prepared(prepared).await.unwrap();
    let sent = wire.sent(1).await;
    assert_eq!(sent[0].payload.len(), len);
    let sent_request = Request::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(sent_request.headers().get(VIA), Some(&via));

    let mut large = outgoing("large");
    *large.body_mut() = Bytes::from(vec![b'x'; 1200]);
    let prepared = endpoint.prepare(large, target.clone()).await.unwrap();
    assert!(prepared.encoded_len() > 1300);
    let large = prepared.into_request();
    assert!(large.headers().get(VIA).is_none());
    let prepared = endpoint.prepare(large, target.clone()).await.unwrap();
    assert!(
        endpoint.start_prepared(prepared).await.unwrap_err().is_too_large()
    );
    assert_eq!(wire.count(), 1);

    wire.deliver(datagram(options("large")));
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    let route = responder.reply_route();
    let response = |body: usize| {
        Response::reply_to(&request.request)
            .status(200)
            .to_tag("bob")
            .body(Bytes::from(vec![b'x'; body]))
            .unwrap()
    };
    responder.respond(response(1200)).await.unwrap();
    let sent = wire.sent(2).await;
    assert!(sent[1].payload.len() > 1300);
    let Err(signa_core::endpoint::ReplyError::Transport(error)) =
        route.send(response(1500)).await
    else {
        panic!("a response over the backend's maximum fails");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

// The endpoint's own socket accepts a path from its own address without
// context, and sends on it.
#[tokio::test]
async fn the_socket_takes_paths_from_its_own_address() {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let local = endpoint.udp_addr().unwrap();

    let other_port = SocketAddr::new(local.ip(), local.port().wrapping_add(1));
    let error = endpoint
        .prepare_path(PathSelection::new(other_port, peer_addr))
        .await
        .unwrap_err();
    assert!(error.is_path_refused());
    let error = endpoint
        .prepare_path(
            PathSelection::new(local, peer_addr).context(context("x")),
        )
        .await
        .unwrap_err();
    assert!(error.is_path_refused());

    let path = endpoint
        .prepare_path(PathSelection::new(local, peer_addr))
        .await
        .unwrap();
    endpoint
        .send_request(outgoing("socket"), Target::path(path), ViaMode::Fresh)
        .await
        .unwrap();
    let mut buffer = [0; 2048];
    let (_, source) =
        timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source, local);
}

fn cancel_of(branch: &str) -> String {
    format!(
        "CANCEL sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@192.0.2.20>;tag=alice\r\n\
         To: <sip:bob@192.0.2.10>\r\n\
         Call-ID: {branch}\r\n\
         CSeq: 1 CANCEL\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

// A stateless endpoint keeps a request's context for its reply route and
// shows a response's in its envelope.
#[tokio::test]
async fn a_stateless_endpoint_keeps_contexts_too() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .reception(Reception::Stateless)
        .bind()
        .unwrap();

    wire.deliver(arriving(options("stateless"), "nic0"));
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::StatelessRequest(received)) = event.unwrap()
    else {
        panic!("expected a stateless request");
    };
    assert_eq!(received.received.context().as_bytes(), "nic0");
    received.reply.send(ok(&received.request)).await.unwrap();
    assert_eq!(wire.sent(1).await[0].path, Way::reply("nic0"));

    let request = Request::from_bytes(options("upstream").as_bytes()).unwrap();
    wire.deliver(
        Ok(Datagram::new(ok(&request).to_bytes(), PEER, LOCAL))
            .map(|datagram| datagram.with_context(context("nic1"))),
    );
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::StatelessResponse(response)) = event.unwrap()
    else {
        panic!("expected a stateless response");
    };
    assert_eq!(response.received.context().as_bytes(), "nic1");
}

// ACKs and matched CANCELs may use the quarter of the context limits that
// new requests leave. An ACK past all of it is discarded and counted, as one
// past the control event limits is.
#[tokio::test]
async fn control_messages_keep_a_share_of_the_context_limits() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .context_limits(WriteLimits { messages: 4, bytes: 64 * 1024 })
        .bind()
        .unwrap();

    let mut held = Vec::new();
    for branch in ["one", "two", "three"] {
        wire.deliver(arriving(invite(branch), "nic0"));
        held.push(request(&mut incoming).await);
    }
    wire.deliver(arriving(cancel_of("one"), "nic9"));
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::Cancel(cancel)) = event.unwrap() else {
        panic!("expected the CANCEL");
    };
    assert_eq!(cancel.received.context().as_bytes(), "nic9");

    wire.deliver(arriving(stray_ack(), "nic2"));
    timeout(Duration::from_secs(2), async {
        while endpoint.reception_stats().dropped_acks == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the ACK is counted");
    let event = timeout(Duration::from_millis(50), incoming.recv()).await;
    assert!(event.is_err(), "the ACK reaches no TU");
}

// A path counts against the context limits until its last clone and the
// last transaction sent on it drop. New paths get three quarters.
#[tokio::test]
async fn a_path_is_counted_until_nothing_holds_it() {
    let wire = Wire::default();
    let timers =
        Timers::builder().t1(Duration::from_millis(5)).build().unwrap();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(timers)
        .context_limits(WriteLimits { messages: 4, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let prepare = || {
        let selection =
            PathSelection::new(LOCAL, PEER).context(context("vlan"));
        endpoint.prepare_path(selection)
    };

    let mut paths = Vec::new();
    for _ in 0..3 {
        paths.push(prepare().await.unwrap());
    }
    assert!(prepare().await.unwrap_err().is_busy());
    let clone = paths[1].clone();
    drop(paths.remove(1));
    assert!(prepare().await.unwrap_err().is_busy(), "a clone holds it");
    drop(clone);
    paths.push(prepare().await.unwrap());

    // The transaction keeps its path until Timer F ends it, 64 T1 later.
    let (_control, mut responses) = endpoint
        .start(outgoing("held"), Target::path(paths.remove(0)))
        .await
        .unwrap()
        .into_parts();
    assert!(
        prepare().await.unwrap_err().is_busy(),
        "the transaction holds it"
    );
    let end = timeout(Duration::from_secs(2), responses.next()).await;
    assert!(end.unwrap().unwrap().unwrap_err().is_timeout());
    let freed = timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(path) = prepare().await {
                return path;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(freed.is_ok(), "the ended transaction frees its path");
}

// A backend that reports an IPv4 peer by its IPv4-mapped IPv6 address gets
// it named in its IPv4 form, as a Via names it, so a request whose Via
// names that address and asks for no `rport` gets no `received`.
#[tokio::test]
async fn mapped_ipv4_addresses_are_named_in_their_own_form() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);
    let mapped = |addr: SocketAddr| match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            SocketAddr::new(ip.to_ipv6_mapped().into(), addr.port())
        }
        std::net::IpAddr::V6(_) => addr,
    };

    let text = options("mapped")
        .replace("192.0.2.20:5060", "192.0.2.20:5070")
        .replace(";rport", "");
    wire.deliver(Ok(Datagram::new(
        Bytes::from(text),
        mapped(PEER),
        mapped(LOCAL),
    )));

    let request = request(&mut incoming).await;
    assert_eq!(request.received.source(), PEER);
    assert_eq!(request.received.destination(), LOCAL);
    let via = request.request.headers().get(VIA).unwrap().as_str();
    assert!(!via.contains("received="), "{via}");
}

// A dual-stack socket sends to an IPv4 peer at its mapped address, so it
// takes an IPv4 path from an address of this host too, where the platform
// sends from a named source. Elsewhere, as on Windows, the kernel picks the
// source of a wildcard socket, a path could not fix it, and the socket
// refuses the path. A socket bound to the address takes it there too, see
// `the_socket_takes_paths_from_its_own_address`.
#[tokio::test]
async fn a_dual_stack_socket_takes_ipv4_paths() {
    let Ok((endpoint, _incoming)) =
        Endpoint::builder().udp("[::]:0".parse().unwrap()).bind()
    else {
        return; // No IPv6 here.
    };
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let port = endpoint.udp_addr().unwrap().port();
    let source = SocketAddr::new([127, 0, 0, 1].into(), port);

    let prepared =
        endpoint.prepare_path(PathSelection::new(source, peer_addr)).await;
    let names_source = cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ));
    if !names_source {
        assert!(prepared.unwrap_err().is_path_refused());
        return;
    }
    let path = prepared.unwrap();
    endpoint
        .send_request(outgoing("dual"), Target::path(path), ViaMode::Fresh)
        .await
        .unwrap();

    let mut buffer = [0; 2048];
    let (_, from) =
        timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(from, source);
}
