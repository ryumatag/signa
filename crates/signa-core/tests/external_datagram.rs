/*!
An endpoint whose UDP datagrams travel over a backend of the application's
own, through the public API only.

The backend here is an in-memory packet wire, standing in for an adapter that
reads and writes frames on a NIC. The test decides when each write completes,
fails or waits, which a socket cannot be made to do on demand.
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
        Endpoint, Incoming, IncomingEvent, ServerRequest, ShutdownOutcome,
        Target, ViaMode,
    },
    message::header::{Tag, VIA},
    transport::{
        Flow, Transport, WriteLimits,
        datagram::{
            Capabilities, Datagram, DatagramIo, DatagramWrite,
            MAX_CONTEXT_LEN, RecvError, Submit, TransportContext, WriteId,
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
        request.flow,
        Flow { transport: Transport::Udp, local: LOCAL, remote: PEER }
    );
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, PEER));
    let response = Response::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

// A client transaction sends from the backend's address and names it in its
// Via. Its response arrives through the backend too.
#[tokio::test]
async fn a_client_transaction_runs_over_the_wire() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);

    let target = Target::new(Transport::Udp, PEER);
    let (control, mut responses) =
        endpoint.start(outgoing("uac"), target).await.unwrap().into_parts();
    assert_eq!(control.flow().local, LOCAL);

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, PEER));
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

    let mut send =
        pin!(endpoint.send_request(outgoing("delay"), target, ViaMode::Fresh));
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
        .send_request(outgoing("fail"), target, ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_transport());
    let error =
        endpoint.start(outgoing("fail-at-once"), target).await.unwrap_err();
    assert!(error.is_transport());

    wire.writes(Writes::Delay);
    let (_control, mut responses) = endpoint
        .start(outgoing("fail-later"), target)
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

    let first = endpoint.send_request(outgoing("1"), target, ViaMode::Fresh);
    let second = endpoint.send_request(outgoing("2"), target, ViaMode::Fresh);
    let mut both = pin!(async { tokio::join!(first, second) });
    assert!(timeout(Duration::from_millis(50), &mut both).await.is_err());
    let error = endpoint
        .send_request(outgoing("3"), target, ViaMode::Fresh)
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
    let mut send =
        pin!(endpoint.send_request(outgoing("drain"), target, ViaMode::Fresh));
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
    let mut taken =
        pin!(endpoint.send_request(outgoing("taken"), target, ViaMode::Fresh));
    tokio::select! {
        _ = &mut taken => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }
    wire.writes(Writes::Hold);
    let held = endpoint.send_request(outgoing("held"), target, ViaMode::Fresh);
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
    let mut send =
        pin!(endpoint.send_request(outgoing("stuck"), target, ViaMode::Fresh));
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
