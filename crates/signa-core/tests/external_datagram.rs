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
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use quickcheck::{Arbitrary, Gen, QuickCheck};
use signa_core::{
    Message, Request, Response,
    endpoint::{
        CancelOutcome, Endpoint, Error, Incoming, IncomingEvent,
        PathSelection, ReceivedResponse, Reception, ServerEvent,
        ServerRequest, ShutdownOutcome, Target, ViaMode,
        observe::{
            self, Observed, Observer, Record, WriteEnd, WriteOrigin, WriteRef,
        },
        port::{
            self, Capture, DatagramPort, Ingress, RawPath, ReceivedDatagram,
        },
    },
    message::header::{Tag, VIA},
    transaction::Timers,
    transport::{
        Flow, Limits, Transport,
        datagram::{
            Capabilities, Datagram, DatagramIo, DatagramWrite,
            MAX_CONTEXT_LEN, RecvError, Submit, TransportContext, WriteId,
            WriteOutcome, WritePath,
        },
    },
};
use tokio::{
    sync::Notify,
    task::{JoinHandle, yield_now},
    time::{advance, sleep, timeout},
};

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
/// A link-local address of the wire on interface 7. The scope says which
/// interface, and nothing else in the endpoint reads it.
const LINK_LOCAL: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x10),
    5060,
    0,
    7,
));
/// A link-local peer on the same interface, with a flow label.
const LINK_PEER: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x20),
    5070,
    0x12345,
    7,
));
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
    /// Refuses it when it is offered.
    Reject,
    /// Refuses it with `WouldBlock`, as a backend whose own queue is full.
    Busy,
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
    completions: VecDeque<(WriteId, WriteOutcome)>,
    complete: Option<Waker>,
    delayed: VecDeque<WriteId>,
    closed: bool,
    /// Makes the close never finish, as a backend with a stuck writer task.
    stuck: bool,
    /// Path contexts the wire refuses to send on any more, as for a PPPoE
    /// session that has ended.
    stale: Vec<Bytes>,
    /// The address the wire names as its own, `LOCAL` unless set.
    local: Option<SocketAddr>,
    /// Writes refused in `Writes::Reject` or `Writes::Busy`.
    refused: usize,
}

#[derive(Clone, Default)]
struct Wire {
    state: Arc<Mutex<State>>,
    sent: Arc<Notify>,
}

impl Wire {
    /// A wire that names `local` as its own address.
    fn at(local: SocketAddr) -> Wire {
        let wire = Wire::default();
        wire.state.lock().unwrap().local = Some(local);
        wire
    }

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

    /// Reports the newest delayed write.
    fn finish_newest(&self, outcome: impl Into<WriteOutcome>) {
        let mut state = self.state.lock().unwrap();
        let id = state.delayed.pop_back().expect("a delayed write");
        state.completions.push_back((id, outcome.into()));
        if let Some(waker) = state.complete.take() {
            waker.wake();
        }
    }

    /// Reports the oldest delayed write.
    fn finish(&self, outcome: impl Into<WriteOutcome>) {
        let mut state = self.state.lock().unwrap();
        let id = state.delayed.pop_front().expect("a delayed write");
        state.completions.push_back((id, outcome.into()));
        if let Some(waker) = state.complete.take() {
            waker.wake();
        }
    }

    /// Waits until the wire has accepted `n` writes, and returns them.
    async fn sent(&self, n: usize) -> Vec<Sent> {
        self.until(|state| state.sent.len() >= n).await;
        self.state.lock().unwrap().sent.clone()
    }

    /// Waits until `done` holds of the wire, as a write is accepted, held or
    /// refused.
    async fn until(&self, done: impl Fn(&State) -> bool) {
        timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.sent.notified();
                if done(&self.state.lock().unwrap()) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("the wire within two seconds")
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
        self.state.lock().unwrap().local.unwrap_or(LOCAL)
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
            Writes::Complete => {
                state.completions.push_back((id, WriteOutcome::Written));
            }
            Writes::Delay => state.delayed.push_back(id),
            Writes::Fail => state.completions.push_back((
                id,
                WriteOutcome::NotWritten(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "link down",
                )),
            )),
            Writes::Hold => {
                state.submit = Some(cx.waker().clone());
                self.sent.notify_waiters();
                return Submit::Pending(write);
            }
            Writes::Reject => {
                state.refused += 1;
                self.sent.notify_waiters();
                return Submit::Rejected(
                    write,
                    io::Error::new(io::ErrorKind::NotConnected, "refused"),
                );
            }
            Writes::Busy => {
                state.refused += 1;
                self.sent.notify_waiters();
                return Submit::Rejected(
                    write,
                    io::Error::new(io::ErrorKind::WouldBlock, "queue full"),
                );
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
    ) -> Poll<(WriteId, WriteOutcome)> {
        let mut state = self.state.lock().unwrap();
        match state.completions.pop_front() {
            Some(completion) => Poll::Ready(completion),
            None => {
                state.complete = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    // The wire may send from its own address, the alternate one or its
    // link-local one, with any context. Another source, or the link-local
    // address on another interface, is not this host's to use.
    fn check_path(
        &mut self,
        source: SocketAddr,
        _destination: SocketAddr,
        _context: &TransportContext,
    ) -> io::Result<()> {
        if [LOCAL, ALTERNATE, LINK_LOCAL].contains(&source) {
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
                WriteOutcome::NotWritten(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "closed",
                )),
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
        .unwrap()
        .response;
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

// A backend may refuse a write with `WouldBlock`, as one whose own queue is
// full would. That is the backend's refusal, not the endpoint's limits, so a
// one-shot send, a client transaction's request and a reply all fail as
// transport errors, and none is told that the endpoint is busy.
#[tokio::test]
async fn a_backend_refusing_with_would_block_is_a_transport_error() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    wire.deliver(datagram(options("refused-reply")));
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    let route = responder.reply_route();
    let target = Target::new(Transport::Udp, PEER);
    wire.writes(Writes::Busy);

    let sent = endpoint
        .send_request(outgoing("refused-send"), target.clone(), ViaMode::Fresh)
        .await
        .unwrap_err();
    let started =
        endpoint.start(outgoing("refused-start"), target).await.unwrap_err();
    let replied = route.send(ok(&request.request)).await;

    assert!(sent.is_transport() && !sent.is_busy(), "{sent}");
    assert!(started.is_transport() && !started.is_busy(), "{started}");
    assert!(
        matches!(replied, Err(signa_core::endpoint::ReplyError::Transport(_))),
        "{replied:?}"
    );
    assert_eq!(wire.state.lock().unwrap().refused, 3);
    drop(responder);
}

// A retransmission the backend refuses with `WouldBlock` is a transport
// error, which ends the client transaction (RFC 3261 section 17.1.2.2). Only
// a full limit of the endpoint's own skips a retransmission as if UDP had
// lost it.
#[tokio::test]
async fn a_refused_retransmission_ends_its_transaction() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing("retransmission"), target)
        .await
        .unwrap()
        .into_parts();
    wire.sent(1).await;

    wire.writes(Writes::Busy);

    let ended = timeout(Duration::from_secs(2), responses.next()).await;
    let ended = ended.unwrap().unwrap().unwrap_err();
    assert!(ended.is_transport() && !ended.is_timeout(), "{ended}");
    assert_eq!(wire.count(), 1);
}

/// What a wire reports for a write it took and can no longer account for.
fn unknown() -> WriteOutcome {
    WriteOutcome::Unknown(io::Error::other("the writer stopped"))
}

// A write the wire took and cannot account for may have gone out, so it is
// not a failure. A one-shot send and a one-shot reply report the outcome
// unknown, and a client transaction goes on until its response. Only a
// request that did not go out ends a transaction (RFC 3261 sections 17.1.1.2
// and 17.1.2.2).
#[tokio::test]
async fn an_unknown_write_outcome_is_not_a_failure() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    wire.writes(Writes::Delay);

    let send = send_options(&endpoint, "unknown");
    wire.sent(1).await;
    wire.finish(unknown());
    let error = timeout(Duration::from_secs(2), send)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is_outcome_unknown());
    assert!(!error.is_transport() && !error.is_closed());

    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing("uac-unknown"), target)
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(2).await;
    wire.finish(unknown());
    assert!(
        timeout(Duration::from_millis(50), responses.next()).await.is_err(),
        "the transaction ended on an unknown outcome"
    );
    let sent_request = Request::from_bytes(&sent[1].payload).unwrap();
    let response = ok(&sent_request).to_bytes();
    wire.deliver(Ok(Datagram::new(response, PEER, LOCAL)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);

    wire.writes(Writes::Complete);
    wire.deliver(datagram(options("reply-unknown")));
    let request = request(&mut incoming).await;
    // The responder stays alive, so that its drop sends no 500 meanwhile.
    let (responder, _) = request.transaction.into_parts();
    let route = responder.reply_route();
    wire.writes(Writes::Delay);
    let reply = tokio::spawn({
        let response = ok(&request.request);
        async move { route.send(response).await }
    });
    wire.until(|state| !state.delayed.is_empty()).await;
    wire.finish(unknown());
    let reply = timeout(Duration::from_secs(2), reply).await.unwrap();
    assert!(matches!(
        reply.unwrap(),
        Err(signa_core::endpoint::ReplyError::OutcomeUnknown(_))
    ));
    drop(responder);
}

// A final the wire cannot account for is observed as an unknown outcome, not
// as a transport failure, and the transaction keeps its state as it does
// after one (RFC 6026 section 8.8). A retransmission of the request is
// absorbed and gets the cached final.
#[tokio::test]
async fn an_unknown_final_is_observed_apart_from_failures() {
    for is_invite in [false, true] {
        let branch =
            if is_invite { "unknown-invite" } else { "unknown-options" };
        let text = if is_invite { invite(branch) } else { options(branch) };
        let code = if is_invite { 486 } else { 200 };
        let wire = Wire::default();
        let (_endpoint, mut incoming) = bind(&wire);
        wire.deliver(datagram(text.clone()));
        let request = request(&mut incoming).await;
        if is_invite {
            wire.sent(1).await; // The automatic 100.
        }
        let (responder, mut events) = request.transaction.into_parts();
        let response = Response::reply_to(&request.request)
            .status(code)
            .to_tag(Tag::random())
            .body(Bytes::new())
            .unwrap();

        wire.writes(Writes::Delay);
        responder.respond(response).await.unwrap();
        wire.until(|state| !state.delayed.is_empty()).await;
        wire.finish(unknown());

        let event =
            timeout(Duration::from_secs(2), events.next()).await.unwrap();
        assert!(
            matches!(
                event,
                Some(ServerEvent::OutcomeUnknown { operation: Some(_), .. })
            ),
            "{is_invite}: {event:?}"
        );
        wire.writes(Writes::Complete);
        let before = wire.count();
        wire.deliver(datagram(text));
        let sent = wire.sent(before + 1).await;
        assert_eq!(status(&sent[before]), code, "{is_invite}");
        assert!(
            timeout(Duration::from_millis(50), incoming.recv()).await.is_err(),
            "{is_invite}: the retransmission reached the TU"
        );
    }
}

// Writes the wire cannot take wait in the endpoint, within its UDP write
// limits, and go out in order once the wire can take them.
#[tokio::test]
async fn a_held_wire_fills_the_write_limits() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .udp_write_limits(Limits { count: 2, bytes: 64 * 1024 })
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
        ) -> Poll<(WriteId, WriteOutcome)> {
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
    assert_eq!(busy_invite.received.flow().remote, PEER);
    assert_eq!(busy_invite.received.flow().local, LOCAL);
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
    assert_eq!(request.received.flow().remote, PEER);
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
// retransmission, since the NIC is no part of the matching key of RFC 3261
// section 17.2.3. Its cached response goes back the way the first copy came.
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
        .context_limits(Limits { count: 4, bytes: 64 * 1024 })
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
        .start(outgoing_invite("path"), Target::on_path(path))
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
        .unwrap()
        .response;
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

    let on_path = || Target::on_path(path.clone());
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
    let error =
        a.start(outgoing("5"), Target::on_path(path)).await.unwrap_err();
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
        .send_request(
            outgoing("socket"),
            Target::on_path(path),
            ViaMode::Fresh,
        )
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
        .context_limits(Limits { count: 4, bytes: 64 * 1024 })
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
            yield_now().await;
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
        .context_limits(Limits { count: 4, bytes: 64 * 1024 })
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
        .start(outgoing("held"), Target::on_path(paths.remove(0)))
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
            yield_now().await;
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
    assert_eq!(request.received.flow().remote, PEER);
    assert_eq!(request.received.flow().local, LOCAL);
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
        .send_request(outgoing("dual"), Target::on_path(path), ViaMode::Fresh)
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

// A link-local peer is reachable only through the interface its scope names.
// The request comes up with the scope and flow label the wire reported, and
// the response goes back with them, to the source port with `rport` and to
// the Via port without it (RFC 3581 section 4, RFC 3261 section 18.2.2), and
// so does the response a retransmission gets.
#[tokio::test]
async fn a_link_local_peer_is_answered_on_its_interface() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);
    let scoped =
        |branch| options(branch).replace("192.0.2.20:5060", "[fe80::20]:5060");
    let mut via_port = LINK_PEER;
    via_port.set_port(5060);

    for (text, destination) in [
        (scoped("rport"), LINK_PEER),
        (scoped("plain").replace(";rport", ""), via_port),
    ] {
        let sent = wire.count();
        let text = Bytes::from(text);
        wire.deliver(Ok(Datagram::new(text.clone(), LINK_PEER, LINK_LOCAL)));
        let request = request(&mut incoming).await;
        assert_eq!(request.received.flow().remote, LINK_PEER);
        assert_eq!(request.received.flow().local, LINK_LOCAL);

        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request)).await.unwrap();

        let response = &wire.sent(sent + 1).await[sent];
        assert_eq!(
            (response.source, response.destination),
            (LINK_LOCAL, destination)
        );

        // A retransmission gets the cached response the same way.
        wire.deliver(Ok(Datagram::new(text, LINK_PEER, LINK_LOCAL)));
        let resent = &wire.sent(sent + 2).await[sent + 1];
        assert_eq!(
            (resent.source, resent.destination),
            (LINK_LOCAL, destination)
        );
        assert_eq!(resent.payload, response.payload);
    }
}

// A path keeps the scope of its addresses, which the wire checks, and its
// requests go out with it. The `sent-by` has none, since a Via cannot name
// one (RFC 3261 section 25.1), and the response is matched against it.
#[tokio::test]
async fn a_scoped_path_keeps_its_scope_and_advertises_none() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let mut elsewhere = LINK_LOCAL;
    if let SocketAddr::V6(addr) = &mut elsewhere {
        addr.set_scope_id(8);
    }

    let refused = endpoint
        .prepare_path(PathSelection::new(elsewhere, LINK_PEER))
        .await
        .unwrap_err();
    let path = endpoint
        .prepare_path(PathSelection::new(LINK_LOCAL, LINK_PEER))
        .await
        .unwrap();

    assert!(refused.is_path_refused());
    assert_eq!((path.source(), path.destination()), (LINK_LOCAL, LINK_PEER));
    assert_eq!(path.sent_by(), "[fe80::10]:5060".parse().unwrap());

    let (_control, mut responses) = endpoint
        .start(outgoing("scoped-path"), Target::on_path(path))
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LINK_LOCAL, LINK_PEER));
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    let via = request.headers().get(VIA).unwrap().as_str();
    assert!(
        via.starts_with("SIP/2.0/UDP [fe80::10]:5060;rport;branch="),
        "{via}"
    );

    wire.deliver(Ok(Datagram::new(
        ok(&request).to_bytes(),
        LINK_PEER,
        LINK_LOCAL,
    )));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);
}

// A dual-stack socket reports an IPv4 peer by its mapped address, and the
// endpoint names it in its IPv4 form, as a Via does. An IPv6 socket takes
// IPv4 by default on Linux, Android and Apple's systems, which also report
// the address a datagram came to. Windows and some BSDs bind it to IPv6 only
// unless told otherwise, and a Linux host can be set up so too.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
))]
#[tokio::test]
async fn a_dual_stack_socket_names_ipv4_peers_in_their_own_form() {
    let Ok((endpoint, mut incoming)) =
        Endpoint::builder().udp("[::]:0".parse().unwrap()).bind()
    else {
        return; // No IPv6 here.
    };
    let port = endpoint.udp_addr().unwrap().port();
    let local = SocketAddr::new([127, 0, 0, 1].into(), port);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let text =
        options("dual").replace("192.0.2.20:5060", &peer_addr.to_string());

    peer.send_to(text.as_bytes(), local).await.unwrap();

    let request = request(&mut incoming).await;
    assert_eq!(request.received.flow().remote, peer_addr);
    assert_eq!(request.received.flow().local, local);

    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();
    let mut buffer = [0; 2048];
    let (n, _) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let response = Response::from_bytes(&buffer[..n]).unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

// A request to a link-local peer goes from the wire's link-local address on
// the peer's interface, which the peer's scope names. The Via names the
// address without one.
#[tokio::test]
async fn a_request_to_a_link_local_peer_goes_out_on_its_interface() {
    let mut unscoped = LINK_LOCAL;
    if let SocketAddr::V6(addr) = &mut unscoped {
        addr.set_scope_id(0);
    }
    let wire = Wire::at(unscoped);
    let (endpoint, _incoming) = bind(&wire);

    endpoint
        .send_request(
            outgoing("link-local"),
            Target::new(Transport::Udp, LINK_PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap();

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LINK_LOCAL, LINK_PEER));
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    let via = request.headers().get(VIA).unwrap().as_str();
    assert!(via.starts_with("SIP/2.0/UDP [fe80::10]:5060;rport;"), "{via}");
}

/// When a write of a server transaction fails.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// The wire refuses it when it is offered.
    Refused,
    /// The wire holds it, then refuses it.
    HeldThenRefused,
    /// The wire takes it and reports that writing it failed.
    Failed,
}

// RFC 6026 section 8.8 replaces the paragraph of RFC 3261 section 17.2.4 that
// ended a server transaction whose response could not be sent. It now
// "SHOULD inform the TU that a failure has occurred, and MUST remain in the
// current state". However the final fails, and whether or not the TU
// observes, an INVITE and a non-INVITE stay in Completed. A retransmission
// of the request is absorbed rather than reaching the TU again, and its
// cached final goes out once the wire takes writes again.
#[tokio::test]
async fn a_failed_final_leaves_the_server_transaction_in_its_state() {
    for failure in
        [Failure::Refused, Failure::HeldThenRefused, Failure::Failed]
    {
        for observed in [true, false] {
            for is_invite in [false, true] {
                let case = format!("{failure:?} {observed} {is_invite}");
                let branch = case.replace(' ', "-").to_lowercase();
                let text =
                    if is_invite { invite(&branch) } else { options(&branch) };
                let code = if is_invite { 486 } else { 200 };
                let wire = Wire::default();
                let (_endpoint, mut incoming) = bind(&wire);

                wire.deliver(datagram(text.clone()));
                let request = request(&mut incoming).await;
                if is_invite {
                    wire.sent(1).await; // The automatic 100.
                }
                let (responder, events) = request.transaction.into_parts();
                let mut events = observed.then_some(events);
                let response = Response::reply_to(&request.request)
                    .status(code)
                    .to_tag(Tag::random())
                    .body(Bytes::new())
                    .unwrap();
                let accepted = wire.count();
                wire.writes(match failure {
                    Failure::Refused => Writes::Reject,
                    Failure::HeldThenRefused => Writes::Hold,
                    Failure::Failed => Writes::Fail,
                });
                responder.respond(response).await.unwrap();
                // The write has failed once the wire has refused it or taken
                // it, since the wire reports a failure as it takes the write.
                if let Failure::HeldThenRefused = failure {
                    wire.until(|state| state.submit.is_some()).await;
                    wire.writes(Writes::Reject);
                }
                match failure {
                    Failure::Refused | Failure::HeldThenRefused => {
                        wire.until(|state| state.refused >= 1).await;
                    }
                    Failure::Failed => {
                        wire.sent(accepted + 1).await;
                    }
                }

                if let Some(events) = &mut events {
                    let event = timeout(Duration::from_secs(2), events.next())
                        .await
                        .unwrap();
                    assert!(
                        matches!(
                            event,
                            Some(ServerEvent::TransportFailure {
                                operation: Some(_),
                                ..
                            })
                        ),
                        "{case}: {event:?}"
                    );
                }

                wire.deliver(datagram(text.clone()));
                if let Some(events) = &mut events {
                    let event = timeout(Duration::from_secs(2), events.next())
                        .await
                        .unwrap();
                    assert!(
                        matches!(
                            event,
                            Some(ServerEvent::TransportFailure {
                                operation: None,
                                ..
                            })
                        ),
                        "{case}: {event:?}"
                    );
                }
                assert!(
                    timeout(Duration::from_millis(50), incoming.recv())
                        .await
                        .is_err(),
                    "{case}: the retransmission reached the TU"
                );

                wire.writes(Writes::Complete);
                let before = wire.count();
                wire.deliver(datagram(text));
                let sent = wire.sent(before + 1).await;
                assert_eq!(status(&sent[before]), code, "{case}");
            }
        }
    }
}

// A failed provisional leaves a server transaction in Proceeding too (RFC 6026
// section 8.8). For an INVITE it is the TU's 180. For a non-INVITE it is the
// automatic 100, which a non-INVITE over UDP gets once the client's Timer E
// would reach T2 (RFC 4320 section 4.1), and whose failure used to end it. A
// retransmission then gets the provisional again, and the final still goes.
#[tokio::test]
async fn a_failed_provisional_leaves_the_server_transaction_in_proceeding() {
    let timers = Timers::builder()
        .t1(Duration::from_millis(5))
        .t2(Duration::from_millis(20))
        .build()
        .unwrap();
    for failure in
        [Failure::Refused, Failure::HeldThenRefused, Failure::Failed]
    {
        for is_invite in [false, true] {
            let case = format!("{failure:?} {is_invite}");
            let branch = case.replace(' ', "-").to_lowercase() + "-1xx";
            let text =
                if is_invite { invite(&branch) } else { options(&branch) };
            let wire = Wire::default();
            let (_endpoint, mut incoming) = Endpoint::builder()
                .udp_io(wire.clone())
                .timers(timers)
                .bind()
                .unwrap();
            let failing = match failure {
                Failure::Refused => Writes::Reject,
                Failure::HeldThenRefused => Writes::Hold,
                Failure::Failed => Writes::Fail,
            };

            if !is_invite {
                wire.writes(failing);
            }
            wire.deliver(datagram(text.clone()));
            let request = request(&mut incoming).await;
            let (responder, mut events) = request.transaction.into_parts();
            let tag = Tag::random();
            if is_invite {
                wire.sent(1).await; // The automatic 100.
                wire.writes(failing);
                let ringing = Response::reply_to(&request.request)
                    .status(180)
                    .to_tag(tag.clone())
                    .body(Bytes::new())
                    .unwrap();
                responder.respond(ringing).await.unwrap();
            }
            if let Failure::HeldThenRefused = failure {
                wire.until(|state| state.submit.is_some()).await;
                wire.writes(Writes::Reject);
            }
            let event =
                timeout(Duration::from_secs(2), events.next()).await.unwrap();
            assert!(
                matches!(
                    event,
                    Some(ServerEvent::TransportFailure { operation, .. })
                        if operation.is_some() == is_invite
                ),
                "{case}: {event:?}"
            );

            wire.writes(Writes::Complete);
            let before = wire.count();
            wire.deliver(datagram(text));
            let resent = &wire.sent(before + 1).await[before];
            let provisional = if is_invite { 180 } else { 100 };
            assert_eq!(status(resent), provisional, "{case}");

            let code = if is_invite { 486 } else { 200 };
            let response = Response::reply_to(&request.request)
                .status(code)
                .to_tag(tag.clone())
                .body(Bytes::new())
                .unwrap();
            responder.respond(response).await.unwrap();
            let sent = wire.sent(before + 2).await;
            assert_eq!(status(&sent[before + 1]), code, "{case}");
        }
    }
}

/// A port on `wire` whose datagrams the test disposes of.
fn intercept(wire: &Wire) -> (DatagramPort, Ingress) {
    DatagramPort::builder().udp_io(wire.clone()).intercept().unwrap()
}

/// The next datagram the port received.
async fn next(ingress: &mut Ingress) -> ReceivedDatagram {
    timeout(Duration::from_secs(2), ingress.recv())
        .await
        .expect("a datagram within two seconds")
        .expect("an open port")
}

// A datagram the application delivers to an endpoint on the port is received
// as from the endpoint's own socket. Its envelope shows how it arrived, the
// endpoint fills in `received` in its own copy, and its response goes out
// through the port with the request's context (RFC 3261 section 18.2.2).
#[tokio::test]
async fn a_delivered_datagram_is_received_and_answered_by_its_endpoint() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    assert_eq!(endpoint.udp_addr(), Some(LOCAL));
    // The Via names another host, so the endpoint marks its copy with
    // `received`, and without `rport` the response goes to that address at
    // the Via's port.
    let text = options("port")
        .replace("192.0.2.20:5060", "192.0.2.99:5060")
        .replace(";rport", "");

    wire.deliver(arriving(text.clone(), "nic0"));
    let datagram = next(&mut ingress).await;
    assert_eq!(datagram.payload(), text.as_bytes());
    assert_eq!(
        (datagram.received().flow().remote, datagram.received().flow().local),
        (PEER, LOCAL)
    );
    assert_eq!(datagram.received().context().as_bytes(), "nic0");
    datagram.try_deliver(&to_endpoint).unwrap();

    let request = request(&mut incoming).await;
    assert_eq!(request.received.flow().remote, PEER);
    assert_eq!(request.received.context().as_bytes(), "nic0");
    let via = request.request.headers().get(VIA).unwrap().as_str();
    assert!(via.contains("received=192.0.2.20"), "{via}");
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    let via_port = SocketAddr::new(PEER.ip(), 5060);
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, via_port));
    assert_eq!(sent[0].path, Way::reply("nic0"));
    assert_eq!(status(&sent[0]), 200);
    let stats = port.stats();
    assert_eq!((stats.received, stats.delivered), (1, 1));
}

/// Waits until the port's counts satisfy `done`.
async fn stats_until(port: &DatagramPort, done: impl Fn(port::Stats) -> bool) {
    timeout(Duration::from_secs(2), async {
        while !done(port.stats()) {
            yield_now().await;
        }
    })
    .await
    .expect("the counts within two seconds");
}

/// A raw path from the wire's address to the public address, along `nic1`.
async fn upstream(port: &DatagramPort) -> RawPath {
    let selection = PathSelection::new(LOCAL, PUBLIC).context(context("nic1"));
    port.prepare_path(selection).await.unwrap()
}

/// Short timers, so that a transaction ends at Timer J within a test.
fn short_timers() -> Timers {
    Timers::builder().t1(Duration::from_millis(5)).build().unwrap()
}

/// Sends a one-shot OPTIONS from `endpoint` in a task of its own, which
/// resolves with the write's local outcome.
fn send_options(
    endpoint: &Endpoint,
    call: &'static str,
) -> JoinHandle<Result<(), Error>> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        endpoint
            .send_request(
                outgoing(call),
                Target::new(Transport::Udp, PEER),
                ViaMode::Fresh,
            )
            .await
            .map(|_| ())
    })
}

// Forwarding sends the payload once, byte for byte, whether or not it parses
// as SIP. Compact and mixed-case headers stay as they came, and a payload that
// is not SIP goes too. Nothing else goes out: an INVITE forwarded this way
// gets no 100 Trying, no transaction and no retransmission, and the endpoint
// on the port sees nothing.
#[tokio::test]
async fn forwarding_sends_the_bytes_once_and_nothing_else() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (_endpoint, mut incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    let compact = Bytes::from_static(
        b"INVITE sip:bob@192.0.2.10 SIP/2.0\r\n\
          v: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bKcompact\r\n\
          f: <sip:alice@192.0.2.20>;tag=a\r\n\
          t: <sip:bob@192.0.2.10>\r\n\
          i: compact\r\n\
          cSeQ: 1 INVITE\r\n\
          mAX-fORWARDS: 70\r\n\
          l: 0\r\n\r\n",
    );
    let malformed = Bytes::from_static(b"INVITE this is not SIP\r\n\r\n\xff");

    for payload in [&compact, &malformed] {
        wire.deliver(Ok(Datagram::new(payload.clone(), PEER, LOCAL)));
        let datagram = next(&mut ingress).await;
        assert_eq!(datagram.parse().is_ok(), payload == &compact);
        datagram.try_forward(&upstream).unwrap().await.unwrap();
    }

    let sent = wire.sent(2).await;
    for (sent, payload) in sent.iter().zip([&compact, &malformed]) {
        assert_eq!(&sent.payload, payload);
        assert_eq!((sent.source, sent.destination), (LOCAL, PUBLIC));
        assert_eq!(sent.path, Way::prepared("nic1"));
    }
    assert!(
        timeout(Duration::from_millis(100), incoming.recv()).await.is_err()
    );
    assert_eq!(wire.count(), 2);
    assert_eq!(port.stats().forwarded, 2);
}

// A request the endpoint generates must go over a congestion-controlled
// transport once it is over 1300 bytes with no known path MTU (RFC 3261
// section 18.1.1), so the endpoint refuses it over UDP. A raw send is not a
// generated request and has only the backend's limit, so the same size goes.
// One over the backend's maximum is refused before anything is sent.
#[tokio::test]
async fn a_raw_send_has_only_the_backend_s_size_limit() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    let mut large = outgoing("large");
    *large.body_mut() = Bytes::from(vec![b'x'; 1250]);

    let generated = endpoint
        .send_request(
            large.clone(),
            Target::new(Transport::Udp, PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap_err();
    let raw = large.to_bytes();
    port.send_bytes(raw.clone(), &upstream).unwrap().await.unwrap();
    let over =
        port.send_bytes(Bytes::from(vec![0; 1473]), &upstream).unwrap_err();

    assert!(generated.is_too_large());
    assert!(raw.len() > 1300 && raw.len() <= 1472, "{}", raw.len());
    assert!(over.is_too_large());
    let sent = wire.sent(1).await;
    assert_eq!(sent[0].payload, raw);
    assert_eq!(wire.count(), 1);
}

// Delivery commits when the endpoint's queue takes the datagram. A full queue
// refuses it before then and hands it back with its disposition, so it can be
// tried again, go elsewhere or be discarded. It is never processed twice.
#[tokio::test]
async fn a_full_endpoint_queue_hands_the_datagram_back() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .delivery_queue(1)
        .intercept()
        .unwrap();
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    wire.deliver(datagram(options("first")));
    wire.deliver(datagram(options("second")));
    let first = next(&mut ingress).await;
    let second = next(&mut ingress).await;

    // Nothing awaits between the two, so the endpoint's driver has not run.
    first.try_deliver(&to_endpoint).unwrap();
    let refused = second.try_deliver(&to_endpoint).unwrap_err();

    assert!(refused.error().is_busy());
    assert_eq!(
        refused.error().to_string(),
        "the endpoint's delivery queue is full"
    );
    let second = refused.into_datagram();
    assert_eq!(second.payload(), options("second").as_bytes());
    let taken = request(&mut incoming).await;
    assert_eq!(taken.request.headers().get("Call-ID").unwrap(), "first");
    second.try_deliver(&to_endpoint).unwrap();
    let taken = request(&mut incoming).await;
    assert_eq!(taken.request.headers().get("Call-ID").unwrap(), "second");
    assert!(
        timeout(Duration::from_millis(50), incoming.recv()).await.is_err()
    );
    assert_eq!(port.stats().delivered, 2);
}

// After its deadline a datagram can no longer be delivered or forwarded, and
// it comes back from either. It still holds its share of the ingress limits
// until it drops, since the application still holds its bytes, so a datagram
// that arrives meanwhile finds them full. The clock is paused, so the
// deadline passes exactly when the test says.
#[tokio::test(start_paused = true)]
async fn an_expired_datagram_is_refused_but_still_counted() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .ingress_limits(Limits { count: 1, bytes: 64 * 1024 })
        .decision_deadline(Duration::from_millis(500))
        .intercept()
        .unwrap();
    let (_endpoint, _incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.deliver(datagram(options("late")));
    let held = next(&mut ingress).await;

    advance(Duration::from_millis(500)).await;
    let refused = held.try_deliver(&to_endpoint).unwrap_err();
    assert!(refused.error().is_expired());
    let refused = refused.into_datagram().try_forward(&upstream).unwrap_err();
    assert!(refused.error().is_expired());
    let held = refused.into_datagram();

    wire.deliver(datagram(options("meanwhile")));
    stats_until(&port, |stats| stats.overflow == 1).await;
    drop(held);
    wire.deliver(datagram(options("after")));
    let after = next(&mut ingress).await;
    assert_eq!(after.payload(), options("after").as_bytes());
    let stats = port.stats();
    assert_eq!((stats.received, stats.expired, stats.overflow), (3, 1, 1));
    assert_eq!(wire.count(), 0);
}

// An application that reads slowly loses traffic. The datagrams beyond the
// ingress limits are dropped on receipt and counted, and no SIP goes out for
// them. ACK and CANCEL progress is the endpoint's to guarantee once a
// datagram reaches it, not the port's.
#[tokio::test]
async fn a_slow_classifier_loses_what_is_beyond_the_ingress_limits() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .ingress_limits(Limits { count: 2, bytes: 64 * 1024 })
        .intercept()
        .unwrap();

    for n in 0..5 {
        wire.deliver(datagram(options(&format!("slow{n}"))));
    }
    stats_until(&port, |stats| stats.received == 5).await;

    assert_eq!(port.stats().overflow, 3);
    for n in 0..2 {
        let kept = next(&mut ingress).await;
        assert_eq!(kept.payload(), options(&format!("slow{n}")).as_bytes());
        kept.discard();
    }
    assert!(timeout(Duration::from_millis(50), ingress.recv()).await.is_err());
    assert_eq!(port.stats().discarded, 2);
    assert_eq!(wire.count(), 0);
}

// Two endpoints on one port are two network domains. The same request
// delivered to each makes a transaction in each, and each answers it. A path
// one endpoint prepared is refused by the other. When one stops, the other
// goes on, and the stopped one refuses a delivery and hands it back.
#[tokio::test]
async fn endpoints_on_one_port_stay_apart() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let bind =
        || Endpoint::builder().timers(short_timers()).bind_on(&port).unwrap();
    let (a, mut a_incoming, to_a) = bind();
    let (b, mut b_incoming, to_b) = bind();

    for (to, incoming) in [(&to_a, &mut a_incoming), (&to_b, &mut b_incoming)]
    {
        wire.deliver(datagram(options("both")));
        next(&mut ingress).await.try_deliver(to).unwrap();
        let request = request(incoming).await;
        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request)).await.unwrap();
    }
    let sent = wire.sent(2).await;
    assert_eq!(sent.iter().map(status).collect::<Vec<_>>(), [200, 200]);

    let path = a.prepare_path(PathSelection::new(LOCAL, PEER)).await.unwrap();
    let refused =
        b.start(outgoing("stale"), Target::on_path(path)).await.unwrap_err();
    assert!(refused.is_stale_path());

    let outcome = a.shutdown(Duration::from_secs(2)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    wire.deliver(datagram(options("after")));
    let refused = next(&mut ingress).await.try_deliver(&to_a).unwrap_err();
    assert!(refused.error().is_closed());
    refused.into_datagram().try_deliver(&to_b).unwrap();
    let request = request(&mut b_incoming).await;
    assert_eq!(request.request.headers().get("Call-ID").unwrap(), "after");
}

// A datagram goes only to an endpoint or along a path of the port that
// received it. One of another port is foreign, and the datagram comes back
// with its disposition, so it can still go where it belongs.
#[tokio::test]
async fn a_port_refuses_the_targets_of_another_port() {
    let (wire, other_wire) = (Wire::default(), Wire::default());
    let (port, mut ingress) = intercept(&wire);
    let (other, _other_ingress) = intercept(&other_wire);
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let (_stranger, _, to_stranger) =
        Endpoint::builder().bind_on(&other).unwrap();
    let foreign_path = upstream(&other).await;
    wire.deliver(datagram(options("foreign")));
    let held = next(&mut ingress).await;

    let refused = held.try_deliver(&to_stranger).unwrap_err();
    assert!(refused.error().is_foreign());
    let refused = refused.into_datagram().try_forward(&foreign_path);
    let refused = refused.unwrap_err();
    assert!(refused.error().is_foreign());
    assert_eq!(
        refused.error().to_string(),
        "the endpoint ingress or path belongs to another port"
    );
    let raw = Bytes::from_static(b"raw");
    let error = port.send_bytes(raw, &foreign_path).unwrap_err();
    assert!(error.is_foreign());

    refused.into_datagram().try_deliver(&to_endpoint).unwrap();
    let taken = request(&mut incoming).await;
    assert_eq!(taken.request.headers().get("Call-ID").unwrap(), "foreign");
    assert_eq!(port.stats().delivered, 1);
    assert_eq!(other_wire.count(), 0);
}

// The port numbers every write, the endpoints' and its raw sends, in one
// sequence of its own, and sends each outcome back to the write that made it.
// The wire here reports three writes in reverse order and fails the middle
// one, and only its sender sees the failure.
#[tokio::test]
async fn each_write_outcome_goes_back_to_its_own_write() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);

    let raw = port.send_bytes(Bytes::from_static(b"raw"), &upstream).unwrap();
    wire.sent(1).await;
    let from_a = send_options(&a, "a");
    wire.sent(2).await;
    let from_b = send_options(&b, "b");
    wire.sent(3).await;
    wire.finish_newest(Ok(()));
    wire.finish_newest(Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "down",
    )));
    wire.finish_newest(Ok(()));

    assert!(from_b.await.unwrap().is_ok());
    assert!(from_a.await.unwrap().unwrap_err().is_transport());
    raw.await.unwrap();
}

// An endpoint that stops at its deadline leaves unsent the writes the port
// still queues for it, and its outcome is an expiry. A write the backend had
// taken could not be taken back, but this one never reached it. The other
// endpoint's writes go out once the wire takes them.
#[tokio::test]
async fn an_endpoint_that_stops_withdraws_its_queued_writes() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Hold);

    let from_a = send_options(&a, "a");
    wire.until(|state| state.submit.is_some()).await;
    let outcome = a.shutdown(Duration::from_millis(50)).await;
    let from_b = send_options(&b, "b");
    yield_now().await;
    wire.writes(Writes::Complete);

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(from_a.await.unwrap().is_err());
    assert!(from_b.await.unwrap().is_ok());
    let sent = wire.sent(1).await;
    assert_eq!(sent.len(), 1);
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(request.headers().get("Call-ID").unwrap(), "b");
}

// Quiescing refuses new endpoints and new raw paths, and nothing else.
// Delivery, the endpoint's responses and paths, and raw sends on an existing
// path go on, so that registered endpoints can finish their work.
#[tokio::test]
async fn quiescing_refuses_only_new_endpoints_and_raw_paths() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;

    port.quiesce();

    let refused = Endpoint::builder().bind_on(&port).unwrap_err();
    assert!(refused.is_closed());
    let selection = PathSelection::new(LOCAL, PEER);
    let refused = port.prepare_path(selection.clone()).await.unwrap_err();
    assert!(refused.is_closed());
    assert_eq!(
        refused.to_string(),
        "the port is quiesced and takes no new paths"
    );
    assert!(endpoint.prepare_path(selection).await.is_ok());
    wire.deliver(datagram(options("quiet")));
    next(&mut ingress).await.try_deliver(&to_endpoint).unwrap();
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();
    let raw = Bytes::from_static(b"raw");
    port.send_bytes(raw, &upstream).unwrap().await.unwrap();
    assert_eq!(wire.sent(2).await.len(), 2);
}

// Closing drains the writes already admitted, then closes the backend, and
// everything of the port turns invalid: a raw send is refused, a datagram the
// application still holds can no longer be delivered, and the ingress ends.
#[tokio::test]
async fn closing_the_port_drains_its_writes_then_closes_the_backend() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (_endpoint, _incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.deliver(datagram(options("held")));
    let held = next(&mut ingress).await;
    wire.writes(Writes::Delay);
    let raw = port.send_bytes(Bytes::from_static(b"raw"), &upstream).unwrap();
    wire.sent(1).await;

    let close = tokio::spawn(port.close(Duration::from_secs(2)));
    yield_now().await;
    assert!(!wire.closed());
    wire.finish(Ok(()));

    raw.await.unwrap();
    assert_eq!(close.await.unwrap(), ShutdownOutcome::Drained);
    assert!(wire.closed());
    let refused = port.send_bytes(Bytes::from_static(b"late"), &upstream);
    assert!(refused.unwrap_err().is_closed());
    let refused = held.try_deliver(&to_endpoint).unwrap_err();
    assert!(refused.error().is_closed());
    assert!(ingress.recv().await.is_none());
}

// At the close's deadline the writes left fail, and a backend that does not
// finish closing is dropped, as an endpoint drops its own. The outcome says
// the deadline came first. The raw write the backend took and never reported
// may have gone out, and its waiter learns that its outcome is unknown, not
// that it failed.
#[tokio::test]
async fn a_port_close_gives_up_at_its_deadline() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);
    wire.state.lock().unwrap().stuck = true;
    let raw = port.send_bytes(Bytes::from_static(b"raw"), &upstream).unwrap();
    wire.sent(1).await;

    let close = port.close(Duration::from_millis(50));
    let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    let error = raw.await.unwrap_err();
    assert!(error.is_outcome_unknown());
    assert!(!error.is_transport() && !error.is_closed());
}

/// A backend over a [`Wire`] whose `Drop` holds until the test opens its
/// gate, so that a test can watch what a close does while the backend is
/// being dropped.
struct Gated {
    wire: Wire,
    dropping: Arc<Notify>,
    gate: std::sync::mpsc::Receiver<()>,
    dropped: Arc<AtomicBool>,
}

/// The test's side of a [`Gated`] backend.
struct Gate {
    dropping: Arc<Notify>,
    open: std::sync::mpsc::Sender<()>,
    dropped: Arc<AtomicBool>,
}

fn gated(wire: Wire) -> (Gated, Gate) {
    let dropping = Arc::new(Notify::new());
    let (open, gate) = std::sync::mpsc::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let backend = Gated {
        wire,
        dropping: dropping.clone(),
        gate,
        dropped: dropped.clone(),
    };
    (backend, Gate { dropping, open, dropped })
}

impl Drop for Gated {
    // The task that drops the backend waits here. `block_in_place` hands the
    // worker's other duties to another thread first. A worker blocked
    // outright can be the one that drives the timers, and then no timeout in
    // the test would fire. A test that dropped its gate has opened it too.
    fn drop(&mut self) {
        self.dropping.notify_one();
        tokio::task::block_in_place(|| {
            let _ = self.gate.recv();
        });
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl DatagramIo for Gated {
    fn local_addr(&self) -> SocketAddr {
        self.wire.local_addr()
    }

    fn capabilities(&self) -> Capabilities {
        self.wire.capabilities()
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
    ) -> Poll<(WriteId, WriteOutcome)> {
        self.wire.poll_complete(cx)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.wire.poll_close(cx)
    }
}

/// Checks that `closing` resolves only once the gated backend has dropped,
/// and returns its outcome.
async fn resolves_after_drop(
    gate: Gate,
    mut closing: JoinHandle<ShutdownOutcome>,
    case: &str,
) -> ShutdownOutcome {
    timeout(Duration::from_secs(2), gate.dropping.notified())
        .await
        .unwrap_or_else(|_| panic!("{case}: the backend is dropped"));
    let early = timeout(Duration::from_millis(50), &mut closing).await.ok();
    // Opened before any assertion, so that a failure cannot leave the task
    // that drops the backend blocked.
    gate.open.send(()).unwrap();
    let resolved_early = early.is_some();
    let outcome = match early {
        Some(outcome) => outcome,
        None => timeout(Duration::from_secs(2), closing).await.unwrap(),
    };

    assert!(
        !resolved_early,
        "{case}: resolved while the backend was dropping"
    );
    assert!(gate.dropped.load(Ordering::SeqCst), "{case}");
    outcome.unwrap()
}

// A port's close resolves only once its backend has dropped. The backend's
// `Drop` is the last thing that stops its tasks when it does not finish
// closing in time, and a socket is released only as it drops, so a closer
// told the outcome before could rebind the address or count on silence too
// early. An endpoint's shutdown and a capture's close keep the same order.
// Each closes in time with a wire that closes, and at the deadline with one
// that never does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_resolves_after_its_backend_has_dropped() {
    for stuck in [false, true] {
        let expected = if stuck {
            ShutdownOutcome::DeadlineExpired
        } else {
            ShutdownOutcome::Drained
        };
        let backend = || {
            let wire = Wire::default();
            wire.state.lock().unwrap().stuck = stuck;
            gated(wire)
        };

        let (gated, gate) = backend();
        let (port, _ingress) =
            DatagramPort::builder().udp_io(gated).intercept().unwrap();
        let closing = tokio::spawn(port.close(Duration::from_millis(50)));
        let case = format!("port {stuck}");
        assert_eq!(resolves_after_drop(gate, closing, &case).await, expected);

        let (gated, gate) = backend();
        let (endpoint, _incoming) =
            Endpoint::builder().udp_io(gated).bind().unwrap();
        let closing =
            tokio::spawn(endpoint.shutdown(Duration::from_millis(50)));
        let case = format!("endpoint {stuck}");
        assert_eq!(resolves_after_drop(gate, closing, &case).await, expected);

        let (gated, gate) = backend();
        let capture = Capture::builder().udp_io(gated).open().unwrap();
        let closing = tokio::spawn(capture.close(Duration::from_millis(50)));
        let case = format!("capture {stuck}");
        assert_eq!(resolves_after_drop(gate, closing, &case).await, expected);
    }
}

// Both closes start when they are called, not when their futures are first
// polled. A port takes no new endpoint from the call on, and a capture's
// deadline runs from it, so a close first polled after the deadline gives up
// at once on a backend that never finishes closing.
#[tokio::test(start_paused = true)]
async fn a_close_starts_when_it_is_called() {
    let (port, _ingress) = intercept(&Wire::default());
    let stuck = Wire::default();
    stuck.state.lock().unwrap().stuck = true;
    let capture = Capture::builder().udp_io(stuck).open().unwrap();

    let port_close = port.close(Duration::from_secs(1));
    let capture_close = capture.close(Duration::from_millis(50));
    advance(Duration::from_millis(60)).await;

    assert!(Endpoint::builder().bind_on(&port).unwrap_err().is_closed());
    let mut capture_close = pin!(capture_close);
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        capture_close.as_mut().poll(&mut cx),
        Poll::Ready(ShutdownOutcome::DeadlineExpired)
    );
    assert_eq!(port_close.await, ShutdownOutcome::Drained);
}

// A task that receives or closes can move between threads.
#[tokio::test]
async fn the_receive_and_close_futures_are_send() {
    fn send<T: Send>(_: T) {}
    let (port, mut ingress) = intercept(&Wire::default());
    let mut capture =
        Capture::builder().udp_io(Wire::default()).open().unwrap();
    let mut observer = port.observe(observe::Config::new()).await.unwrap();

    send(ingress.recv());
    send(capture.recv());
    send(observer.recv());
    send(capture.close(Duration::ZERO));
    send(port.close(Duration::ZERO));
}

/// A backend that panics in `poll_recv` once its fuse is lit, as an adapter
/// with a bug might.
struct Panicking<B> {
    backend: B,
    fuse: Arc<AtomicBool>,
}

impl<B: DatagramIo> DatagramIo for Panicking<B> {
    fn local_addr(&self) -> SocketAddr {
        self.backend.local_addr()
    }

    fn capabilities(&self) -> Capabilities {
        self.backend.capabilities()
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        let received = self.backend.poll_recv(cx);
        if self.fuse.load(Ordering::SeqCst) && received.is_ready() {
            panic!("the backend panics, as the test asked");
        }
        received
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        self.backend.poll_submit(cx, write)
    }

    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, WriteOutcome)> {
        self.backend.poll_complete(cx)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.backend.poll_close(cx)
    }
}

// A port whose backend panics still closes, as one that ran out of time
// would. Its task drops the backend before it reports the close expired, so
// a closer neither waits forever nor hears of the close while the backend is
// still dropping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_whose_backend_panics_still_closes() {
    let wire = Wire::default();
    let (gated, gate) = gated(wire.clone());
    let fuse = Arc::new(AtomicBool::new(true));
    let backend = Panicking { backend: gated, fuse };
    let (port, _ingress) =
        DatagramPort::builder().udp_io(backend).intercept().unwrap();

    wire.deliver(datagram(options("panic")));
    // The close comes once the task has panicked. One that came first would
    // stop reception before the panic.
    timeout(Duration::from_secs(2), gate.dropping.notified())
        .await
        .expect("the backend is dropped");
    let mut closing = tokio::spawn(port.close(Duration::from_secs(60)));
    let early = timeout(Duration::from_millis(50), &mut closing).await.ok();
    // Opened before any assertion, so that a failure cannot leave the task
    // that drops the backend blocked.
    gate.open.send(()).unwrap();
    let resolved_early = early.is_some();
    let outcome = match early {
        Some(outcome) => outcome,
        None => timeout(Duration::from_secs(2), closing).await.unwrap(),
    };

    assert!(!resolved_early, "resolved while the backend was dropping");
    assert!(gate.dropped.load(Ordering::SeqCst));
    assert_eq!(outcome.unwrap(), ShutdownOutcome::DeadlineExpired);
}

// The endpoints on a port whose backend panics learn how their writes ended
// rather than wait forever. A write the backend had taken may have gone out,
// so its outcome is unknown. One still waiting for room in the port's limits
// never went out.
#[tokio::test]
async fn an_endpoint_learns_its_writes_when_the_port_s_backend_panics() {
    let wire = Wire::default();
    let fuse = Arc::new(AtomicBool::new(false));
    let backend = Panicking { backend: wire.clone(), fuse: fuse.clone() };
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(backend)
        .write_limits(Limits { count: 1, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);
    let taken = send_options(&endpoint, "taken");
    wire.sent(1).await;
    let waiting = send_options(&endpoint, "waiting");
    sleep(Duration::from_millis(20)).await;

    fuse.store(true, Ordering::SeqCst);
    wire.deliver(datagram(options("panic")));

    let taken = timeout(Duration::from_secs(2), taken).await.unwrap();
    let waiting = timeout(Duration::from_secs(2), waiting).await.unwrap();
    let (taken, waiting) =
        (taken.unwrap().unwrap_err(), waiting.unwrap().unwrap_err());
    assert!(taken.is_outcome_unknown() && !taken.is_transport(), "{taken}");
    assert!(
        waiting.is_transport() && !waiting.is_outcome_unknown(),
        "{waiting}"
    );
    assert_eq!(wire.count(), 1);
    let close = port.close(Duration::from_secs(1));
    let closed = timeout(Duration::from_secs(2), close).await.unwrap();
    assert_eq!(closed, ShutdownOutcome::DeadlineExpired);
}

// A port on a socket of its own has released its address once its close
// resolves, so another socket can bind it at once. A few rounds give a close
// that published early more chances to lose the race.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_port_s_address_can_be_bound_again() {
    for _ in 0..20 {
        let (port, _ingress) = DatagramPort::builder()
            .udp("127.0.0.1:0".parse().unwrap())
            .intercept()
            .unwrap();
        let addr = port.local_addr();

        let outcome = port.close(Duration::from_secs(1)).await;

        assert_eq!(outcome, ShutdownOutcome::Drained);
        std::net::UdpSocket::bind(addr).unwrap();
    }
}

// A close starts when it is called. Dropping its future does not stop it,
// and a call after the close finished gets the same outcome at once.
#[tokio::test]
async fn a_dropped_close_still_closes_the_port() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);

    drop(port.close(Duration::from_secs(1)));

    let ended = timeout(Duration::from_secs(2), ingress.recv()).await.unwrap();
    assert!(ended.is_none());
    timeout(Duration::from_secs(2), async {
        while !wire.closed() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the backend closes");
    let again = timeout(Duration::from_millis(50), port.close(Duration::ZERO));
    assert_eq!(again.await.unwrap(), ShutdownOutcome::Drained);
}

// A later close with an earlier deadline brings the close forward, both
// while the port drains a write its wire holds and while the wire never
// finishes closing. Both callers get the outcome by the earlier deadline.
#[tokio::test]
async fn a_later_close_brings_the_deadline_forward() {
    for draining in [true, false] {
        let wire = Wire::default();
        let (port, mut ingress) = intercept(&wire);
        let upstream = upstream(&port).await;
        wire.writes(Writes::Delay);
        if !draining {
            wire.state.lock().unwrap().stuck = true;
        }
        let held = port.send_bytes(Bytes::from_static(b"raw"), &upstream);
        wire.sent(1).await;
        if !draining {
            wire.finish(Ok(()));
        }

        let first = tokio::spawn(port.close(Duration::from_secs(60)));
        // The ingress ends as the task turns to closing, and a stuck wire
        // reports itself closed once the drain is over and its close began.
        assert!(
            timeout(Duration::from_secs(2), ingress.recv())
                .await
                .unwrap()
                .is_none()
        );
        if !draining {
            timeout(Duration::from_secs(2), async {
                while !wire.closed() {
                    sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the wire starts to close");
        }
        let second = port.close(Duration::from_millis(50));

        let second = timeout(Duration::from_secs(2), second).await;
        let first = timeout(Duration::from_secs(2), first).await;
        assert_eq!(
            second.unwrap(),
            ShutdownOutcome::DeadlineExpired,
            "{draining}"
        );
        assert_eq!(first.unwrap().unwrap(), ShutdownOutcome::DeadlineExpired);
        let held = held.unwrap().await;
        if draining {
            assert!(held.unwrap_err().is_transport(), "the wire closed it");
        } else {
            held.unwrap();
        }
    }
}

// A capture only receives. Its datagrams carry no disposition and it has no
// send, so an INVITE it captures gets no 100 Trying and nothing else goes out.
#[tokio::test]
async fn a_capture_receives_and_sends_nothing() {
    let wire = Wire::default();
    let mut capture = Capture::builder().udp_io(wire.clone()).open().unwrap();

    wire.deliver(arriving(invite("captured"), "tap0"));
    let captured =
        timeout(Duration::from_secs(2), capture.recv()).await.unwrap();

    assert_eq!(capture.local_addr(), LOCAL);
    assert_eq!(capture.capabilities().max_payload, 1472);
    assert_eq!(captured.payload(), invite("captured").as_bytes());
    assert_eq!(captured.received().context().as_bytes(), "tap0");
    assert!(matches!(captured.parse(), Ok(Message::Request(_))));
    sleep(Duration::from_millis(50)).await;
    assert_eq!(wire.count(), 0);
    let outcome = capture.close(Duration::from_secs(1)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    assert!(wire.closed());
}

// A captured datagram keeps a copy of its context, so holding it does not
// keep alive the buffer the backend sliced the context out of.
#[tokio::test]
async fn a_captured_datagram_does_not_hold_the_capture_buffer() {
    let wire = Wire::default();
    let mut capture = Capture::builder().udp_io(wire.clone()).open().unwrap();
    let buffer =
        Bytes::from(b"nic0 vlan 100, then the rest of a frame".to_vec());
    let context = TransportContext::new(buffer.slice(..13)).unwrap();

    wire.deliver(
        datagram(options("buffer"))
            .map(|datagram| datagram.with_context(context)),
    );
    let captured =
        timeout(Duration::from_secs(2), capture.recv()).await.unwrap();

    assert_eq!(captured.received().context().as_bytes(), "nic0 vlan 100");
    assert!(buffer.is_unique(), "the captured datagram holds the buffer");
}

// A port runs while a handle or a registered endpoint is left. Once the last
// endpoint has stopped and every handle is gone, it closes its backend.
#[tokio::test]
async fn a_port_closes_once_nothing_uses_it() {
    let wire = Wire::default();
    let (port, ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    drop(port);
    drop(ingress);
    sleep(Duration::from_millis(50)).await;
    assert!(!wire.closed());

    let outcome = endpoint.shutdown(Duration::from_secs(1)).await;

    assert_eq!(outcome, ShutdownOutcome::Drained);
    timeout(Duration::from_secs(2), async {
        while !wire.closed() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the wire closed");
}

// A port takes as many endpoints as it is configured for, and one more once
// an endpoint has stopped and ended its registration.
#[tokio::test]
async fn registrations_are_bounded() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire)
        .max_registrations(1)
        .intercept()
        .unwrap();
    let (first, _first_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();

    assert!(Endpoint::builder().bind_on(&port).unwrap_err().is_busy());
    let outcome = first.shutdown(Duration::from_secs(1)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    yield_now().await;
    assert!(Endpoint::builder().bind_on(&port).is_ok());
}

/// What becomes of one datagram in the disposition property.
#[derive(Clone, Copy, Debug)]
enum Fate {
    Deliver,
    Forward,
    Discard,
    Drop,
    /// Held until the end, so that later datagrams may find the limits full.
    Hold,
    /// Tried after its deadline, then dropped.
    Expire,
}

impl Arbitrary for Fate {
    fn arbitrary(g: &mut Gen) -> Fate {
        *g.choose(&[
            Fate::Deliver,
            Fate::Forward,
            Fate::Discard,
            Fate::Drop,
            Fate::Hold,
            Fate::Expire,
        ])
        .unwrap()
    }
}

// Whatever the application does, each datagram ends exactly once: delivered,
// forwarded, discarded, abandoned, expired, or dropped on receipt when the
// ingress limits are full. Once none is held, the limits are whole again.
// The clock is paused, so expiry is exact.
#[test]
fn every_datagram_ends_once_and_gives_back_its_share() {
    const LIMIT: usize = 3;

    fn property(fates: Vec<Fate>) -> bool {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async move {
            let wire = Wire::default();
            let (port, mut ingress) = DatagramPort::builder()
                .udp_io(wire.clone())
                .ingress_limits(Limits { count: LIMIT, bytes: 64 * 1024 })
                .decision_deadline(Duration::from_millis(500))
                .intercept()
                .unwrap();
            let (_endpoint, _incoming, to_endpoint) =
                Endpoint::builder().bind_on(&port).unwrap();
            let upstream = upstream(&port).await;
            let mut held = Vec::new();

            for (n, fate) in fates.iter().take(12).enumerate() {
                wire.deliver(datagram(options(&format!("q{n}"))));
                stats_until(&port, |stats| stats.received == n as u64 + 1)
                    .await;
                let stats = port.stats();
                let ended = stats.overflow
                    + stats.delivered
                    + stats.forwarded
                    + stats.discarded
                    + stats.abandoned
                    + stats.expired;
                if ended + held.len() as u64 == stats.received {
                    continue; // Dropped on receipt.
                }
                let datagram = next(&mut ingress).await;
                match fate {
                    Fate::Deliver => {
                        datagram.try_deliver(&to_endpoint).unwrap();
                    }
                    Fate::Forward => {
                        datagram
                            .try_forward(&upstream)
                            .unwrap()
                            .await
                            .unwrap();
                    }
                    Fate::Discard => datagram.discard(),
                    Fate::Drop => drop(datagram),
                    Fate::Hold => held.push(datagram),
                    Fate::Expire => {
                        advance(Duration::from_millis(500)).await;
                        let refused =
                            datagram.try_deliver(&to_endpoint).unwrap_err();
                        assert!(refused.error().is_expired());
                    }
                }
            }
            drop(held);

            let stats = port.stats();
            let ended = stats.overflow
                + stats.delivered
                + stats.forwarded
                + stats.discarded
                + stats.abandoned
                + stats.expired;
            let mut whole = true;
            for n in 0..LIMIT {
                wire.deliver(datagram(options(&format!("after{n}"))));
            }
            let received = stats.received + LIMIT as u64;
            stats_until(&port, |stats| stats.received == received).await;
            whole &= port.stats().overflow == stats.overflow;
            ended == stats.received && whole
        })
    }

    QuickCheck::new().tests(40).quickcheck(property as fn(Vec<Fate>) -> bool);
}

// A port can intercept the endpoint's own kind of socket too. A request from
// an ordinary endpoint reaches the endpoint on the port through the
// application, and its response comes back through the port's socket.
#[tokio::test]
async fn a_socket_port_carries_a_round_trip() {
    let (port, mut ingress) = DatagramPort::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .intercept()
        .unwrap();
    let (_server, mut incoming, to_server) =
        Endpoint::builder().bind_on(&port).unwrap();
    let (client, _client_incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, port.local_addr());

    let (_control, mut responses) =
        client.start(outgoing("socket"), target).await.unwrap().into_parts();
    next(&mut ingress).await.try_deliver(&to_server).unwrap();
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);
}

// A port that closes while an endpoint still has writes in it tells the
// endpoint how each ended, so that nothing waits for an outcome forever: the
// write the wire held never went out, and the one it took and never reported
// may have. That holds whether the wire finishes closing or is dropped at the
// deadline.
#[tokio::test]
async fn a_closing_port_ends_the_writes_of_its_endpoints() {
    for stuck in [false, true] {
        let wire = Wire::default();
        let (port, _ingress) = intercept(&wire);
        let (endpoint, _incoming, _) =
            Endpoint::builder().bind_on(&port).unwrap();
        wire.writes(Writes::Delay);
        let taken = send_options(&endpoint, "taken");
        wire.sent(1).await;
        wire.writes(Writes::Hold);
        let held = send_options(&endpoint, "held");
        wire.until(|state| state.submit.is_some()).await;
        wire.state.lock().unwrap().stuck = stuck;

        let close = port.close(Duration::from_millis(50));
        let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

        assert_eq!(outcome, ShutdownOutcome::DeadlineExpired, "{stuck}");
        let taken = timeout(Duration::from_secs(2), taken).await.unwrap();
        let held = timeout(Duration::from_secs(2), held).await.unwrap();
        // A wire that closes reports what it held as not written. One that
        // never finishes closing leaves it unknown.
        let taken = taken.unwrap().unwrap_err();
        if stuck {
            assert!(taken.is_outcome_unknown() && !taken.is_transport());
        } else {
            assert!(taken.is_transport() && !taken.is_outcome_unknown());
        }
        // The port never offered the held write, so it did not go out.
        assert!(held.unwrap().unwrap_err().is_transport(), "{stuck}");
        assert_eq!(wire.count(), 1);
    }
}

// What a raw write's waiter learns, for each way it can end. A write the
// wire reports written is `Ok`. One it reports failed, and one the port
// never offered before a forced close, did not go out. One the wire reports
// unknown, and one it held unreported through a forced close, may have.
#[tokio::test]
async fn a_raw_write_tells_a_failure_from_an_unknown_outcome() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);
    let send = || port.send_bytes(Bytes::from_static(b"raw"), &upstream);

    let written = send().unwrap();
    let failed = send().unwrap();
    let unknown_write = send().unwrap();
    wire.sent(3).await;
    wire.finish(Ok(()));
    wire.finish(Err(io::Error::new(io::ErrorKind::NotConnected, "link down")));
    wire.finish(unknown());

    written.await.unwrap();
    let error = failed.await.unwrap_err();
    assert!(error.is_transport() && !error.is_outcome_unknown());
    let error = unknown_write.await.unwrap_err();
    assert!(error.is_outcome_unknown() && !error.is_transport());

    let taken = send().unwrap();
    wire.sent(4).await;
    wire.writes(Writes::Hold);
    let held = send().unwrap();
    wire.until(|state| state.submit.is_some()).await;
    wire.state.lock().unwrap().stuck = true;
    let close = port.close(Duration::from_millis(50));
    let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(taken.await.unwrap_err().is_outcome_unknown());
    assert!(held.await.unwrap_err().is_transport());
}

// An endpoint on a port learns the same of its writes as over a wire of its
// own: written, failed, or unknown, as the port's wire reported them.
#[tokio::test]
async fn an_endpoint_on_a_port_learns_each_write_outcome() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);

    let written = send_options(&endpoint, "written");
    wire.sent(1).await;
    let failed = send_options(&endpoint, "failed");
    wire.sent(2).await;
    let unknown_write = send_options(&endpoint, "unknown");
    wire.sent(3).await;
    wire.finish(Ok(()));
    wire.finish(Err(io::Error::new(io::ErrorKind::NotConnected, "link down")));
    wire.finish(unknown());

    async fn outcome(
        write: JoinHandle<Result<(), Error>>,
    ) -> Result<(), Error> {
        timeout(Duration::from_secs(2), write).await.unwrap().unwrap()
    }
    outcome(written).await.unwrap();
    let error = outcome(failed).await.unwrap_err();
    assert!(error.is_transport() && !error.is_outcome_unknown());
    let error = outcome(unknown_write).await.unwrap_err();
    assert!(error.is_outcome_unknown() && !error.is_transport());
}

// A response the port's wire took and never reported, when the port closes
// at its deadline, is observed as an unknown outcome. The endpoint is still
// running, so it is not told that it closed, and the server transaction keeps
// its state.
#[tokio::test]
async fn a_forced_port_close_leaves_an_endpoint_s_response_unknown() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    wire.deliver(arriving(options("forced"), "nic0"));
    let datagram = next(&mut ingress).await;
    datagram.try_deliver(&to_endpoint).unwrap();
    let request = request(&mut incoming).await;
    let (responder, mut events) = request.transaction.into_parts();
    wire.writes(Writes::Delay);
    wire.state.lock().unwrap().stuck = true;
    responder.respond(ok(&request.request)).await.unwrap();
    wire.sent(1).await;

    let close = port.close(Duration::from_millis(50));
    let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    let event = timeout(Duration::from_secs(2), events.next()).await.unwrap();
    assert!(
        matches!(
            event,
            Some(ServerEvent::OutcomeUnknown { operation: Some(_), .. })
        ),
        "{event:?}"
    );
    drop(endpoint);
}

// An endpoint stopped at its deadline leaves the port to the others. A write
// of its that the wire took before may still go out, and the wire's late
// report of it reaches nobody: not the sibling still running, and not an
// endpoint registered after the stop, whose own first write has the same
// local ID as the stopped endpoint's.
#[tokio::test]
async fn a_forced_stop_leaves_the_port_to_the_other_endpoints() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (stopping, _stopping_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    let (sibling, _sibling_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);
    let from_stopping = send_options(&stopping, "stopping");
    wire.sent(1).await;

    let stopped =
        timeout(Duration::from_secs(2), stopping.shutdown(Duration::ZERO))
            .await
            .unwrap();

    assert_eq!(stopped, ShutdownOutcome::DeadlineExpired);
    let (late, _late_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    let mut from_late = send_options(&late, "late");
    wire.sent(2).await;
    let from_sibling = send_options(&sibling, "sibling");
    wire.sent(3).await;
    wire.finish(Ok(()));
    assert!(
        timeout(Duration::from_millis(50), &mut from_late).await.is_err(),
        "the stopped endpoint's outcome reached a later one"
    );
    wire.finish(Ok(()));
    wire.finish(Ok(()));
    let outcome = |write| timeout(Duration::from_secs(2), write);
    assert!(outcome(from_late).await.unwrap().unwrap().is_ok());
    assert!(outcome(from_sibling).await.unwrap().unwrap().is_ok());
    assert!(outcome(from_stopping).await.unwrap().unwrap().is_err());
}

// Raw sends take three quarters of a port's write limits, rounded down, so
// a byte limit whose share is below the backend's largest payload would
// refuse a raw send that large as busy however idle the port was. The port
// refuses that configuration. 1963 bytes leave a share of 1473.
#[tokio::test]
async fn the_port_s_write_limits_must_hold_a_whole_payload() {
    for (bytes, valid) in [(1000, false), (1472, false), (1963, true)] {
        let bound = DatagramPort::builder()
            .udp_io(Wire::default())
            .write_limits(Limits { count: 1, bytes })
            .intercept();

        match bound {
            Ok(_) => assert!(valid, "{bytes}"),
            Err(error) => {
                assert!(!valid && error.is_invalid_config(), "{bytes}");
                assert!(
                    error
                        .to_string()
                        .starts_with("invalid port configuration"),
                    "{error}"
                );
            }
        }
    }
}

// An endpoint's new requests take three quarters of its UDP write limits.
// With a backend, or on a port, a share without a write or smaller than the
// backend's largest payload would refuse such requests as busy however idle
// the endpoint was, so bind refuses it. An endpoint with a socket of its own
// keeps zero limits valid, as a way to refuse its writes.
#[tokio::test]
async fn an_endpoint_s_write_limits_must_hold_a_whole_payload() {
    let (port, _ingress) = intercept(&Wire::default());
    for limits in [
        Limits { count: 0, bytes: 64 * 1024 },
        Limits { count: 16, bytes: 1472 },
    ] {
        let own = Endpoint::builder()
            .udp_io(Wire::default())
            .udp_write_limits(limits)
            .bind();
        let shared =
            Endpoint::builder().udp_write_limits(limits).bind_on(&port);

        assert!(own.unwrap_err().is_invalid_config(), "{limits:?}");
        assert!(shared.unwrap_err().is_invalid_config(), "{limits:?}");
    }

    let fits = Limits { count: 1, bytes: 1963 };
    Endpoint::builder()
        .udp_io(Wire::default())
        .udp_write_limits(fits)
        .bind()
        .unwrap();
    Endpoint::builder().udp_write_limits(fits).bind_on(&port).unwrap();
    Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .udp_write_limits(Limits { count: 0, bytes: 0 })
        .bind()
        .unwrap();
}

// Endpoints whose writes find the port's limits full wait, and go out as
// room frees up, without losing a write or an outcome.
#[tokio::test]
async fn endpoints_wait_for_room_in_the_port_s_limits() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 1, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);

    let from_a = send_options(&a, "a");
    wire.sent(1).await;
    let from_b = send_options(&b, "b");
    sleep(Duration::from_millis(20)).await;
    assert_eq!(wire.count(), 1);
    wire.finish(Ok(()));
    wire.sent(2).await;
    wire.finish(Ok(()));

    assert!(from_a.await.unwrap().is_ok());
    assert!(from_b.await.unwrap().is_ok());
}

// A raw send refused for room takes none of it, not even for a moment. An
// endpoint waiting while one is refused goes out as soon as the write ahead
// of it ends, with no other traffic to wake it.
#[tokio::test]
async fn a_refused_raw_send_does_not_hold_back_a_waiting_endpoint() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 1, bytes: 2000 })
        .intercept()
        .unwrap();
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    // Within the three quarters that raw sends may take, but not beside the
    // endpoint's write.
    let large = Bytes::from(vec![b'x'; 1200]);

    wire.writes(Writes::Delay);
    let from_a = send_options(&a, "a");
    wire.sent(1).await;
    let refused = port.send_bytes(large.clone(), &upstream);
    assert!(refused.unwrap_err().is_busy());
    let from_b = send_options(&b, "b");
    sleep(Duration::from_millis(20)).await;
    let refused = port.send_bytes(large, &upstream);
    assert!(refused.unwrap_err().is_busy());
    assert_eq!(wire.count(), 1);

    wire.finish(Ok(()));
    wire.sent(2).await;
    wire.finish(Ok(()));
    assert!(from_a.await.unwrap().is_ok());
    assert!(from_b.await.unwrap().is_ok());
}

// The same with endpoints on several threads at once, where a waiter and a
// release race. Every write still goes out and reports back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoints_on_several_threads_share_the_port_s_limits() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 2, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let mut endpoints = Vec::new();
    for _ in 0..4 {
        endpoints.push(Endpoint::builder().bind_on(&port).unwrap());
    }

    let mut sends = Vec::new();
    for (endpoint, _incoming, _) in &endpoints {
        for _ in 0..25 {
            sends.push(send_options(endpoint, "busy"));
        }
    }
    for send in sends {
        let sent = timeout(Duration::from_secs(10), send).await.unwrap();
        sent.unwrap().unwrap();
    }

    assert_eq!(wire.count(), 100);
}

// Raw sends take at most three quarters of the port's write limits, so that
// a busy forwarder leaves endpoints room for their own writes.
#[tokio::test]
async fn raw_sends_leave_endpoints_room() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 4, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);

    let raw: Vec<_> = (0..3)
        .map(|_| port.send_bytes(Bytes::from_static(b"raw"), &upstream))
        .collect::<Result<_, _>>()
        .unwrap();
    let refused = port.send_bytes(Bytes::from_static(b"raw"), &upstream);
    let from_endpoint = send_options(&endpoint, "room");

    assert!(refused.unwrap_err().is_busy());
    wire.sent(4).await;
    for _ in 0..4 {
        wire.finish(Ok(()));
    }
    assert!(from_endpoint.await.unwrap().is_ok());
    for write in raw {
        write.await.unwrap();
    }
}

// A datagram on a shared port gets its ID and time when the port's task
// takes it from the backend. The endpoint it is delivered to keeps both,
// however long the application held it before deciding.
#[tokio::test(start_paused = true)]
async fn a_held_datagram_keeps_its_id_and_arrival_time() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();

    wire.deliver(arriving(options("held"), "nic0"));
    let datagram = next(&mut ingress).await;
    let (id, arrived) =
        (datagram.received().id(), datagram.received().received_at());
    assert_eq!(datagram.deadline(), arrived + Duration::from_secs(1));
    advance(Duration::from_millis(300)).await;
    datagram.try_deliver(&to_endpoint).unwrap();

    let request = request(&mut incoming).await;
    assert_eq!(request.received.id(), id);
    assert_eq!(request.received.received_at(), arrived);
    assert_eq!(request.received.context().as_bytes(), "nic0");
    let held = tokio::time::Instant::now().into_std() - arrived;
    assert!(held >= Duration::from_millis(300), "{held:?}");

    wire.deliver(arriving(options("after"), "nic0"));
    let after = next(&mut ingress).await;
    assert_eq!(after.received().id().domain(), id.domain());
    assert_eq!(after.received().id().sequence(), id.sequence() + 1);
}

/// A second peer of the wire, which a response may come from.
const OTHER_PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 21)),
    5070,
);

// Each response of a client transaction comes with its own arrival, not the
// transaction's: the address and context it came with, its ID and its time.
// The responses of two forks, and of one fork along two ways, keep theirs
// apart, and the transaction still sends the way it chose.
#[tokio::test]
async fn each_response_keeps_how_it_arrived() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing_invite("forks"), target)
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(1).await;
    let invite = Request::from_bytes(&sent[0].payload).unwrap();
    let reply = |status: u16, tag: &str| {
        Response::reply_to(&invite)
            .status(status)
            .to_tag(tag)
            .body(Bytes::new())
            .unwrap()
            .to_bytes()
    };
    let arrivals = [
        (180, "a", PEER, "nic0"),
        (183, "a", OTHER_PEER, "nic1"),
        (200, "a", PEER, "nic0"),
        (200, "b", OTHER_PEER, "nic2"),
    ];

    for (status, tag, source, on) in arrivals {
        let datagram = Datagram::new(reply(status, tag), source, LOCAL)
            .with_context(context(on));
        wire.deliver(Ok(datagram));
    }

    let mut ids = Vec::new();
    for (status, tag, source, on) in arrivals {
        let ReceivedResponse { response, received } =
            timeout(Duration::from_secs(2), responses.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(response.status().as_u16(), status);
        let to = response.headers().get("To").unwrap().as_str();
        assert!(to.ends_with(&format!(";tag={tag}")), "{to}");
        assert_eq!(
            (received.flow().remote, received.flow().local),
            (source, LOCAL)
        );
        assert_eq!(received.context().as_bytes(), on);
        ids.push((received.id(), received.received_at()));
    }
    for pair in ids.windows(2) {
        let ((before, at), (after, then)) = (pair[0], pair[1]);
        assert_eq!(after.domain(), before.domain());
        assert_eq!(after.sequence(), before.sequence() + 1);
        assert!(at <= then);
    }
    assert!(wire.sent(1).await.iter().all(|sent| sent.path == Way::Default));
}

// A 2xx and its retransmission reach the TU apart (RFC 6026 section 8.4),
// each with its own ID and context. Each is charged to the stream's limits
// with its context, so a retransmission that cannot keep its context ends
// the stream rather than arriving without it.
#[tokio::test]
async fn each_2xx_retransmission_arrives_with_its_own_id_and_charge() {
    let target = Target::new(Transport::Udp, PEER);
    // The limits hold two 200s with small contexts, whose copies take well
    // under 128 bytes each, and not with the large one. The 200's length
    // comes from one exchange.
    let ok_len = {
        let wire = Wire::default();
        let (endpoint, _incoming) = bind(&wire);
        let call = outgoing_invite("retransmitted");
        let _call = endpoint.start(call, target.clone()).await.unwrap();
        let sent = wire.sent(1).await;
        ok(&Request::from_bytes(&sent[0].payload).unwrap()).to_bytes().len()
    };
    let limit = 2 * ok_len + 2 * 128;
    let large =
        TransportContext::new(Bytes::from(vec![b'x'; MAX_CONTEXT_LEN]))
            .unwrap();

    for again in [context("nic1"), large] {
        let wire = Wire::default();
        let (endpoint, _incoming) = Endpoint::builder()
            .udp_io(wire.clone())
            .client_response_limits(Limits { count: 8, bytes: limit })
            .bind()
            .unwrap();
        let (_control, mut responses) = endpoint
            .start(outgoing_invite("retransmitted"), target.clone())
            .await
            .unwrap()
            .into_parts();
        let sent = wire.sent(1).await;
        let invite = Request::from_bytes(&sent[0].payload).unwrap();
        let ok = ok(&invite).to_bytes();
        assert_eq!(ok.len(), ok_len);
        let first = Datagram::new(ok.clone(), PEER, LOCAL)
            .with_context(context("nic0"));
        let second =
            Datagram::new(ok, PEER, LOCAL).with_context(again.clone());

        wire.deliver(Ok(first));
        wire.deliver(Ok(second));
        // Both wait in the stream before it is read.
        sleep(Duration::from_millis(100)).await;

        let mut next = async || {
            timeout(Duration::from_secs(2), responses.next())
                .await
                .unwrap()
                .unwrap()
        };
        let first = next().await.unwrap();
        assert_eq!(first.received.context().as_bytes(), "nic0");
        let second = next().await;
        if again.len() == MAX_CONTEXT_LEN {
            assert!(second.unwrap_err().is_delivery_overflow());
            continue;
        }
        let second = second.unwrap();
        assert_eq!(second.response.status().as_u16(), 200);
        assert_eq!(second.received.context().as_bytes(), "nic1");
        let (before, after) = (first.received.id(), second.received.id());
        assert_eq!(after.domain(), before.domain());
        assert_eq!(after.sequence(), before.sequence() + 1);
    }
}

// A non-2xx final that overflows its stream still gets its ACK. The
// transaction acknowledges the response whatever becomes of its delivery
// (RFC 3261 section 17.1.1.3).
#[tokio::test]
async fn a_final_that_overflows_its_stream_still_gets_its_ack() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .client_response_limits(Limits { count: 8, bytes: 1 })
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing_invite("overflowed"), target)
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(1).await;
    let invite = Request::from_bytes(&sent[0].payload).unwrap();
    let busy = Response::reply_to(&invite)
        .status(486)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap();

    wire.deliver(Ok(Datagram::new(busy.to_bytes(), PEER, LOCAL)));

    let ended = timeout(Duration::from_secs(2), responses.next()).await;
    assert!(ended.unwrap().unwrap().unwrap_err().is_delivery_overflow());
    let sent = wire.sent(2).await;
    assert_eq!(method(&sent[1]).as_deref(), Some("ACK"));
}

// Each receive point numbers what it receives in a domain of its own: two
// endpoints, an endpoint and a shared port, and a capture never share one.
// An endpoint's own backend numbers its arrivals in the domain of its
// writes, as a shared port does, so an observer's records of one backend
// name one domain.
#[tokio::test]
async fn each_receive_point_numbers_in_a_domain_of_its_own() {
    let wires: [Wire; 4] = Default::default();
    let (first, mut first_incoming) = bind(&wires[0]);
    let (_second, mut second_incoming) = bind(&wires[1]);
    let (_port, mut ingress) = intercept(&wires[2]);
    let mut capture =
        Capture::builder().udp_io(wires[3].clone()).open().unwrap();
    let mut observer = first.observe(observe::Config::new()).await.unwrap();

    wires[0].deliver(datagram(invite("first")));
    wires[1].deliver(datagram(options("second")));
    wires[2].deliver(datagram(options("port")));
    wires[3].deliver(datagram(options("capture")));
    let first_request = request(&mut first_incoming).await;
    let second_request = request(&mut second_incoming).await;
    let held = next(&mut ingress).await;
    let captured =
        timeout(Duration::from_secs(2), capture.recv()).await.unwrap();

    let ids = [
        first_request.received.id(),
        second_request.received.id(),
        held.received().id(),
        captured.received().id(),
    ];
    for (n, id) in ids.iter().enumerate() {
        for other in &ids[n + 1..] {
            assert_ne!(id.domain(), other.domain(), "{ids:?}");
        }
    }
    let arrival = record(&mut observer).await;
    assert!(matches!(arrival.observed(), Observed::Received { .. }));
    let trying = record(&mut observer).await;
    let Observed::WriteStarted { write, .. } = trying.observed() else {
        panic!("the 100 Trying's write, got {trying:?}");
    };
    assert_eq!(write.domain(), ids[0].domain());
}

// A response's context counts against its stream's limits with its bytes.
// One that cannot keep its context ends the stream with the overflow error,
// after the responses already queued, rather than arriving without it.
#[tokio::test]
async fn a_response_never_arrives_without_its_context() {
    const LIMIT: usize = 500;
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .client_response_limits(Limits { count: 8, bytes: LIMIT })
        .bind()
        .unwrap();
    let large =
        TransportContext::new(Bytes::from(vec![b'x'; MAX_CONTEXT_LEN]))
            .unwrap();

    for (call, context) in [("small", None), ("large", Some(large))] {
        let target = Target::new(Transport::Udp, PEER);
        let (_control, mut responses) =
            endpoint.start(outgoing(call), target).await.unwrap().into_parts();
        let sent = wire.sent(wire.count() + 1).await;
        let request =
            Request::from_bytes(&sent.last().unwrap().payload).unwrap();
        let trying = Response::reply_to(&request)
            .status(100)
            .body(Bytes::new())
            .unwrap()
            .to_bytes();
        let ok = ok(&request).to_bytes();
        // Both fit without the context and not with it.
        assert!(trying.len() + ok.len() <= LIMIT);
        assert!(trying.len() + ok.len() + MAX_CONTEXT_LEN > LIMIT);

        wire.deliver(Ok(Datagram::new(trying, PEER, LOCAL)));
        let mut final_response = Datagram::new(ok, PEER, LOCAL);
        if let Some(context) = context.clone() {
            final_response = final_response.with_context(context);
        }
        wire.deliver(Ok(final_response));
        // Both wait in the stream before it is read.
        sleep(Duration::from_millis(100)).await;

        let mut next = async || {
            timeout(Duration::from_secs(2), responses.next())
                .await
                .unwrap()
                .unwrap()
        };
        let first = next().await.unwrap();
        assert_eq!(first.response.status().as_u16(), 100);
        let second = next().await;
        match context {
            None => {
                assert_eq!(second.unwrap().response.status().as_u16(), 200)
            }
            Some(_) => assert!(second.unwrap_err().is_delivery_overflow()),
        }
    }
}

/// The next record, which must come within two seconds.
async fn record(observer: &mut Observer) -> Record {
    timeout(Duration::from_secs(2), observer.recv())
        .await
        .expect("a record within two seconds")
        .expect("an attached observer")
}

/// The next record, which must be a write stage, with its write.
async fn stage(observer: &mut Observer) -> (WriteRef, Observed) {
    let record = record(observer).await;
    let write = match record.observed() {
        Observed::WriteStarted { write, .. }
        | Observed::WriteAccepted { write, .. }
        | Observed::WriteEnded { write, .. } => *write,
        other => panic!("a write stage, got {other:?}"),
    };
    (write, record.observed().clone())
}

/// Checks that the next three records are one write that started with an
/// origin `origin` accepts and with `cause`, was taken, and was written, and
/// returns its payload.
async fn written(
    observer: &mut Observer,
    origin: impl Fn(&WriteOrigin) -> bool,
    cause: Option<signa_core::transport::ReceiveId>,
) -> Bytes {
    let started = record(observer).await;
    let Observed::WriteStarted { write, origin: seen, cause: why, .. } =
        started.observed()
    else {
        panic!("a started write, got {started:?}");
    };
    assert!(origin(seen), "{seen:?}");
    assert_eq!(*why, cause);
    assert!(write.datagram().is_some());
    let (accepted, taken) = stage(observer).await;
    assert_eq!(accepted, *write);
    assert!(matches!(taken, Observed::WriteAccepted { .. }), "{taken:?}");
    let (ended, end) = stage(observer).await;
    assert_eq!(ended, *write);
    let Observed::WriteEnded { end, accepted, .. } = end else {
        panic!("an ended write, got {end:?}");
    };
    assert_eq!((end, accepted), (WriteEnd::Written, true));
    started.payload().cloned().unwrap_or_default()
}

// An observer sees each datagram as it arrived, before parsing, with the ID
// its envelope carries, and every write the endpoint makes of it: the
// automatic 100 and the cached response resent for a retransmission, which
// name the arrival they answer, and the TU's own response.
#[tokio::test]
async fn an_observer_sees_arrivals_and_every_write_they_cause() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let config = observe::Config::new().payload(4096).context(true);
    let mut observer = endpoint.observe(config).await.unwrap();
    // Compact names and extra spaces, which a re-encoding would change.
    let text = invite("observed")
        .replace("Call-ID:", "i:")
        .replace("CSeq: 1 INVITE", "CSeq:  1   INVITE");

    wire.deliver(arriving(text.clone(), "nic0"));
    let request = request(&mut incoming).await;
    let arrival = record(&mut observer).await;
    let Observed::Received { id, flow, .. } = arrival.observed() else {
        panic!("an arrival, got {arrival:?}");
    };
    assert_eq!(*id, request.received.id());
    assert_eq!(arrival.at(), request.received.received_at());
    assert_eq!((flow.remote, flow.local), (PEER, LOCAL));
    assert_eq!(arrival.payload().unwrap(), text.as_bytes());
    assert_eq!(arrival.context().unwrap().as_bytes(), "nic0");
    let (responder, _) = request.transaction.into_parts();
    let transaction = responder.id();
    let trying = written(
        &mut observer,
        |origin| {
            matches!(
                origin,
                WriteOrigin::Response { transaction: t, operation: None, .. }
                    if *t == transaction
            )
        },
        Some(*id),
    )
    .await;
    assert!(trying.starts_with(b"SIP/2.0 100 "));

    let busy = Response::reply_to(&request.request)
        .status(486)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap();
    let submission = responder.respond(busy);
    let operation = Some(submission.id());
    submission.await.unwrap();
    let final_response = written(
        &mut observer,
        |origin| {
            matches!(
                origin,
                WriteOrigin::Response { transaction: t, operation: o, .. }
                    if (*t, *o) == (transaction, operation)
            )
        },
        None,
    )
    .await;
    assert!(final_response.starts_with(b"SIP/2.0 486 "));

    wire.deliver(arriving(text, "nic1"));
    let again = record(&mut observer).await;
    let Observed::Received { id: again_id, .. } = again.observed() else {
        panic!("an arrival, got {again:?}");
    };
    assert_ne!(again_id, id);
    let resent = written(
        &mut observer,
        |origin| {
            matches!(
                origin,
                WriteOrigin::ResponseRetransmission { transaction: t, .. }
                    if *t == transaction
            )
        },
        Some(*again_id),
    )
    .await;
    assert_eq!(resent, final_response);
    assert_eq!(observer.stats(), observe::Stats::default());
}

// A client transaction's writes name it by the number its control gives:
// the request, its retransmissions, the ACK of its non-2xx final and its
// CANCEL's own transaction. A response that matches nothing is still seen
// arriving.
#[tokio::test(start_paused = true)]
async fn an_observer_names_client_writes_by_their_transaction() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .bind()
        .unwrap();
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (control, mut responses) = endpoint
        .start(outgoing_invite("client"), target)
        .await
        .unwrap()
        .into_parts();
    let transaction = control.number();

    let request_of = |number| {
        move |origin: &WriteOrigin| {
            matches!(origin, WriteOrigin::Request { transaction: t, .. }
                if *t == number)
        }
    };
    written(&mut observer, request_of(transaction), None).await;
    let retransmission = |origin: &WriteOrigin| {
        matches!(origin, WriteOrigin::RequestRetransmission { transaction: t, .. }
            if *t == transaction)
    };
    written(&mut observer, retransmission, None).await;

    let invite = Request::from_bytes(&wire.sent(1).await[0].payload).unwrap();
    let ringing = Response::reply_to(&invite)
        .status(180)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    wire.deliver(Ok(Datagram::new(ringing.to_bytes(), PEER, LOCAL)));
    let Observed::Received { id: ringing_id, .. } =
        *record(&mut observer).await.observed()
    else {
        panic!("an arrival");
    };
    let received = responses.next().await.unwrap().unwrap();
    assert_eq!(received.received.id(), ringing_id);

    let outcome = control.cancel().await.unwrap();
    let CancelOutcome::Sent(cancel) = outcome else {
        panic!("a CANCEL, got {outcome:?}");
    };
    let (cancel, _) = cancel.into_parts();
    assert_ne!(cancel.number(), transaction);
    written(&mut observer, request_of(cancel.number()), None).await;

    let declined = Response::reply_to(&invite)
        .status(487)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    wire.deliver(Ok(Datagram::new(declined.to_bytes(), PEER, LOCAL)));
    let Observed::Received { id: final_id, .. } =
        *record(&mut observer).await.observed()
    else {
        panic!("an arrival");
    };
    let ack = written(
        &mut observer,
        |origin| {
            matches!(origin, WriteOrigin::Ack { transaction: t, .. }
                if *t == transaction)
        },
        Some(final_id),
    )
    .await;
    assert!(ack.is_empty(), "no payload is copied by default");
}

// A full observer loses records, never what the protocol delivers. The
// response channel and the endpoint go on, the losses show in the stats and
// in the gap before the next record that fits, and a record keeps its share
// of the limits until the application drops it.
#[tokio::test]
async fn a_full_observer_loses_records_but_nothing_else() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let config = observe::Config::new().records(2).payload(64);
    let mut observer = endpoint.observe(config).await.unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) =
        endpoint.start(outgoing("full"), target).await.unwrap().into_parts();
    let request = Request::from_bytes(&wire.sent(1).await[0].payload).unwrap();

    // The request's three stages and the response's arrival, with room for
    // two records. The lost end of the write carries no message, so the
    // response is all the lost bytes.
    let ok = ok(&request).to_bytes();
    wire.deliver(Ok(Datagram::new(ok.clone(), PEER, LOCAL)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.response.status().as_u16(), 200);
    let stats = observer.stats();
    assert_eq!((stats.lost, stats.lost_bytes), (2, ok.len() as u64));

    let held = [record(&mut observer).await, record(&mut observer).await];
    let sequences: Vec<_> = held.iter().map(Record::sequence).collect();
    assert_eq!(sequences, [0, 1]);
    // The held records still fill the limits, so all three stages of this
    // write are lost.
    endpoint
        .send_request(
            outgoing("lost"),
            Target::new(Transport::Udp, PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap();
    let lost = wire.sent(2).await[1].payload.len();
    drop(held);
    endpoint
        .send_request(
            outgoing("seen"),
            Target::new(Transport::Udp, PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap();
    let seen = wire.sent(3).await[2].payload.len();
    let next = record(&mut observer).await;
    assert!(matches!(next.observed(), Observed::WriteStarted { .. }));
    assert_eq!((next.sequence(), next.lost_before()), (7, 5));
    // The write's end, behind its start and acceptance, is lost too.
    let stats = observer.stats();
    assert_eq!(stats.lost, 6);
    assert_eq!(stats.lost_bytes, (ok.len() + lost) as u64);
    // Each delivered start copied the first 64 bytes of its message.
    let full = wire.sent(1).await[0].payload.len();
    assert_eq!(stats.truncated_bytes, (full - 64 + seen - 64) as u64);
}

// An overflowing response stream is its own explicit error, however much
// room the observer has, and the observer goes on seeing the responses the
// stream could not take.
#[tokio::test]
async fn response_overflow_does_not_depend_on_the_observer() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .client_response_limits(Limits { count: 1, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing_invite("overflow"), target)
        .await
        .unwrap()
        .into_parts();
    let invite = Request::from_bytes(&wire.sent(1).await[0].payload).unwrap();
    for status in [180, 183] {
        let response = Response::reply_to(&invite)
            .status(status)
            .to_tag("alice")
            .body(Bytes::new())
            .unwrap();
        wire.deliver(Ok(Datagram::new(response.to_bytes(), PEER, LOCAL)));
    }
    sleep(Duration::from_millis(100)).await;

    let first = responses.next().await.unwrap().unwrap();
    assert_eq!(first.response.status().as_u16(), 180);
    assert!(
        responses.next().await.unwrap().unwrap_err().is_delivery_overflow()
    );
    let mut arrivals = Vec::new();
    while arrivals.len() < 2 {
        if let Observed::Received { id, .. } =
            *record(&mut observer).await.observed()
        {
            arrivals.push(id);
        }
    }
    assert_eq!(arrivals[0], first.received.id());
    assert_eq!(observer.stats(), observe::Stats::default());
}

// One observer at a time. Dropping it changes nothing on the wire, and
// another can attach.
#[tokio::test]
async fn one_observer_at_a_time_and_dropping_it_changes_nothing() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let first = endpoint.observe(observe::Config::new()).await.unwrap();
    let busy = endpoint.observe(observe::Config::new()).await.unwrap_err();
    assert!(busy.is_busy());

    drop(first);
    wire.deliver(datagram(options("dropped")));
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();
    assert_eq!(status(&wire.sent(1).await[0]), 200);

    let mut second = endpoint.observe(observe::Config::new()).await.unwrap();
    wire.deliver(datagram(options("second")));
    let record = record(&mut second).await;
    assert!(matches!(record.observed(), Observed::Received { .. }));
    assert_eq!(record.sequence(), 0);
}

// An `observe` dropped after it asked the driver to attach leaves nothing
// behind. Another observer attaches, and only it sees what comes next, from
// the first number on.
#[tokio::test]
async fn an_observe_dropped_while_attaching_lets_another_attach() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    // One poll sends the request, and the driver has not answered yet.
    let mut dropped = Box::pin(endpoint.observe(observe::Config::new()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(dropped.as_mut().poll(&mut cx).is_pending());
    drop(dropped);

    let mut second = endpoint.observe(observe::Config::new()).await.unwrap();
    wire.deliver(datagram(options("second")));

    let record = record(&mut second).await;
    assert!(matches!(record.observed(), Observed::Received { .. }));
    assert_eq!((record.sequence(), record.lost_before()), (0, 0));
    assert_eq!(second.stats(), observe::Stats::default());
}

// The write stages keep the backend's word apart: a write it holds is taken
// once it can, a refused one ends without being taken, an unknown outcome
// stays unknown, and a write the limits refuse ends before the backend sees
// it.
#[tokio::test]
async fn write_records_keep_each_stage_and_outcome() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .udp_write_limits(Limits { count: 1, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let target = || Target::new(Transport::Udp, PEER);
    let send = |call: &'static str| {
        endpoint.send_request(outgoing(call), target(), ViaMode::Fresh)
    };

    wire.writes(Writes::Hold);
    let held = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            endpoint
                .send_request(
                    outgoing("held"),
                    Target::new(Transport::Udp, PEER),
                    ViaMode::Fresh,
                )
                .await
        }
    });
    let (write, started) = stage(&mut observer).await;
    assert!(matches!(started, Observed::WriteStarted { .. }));
    // The limits hold one write, so the next ends before the backend.
    assert!(send("refused").await.is_err());
    let (refused, _) = stage(&mut observer).await;
    let (ended, stage_seen) = stage(&mut observer).await;
    assert_eq!(ended, refused);
    assert!(matches!(
        stage_seen,
        Observed::WriteEnded {
            accepted: false,
            end: WriteEnd::NotWritten(_),
            ..
        }
    ));
    wire.writes(Writes::Complete);
    assert!(held.await.unwrap().is_ok());
    let (taken, stage_seen) = stage(&mut observer).await;
    assert_eq!(taken, write);
    assert!(matches!(stage_seen, Observed::WriteAccepted { .. }));
    let (_, stage_seen) = stage(&mut observer).await;
    assert!(matches!(stage_seen, Observed::WriteEnded { accepted: true, .. }));

    wire.writes(Writes::Reject);
    assert!(send("rejected").await.is_err());
    let (_, started) = stage(&mut observer).await;
    assert!(matches!(started, Observed::WriteStarted { .. }));
    let (_, stage_seen) = stage(&mut observer).await;
    assert!(matches!(
        stage_seen,
        Observed::WriteEnded { accepted: false, .. }
    ));

    wire.writes(Writes::Delay);
    let unknown_write = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let target = Target::new(Transport::Udp, PEER);
            endpoint
                .send_request(outgoing("unknown"), target, ViaMode::Fresh)
                .await
        }
    });
    stage(&mut observer).await;
    stage(&mut observer).await;
    wire.finish(unknown());
    let outcome = unknown_write.await.unwrap();
    assert!(outcome.unwrap_err().is_outcome_unknown());
    let (_, stage_seen) = stage(&mut observer).await;
    assert!(matches!(
        stage_seen,
        Observed::WriteEnded { accepted: true, end: WriteEnd::Unknown(_), .. }
    ));
}

// A record copies what it shows, so it keeps no received buffer alive, and
// a payload beyond the configured length is cut and counted.
#[tokio::test]
async fn records_copy_their_bytes_and_cut_long_ones() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let config = observe::Config::new().payload(16).context(true);
    let mut observer = endpoint.observe(config).await.unwrap();
    let text = options("copied");
    // The datagram is a slice of a much larger capture buffer.
    let mut capture = vec![0u8; 64 * 1024];
    capture[..text.len()].copy_from_slice(text.as_bytes());
    let capture = Bytes::from(capture);
    let payload = capture.slice(..text.len());
    let context =
        TransportContext::new(capture.slice(text.len()..text.len() + 8))
            .unwrap();

    wire.deliver(
        Ok(Datagram::new(payload, PEER, LOCAL).with_context(context)),
    );
    let _request = request(&mut incoming).await;
    let arrival = record(&mut observer).await;
    let copy = arrival.payload().unwrap();
    assert_eq!(&copy[..], &text.as_bytes()[..16]);
    assert_eq!(arrival.message_len(), text.len());
    let range = capture.as_ptr_range();
    assert!(!range.contains(&copy.as_ptr()));
    assert!(!range.contains(&arrival.context().unwrap().as_bytes().as_ptr()));
    assert_eq!(observer.stats().truncated_bytes, (text.len() - 16) as u64);
}

// A response the endpoint makes without a transaction names the arrival it
// answers too, here a 400 for a request without a Call-ID.
#[tokio::test]
async fn a_stateless_refusal_names_the_arrival_it_answers() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let text = options("refused").replace("Call-ID: refused\r\n", "");

    // What is not SIP at all arrives too, and nothing answers it.
    wire.deliver(datagram("not SIP\r\n\r\n".to_owned()));
    let garbage = record(&mut observer).await;
    assert!(matches!(garbage.observed(), Observed::Received { .. }));
    assert_eq!(garbage.message_len(), 11);
    wire.deliver(datagram(text));
    let arrival = record(&mut observer).await;
    let Observed::Received { id, .. } = *arrival.observed() else {
        panic!("an arrival, got {arrival:?}");
    };
    written(&mut observer, |o| *o == WriteOrigin::Stateless, Some(id)).await;
    assert_eq!(status(&wire.sent(1).await[0]), 400);
}

/// Records until `n` of them satisfy `keep`, which are returned.
async fn records_where(
    observer: &mut Observer,
    n: usize,
    keep: impl Fn(&Record) -> bool,
) -> Vec<Record> {
    let mut kept = Vec::new();
    while kept.len() < n {
        let record = record(observer).await;
        if keep(&record) {
            kept.push(record);
        }
    }
    kept
}

fn started(record: &Record) -> Option<(WriteRef, WriteOrigin)> {
    match record.observed() {
        Observed::WriteStarted { write, origin, .. } => {
            Some((*write, *origin))
        }
        _ => None,
    }
}

// A port's observer sees each endpoint write once, as the backend gets it,
// and names the endpoint's own record of it. Two endpoints number their
// writes alike, each in a domain of its own, so the port never mixes them,
// and it numbers the physical writes in its own domain.
#[tokio::test]
async fn a_port_observer_ties_each_backend_write_to_its_endpoint() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let mut on_port = port.observe(observe::Config::new()).await.unwrap();
    let mut endpoints = Vec::new();
    for _ in 0..2 {
        let (endpoint, incoming, _) =
            Endpoint::builder().bind_on(&port).unwrap();
        let observer = endpoint.observe(observe::Config::new()).await.unwrap();
        endpoints.push((endpoint, incoming, observer));
    }

    let mut local = Vec::new();
    for (endpoint, _, observer) in &mut endpoints {
        send_options(endpoint, "tied").await.unwrap().unwrap();
        let records =
            records_where(observer, 1, |r| started(r).is_some()).await;
        let (write, origin) = started(&records[0]).unwrap();
        assert_eq!(origin, WriteOrigin::Send);
        local.push(write);
    }
    assert_eq!(local[0].number(), local[1].number());
    assert_ne!(local[0].domain(), local[1].domain());

    let physical =
        records_where(&mut on_port, 2, |r| started(r).is_some()).await;
    let physical: Vec<_> =
        physical.iter().map(|r| started(r).unwrap()).collect();
    let origins: Vec<_> = physical
        .iter()
        .map(|(_, origin)| match origin {
            WriteOrigin::Endpoint { write, .. } => *write,
            other => panic!("an endpoint's write, got {other:?}"),
        })
        .collect();
    assert_eq!(origins, local);
    let (first, second) = (physical[0].0, physical[1].0);
    assert_eq!(first.domain(), second.domain());
    assert!(!local.iter().any(|write| write.domain() == first.domain()));
    assert_eq!(second.number(), first.number() + 1);
    assert_eq!(wire.count(), 2);
}

// A port's observer sees each datagram as its task takes it, under the ID
// the endpoint it is delivered to keeps, and before the ingress limits drop
// one. A forward names the datagram it sends on, and a raw send nothing.
#[tokio::test]
async fn a_port_observer_sees_arrivals_raw_sends_and_forwards() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .ingress_limits(Limits { count: 1, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    let config = observe::Config::new().payload(1500);
    let mut on_port = port.observe(config).await.unwrap();

    wire.deliver(arriving(options("held"), "nic0"));
    wire.deliver(arriving(options("dropped"), "nic0"));
    let arrivals = records_where(&mut on_port, 2, |r| {
        matches!(r.observed(), Observed::Received { .. })
    })
    .await;
    stats_until(&port, |stats| stats.overflow == 1).await;
    let held = next(&mut ingress).await;
    let Observed::Received { id: held_id, .. } = *arrivals[0].observed()
    else {
        unreachable!()
    };
    assert_eq!(held.received().id(), held_id);
    assert_eq!(arrivals[1].payload().unwrap(), options("dropped").as_bytes());

    held.try_forward(&upstream).unwrap().await.unwrap();
    let forwarded =
        records_where(&mut on_port, 1, |r| started(r).is_some()).await;
    let Observed::WriteStarted { origin, cause, .. } =
        *forwarded[0].observed()
    else {
        unreachable!()
    };
    assert_eq!((origin, cause), (WriteOrigin::Raw, Some(held_id)));

    port.send_bytes(Bytes::from_static(b"raw"), &upstream)
        .unwrap()
        .await
        .unwrap();
    let raw = records_where(&mut on_port, 1, |r| started(r).is_some()).await;
    let Observed::WriteStarted { write, origin, cause, .. } =
        *raw[0].observed()
    else {
        unreachable!()
    };
    assert_eq!((origin, cause), (WriteOrigin::Raw, None));
    let Observed::WriteStarted { write: first, .. } = *forwarded[0].observed()
    else {
        unreachable!()
    };
    assert_eq!(write.domain(), first.domain());
    assert_ne!(write.number(), first.number());

    wire.deliver(arriving(options("delivered"), "nic0"));
    let arrival = records_where(&mut on_port, 1, |r| {
        matches!(r.observed(), Observed::Received { .. })
    })
    .await;
    next(&mut ingress).await.try_deliver(&to_endpoint).unwrap();
    let request = request(&mut incoming).await;
    let Observed::Received { id, .. } = *arrival[0].observed() else {
        unreachable!()
    };
    assert_eq!(request.received.id(), id);
}

// The backend's stages reach the port's observer as they happen: a write it
// takes and later reports unknown, and an endpoint write the port held when
// the endpoint stopped, which the port withdrew before the backend took it.
#[tokio::test]
async fn a_port_observer_sees_late_unknown_and_withdrawn_writes() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let mut on_port = port.observe(observe::Config::new()).await.unwrap();
    let end = |record: &Record| match record.observed() {
        Observed::WriteEnded { end, accepted, .. } => Some((*end, *accepted)),
        _ => None,
    };

    wire.writes(Writes::Delay);
    let late = send_options(&endpoint, "late");
    wire.sent(1).await;
    wire.finish(unknown());
    assert!(late.await.unwrap().unwrap_err().is_outcome_unknown());
    let ended = records_where(&mut on_port, 1, |r| end(r).is_some()).await;
    assert!(matches!(end(&ended[0]), Some((WriteEnd::Unknown(_), true))));

    wire.writes(Writes::Hold);
    let held = send_options(&endpoint, "held");
    wire.until(|state| state.submit.is_some()).await;
    let stopped =
        timeout(Duration::from_secs(2), endpoint.shutdown(Duration::ZERO))
            .await
            .unwrap();
    assert_eq!(stopped, ShutdownOutcome::DeadlineExpired);
    let ended = records_where(&mut on_port, 1, |r| end(r).is_some()).await;
    assert!(matches!(end(&ended[0]), Some((WriteEnd::NotWritten(_), false))));
    wire.writes(Writes::Complete);
    assert!(held.await.unwrap().is_err());
    assert_eq!(wire.count(), 1, "nothing went out after the stop");
}
