/*!
The UA's runtime through its public API, against raw UDP and TCP peers.

Each test drives a UA attached to a loopback endpoint and plays the other
side by hand, so that what goes on the wire is what the test checks.
*/

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    HeaderValue, Request, Response, StatusCode,
    endpoint::{Endpoint, Incoming, Reception, Target},
    message::header::SUBJECT,
    transaction::Timers,
};
use signa_ua::{
    AttachError, AttemptResult, CancelResult, Config, Description, EndReason,
    Error, Event, IncomingInvite, InvitePlan, Negotiate, NegotiationState,
    Offer, Query, ReinvitePlan, Resolve, ResolveError, Session, SessionPhase,
    StaticResolver, Ua, UaEvents, attach,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Notify,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(2);

fn bind() -> (Endpoint, Incoming) {
    Endpoint::builder().udp("127.0.0.1:0".parse().unwrap()).bind().unwrap()
}

fn config() -> Config {
    Config::new("sip:ua@127.0.0.1").unwrap()
}

/// Timers short enough that a test sees a 2xx retransmitted several times,
/// and its ACK deadline of 64 T1 pass, within a second or two.
fn fast() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(80))
        .build()
        .unwrap()
}

/// A UA whose endpoint and configuration both run on [`fast`] timers, on
/// UDP and TCP.
fn start_fast() -> (Ua, SocketAddr, SocketAddr) {
    start_fast_with(config())
}

/// [`start_fast`] with `config`, whose timers it sets.
fn start_fast_with<R: Resolve>(
    config: Config<R>,
) -> (Ua, SocketAddr, SocketAddr) {
    let local = "127.0.0.1:0".parse().unwrap();
    let (endpoint, incoming) = Endpoint::builder()
        .udp(local)
        .tcp(local)
        .timers(fast())
        .bind()
        .unwrap();
    let (udp, tcp) =
        (endpoint.udp_addr().unwrap(), endpoint.tcp_addr().unwrap());
    let ua = attach(endpoint, incoming, config.timers(fast())).unwrap();
    (ua, udp, tcp)
}

/// The answer the application gives to the peer's offer.
fn sdp() -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(b"v=0\r\n"),
    )
}

fn start<R: Resolve>(config: Config<R>) -> (Ua, SocketAddr) {
    let (endpoint, incoming) = bind();
    let address = endpoint.udp_addr().unwrap();
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// A UDP socket that plays the other side.
struct Peer {
    socket: UdpSocket,
}

impl Peer {
    async fn new() -> Peer {
        Peer { socket: UdpSocket::bind("127.0.0.1:0").await.unwrap() }
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Sends `message`, with each line ending in CRLF whether it was
    /// written with bare line feeds or not.
    async fn send(&self, message: &str, to: SocketAddr) {
        let message = message.replace("\r\n", "\n").replace('\n', "\r\n");
        self.socket.send_to(message.as_bytes(), to).await.unwrap();
    }

    /// Receives the next datagram as text, and where it came from.
    async fn recv(&self) -> (String, SocketAddr) {
        let mut buffer = vec![0; 65_536];
        let (n, from) = timeout(WAIT, self.socket.recv_from(&mut buffer))
            .await
            .expect("a datagram in time")
            .unwrap();
        (String::from_utf8(buffer[..n].to_vec()).unwrap(), from)
    }

    /// Receives datagrams until one starts with `start`, skipping the rest,
    /// such as a 100 Trying.
    async fn recv_starting(&self, start: &str) -> (String, SocketAddr) {
        loop {
            let (message, from) = self.recv().await;
            if message.starts_with(start) {
                return (message, from);
            }
        }
    }

    /// Checks that nothing starting with `start` arrives for a while.
    async fn quiet(&self, start: &str, wait: Duration) {
        let _ = timeout(wait, async {
            loop {
                let (message, _) = self.recv().await;
                assert!(!message.starts_with(start), "unexpected {message}");
            }
        })
        .await;
    }

    /// Checks that each failure response arriving for a while answers the
    /// request on `branch`.
    async fn only_failures_for(&self, branch: &str, wait: Duration) {
        let _ = timeout(wait, async {
            loop {
                let (message, _) = self.recv().await;
                if message.starts_with("SIP/2.0 4") {
                    let via = header(&message, "Via");
                    assert!(via[0].contains(branch), "unexpected {message}");
                }
            }
        })
        .await;
    }

    /// Reads and discards what arrives for a while, such as a copy already
    /// on its way.
    async fn drain(&self, wait: Duration) {
        let _ = timeout(wait, async {
            loop {
                self.recv().await;
            }
        })
        .await;
    }
}

/// A TCP connection that plays the other side.
struct TcpPeer {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl TcpPeer {
    async fn connect(to: SocketAddr) -> TcpPeer {
        TcpPeer {
            stream: TcpStream::connect(to).await.unwrap(),
            buffer: Vec::new(),
        }
    }

    fn address(&self) -> SocketAddr {
        self.stream.local_addr().unwrap()
    }

    async fn send(&mut self, message: &str) {
        let message = message.replace("\r\n", "\n").replace('\n', "\r\n");
        self.stream.write_all(message.as_bytes()).await.unwrap();
    }

    /// Receives the next message off the stream, framed by its
    /// Content-Length.
    async fn recv(&mut self) -> String {
        let read = async {
            loop {
                if let Some(message) = self.framed() {
                    return message;
                }
                let mut chunk = [0; 4096];
                let n = self.stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the UA closed the connection");
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        };
        timeout(WAIT, read).await.expect("a message in time")
    }

    /// Takes the first whole message out of the buffer.
    fn framed(&mut self) -> Option<String> {
        let end = self.buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = std::str::from_utf8(&self.buffer[..end]).unwrap();
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| {
                name.trim().eq_ignore_ascii_case("content-length")
            })
            .map_or(0, |(_, value)| value.trim().parse().unwrap());
        let total = end + 4 + length;
        if self.buffer.len() < total {
            return None;
        }
        let message = self.buffer.drain(..total).collect();
        Some(String::from_utf8(message).unwrap())
    }

    async fn recv_starting(&mut self, start: &str) -> String {
        loop {
            let message = self.recv().await;
            if message.starts_with(start) {
                return message;
            }
        }
    }
}

fn invite_to_ua(peer: SocketAddr, call: &str) -> String {
    invite_over("UDP", peer, call)
}

fn invite_over(transport: &str, peer: SocketAddr, call: &str) -> String {
    format!(
        "INVITE sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 INVITE
Contact: <sip:peer@{peer}>
Record-Route: <sip:proxy.example.com;lr>
Content-Type: application/sdp
Content-Length: 5

v=0
"
    )
}

/// A plan for an INVITE from the UA to `to`, with an offer. `call` goes in
/// its Subject, so that a test can tell its INVITEs apart, since the UA
/// picks each Call-ID.
fn plan_to(to: &str, call: &str) -> InvitePlan {
    InvitePlan::new(
        format!("sip:peer@{to}").parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
        sdp(),
    )
    .header(SUBJECT, HeaderValue::try_from(call).unwrap())
}

/// An INVITE to `to` as the endpoint takes it, without the UA.
fn invite_from_ua(to: &str, call: &str) -> Request<Bytes> {
    Request::builder()
        .method("INVITE")
        .uri(format!("sip:peer@{to}").as_str())
        .header("To", format!("<sip:peer@{to}>").as_str())
        .header("From", format!("<sip:ua@127.0.0.1>;tag=ua-{call}").as_str())
        .header("Call-ID", call)
        .header("CSeq", "1 INVITE")
        .header("Max-Forwards", "70")
        .header("Contact", "<sip:ua@127.0.0.1>")
        .header("Content-Type", "application/sdp")
        .body(Bytes::from_static(b"v=0\r\n"))
        .unwrap()
}

/// The response of the peer to an INVITE it received as `request`.
/// A 2xx carries the answer to the INVITE's offer.
fn answer(request: &str, status: &str, tag: &str, contact: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let status = StatusCode::from_bytes(status.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(status)
        .to_tag(tag)
        .header("Contact", format!("<{contact}>").as_str());
    let response = if status.is_success() {
        response
            .header("Content-Type", "application/sdp")
            .body(Bytes::from_static(b"v=0\r\n"))
    } else {
        response.body(Bytes::new())
    };
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

fn header<'a>(message: &'a str, name: &str) -> Vec<&'a str> {
    message
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
        .collect()
}

/// The ACK of the peer for the 2xx `ok` it received for its INVITE `call`,
/// with `cseq` as its CSeq number.
fn ack_for(ok: &str, peer: SocketAddr, call: &str, cseq: u32) -> String {
    format!(
        "ACK sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-ack-{call}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} ACK
Content-Length: 0

",
        to = header(ok, "To")[0],
    )
}

async fn invite(events: &mut UaEvents) -> signa_ua::IncomingInvite {
    loop {
        match timeout(WAIT, events.recv()).await.unwrap().unwrap() {
            Event::Invite(invite) => return invite,
            _ => continue,
        }
    }
}

/// Says whether an INVITE reaches the application within `wait`.
async fn invite_within(events: &mut UaEvents, wait: Duration) -> bool {
    let next = async {
        loop {
            if let Event::Invite(_) = events.recv().await.unwrap() {
                return;
            }
        }
    };
    timeout(wait, next).await.is_ok()
}

/// The UA takes the only receiver of its endpoint, and refuses an endpoint
/// that creates no transactions.
#[tokio::test]
async fn single_incoming_owner() {
    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .reception(Reception::Stateless)
        .bind()
        .unwrap();
    assert_eq!(
        attach(endpoint, incoming, config()).unwrap_err(),
        AttachError::Stateless,
    );

    let (endpoint, incoming) = bind();
    // `incoming` moves into the UA, so nothing else can receive from it.
    assert!(attach(endpoint, incoming, config()).is_ok());
}

/// The application accepts and drops the operation at once. The 200 still
/// goes out, with the dialog's Record-Route and the UA's Contact.
#[tokio::test]
async fn waiting_operation_drop_does_not_withdraw_accepted_command() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "drop-wait"), address).await;
    let invite = invite(&mut ua.events).await;
    drop(invite.try_accept(sdp()).unwrap());

    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert!(header(&ok, "To")[0].contains(";tag="));
    assert_eq!(header(&ok, "Contact"), ["<sip:ua@127.0.0.1>"]);
    assert_eq!(header(&ok, "Record-Route"), ["<sip:proxy.example.com;lr>"]);
    assert_eq!(header(&ok, "Allow"), ["INVITE, ACK, CANCEL, BYE, OPTIONS"]);
}

/// Dropping every handle of the application sends nothing on its own. The
/// UAS keeps its responder, so no 500 follows the 200, and the UAC keeps its
/// client transaction, so the 2xx still gets its ACK.
#[tokio::test]
async fn observer_drop_does_not_drop_responder_or_client_control() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "drop-uas"), address).await;
    let invite = invite(&mut ua.events).await;
    // The session handle goes at once.
    let _ = invite.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.quiet("SIP/2.0 500", Duration::from_millis(300)).await;

    // So does the attempt handle, and the events with it.
    let _ = ua
        .handle
        .try_invite(plan_to(&peer.address().to_string(), "drop-uac"))
        .unwrap()
        .await
        .unwrap();
    drop(ua.events);

    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{}", peer.address());
    peer.send(&answer(&request, "200", "peer", &contact), from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    let number = header(&request, "CSeq")[0].replace("INVITE", "ACK");
    assert_eq!(header(&ack, "CSeq"), [number]);
    assert_eq!(header(&ack, "Call-ID"), header(&request, "Call-ID"));
    // The To is the Request-URI without its port, which a To may not have
    // (Table 1 of RFC 3261 section 19.1.1).
    assert_eq!(header(&ack, "To"), ["<sip:peer@127.0.0.1>;tag=peer"]);
    peer.quiet("CANCEL", Duration::from_millis(300)).await;
}

/// A resolver that never answers for `slow.invalid`, and resolves IP
/// literals otherwise.
struct Slow;

impl Resolve for Slow {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        if query.uri().contains("slow.invalid") {
            std::future::pending::<()>().await;
        }
        StaticResolver::new().resolve(query).await
    }
}

/// The ACK of one dialog waits for its next hop, which never resolves. The
/// ACK of another dialog goes out meanwhile.
#[tokio::test]
async fn slow_resolver_does_not_block_other_dialog_ack() {
    let (ua, _) = start(config().resolver(Slow));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    for call in ["slow", "fast"] {
        ua.handle.try_invite(plan_to(&to, call)).unwrap().await.unwrap();
    }
    let (first, from) = peer.recv_starting("INVITE").await;
    let (second, _) = peer.recv_starting("INVITE").await;
    let (slow, fast) = if header(&first, "Subject") == ["slow"] {
        (first, second)
    } else {
        (second, first)
    };

    peer.send(&answer(&slow, "200", "s", "sip:peer@slow.invalid"), from).await;
    peer.send(&answer(&fast, "200", "f", &format!("sip:peer@{to}")), from)
        .await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(header(&ack, "Call-ID"), header(&fast, "Call-ID"));
}

/// With a command queue of one and the driver not yet running, a second
/// INVITE is refused and handed back. Nothing goes out for it, then or later.
#[tokio::test]
async fn command_queue_full_returns_busy_without_state_mutation() {
    let (ua, _) = start(config().command_capacity(1));
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let first = ua.handle.try_invite(plan_to(&to, "first")).unwrap();
    let refused = ua.handle.try_invite(plan_to(&to, "second")).unwrap_err();

    assert_eq!(refused.error(), Error::Busy);
    let returned = refused.into_inner();
    assert!(format!("{returned:?}").contains("second"));

    tokio::spawn(ua.driver);
    first.await.unwrap();
    let (request, _) = peer.recv_starting("INVITE").await;
    assert_eq!(header(&request, "Subject"), ["first"]);
    peer.quiet("INVITE", Duration::from_millis(300)).await;
}

/// The application does not read events, and the queue of one overflows.
/// The end of the attempt still gets through, since its place was set aside
/// when the INVITE went out, and the loss is reported once there is room.
#[tokio::test]
async fn terminal_outcome_survives_notification_overflow() {
    let config = config().event_capacity(1).max_attempts(1);
    let (mut ua, _, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let attempt =
        ua.handle.try_invite(plan_to(&to, "fills")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "p", &format!("sip:peer@{to}")), from)
        .await;
    peer.recv_starting("ACK").await;

    // The confirmation fits, the negotiation does not. Timer M then ends
    // the attempt, 64 T1 after the 2xx.
    let session = match ua.events.recv().await.unwrap() {
        Event::Confirmed { session, .. } => session,
        other => panic!("expected the confirmation, got {other:?}"),
    };
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, signa_ua::SessionPhase::Established);
    match timeout(WAIT, ua.events.recv()).await.unwrap().unwrap() {
        Event::Lagged { missed, .. } => assert_eq!(missed, 1),
        other => panic!("expected the loss to be reported, got {other:?}"),
    }
    match timeout(WAIT, ua.events.recv()).await.unwrap().unwrap() {
        Event::AttemptEnded { attempt: ended, result, complete, .. } => {
            assert_eq!(ended, attempt.id());
            assert_eq!(result, AttemptResult::Answered);
            assert!(complete);
        }
        other => panic!("expected the end of the attempt, got {other:?}"),
    }
}

/// A resolver that waits until told to resolve.
struct Gate(Arc<Notify>);

impl Resolve for Gate {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        self.0.notified().await;
        StaticResolver::new().resolve(query).await
    }
}

/// Dropping the driver stops the UA at once. An operation in flight fails
/// with `DriverStopped`, the handle takes nothing more, the copies of a 2xx
/// stop, and the endpoint shuts down with it.
#[tokio::test]
async fn driver_drop_is_forced_stop_not_graceful_shutdown() {
    let local = "127.0.0.1:0".parse().unwrap();
    let (endpoint, incoming) =
        Endpoint::builder().udp(local).timers(fast()).bind().unwrap();
    let address = endpoint.udp_addr().unwrap();
    let gate = Arc::new(Notify::new());
    let config = config().resolver(Gate(gate)).timers(fast());
    let mut ua = attach(endpoint.clone(), incoming, config).unwrap();
    let driver = tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    // A 2xx the peer never acknowledges goes out again and again.
    peer.send(&invite_to_ua(peer.address(), "copies"), address).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.recv_starting("SIP/2.0 200").await;
    // The INVITE waits on the gate, so the driver has taken it once the
    // event of the 2xx, which comes after, is in.
    let pending = ua.handle.try_invite(plan_to(&to, "stuck")).unwrap();
    peer.send(&invite_to_ua(peer.address(), "marker"), address).await;
    invite(&mut ua.events).await;
    driver.abort();

    assert_eq!(
        timeout(WAIT, pending).await.unwrap().unwrap_err(),
        Error::DriverStopped
    );
    let refused = ua.handle.try_invite(plan_to(&to, "late")).unwrap_err();
    assert_eq!(refused.error(), Error::Closed);
    let target =
        Target::new(signa_core::transport::Transport::Udp, peer.address());
    let error = endpoint
        .start(invite_from_ua(&to, "direct"), target)
        .await
        .unwrap_err();
    assert!(error.is_closed());
    peer.drain(Duration::from_millis(50)).await;
    peer.quiet("SIP/2.0 200", Duration::from_millis(300)).await;
}

/// An INVITE whose decision is dropped gets a 500, and a rejected one the
/// status the application chose.
#[tokio::test]
async fn an_undecided_invite_gets_a_500_and_a_rejected_one_its_status() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "dropped"), address).await;
    drop(invite(&mut ua.events).await);
    let (response, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&response, "Call-ID"), ["dropped"]);
    assert!(header(&response, "To")[0].contains(";tag="));

    peer.send(&invite_to_ua(peer.address(), "busy"), address).await;
    let busy = StatusCode::from_u16(486).unwrap();
    invite(&mut ua.events).await.try_reject(busy).unwrap().await.unwrap();
    let (response, _) = peer.recv_starting("SIP/2.0 486").await;
    assert_eq!(header(&response, "Call-ID"), ["busy"]);
}

/// A rejection needs a final status other than a 2xx, and a refused one
/// leaves the decision with the application.
#[tokio::test]
async fn an_invalid_rejection_hands_the_invite_back() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "retry"), address).await;
    let invite = invite(&mut ua.events).await;
    let refused = invite.try_reject(StatusCode::OK).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);

    refused.into_inner().try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ok, "Call-ID"), ["retry"]);
}

/// A resolution that never ends counts as unresolved after the timeout, and
/// frees its job. With one job slot, a final response still gets out after
/// it.
#[tokio::test]
async fn a_hung_resolver_gives_up_and_frees_its_job() {
    let config = config()
        .resolver(Slow)
        .max_jobs(1)
        .resolve_timeout(Duration::from_millis(100));
    let (mut ua, address) = start(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    let hung = ua.handle.try_invite(plan_to("slow.invalid", "hung"));
    peer.send(&invite_to_ua(peer.address(), "behind"), address).await;
    let invite = invite(&mut ua.events).await;
    let accepted = invite.try_accept(sdp()).unwrap();

    assert_eq!(
        timeout(WAIT, hung.unwrap()).await.unwrap().unwrap_err(),
        Error::Unroutable,
    );
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ok, "Call-ID"), ["behind"]);
    timeout(WAIT, accepted).await.unwrap().unwrap();
}

/// Every response to an INVITE carries the To tag of its first one: the
/// 180, the 200 and each copy of the 200. The 180 forms an early dialog at
/// the caller, so it carries the Contact and Record-Route as the 200 does.
#[tokio::test]
async fn uas_to_tag_is_stable() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "tag"), udp).await;
    let invite = invite(&mut ua.events).await;
    let ringing = StatusCode::from_u16(180).unwrap();
    invite.try_provisional(ringing).unwrap().await.unwrap();
    let (ringing, _) = peer.recv_starting("SIP/2.0 180").await;
    invite.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    let (copy, _) = peer.recv_starting("SIP/2.0 200").await;

    let to = header(&ringing, "To");
    assert!(to[0].contains(";tag="));
    assert_eq!(header(&ok, "To"), to);
    assert_eq!(header(&copy, "To"), to);
    assert_eq!(header(&ringing, "Contact"), ["<sip:ua@127.0.0.1>"]);
    assert_eq!(
        header(&ringing, "Record-Route"),
        ["<sip:proxy.example.com;lr>"]
    );
}

/// The 2xx goes out again until its ACK, over TCP as over UDP. A reliable
/// transport does not excuse it, since a proxy on the way may forward over
/// UDP (RFC 3261 section 13.3.1.4).
#[tokio::test]
async fn uas_2xx_retransmits_on_udp_and_tcp() {
    let (mut ua, udp, tcp) = start_fast();
    tokio::spawn(ua.driver);

    let peer = Peer::new().await;
    peer.send(&invite_to_ua(peer.address(), "over-udp"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    for _ in 0..3 {
        let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Call-ID"), ["over-udp"]);
    }

    let mut stream = TcpPeer::connect(tcp).await;
    let request = invite_over("TCP", stream.address(), "over-tcp");
    stream.send(&request).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    for _ in 0..3 {
        let ok = stream.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Call-ID"), ["over-tcp"]);
    }
}

/// Each copy of the 2xx is the message that first went out, answer and
/// all, from the address the INVITE reached. It goes through the INVITE's
/// reply route, which takes nothing but the request's Via, From, Call-ID and
/// CSeq as they were received.
#[tokio::test]
async fn response_replay_preserves_reply_route_identity() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "replay"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, first) = peer.recv_starting("SIP/2.0 200").await;
    let (copy, second) = peer.recv_starting("SIP/2.0 200").await;

    assert_eq!(copy, ok);
    assert_eq!((first, second), (udp, udp));
    assert_eq!(header(&ok, "Content-Type"), ["application/sdp"]);
    assert!(ok.ends_with("\r\n\r\nv=0\r\n"));
}

/// An ACK with another CSeq, another To tag or another From tag is not the
/// 2xx's, and the copies go on. The ACK that matches stops them.
#[tokio::test]
async fn matching_ack_stops_retransmission_unrelated_ack_does_not() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "ack"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    let matching = ack_for(&ok, peer.address(), "ack", 1);
    let to = header(&ok, "To")[0];
    let other_to = matching.replace(to, "<sip:ua@127.0.0.1>;tag=other");
    let other_from = matching.replace("tag=peer-ack", "tag=other");

    for ack in [ack_for(&ok, peer.address(), "ack", 2), other_to, other_from] {
        peer.send(&ack, udp).await;
        peer.recv_starting("SIP/2.0 200").await;
        peer.recv_starting("SIP/2.0 200").await;
    }

    peer.send(&ack_for(&ok, peer.address(), "ack", 1), udp).await;
    peer.drain(Duration::from_millis(50)).await;
    // Neither a copy of the 200 nor any response to the ACKs.
    peer.quiet("SIP/2.0", Duration::from_millis(400)).await;
}

/// An INVITE from `peer` straight to the UA, with no proxy on the way, so
/// that the dialog's requests go to the peer.
fn direct_invite(peer: SocketAddr, call: &str) -> String {
    invite_to_ua(peer, call)
        .replace("Record-Route: <sip:proxy.example.com;lr>\n", "")
}

/// Without an ACK, the copies stop 64 T1 after the first 2xx, and the
/// session ends with a BYE (RFC 3261 section 13.3.1.4), with the reason
/// before the end. The session's snapshot still says why afterwards.
#[tokio::test]
async fn an_unacknowledged_2xx_ends_its_session() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&direct_invite(peer.address(), "no-ack"), udp).await;
    let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
    let session = accepted.await.unwrap();

    let mut ends = Vec::new();
    while ends.len() < 2 {
        match timeout(WAIT, ua.events.recv()).await.unwrap().unwrap() {
            Event::AckTimeout { session: ended, .. } => {
                ends.push(("timeout", ended))
            }
            Event::Ended { session: ended, reason, .. } => {
                assert_eq!(reason, EndReason::AckTimeout);
                ends.push(("ended", ended));
            }
            _ => {}
        }
    }
    assert_eq!(
        ends,
        [("timeout", session.clone()), ("ended", session.clone())]
    );
    let (bye, _) = peer.recv_starting("BYE").await;
    assert!(bye.starts_with(&format!("BYE sip:peer@{} ", peer.address())));
    assert_eq!(header(&bye, "Call-ID"), ["no-ack"]);
    peer.quiet("SIP/2.0 200", Duration::from_millis(300)).await;
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Ended);
    assert_eq!(snapshot.end_reason, Some(EndReason::AckTimeout));
}

/// A retransmission of the INVITE is the core's to absorb, before and after
/// the 2xx, so the application sees one INVITE and one session. A copy that
/// came by another path, with another branch, gets a 482 (RFC 3261 section
/// 8.2.2.2).
#[tokio::test]
async fn retransmitted_invite_does_not_create_second_usage() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let request = invite_to_ua(peer.address(), "again");
    let merged =
        request.replace("branch=z9hG4bK-again", "branch=z9hG4bK-other");

    peer.send(&request, udp).await;
    let invite = invite(&mut ua.events).await;
    peer.send(&request, udp).await;
    peer.send(&merged, udp).await;

    // The 482 answers the merged copy, and the copy on the same branch gets
    // none. The core sends the 482 again until its ACK, which this peer
    // does not send, so each failure that arrives is that 482.
    let (loop_detected, _) = peer.recv_starting("SIP/2.0 482").await;
    assert_eq!(header(&loop_detected, "Call-ID"), ["again"]);
    peer.only_failures_for("z9hG4bK-other", Duration::from_millis(200)).await;
    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);

    invite.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.send(&request, udp).await;
    peer.only_failures_for("z9hG4bK-other", Duration::from_millis(200)).await;
    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
}

/// An INVITE the application holds past the decision timeout gets a 500,
/// and the accept that comes after it sends nothing.
#[tokio::test]
async fn the_decision_timeout_answers_an_undecided_invite() {
    let config = config().decision_timeout(Duration::from_millis(100));
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "slow"), udp).await;
    let invite = invite(&mut ua.events).await;
    let (error, _) = peer.recv_starting("SIP/2.0 500").await;
    let late = invite.try_accept(sdp()).unwrap().await.unwrap_err();

    assert_eq!(header(&error, "Call-ID"), ["slow"]);
    assert!(matches!(late, Error::AlreadyFinalized | Error::StaleDecision));
    peer.quiet("SIP/2.0 200", Duration::from_millis(200)).await;
}

/// An INVITE whose body may hold its offer where the UA cannot take it out,
/// as a multipart body, gets a 415 that says what the UA takes (RFC 3261
/// section 21.4.13), before the application sees it. One that requires an
/// extension gets a 420 that lists it as unsupported.
#[tokio::test]
async fn a_multipart_or_extended_invite_is_refused() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let multipart = invite_to_ua(peer.address(), "multipart").replace(
        "Content-Type: application/sdp\n",
        "Content-Type: multipart/mixed;boundary=x\n",
    );
    let extended = invite_to_ua(peer.address(), "extended").replace(
        "Max-Forwards: 70\n",
        "Max-Forwards: 70\nRequire: 100rel, timer\n",
    );

    peer.send(&multipart, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 415").await;
    assert_eq!(header(&refused, "Call-ID"), ["multipart"]);
    assert_eq!(header(&refused, "Accept"), ["application/sdp"]);
    assert!(header(&refused, "To")[0].contains(";tag="));

    peer.send(&extended, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 420").await;
    assert_eq!(header(&refused, "Call-ID"), ["extended"]);
    assert_eq!(header(&refused, "Unsupported"), ["100rel, timer"]);

    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
}

/// Receives events until the attempt ends, and returns what it came to.
async fn attempt_end(events: &mut UaEvents) -> (AttemptResult, bool) {
    loop {
        if let Event::AttemptEnded { result, complete, .. } =
            timeout(WAIT, events.recv()).await.unwrap().unwrap()
        {
            return (result, complete);
        }
    }
}

/// The value of the `branch` parameter of the top Via of `message`.
fn branch(message: &str) -> &str {
    let via = header(message, "Via")[0];
    let start = via.find("branch=").unwrap() + "branch=".len();
    via[start..].split(';').next().unwrap()
}

/// The ACK of a 2xx goes where the dialog says: to the first entry of the
/// route set the 2xx's Record-Route makes, with the Contact as its
/// Request-URI. Neither the address the 2xx came from nor the Contact gets
/// it (RFC 3261 sections 12.2.1.1 and 13.2.2.4).
#[tokio::test]
async fn uac_ack_uses_dialog_route_not_response_source() {
    let (ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let callee = Peer::new().await;
    let proxy = Peer::new().await;
    let contact = Peer::new().await;

    ua.handle
        .try_invite(plan_to(&callee.address().to_string(), "routed"))
        .unwrap()
        .await
        .unwrap();
    let (request, from) = callee.recv_starting("INVITE").await;
    let target = format!("sip:callee@{}", contact.address());
    let ok = answer(&request, "200", "routed", &target).replacen(
        "\r\n",
        &format!("\r\nRecord-Route: <sip:{};lr>\r\n", proxy.address()),
        1,
    );
    callee.send(&ok, from).await;

    let (ack, _) = proxy.recv_starting("ACK").await;
    assert!(ack.starts_with(&format!("ACK {target} SIP/2.0")));
    assert_eq!(
        header(&ack, "Route"),
        [format!("<sip:{};lr>", proxy.address())]
    );
    callee.quiet("ACK", Duration::from_millis(200)).await;
    contact.quiet("ACK", Duration::from_millis(200)).await;
}

/// Each copy of a 2xx gets the ACK that went out for the first, unchanged,
/// branch and all. That branch is not the INVITE's, and the CSeq is the
/// INVITE's number, not a new one.
#[tokio::test]
async fn duplicate_2xx_reuses_frozen_ack() {
    let (ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "copies")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let ok = answer(&request, "200", "copies", &format!("sip:peer@{to}"));
    peer.send(&ok, from).await;
    let (first, _) = peer.recv_starting("ACK").await;
    peer.send(&ok, from).await;
    let (second, _) = peer.recv_starting("ACK").await;

    assert_eq!(second, first);
    assert_ne!(branch(&first), branch(&request));
    let number = header(&request, "CSeq")[0].replace("INVITE", "ACK");
    assert_eq!(header(&first, "CSeq"), [number]);
}

/// The ACK of a final response other than a 2xx is the endpoint's, sent in
/// the INVITE's transaction with the INVITE's branch (RFC 3261 section
/// 17.1.1.3). The UA sends none of its own, and the attempt ends with the
/// peer's status.
#[tokio::test]
async fn uac_non_2xx_ack_remains_core_owned() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "busy")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(
        &answer(&request, "486", "busy", &format!("sip:peer@{to}")),
        from,
    )
    .await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(branch(&ack), branch(&request));
    peer.quiet("ACK", Duration::from_millis(300)).await;
    let busy = StatusCode::from_u16(486).unwrap();
    assert_eq!(
        attempt_end(&mut ua.events).await,
        (AttemptResult::Failed(Error::RemoteFailure(busy)), true),
    );
}

/// Dropping the attempt and the events is neither a CANCEL nor an end to
/// the UA's work. The 2xx that comes later still gets its ACK.
#[tokio::test]
async fn attempt_observer_drop_does_not_cancel_invite() {
    let (ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let attempt =
        ua.handle.try_invite(plan_to(&to, "dropped")).unwrap().await.unwrap();
    drop((attempt, ua.events));

    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{to}");
    peer.send(&answer(&request, "180", "dropped", &contact), from).await;
    peer.quiet("CANCEL", Duration::from_millis(200)).await;
    peer.send(&answer(&request, "200", "dropped", &contact), from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(header(&ack, "Call-ID"), header(&request, "Call-ID"));
    peer.quiet("CANCEL", Duration::from_millis(200)).await;
}

/// A final response from the peer and a transport that fails are told
/// apart: the first ends the attempt with the peer's status, and the second
/// fails the INVITE before any attempt exists, since the endpoint could not
/// open the connection.
#[tokio::test]
async fn remote_failure_and_core_transport_failure_are_distinct() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "rejected")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "603", "no", &format!("sip:peer@{to}")), from)
        .await;
    let decline = StatusCode::from_u16(603).unwrap();
    assert_eq!(
        attempt_end(&mut ua.events).await,
        (AttemptResult::Failed(Error::RemoteFailure(decline)), true),
    );

    // Nothing listens on the port once the listener is gone.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let unreachable = format!("{closed};transport=tcp");
    let started = ua.handle.try_invite(plan_to(&unreachable, "lost")).unwrap();
    assert_eq!(started.await.unwrap_err(), Error::TransportFailure);
}

/// A resolver that knows a few host names by heart: `flaky.invalid` fails
/// the first time and then resolves to `peer`, `gated.invalid` waits on the
/// gate, `panic.invalid` panics, and IP literals resolve as they are.
struct Hosts {
    peer: SocketAddr,
    flaky: AtomicUsize,
    gate: Arc<Notify>,
}

impl Hosts {
    fn new(peer: SocketAddr) -> Hosts {
        Hosts {
            peer,
            flaky: AtomicUsize::new(0),
            gate: Arc::new(Notify::new()),
        }
    }
}

impl Resolve for Hosts {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        let udp = signa_core::transport::Transport::Udp;
        if query.uri().contains("flaky.invalid") {
            if self.flaky.fetch_add(1, Ordering::Relaxed) == 0 {
                return Err(ResolveError::Unresolved);
            }
            return Ok(Target::new(udp, self.peer));
        }
        if query.uri().contains("gated.invalid") {
            self.gate.notified().await;
            return Ok(Target::new(udp, self.peer));
        }
        if query.uri().contains("panic.invalid") {
            panic!("a resolver that fails as badly as it can");
        }
        StaticResolver::new().resolve(query).await
    }
}

/// The first ACK of a 2xx does not get out, here for a next hop that fails
/// to resolve. The next copy of the 2xx gets the ACK all the same (RFC 3261
/// section 13.2.2.4), rather than nothing for good.
#[tokio::test]
async fn a_failed_ack_goes_out_with_the_next_copy_of_its_2xx() {
    let peer = Peer::new().await;
    let (ua, _, _) =
        start_fast_with(config().resolver(Hosts::new(peer.address())));
    tokio::spawn(ua.driver);
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "flaky")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let ok = answer(&request, "200", "flaky", "sip:peer@flaky.invalid");
    peer.send(&ok, from).await;
    peer.quiet("ACK", Duration::from_millis(200)).await;
    peer.send(&ok, from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert!(ack.starts_with("ACK sip:peer@flaky.invalid SIP/2.0"));
}

/// Copies of a 2xx that arrive while its ACK is still on its way wait for
/// that ACK rather than queue one each, so a peer that floods copies gets
/// one ACK for them.
#[tokio::test]
async fn copies_of_a_2xx_share_the_ack_in_flight() {
    let peer = Peer::new().await;
    let hosts = Hosts::new(peer.address());
    let gate = hosts.gate.clone();
    let (ua, _, _) = start_fast_with(config().resolver(hosts));
    tokio::spawn(ua.driver);
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "gated")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let ok = answer(&request, "200", "gated", "sip:peer@gated.invalid");
    for _ in 0..5 {
        peer.send(&ok, from).await;
    }
    peer.quiet("ACK", Duration::from_millis(100)).await;
    // Every resolution waiting on the gate goes on, so each ACK job would
    // send one.
    gate.notify_waiters();

    peer.recv_starting("ACK").await;
    peer.quiet("ACK", Duration::from_millis(300)).await;
}

/// An INVITE that fits 1300 bytes only without the Via the endpoint adds goes
/// over TCP, as RFC 3261 section 18.1.1 asks, rather than fail at the
/// endpoint over UDP.
#[tokio::test]
async fn a_request_near_1300_bytes_goes_over_tcp() {
    let (ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let to = listener.local_addr().unwrap().to_string();
    // About 1250 bytes without a Via, and over 1300 with one.
    let offer = Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from(format!("v=0\r\n{}\r\n", "a".repeat(940))),
    );
    let plan = InvitePlan::new(
        format!("sip:peer@{to}").parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
        offer,
    );

    let started = ua.handle.try_invite(plan).unwrap();
    let (stream, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
    let mut peer = TcpPeer { stream, buffer: Vec::new() };

    let request = peer.recv_starting("INVITE").await;
    assert!(header(&request, "Via")[0].starts_with("SIP/2.0/TCP"));
    timeout(WAIT, started).await.unwrap().unwrap();
}

/// Each running operation holds one of `max_operations` places, so one
/// beyond it is refused and handed back. The place comes back with the
/// outcome.
#[tokio::test]
async fn operations_beyond_the_limit_are_busy_until_one_ends() {
    let (ua, _) = start(config().max_operations(1));
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let first = ua.handle.try_invite(plan_to(&to, "first")).unwrap();
    let refused = ua.handle.try_invite(plan_to(&to, "second")).unwrap_err();
    assert_eq!(refused.error(), Error::Busy);

    tokio::spawn(ua.driver);
    first.await.unwrap();
    ua.handle.try_invite(refused.into_inner()).unwrap().await.unwrap();
}

/// Limits as large as a `usize` holds are capped rather than overflow or
/// fail to build a channel, and the UA runs.
#[tokio::test]
async fn a_config_at_its_extremes_still_runs() {
    let config = config()
        .command_capacity(usize::MAX)
        .event_capacity(usize::MAX)
        .max_operations(usize::MAX)
        .max_pending_invites(usize::MAX)
        .max_attempts(usize::MAX)
        .max_dialogs(usize::MAX)
        .max_routes(usize::MAX)
        .max_jobs(usize::MAX)
        .resolve_timeout(Duration::MAX)
        .decision_timeout(Duration::MAX);
    let (ua, _) = start(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    let to = peer.address().to_string();
    ua.handle.try_invite(plan_to(&to, "large")).unwrap().await.unwrap();
    peer.recv_starting("INVITE").await;
}

/// A resolver that panics fails the INVITE it was resolving, and the UA
/// goes on with the next one.
#[tokio::test]
async fn a_panicking_resolver_fails_only_its_request() {
    let peer = Peer::new().await;
    let (ua, _) = start(config().resolver(Hosts::new(peer.address())));
    tokio::spawn(ua.driver);

    let failed = ua.handle.try_invite(plan_to("panic.invalid", "panic"));
    assert_eq!(
        timeout(WAIT, failed.unwrap()).await.unwrap().unwrap_err(),
        Error::Internal,
    );
    let to = peer.address().to_string();
    ua.handle.try_invite(plan_to(&to, "after")).unwrap().await.unwrap();
    peer.recv_starting("INVITE").await;
}

/// The count of dropped notifications comes as soon as the application
/// makes room, even if nothing else happens.
#[tokio::test]
async fn a_lag_is_reported_once_there_is_room() {
    // The attempt has a place of its own for its end, and one place is left
    // for its notifications.
    let config = config().event_capacity(1).max_attempts(1);
    let (mut ua, _, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "lag")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "p", &format!("sip:peer@{to}")), from)
        .await;
    peer.recv_starting("ACK").await;

    // The confirmation fits, and the negotiation that follows it does not.
    let next = timeout(WAIT, ua.events.recv()).await.unwrap().unwrap();
    assert!(matches!(next, Event::Confirmed { .. }), "{next:?}");
    let next = timeout(WAIT, ua.events.recv()).await.unwrap().unwrap();
    assert!(matches!(next, Event::Lagged { missed: 1, .. }), "{next:?}");
}

/// Once nobody reads the events, nobody can decide an INVITE, and a new one
/// gets a 503. A request the UA refuses anyway still gets its own status,
/// such as the 481 of a dialog the UA does not know.
#[tokio::test]
async fn an_invite_nobody_can_decide_gets_a_503_after_its_checks() {
    let (ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    drop(ua.events);
    let peer = Peer::new().await;
    let unknown = invite_to_ua(peer.address(), "unknown")
        .replace("To: <sip:ua@127.0.0.1>", "To: <sip:ua@127.0.0.1>;tag=gone");

    peer.send(&invite_to_ua(peer.address(), "unheard"), udp).await;
    let (response, _) = peer.recv_starting("SIP/2.0 503").await;
    assert_eq!(header(&response, "Call-ID"), ["unheard"]);

    peer.send(&unknown, udp).await;
    let (response, _) = peer.recv_starting("SIP/2.0 481").await;
    assert_eq!(header(&response, "Call-ID"), ["unknown"]);
}

/// Without TLS, a SIPS Request-URI gets a 416 (RFC 3261 section 8.2.2.1),
/// and a SIPS Record-Route a 480 with the warning 380 (RFC 5630 section
/// 5.1.2). Neither reaches the application.
#[tokio::test]
async fn a_sips_invite_is_refused_without_tls() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let secure = invite_to_ua(peer.address(), "secure")
        .replace("INVITE sip:ua@", "INVITE sips:ua@");
    let routed = invite_to_ua(peer.address(), "routed")
        .replace("<sip:proxy.example.com;lr>", "<sips:proxy.example.com;lr>");

    peer.send(&secure, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 416").await;
    assert_eq!(header(&refused, "Call-ID"), ["secure"]);

    peer.send(&routed, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 480").await;
    assert_eq!(header(&refused, "Call-ID"), ["routed"]);
    assert_eq!(
        header(&refused, "Warning"),
        ["380 127.0.0.1 \"SIPS Not Allowed\""]
    );

    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
}

/// An INVITE whose Expires passes before the application decides gets a
/// 487 (RFC 3261 section 13.3.1), and the accept after it sends nothing.
#[tokio::test]
async fn an_expired_invite_gets_a_487() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let expiring = invite_to_ua(peer.address(), "expiring")
        .replace("Max-Forwards: 70\n", "Max-Forwards: 70\nExpires: 1\n");

    peer.send(&expiring, udp).await;
    let invite = invite(&mut ua.events).await;
    let read = async {
        loop {
            let (message, _) = peer.recv().await;
            if message.starts_with("SIP/2.0 487") {
                return message;
            }
        }
    };
    let terminated = timeout(Duration::from_secs(3), read).await.unwrap();
    assert_eq!(header(&terminated, "Call-ID"), ["expiring"]);

    let late = invite.try_accept(sdp()).unwrap().await.unwrap_err();
    assert!(matches!(late, Error::AlreadyFinalized | Error::StaleDecision));
    peer.quiet("SIP/2.0 200", Duration::from_millis(200)).await;
}

/// A request outside a dialog other than INVITE gets an answer of its own
/// (RFC 3261 section 8.2.1): OPTIONS a 200 with the methods the UA takes, a
/// method the UA knows but does not take a 405 with them, one it does not
/// know a 501, and a BYE a 481 (section 15.1.2).
#[tokio::test]
async fn requests_outside_a_dialog_get_their_own_answers() {
    let (ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let request = |method: &str, call: &str| {
        format!(
            "{method} sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 {method}
Content-Length: 0

",
            peer = peer.address(),
        )
    };

    for (method, status, allow) in [
        ("OPTIONS", "200", true),
        ("MESSAGE", "405", true),
        ("FROBNICATE", "501", false),
        ("BYE", "481", false),
    ] {
        peer.send(&request(method, method), udp).await;
        let (response, _) =
            peer.recv_starting(&format!("SIP/2.0 {status}")).await;
        assert_eq!(header(&response, "Call-ID"), [method]);
        assert!(header(&response, "To")[0].contains(";tag="), "{method}");
        let expected: &[&str] =
            if allow { &["INVITE, ACK, CANCEL, BYE, OPTIONS"] } else { &[] };
        assert_eq!(header(&response, "Allow"), expected, "{method}");
    }
}

/// INVITEs this UA sends each set a place in the event queue aside for
/// their end, apart from the places of other events. With every attempt in
/// flight, an incoming INVITE still reaches the application.
#[tokio::test]
async fn invites_in_flight_do_not_crowd_out_other_events() {
    let config = config().event_capacity(1).max_attempts(2);
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let callee = Peer::new().await;
    let caller = Peer::new().await;
    let to = callee.address().to_string();

    for call in ["first", "second"] {
        ua.handle.try_invite(plan_to(&to, call)).unwrap().await.unwrap();
    }
    caller.send(&invite_to_ua(caller.address(), "incoming"), udp).await;

    let incoming = invite(&mut ua.events).await;
    assert_eq!(
        incoming.request().headers().get("Call-ID").unwrap(),
        "incoming"
    );
}

/// An accepted INVITE waits for its ACK outside the limit of pending
/// INVITEs and of attempts. Another INVITE still reaches the application,
/// and the UA can still send one.
#[tokio::test]
async fn invites_awaiting_ack_leave_room_for_others() {
    let config = config().max_pending_invites(1).max_attempts(1);
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "unacked"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    peer.send(&invite_to_ua(peer.address(), "next"), udp).await;
    invite(&mut ua.events).await;

    let to = peer.address().to_string();
    ua.handle.try_invite(plan_to(&to, "outgoing")).unwrap().await.unwrap();
}

/// An INVITE nobody answers fails with the timeout of its transaction,
/// Timer B, and not with a 408 that no peer sent.
#[tokio::test]
async fn an_unanswered_invite_times_out() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "silent")).unwrap().await.unwrap();
    peer.recv_starting("INVITE").await;

    assert_eq!(
        attempt_end(&mut ua.events).await,
        (AttemptResult::Failed(Error::Timeout), true),
    );
}

/// With room for one response at a time between the endpoint and the UA, a
/// burst of responses overflows. The attempt then says its set of responses
/// is not complete, rather than report what it saw as everything.
#[tokio::test]
async fn responses_overflow_on_the_wire_marks_the_attempt_incomplete() {
    let local = "127.0.0.1:0".parse().unwrap();
    let limits =
        signa_core::transport::WriteLimits { messages: 1, bytes: 1 << 20 };
    let (endpoint, incoming) = Endpoint::builder()
        .udp(local)
        .timers(fast())
        .client_response_limits(limits)
        .bind()
        .unwrap();
    let mut ua = attach(endpoint, incoming, config().timers(fast())).unwrap();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(plan_to(&to, "burst")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{to}");
    for n in 0..200 {
        let ringing = answer(&request, "180", &format!("fork{n}"), &contact);
        peer.send(&ringing, from).await;
    }
    peer.send(&answer(&request, "200", "fork0", &contact), from).await;

    let (_, complete) = attempt_end(&mut ua.events).await;
    assert!(!complete);
}

/// What the events of an attempt said by its end: the sessions each 2xx
/// confirmed, in order, and what [`Event::AttemptEnded`] reported.
struct Ending {
    confirmed: Vec<Session>,
    result: AttemptResult,
    complete: bool,
    degraded: bool,
    sessions: Vec<Session>,
}

/// Receives events until the attempt ends, keeping the sessions the 2xx
/// responses confirmed.
async fn ending(events: &mut UaEvents) -> Ending {
    let mut confirmed = Vec::new();
    loop {
        match timeout(WAIT, events.recv()).await.unwrap().unwrap() {
            Event::Confirmed { session, .. } => confirmed.push(session),
            Event::AttemptEnded {
                result,
                complete,
                degraded,
                sessions,
                ..
            } => {
                return Ending {
                    confirmed,
                    result,
                    complete,
                    degraded,
                    sessions,
                };
            }
            _ => {}
        }
    }
}

/// The 200 of the peer to a request it received as `request`.
fn ok_to(request: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response =
        Response::reply_to(&request).status(StatusCode::OK).body(Bytes::new());
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

/// A forking proxy has two callees answer the INVITE, here played by one
/// socket with two tags. Each 2xx is a session of its own, and gets an ACK
/// of its own with its tag and a branch of its own (RFC 3261 section
/// 13.2.2.4). The attempt lists both while it runs, and ends complete.
#[tokio::test]
async fn two_forks_on_the_wire_get_an_ack_each() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    let attempt =
        ua.handle.try_invite(plan_to(&to, "forks")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "bob", &contact), from).await;
    let (bob, _) = peer.recv_starting("ACK").await;
    peer.send(&answer(&request, "200", "carol", &contact), from).await;
    let (carol, _) = peer.recv_starting("ACK").await;
    let snapshot =
        ua.handle.attempt_snapshot(&attempt).await.unwrap().unwrap();

    assert!(header(&bob, "To")[0].ends_with(";tag=bob"));
    assert!(header(&carol, "To")[0].ends_with(";tag=carol"));
    assert_ne!(branch(&bob), branch(&carol));
    assert_eq!(header(&bob, "CSeq"), header(&carol, "CSeq"));
    assert_eq!(snapshot.sessions.len(), 2);
    let ending = ending(&mut ua.events).await;
    assert_eq!(ending.confirmed, snapshot.sessions);
    assert_eq!(ending.sessions, snapshot.sessions);
    assert_eq!(ending.result, AttemptResult::Answered);
    assert!(ending.complete && !ending.degraded);
}

/// A fork beyond the attempt's limit gets its ACK and then a BYE, the
/// request after the INVITE in its dialog (RFC 3261 sections 13.2.2.4 and
/// 15.1.1), and is no session. A copy of its 2xx that comes after the BYE
/// still gets the ACK, the same one, and no second BYE. The attempt ends
/// incomplete, since it could not report that fork.
#[tokio::test]
async fn bye_then_retransmitted_2xx_still_gets_ack() {
    let (mut ua, _, _) = start_fast_with(config().max_forks(1));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    ua.handle.try_invite(plan_to(&to, "beyond")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "kept", &contact), from).await;
    peer.recv_starting("ACK").await;
    let ended = answer(&request, "200", "ended", &contact);
    peer.send(&ended, from).await;
    let (ack, _) = peer.recv_starting("ACK").await;
    let (bye, bye_from) = peer.recv_starting("BYE").await;
    peer.send(&ok_to(&bye), bye_from).await;
    peer.send(&ended, from).await;
    let (again, _) = peer.recv_starting("ACK").await;
    peer.quiet("BYE", Duration::from_millis(300)).await;

    assert!(header(&ack, "To")[0].ends_with(";tag=ended"));
    assert_eq!(again, ack);
    assert_eq!(header(&bye, "To"), header(&ack, "To"));
    assert_eq!(header(&bye, "Call-ID"), header(&request, "Call-ID"));
    let number: u32 = header(&request, "CSeq")[0]
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(header(&bye, "CSeq"), [format!("{} BYE", number + 1)]);
    assert!(bye.starts_with(&format!("BYE {contact} ")));
    let ending = ending(&mut ua.events).await;
    assert_eq!(ending.confirmed.len(), 1);
    assert_eq!(ending.result, AttemptResult::Answered);
    assert!(!ending.complete && !ending.degraded);
}

/// A flood of forks stays within the limits. One fork is a session and
/// one is acknowledged and ended, and the third gets nothing, which the
/// attempt reports as degraded at its end.
#[tokio::test]
async fn a_fork_flood_on_the_wire_stays_within_its_limits() {
    let (mut ua, _, _) =
        start_fast_with(config().max_forks(1).max_cleanups(1));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    ua.handle.try_invite(plan_to(&to, "flood")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    for tag in ["first", "second", "third"] {
        peer.send(&answer(&request, "200", tag, &contact), from).await;
    }
    let mut tags = Vec::new();
    let _ = timeout(Duration::from_millis(500), async {
        loop {
            let (message, at) = peer.recv().await;
            if message.starts_with("ACK") {
                tags.push(header(&message, "To")[0].to_owned());
            } else if message.starts_with("BYE") {
                peer.send(&ok_to(&message), at).await;
            }
        }
    })
    .await;

    assert_eq!(tags.len(), 2, "{tags:?}");
    assert!(tags.iter().all(|to| !to.ends_with(";tag=third")));
    let ending = ending(&mut ua.events).await;
    assert_eq!(ending.confirmed.len(), 1);
    assert!(!ending.complete && ending.degraded);
}

/// The notifications of a fork can be lost to a full event queue, and the
/// attempt can end before the application asks for its snapshot. Its end,
/// which is never dropped, still lists every session it formed, so none is
/// lost to the application.
#[tokio::test]
async fn forks_whose_notifications_were_lost_are_listed_at_the_end() {
    let config = config().event_capacity(1).max_attempts(1);
    let (mut ua, _, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    ua.handle.try_invite(plan_to(&to, "lost")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    for tag in ["first", "second"] {
        peer.send(&answer(&request, "200", tag, &contact), from).await;
        peer.recv_starting("ACK").await;
    }
    // Timer M, 64 T1 after the first 2xx, ends the attempt meanwhile.
    tokio::time::sleep(Duration::from_millis(1600)).await;

    let ending = ending(&mut ua.events).await;
    assert!(ending.confirmed.len() < 2, "a notification was dropped");
    assert_eq!(ending.sessions.len(), 2);
    for session in &ending.sessions {
        let snapshot = ua.handle.snapshot(session).await.unwrap();
        assert!(snapshot.is_some(), "{session:?} is still up");
    }
}

/// With a strict router first and a loose one after it, the INVITE goes to
/// the strict router, whose URI is its Request-URI. The top Route value is
/// then the loose router, but RFC 3261 section 8.1.2 picks the hop from the
/// route set, not from what is left in Route.
#[tokio::test]
async fn a_strict_first_proxy_gets_the_invite() {
    let (ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let strict = Peer::new().await;
    let loose = Peer::new().await;
    let callee = Peer::new().await;
    let strict_uri = format!("sip:{}", strict.address());
    let plan = plan_to(&callee.address().to_string(), "strict")
        .route(strict_uri.parse().unwrap())
        .route(format!("sip:{};lr", loose.address()).parse().unwrap());

    ua.handle.try_invite(plan).unwrap().await.unwrap();
    let (request, _) = strict.recv_starting("INVITE").await;

    assert!(request.starts_with(&format!("INVITE {strict_uri} SIP/2.0")));
    loose.quiet("INVITE", Duration::from_millis(200)).await;
    callee.quiet("INVITE", Duration::from_millis(1)).await;
}

/// A SIPS target behind a strict router with a SIP URI still needs TLS on
/// the way (RFC 3261 section 26.2.2), though strict routing leaves a SIP
/// Request-URI. With no TLS, the INVITE does not go out.
#[tokio::test]
async fn a_sips_target_behind_a_strict_router_is_not_sent() {
    let (ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let strict = Peer::new().await;
    let plan = InvitePlan::new(
        format!("sips:peer@{}", strict.address()).parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
        sdp(),
    )
    .route(format!("sip:{}", strict.address()).parse().unwrap());

    let result = ua.handle.try_invite(plan).unwrap().await;

    assert_eq!(result.unwrap_err(), Error::Unroutable);
    strict.quiet("INVITE", Duration::from_millis(200)).await;
}

/// A response of the peer to `request`, with `tag` on its To unless it has
/// one, and nothing else.
fn reply_with(request: &str, status: u16, tag: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(status)
        .to_tag(tag)
        .body(Bytes::new());
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

/// The CANCEL of the INVITE [`invite_over`] made for `call` (RFC 3261
/// section 9.1): its Request-URI, top Via, From, To, Call-ID and CSeq
/// number.
fn cancel_of(transport: &str, peer: SocketAddr, call: &str) -> String {
    format!(
        "CANCEL sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 CANCEL
Content-Length: 0

"
    )
}

/// A request of the peer in the dialog its INVITE `call` formed with the
/// 2xx `ok`, numbered `cseq`.
fn in_dialog(
    method: &str,
    transport: &str,
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
) -> String {
    format!(
        "{method} sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{method}-{call}-{cseq}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} {method}
Content-Length: 0

",
        to = header(ok, "To")[0],
    )
}

/// Receives events until `pick` takes one.
async fn event<T>(
    events: &mut UaEvents,
    mut pick: impl FnMut(Event) -> Option<T>,
) -> T {
    loop {
        let next = timeout(WAIT, events.recv()).await.unwrap().unwrap();
        if let Some(found) = pick(next) {
            return found;
        }
    }
}

/// The caller cancels an INVITE the application has not decided. The
/// CANCEL gets a 200 with the To tag the INVITE's 487 carries (RFC 3261
/// section 9.2), the application is told, and its accept after that sends
/// nothing. A CANCEL that matches no INVITE gets a 481.
#[tokio::test]
async fn an_incoming_cancel_gets_a_200_and_its_invite_a_487() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "cancelled"), udp).await;
    let invite = invite(&mut ua.events).await;
    let id = invite.id();
    peer.send(&cancel_of("UDP", peer.address(), "cancelled"), udp).await;

    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ok, "CSeq"), ["1 CANCEL"]);
    let (terminated, _) = peer.recv_starting("SIP/2.0 487").await;
    assert_eq!(header(&terminated, "CSeq"), ["1 INVITE"]);
    assert_eq!(header(&ok, "To"), header(&terminated, "To"));
    let cancelled = event(&mut ua.events, |event| match event {
        Event::Cancelled { invite, .. } => Some(invite),
        _ => None,
    })
    .await;
    assert_eq!(cancelled, id);
    let late = invite.try_accept(sdp()).unwrap().await.unwrap_err();
    assert!(matches!(late, Error::AlreadyFinalized | Error::StaleDecision));
    peer.quiet("SIP/2.0 200", Duration::from_millis(200)).await;

    peer.send(&cancel_of("UDP", peer.address(), "unknown"), udp).await;
    let (unknown, _) = peer.recv_starting("SIP/2.0 481").await;
    assert_eq!(header(&unknown, "Call-ID"), ["unknown"]);
    assert!(header(&unknown, "To")[0].contains(";tag="));
}

/// A CANCEL asked for before any provisional response waits in the
/// endpoint until one comes (RFC 3261 section 9.1). Then it goes, its own
/// transaction, and the INVITE ends with the peer's 487.
#[tokio::test]
async fn cancel_before_provisional_is_deferred_by_core() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let attempt =
        ua.handle.try_invite(plan_to(&to, "early")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let cancelled = ua.handle.try_cancel(&attempt).unwrap();
    peer.quiet("CANCEL", Duration::from_millis(200)).await;

    peer.send(&reply_with(&request, 180, "callee"), from).await;
    let (cancel, cancel_from) = peer.recv_starting("CANCEL").await;
    assert_eq!(branch(&cancel), branch(&request));
    assert_eq!(header(&cancel, "Call-ID"), header(&request, "Call-ID"));
    let number = header(&request, "CSeq")[0].replace("INVITE", "CANCEL");
    assert_eq!(header(&cancel, "CSeq"), [number]);
    peer.send(&reply_with(&cancel, 200, "callee"), cancel_from).await;
    peer.send(&reply_with(&request, 487, "callee"), from).await;

    assert_eq!(cancelled.await.unwrap(), CancelResult::Sent);
    let terminated = StatusCode::from_u16(487).unwrap();
    assert_eq!(
        attempt_end(&mut ua.events).await,
        (AttemptResult::Failed(Error::RemoteFailure(terminated)), true),
    );
}

/// The 200 to a CANCEL ends nothing (RFC 3261 section 9.1, RFC 5407
/// section 3.1.2). A 2xx to the INVITE that wins the race forms a session,
/// which gets its ACK and stays up, since only giving the attempt up ends
/// the sessions it formed.
#[tokio::test]
async fn cancel_200_does_not_imply_invite_terminated() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let attempt =
        ua.handle.try_invite(plan_to(&to, "race")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&reply_with(&request, 180, "callee"), from).await;
    let cancelled = ua.handle.try_cancel(&attempt).unwrap();
    let (cancel, cancel_from) = peer.recv_starting("CANCEL").await;
    peer.send(
        &answer(&request, "200", "callee", &format!("sip:peer@{to}")),
        from,
    )
    .await;
    peer.send(&reply_with(&cancel, 200, "callee"), cancel_from).await;

    peer.recv_starting("ACK").await;
    assert_eq!(cancelled.await.unwrap(), CancelResult::Sent);
    let session = event(&mut ua.events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    peer.quiet("BYE", Duration::from_millis(200)).await;
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);
}

/// A 481 to the CANCEL is a failure of the CANCEL alone, and says nothing
/// about the INVITE, whose final response is what counts (RFC 5407 section
/// 3.1.2). The session the INVITE's 2xx confirmed stays up.
#[tokio::test]
async fn cancel_481_does_not_terminate_confirmed_usage() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let attempt =
        ua.handle.try_invite(plan_to(&to, "lost")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&reply_with(&request, 180, "callee"), from).await;
    let cancelled = ua.handle.try_cancel(&attempt).unwrap();
    let (cancel, cancel_from) = peer.recv_starting("CANCEL").await;
    peer.send(
        &answer(&request, "200", "callee", &format!("sip:peer@{to}")),
        from,
    )
    .await;
    peer.recv_starting("ACK").await;
    peer.send(&reply_with(&cancel, 481, "callee"), cancel_from).await;

    assert_eq!(cancelled.await.unwrap(), CancelResult::Sent);
    let session = event(&mut ua.events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    peer.quiet("BYE", Duration::from_millis(300)).await;
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);
    assert_eq!(snapshot.end_reason, None);
}

/// Giving an attempt up sends its CANCEL, and a 2xx that crosses it gets
/// its ACK and then a BYE (RFC 3261 section 15). No session forms.
#[tokio::test]
async fn a_2xx_after_giving_up_gets_its_ack_and_a_bye() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    let attempt =
        ua.handle.try_invite(plan_to(&to, "given")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&reply_with(&request, 180, "callee"), from).await;
    ua.handle.try_abandon(&attempt).unwrap().await.unwrap();
    let (cancel, cancel_from) = peer.recv_starting("CANCEL").await;
    peer.send(&reply_with(&cancel, 200, "callee"), cancel_from).await;
    peer.send(&answer(&request, "200", "callee", &contact), from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    let (bye, bye_from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&bye, 200, "callee"), bye_from).await;
    assert_eq!(header(&bye, "To"), header(&ack, "To"));
    let ending = ending(&mut ua.events).await;
    assert!(ending.confirmed.is_empty());
    assert!(ending.sessions.is_empty());
    assert_eq!(ending.result, AttemptResult::Answered);
}

/// The flow a request arrived on reaches the application: that of an
/// INVITE through [`IncomingInvite::flow`], and that of the BYE that ends
/// its session in the reason the session ended. Over UDP and TCP, the BYE
/// gets a 200 (RFC 3261 section 15.1.2).
#[tokio::test]
async fn incoming_requests_report_their_flow() {
    let (mut ua, udp, tcp) = start_fast();
    tokio::spawn(ua.driver);
    let transport = signa_core::transport::Transport::Udp;

    let peer = Peer::new().await;
    peer.send(&invite_to_ua(peer.address(), "flow-udp"), udp).await;
    let incoming = invite(&mut ua.events).await;
    let flow = incoming.flow();
    assert_eq!(flow.transport, transport);
    assert_eq!((flow.local, flow.remote), (udp, peer.address()));
    let session = incoming.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, peer.address(), "flow-udp", 1), udp).await;
    let bye = in_dialog("BYE", "UDP", &ok, peer.address(), "flow-udp", 2);
    peer.send(&bye, udp).await;

    let (bye_ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&bye_ok, "CSeq"), ["2 BYE"]);
    let (ended, reason) = event(&mut ua.events, |event| match event {
        Event::Ended { session, reason, .. } => Some((session, reason)),
        _ => None,
    })
    .await;
    assert_eq!(ended, session);
    let EndReason::RemoteBye { flow, .. } = reason else {
        panic!("not ended by the peer: {reason:?}");
    };
    assert_eq!((flow.local, flow.remote), (udp, peer.address()));

    let mut peer = TcpPeer::connect(tcp).await;
    let address = peer.address();
    peer.send(&invite_over("TCP", address, "flow-tcp")).await;
    let incoming = invite(&mut ua.events).await;
    let flow = incoming.flow();
    assert_eq!(flow.transport, signa_core::transport::Transport::Tcp);
    assert_eq!((flow.local, flow.remote), (tcp, address));
    incoming.try_accept(sdp()).unwrap().await.unwrap();
    let ok = peer.recv_starting("SIP/2.0 200").await;
    let ack = ack_for(&ok, address, "flow-tcp", 1).replace("UDP", "TCP");
    peer.send(&ack).await;
    peer.send(&in_dialog("BYE", "TCP", &ok, address, "flow-tcp", 2)).await;
    let bye_ok = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&bye_ok, "CSeq"), ["2 BYE"]);
}

/// A UA with its own endpoint on loopback, whose Contact names its address,
/// so that another UA's requests in the dialog reach it.
fn ua_on(transport: &str) -> (Ua, SocketAddr) {
    let (endpoint, incoming, address) = bound(transport);
    let contact = format!("sip:ua@{address};transport={transport}");
    let config = Config::new(&contact).unwrap().timers(fast());
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// An endpoint on `transport` with [`fast`] timers, and its address.
fn bound(transport: &str) -> (Endpoint, Incoming, SocketAddr) {
    let local = "127.0.0.1:0".parse().unwrap();
    let builder = Endpoint::builder().timers(fast());
    let builder = if transport == "tcp" {
        builder.tcp(local)
    } else {
        builder.udp(local)
    };
    let (endpoint, incoming) = builder.bind().unwrap();
    let address = if transport == "tcp" {
        endpoint.tcp_addr().unwrap()
    } else {
        endpoint.udp_addr().unwrap()
    };
    (endpoint, incoming, address)
}

/// Two UAs make a call, over UDP and over TCP. The caller's INVITE is
/// accepted and acknowledged, and each side then ends a call with a BYE:
/// the caller the first, the callee the second. The side that gets the
/// BYE answers it with a 200 and reports its peer's end, and the side that
/// sent it reports its own, then the 200 as the operation's outcome.
#[tokio::test]
async fn two_uas_call_and_hang_up_over_udp_and_tcp() {
    for transport in ["udp", "tcp"] {
        let (Ua { handle: caller, events: mut caller_events, driver }, _) =
            ua_on(transport);
        tokio::spawn(driver);
        let (
            Ua { handle: callee, events: mut callee_events, driver },
            address,
        ) = ua_on(transport);
        tokio::spawn(driver);

        for hangs_up in ["caller", "callee"] {
            let plan = InvitePlan::new(
                format!("sip:ua@{address};transport={transport}")
                    .parse()
                    .unwrap(),
                "sip:caller@127.0.0.1".parse().unwrap(),
                sdp(),
            );
            caller.try_invite(plan).unwrap().await.unwrap();
            let incoming = invite(&mut callee_events).await;
            let answered = incoming.try_accept(sdp()).unwrap().await.unwrap();
            let calling = event(&mut caller_events, |event| match event {
                Event::Confirmed { session, .. } => Some(session),
                _ => None,
            })
            .await;
            // The ACK lets the callee's BYE go, so it waits for the 2xx's
            // retransmissions to stop.
            let deadline = Duration::from_millis(100);
            tokio::time::sleep(deadline).await;

            let (hanging, hung, ending, other) = if hangs_up == "caller" {
                (&caller, &mut callee_events, calling, answered)
            } else {
                (&callee, &mut caller_events, answered, calling)
            };
            let bye = hanging.try_terminate(&ending).unwrap();
            assert_eq!(bye.await, Ok(()), "{transport} {hangs_up}");
            let (ended, reason) = event(hung, |event| match event {
                Event::Ended { session, reason, .. } => {
                    Some((session, reason))
                }
                _ => None,
            })
            .await;
            assert_eq!(ended, other, "{transport} {hangs_up}");
            assert!(matches!(reason, EndReason::RemoteBye { .. }));
            let snapshot = hanging.snapshot(&ending).await.unwrap().unwrap();
            assert_eq!(snapshot.end_reason, Some(EndReason::LocalBye));
        }
    }
}

/// Each UA numbers its sessions and attempts from the same start, so the
/// handles of one would name the other's if a UA took them. A UA refuses
/// the handles of another, before anything is admitted, and nothing goes
/// on the wire for its own session either.
#[tokio::test]
async fn handles_of_another_ua_are_refused() {
    let (Ua { handle: caller, events: mut caller_events, driver }, _) =
        ua_on("udp");
    tokio::spawn(driver);
    let (Ua { handle: callee, events: mut callee_events, driver }, address) =
        ua_on("udp");
    tokio::spawn(driver);
    let plan = InvitePlan::new(
        format!("sip:ua@{address}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
        sdp(),
    );

    let attempt = caller.try_invite(plan).unwrap().await.unwrap();
    let answered = invite(&mut callee_events)
        .await
        .try_accept(sdp())
        .unwrap()
        .await
        .unwrap();
    let calling = event(&mut caller_events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;

    let refused = callee.try_terminate(&calling).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);
    assert_eq!(
        callee.try_cancel(&attempt).unwrap_err().error(),
        Error::InvalidInput
    );
    assert_eq!(
        callee.try_abandon(&attempt).unwrap_err().error(),
        Error::InvalidInput
    );
    assert_eq!(callee.snapshot(&calling).await, Err(Error::InvalidInput));
    assert_eq!(
        callee.attempt_snapshot(&attempt).await,
        Err(Error::InvalidInput)
    );
    assert_ne!(calling.id(), answered.id());

    tokio::time::sleep(Duration::from_millis(100)).await;
    for (handle, session) in [(&caller, &calling), (&callee, &answered)] {
        let snapshot = handle.snapshot(session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established);
    }
}

/// A BYE that requires an extension gets a 420 that lists it (RFC 3261
/// section 8.2.2.3, which section 15.1.2 applies to BYE), and ends nothing.
/// So does an OPTIONS outside a dialog. The same BYE without Require then
/// ends the session.
#[tokio::test]
async fn a_bye_that_requires_an_extension_gets_a_420() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    peer.send(&direct_invite(peer.address(), "required"), udp).await;
    let session =
        invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, peer.address(), "required", 1), udp).await;
    let bye = in_dialog("BYE", "UDP", &ok, peer.address(), "required", 2);
    let options =
        in_dialog("OPTIONS", "UDP", &ok, peer.address(), "options", 1)
            .replace(
                &format!(
                    ";tag={}",
                    header(&ok, "To")[0].rsplit("tag=").next().unwrap()
                ),
                "",
            );
    let require = "Max-Forwards: 70\r\nRequire: x-feature\r\n";

    peer.send(&bye.replace("Max-Forwards: 70\n", require), udp).await;
    let (bad, _) = peer.recv_starting("SIP/2.0 420").await;
    assert_eq!(header(&bad, "Unsupported"), ["x-feature"]);
    assert_eq!(header(&bad, "CSeq"), ["2 BYE"]);
    peer.send(&options.replace("Max-Forwards: 70\n", require), udp).await;
    let (bad, _) = peer.recv_starting("SIP/2.0 420").await;
    assert_eq!(header(&bad, "CSeq"), ["1 OPTIONS"]);
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);

    peer.send(
        &bye.replace("-required-2", "-required-3").replace("2 BYE", "3 BYE"),
        udp,
    )
    .await;
    let (ended, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ended, "CSeq"), ["3 BYE"]);
}

/// A BYE that arrives while every job is taken changes nothing: its
/// session stays up, and signa-core answers it with a 500. Once there is
/// room, the next BYE ends the session and gets its 200 (RFC 3261 section
/// 15.1.2), never a 500 for a session that ended.
#[tokio::test]
async fn a_bye_without_room_for_its_answer_changes_nothing() {
    let peer = Peer::new().await;
    let hosts = Hosts::new(peer.address());
    let gate = hosts.gate.clone();
    let config = config()
        .resolver(hosts)
        .max_jobs(1)
        .resolve_timeout(Duration::from_secs(1));
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    peer.send(&direct_invite(peer.address(), "busy"), udp).await;
    let session =
        invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, peer.address(), "busy", 1), udp).await;
    peer.drain(Duration::from_millis(100)).await;

    // One INVITE holds the only job while its next hop resolves, and the
    // other waits in the backlog, which is then full.
    let _held =
        ua.handle.try_invite(plan_to("gated.invalid", "held")).unwrap();
    let _waiting =
        ua.handle.try_invite(plan_to("gated.invalid", "waiting")).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bye = in_dialog("BYE", "UDP", &ok, peer.address(), "busy", 2);
    peer.send(&bye, udp).await;

    let (failed, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&failed, "CSeq"), ["2 BYE"]);
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);

    gate.notify_waiters();
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.notify_waiters();
    let again = bye.replace("-busy-2", "-busy-3").replace("2 BYE", "3 BYE");
    peer.send(&again, udp).await;
    let (ended, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ended, "CSeq"), ["3 BYE"]);
    let reason = event(&mut ua.events, |event| match event {
        Event::Ended { reason, .. } => Some(reason),
        _ => None,
    })
    .await;
    assert!(matches!(reason, EndReason::RemoteBye { .. }));
}

/// A stand-in for an SDP component, which an application plugs in as its
/// [`Negotiate`] without signa-ua depending on it. It answers each `m=` line
/// of an offer with the same media on a port of its own, or on port 0 when
/// the UA is to end the dialog, which rejects the stream (RFC 3264 section
/// 6). It has no answer for an offer that does not start with `v=0`, and
/// never answers one whose session name is `hang`, as a component that
/// hangs.
#[derive(Clone, Default)]
struct Sdp {
    calls: Arc<AtomicUsize>,
}

impl Negotiate for Sdp {
    fn answer(
        &self,
        offer: &Offer,
    ) -> impl Future<Output = Option<Description>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let text = String::from_utf8(offer.description().body().to_vec());
        let port = if offer.session().is_some() { 49170 } else { 0 };

        async move {
            let text = text.ok().filter(|text| text.starts_with("v=0"))?;
            if text.contains("s=hang") {
                std::future::pending::<()>().await;
            }
            let mut answer = String::from(
                "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\n\
                 c=IN IP4 127.0.0.1\r\nt=0 0\r\n",
            );
            for line in text.lines().filter(|line| line.starts_with("m=")) {
                let mut fields = line[2..].splitn(3, ' ');
                let (media, _, rest) =
                    (fields.next()?, fields.next()?, fields.next()?);
                answer.push_str(&format!("m={media} {port} {rest}\r\n"));
            }
            Some(Description::new(
                HeaderValue::from_static("application/sdp"),
                Bytes::from(answer),
            ))
        }
    }
}

/// An SDP offer whose session name is `name`.
fn offer_named(name: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns={name}\r\n\
         c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
    )
}

fn described(text: &str) -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from(text.to_owned()),
    )
}

/// The 2xx of the peer to an INVITE it received as `request`, carrying
/// `body` as an SDP offer, as one without an offer gets it.
fn ok_offering(request: &str, tag: &str, contact: &str, body: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(StatusCode::OK)
        .to_tag(tag)
        .header("Contact", format!("<{contact}>").as_str())
        .header("Content-Type", "application/sdp")
        .body(Bytes::from(body.to_owned()));
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

/// The body of a message, after its head.
fn body(message: &str) -> &str {
    message.split_once("\r\n\r\n").unwrap().1
}

/// A UA with the [`Sdp`] stand-in as its negotiator, on UDP with
/// [`fast`] timers, and the stand-in's count of calls.
fn negotiating(answer_timeout: Duration) -> (Ua, SocketAddr, Sdp) {
    negotiating_with(answer_timeout, 64)
}

/// [`negotiating`] with at most `answers` prepared at once.
fn negotiating_with(
    answer_timeout: Duration,
    answers: usize,
) -> (Ua, SocketAddr, Sdp) {
    let (endpoint, incoming, address) = bound("udp");
    let sdp = Sdp::default();
    let config = Config::new(&format!("sip:ua@{address}"))
        .unwrap()
        .timers(fast())
        .negotiator(sdp.clone())
        .max_answers(answers)
        .answer_timeout(answer_timeout);
    (attach(endpoint, incoming, config).unwrap(), address, sdp)
}

/// A UA without a [`Negotiate`] refuses a plan without an offer, and hands
/// it back, since it could only answer the 2xx's offer with an empty ACK.
#[tokio::test]
async fn a_plan_without_an_offer_needs_a_negotiator() {
    let (ua, _, _) = start_fast();
    let plan = InvitePlan::without_offer(
        "sip:peer@127.0.0.1".parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
    );

    let refused = ua.handle.try_invite(plan).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);
}

/// An INVITE sent without an offer gets the offer in its 2xx, and the ACK
/// carries the answer the negotiator prepared (RFC 3261 section 13.2.1). A
/// copy of the 2xx gets the very same ACK, and the negotiator is not asked
/// again.
#[tokio::test]
async fn offerless_invite_offer_in_2xx_answer_in_ack() {
    let (mut ua, _, sdp) = negotiating(WAIT);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let plan = InvitePlan::without_offer(
        format!("sip:peer@{to}").parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
    );

    ua.handle.try_invite(plan).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    assert!(header(&request, "Content-Type").is_empty());
    assert_eq!(body(&request), "");
    let (contact, offer) = (format!("sip:peer@{to}"), offer_named("call"));
    let ok = ok_offering(&request, "late", &contact, &offer);
    peer.send(&ok, from).await;
    let (ack, _) = peer.recv_starting("ACK").await;
    peer.send(&ok, from).await;
    let (again, _) = peer.recv_starting("ACK").await;

    assert_eq!(header(&ack, "Content-Type"), ["application/sdp"]);
    assert!(body(&ack).contains("m=audio 49170 RTP/AVP 0"));
    assert_eq!(again, ack);
    assert_eq!(sdp.calls.load(Ordering::SeqCst), 1);
    let session = event(&mut ua.events, |event| match event {
        Event::Negotiated { session, .. } => Some(session),
        _ => None,
    })
    .await;
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.negotiation, NegotiationState::Settled);
    assert_eq!(snapshot.remote_description, Some(described(&offer)));
}

/// Two UAs make a call with a late offer: the caller sends no offer, the
/// callee's application accepts with one, and the caller's negotiator puts
/// the answer in the ACK. Both sides report the exchange complete, and the
/// callee's session has the answer.
#[tokio::test]
async fn two_uas_negotiate_a_late_offer() {
    let (Ua { handle: caller, events: mut caller_events, driver }, _, _) =
        negotiating(WAIT);
    tokio::spawn(driver);
    let (Ua { handle: callee, events: mut callee_events, driver }, address) =
        ua_on("udp");
    tokio::spawn(driver);
    let plan = InvitePlan::without_offer(
        format!("sip:ua@{address}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
    );

    caller.try_invite(plan).unwrap().await.unwrap();
    let incoming = invite(&mut callee_events).await;
    assert_eq!(incoming.offer(), None);
    let answered = incoming
        .try_accept(described(&offer_named("callee")))
        .unwrap()
        .await
        .unwrap();

    let settled = event(&mut callee_events, |event| match event {
        Event::Negotiated { session, .. } => Some(session),
        _ => None,
    })
    .await;
    assert_eq!(settled, answered);
    event(&mut caller_events, |event| match event {
        Event::Negotiated { .. } => Some(()),
        _ => None,
    })
    .await;
    let snapshot = callee.snapshot(&answered).await.unwrap().unwrap();
    assert_eq!(snapshot.negotiation, NegotiationState::Settled);
    let answer = snapshot.remote_description.unwrap();
    assert!(String::from_utf8_lossy(answer.body()).contains("m=audio 49170"));
}

/// A negotiator that never answers holds up only the ACK that waits for its
/// answer. Another call's ACK and a CANCEL go meanwhile. At the answer
/// timeout the waiting ACK goes without an answer, to stop the 2xx's
/// retransmissions, a BYE ends the session, and the attempt reports itself
/// degraded.
#[tokio::test]
async fn provider_timeout_does_not_block_unrelated_ack_or_cancel() {
    let (mut ua, _, _) = negotiating(Duration::from_millis(500));
    tokio::spawn(ua.driver);
    let (hung, other, cancelled) =
        (Peer::new().await, Peer::new().await, Peer::new().await);
    let late = InvitePlan::without_offer(
        format!("sip:peer@{}", hung.address()).parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
    );

    let attempt = ua.handle.try_invite(late).unwrap().await.unwrap();
    let (request, from) = hung.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{}", hung.address());
    let ok = ok_offering(&request, "hung", &contact, &offer_named("hang"));
    hung.send(&ok, from).await;
    hung.quiet("ACK", Duration::from_millis(100)).await;

    let to = other.address().to_string();
    ua.handle.try_invite(plan_to(&to, "other")).unwrap().await.unwrap();
    let (request, from) = other.recv_starting("INVITE").await;
    let ok_other = answer(&request, "200", "other", &format!("sip:peer@{to}"));
    other.send(&ok_other, from).await;
    let (ack, _) = other.recv_starting("ACK").await;
    assert_eq!(header(&ack, "Call-ID"), header(&request, "Call-ID"));

    let to = cancelled.address().to_string();
    let ringing = ua.handle.try_invite(plan_to(&to, "ring")).unwrap().await;
    let ringing = ringing.unwrap();
    let (request, from) = cancelled.recv_starting("INVITE").await;
    cancelled.send(&reply_with(&request, 180, "ring"), from).await;
    let cancel = ua.handle.try_cancel(&ringing).unwrap();
    assert_eq!(cancel.await, Ok(CancelResult::Sent));
    cancelled.recv_starting("CANCEL").await;

    let (unanswered, _) = hung.recv_starting("ACK").await;
    assert!(header(&unanswered, "Content-Type").is_empty());
    assert_eq!(body(&unanswered), "");
    let (bye, _) = hung.recv_starting("BYE").await;
    assert_eq!(header(&bye, "Call-ID"), header(&unanswered, "Call-ID"));
    let failed = event(&mut ua.events, |event| match event {
        Event::NegotiationFailed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    let state = ua.handle.attempt_snapshot(&attempt).await.unwrap().unwrap();
    assert!(state.degraded);
    let snapshot = ua.handle.snapshot(&failed).await.unwrap().unwrap();
    assert_eq!(snapshot.end_reason, Some(EndReason::NegotiationFailed));
}

/// The ACK of the peer for the 2xx `ok` to its INVITE `call`, carrying
/// `answer` as its body.
fn ack_with(ok: &str, peer: SocketAddr, call: &str, answer: &str) -> String {
    ack_for(ok, peer, call, 1).replace(
        "Content-Length: 0\n",
        &format!(
            "Content-Type: application/sdp\nContent-Length: {}\n",
            answer.len()
        ),
    ) + answer
}

/// An INVITE without an offer reaches the application, whose 2xx carries
/// the offer. The ACK brings the answer, which completes the exchange, and
/// the session keeps it. An ACK without the answer still stops the 2xx's
/// retransmissions, but fails the exchange, and the UA ends the session with
/// a BYE.
#[tokio::test]
async fn an_offerless_invite_gets_its_answer_in_the_ack() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    // Without a Record-Route, so that the BYE goes straight to the peer.
    let offerless = |call: &str| {
        direct_invite(peer.address(), call).replace(
            "Content-Type: application/sdp\nContent-Length: 5\n\nv=0\n",
            "Content-Length: 0\n\n",
        )
    };
    let mine = described(&offer_named("ua"));

    for call in ["answered", "unanswered"] {
        peer.send(&offerless(call), udp).await;
        let incoming = invite(&mut ua.events).await;
        assert_eq!(incoming.offer(), None);
        let session =
            incoming.try_accept(mine.clone()).unwrap().await.unwrap();
        let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Content-Type"), ["application/sdp"]);
        assert_eq!(body(&ok), offer_named("ua"));

        let theirs = "v=0\r\ns=peer\r\n";
        let ack = if call == "answered" {
            ack_with(&ok, peer.address(), call, theirs)
        } else {
            ack_for(&ok, peer.address(), call, 1)
        };
        peer.send(&ack, udp).await;

        if call == "answered" {
            let settled = event(&mut ua.events, |event| match event {
                Event::Negotiated { session, .. } => Some(session),
                _ => None,
            })
            .await;
            assert_eq!(settled, session);
            let snapshot = ua.handle.snapshot(&session).await.unwrap();
            let snapshot = snapshot.unwrap();
            assert_eq!(snapshot.remote_description, Some(described(theirs)));
            assert_eq!(snapshot.phase, SessionPhase::Established);
        } else {
            let failed = event(&mut ua.events, |event| match event {
                Event::NegotiationFailed { session, .. } => Some(session),
                _ => None,
            })
            .await;
            assert_eq!(failed, session);
            let (bye, _) = peer.recv_starting("BYE").await;
            assert_eq!(header(&bye, "Call-ID"), [call]);
            let reason = event(&mut ua.events, |event| match event {
                Event::Ended { reason, .. } => Some(reason),
                _ => None,
            })
            .await;
            assert_eq!(reason, EndReason::NegotiationFailed);
        }
        peer.quiet("SIP/2.0 200", Duration::from_millis(100)).await;
    }
}

/// A provisional response previews the answer, as for early media, and
/// carries it. The 2xx has to carry the same answer, so an accept with
/// another is handed back, and one with the preview goes.
#[tokio::test]
async fn a_provisional_previews_the_answer() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let progress = StatusCode::from_u16(183).unwrap();
    let preview = described("v=0\r\ns=preview\r\n");

    peer.send(&invite_to_ua(peer.address(), "preview"), udp).await;
    let mut incoming = invite(&mut ua.events).await;
    assert_eq!(incoming.offer(), Some(&sdp()));
    let sent = incoming.try_provisional_with(progress, preview.clone());
    assert_eq!(sent.unwrap().await, Ok(()));
    let (early, _) = peer.recv_starting("SIP/2.0 183").await;
    assert_eq!(body(&early), "v=0\r\ns=preview\r\n");

    let refused = incoming.try_accept(sdp()).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);
    let (incoming, _) = refused.into_inner();
    incoming.try_accept(preview).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(body(&ok), body(&early));
    assert_eq!(header(&ok, "To"), header(&early, "To"));
}

/// The answer timeout counts from the 2xx, also for an offer that waits for
/// a free job. With one job and three offers whose answers never come, each
/// ACK goes, without an answer, about one timeout after its 2xx, rather than
/// one timeout after the offer ahead of it gave up.
#[tokio::test]
async fn answers_waiting_for_a_job_are_due_from_their_2xx() {
    let timeout_after = Duration::from_millis(300);
    let (ua, _, _) = negotiating_with(timeout_after, 1);
    tokio::spawn(ua.driver);
    let peers = [Peer::new().await, Peer::new().await, Peer::new().await];

    let mut oks = Vec::new();
    for peer in &peers {
        let plan = InvitePlan::without_offer(
            format!("sip:peer@{}", peer.address()).parse().unwrap(),
            "sip:ua@127.0.0.1".parse().unwrap(),
        );
        ua.handle.try_invite(plan).unwrap().await.unwrap();
        let (request, from) = peer.recv_starting("INVITE").await;
        let contact = format!("sip:peer@{}", peer.address());
        oks.push((
            ok_offering(&request, "hung", &contact, &offer_named("hang")),
            from,
        ));
    }
    let start = tokio::time::Instant::now();
    for (peer, (ok, from)) in peers.iter().zip(&oks) {
        peer.send(ok, *from).await;
    }

    for peer in &peers {
        let (ack, _) = peer.recv_starting("ACK").await;
        assert_eq!(body(&ack), "");
    }
    // Three timeouts one after the other would take 900 ms.
    assert!(start.elapsed() < timeout_after * 2, "{:?}", start.elapsed());
}

/// Receives events until a re-INVITE comes.
async fn reinvite(events: &mut UaEvents) -> IncomingInvite {
    event(events, |event| match event {
        Event::Reinvite(invite) => Some(invite),
        _ => None,
    })
    .await
}

/// A re-INVITE of the peer in the dialog its INVITE `call` formed with the
/// 2xx `ok`, numbered `cseq`, with `contact` as its Contact and `offer` as
/// its SDP offer. `branch` names its transaction.
fn reinvite_of(
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
    contact: SocketAddr,
    offer: &str,
) -> String {
    format!(
        "INVITE sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-reinvite-{call}-{cseq}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} INVITE
Contact: <sip:peer@{contact}>
Content-Type: application/sdp
Content-Length: {length}

{offer}",
        to = header(ok, "To")[0],
        length = offer.len(),
    )
}

/// The CANCEL of [`reinvite_of`] for the same `call` and `cseq`.
fn cancel_of_reinvite(
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
) -> String {
    format!(
        "CANCEL sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-reinvite-{call}-{cseq}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} CANCEL
Content-Length: 0

",
        to = header(ok, "To")[0],
    )
}

/// The ACK of the peer for the 2xx `ok`, numbered `cseq`, with `body` as
/// its body, which may be empty.
fn ack_numbered(
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
    body: &str,
) -> String {
    let content = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\n".to_owned()
    };
    format!(
        "ACK sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-ack-{call}-{cseq}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} ACK
{content}Content-Length: {length}

{body}",
        to = header(ok, "To")[0],
        length = body.len(),
    )
}

/// Has the peer call the UA without a proxy, the application accept, and
/// the peer acknowledge, and returns the UA's 2xx and the session.
async fn call_from(
    peer: &Peer,
    ua: SocketAddr,
    events: &mut UaEvents,
    call: &str,
) -> (String, Session) {
    peer.send(&direct_invite(peer.address(), call), ua).await;
    let session = invite(events).await.try_accept(sdp()).unwrap().await;
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, peer.address(), call, 1), ua).await;
    // The UA sends no re-INVITE of its own before the ACK is in (RFC 3261
    // section 14.1), and the 2xx stops once it is.
    peer.drain(Duration::from_millis(60)).await;
    (ok, session.unwrap())
}

impl Peer {
    /// Receives datagrams for up to `wait` until one starts with `start`.
    async fn recv_starting_within(
        &self,
        start: &str,
        wait: Duration,
    ) -> (String, SocketAddr) {
        let next = async {
            let mut buffer = vec![0; 65_536];
            loop {
                let (n, from) =
                    self.socket.recv_from(&mut buffer).await.unwrap();
                let message = String::from_utf8(buffer[..n].to_vec()).unwrap();
                if message.starts_with(start) {
                    return (message, from);
                }
            }
        };
        timeout(wait, next).await.expect("a datagram in time")
    }
}

/// The peer's re-INVITE asks the application, which accepts it. Its 2xx
/// replaces the remote target with the re-INVITE's Contact (RFC 6141
/// section 4.6), so the BYE goes there. A later re-INVITE the application
/// rejects with a 488 moves neither the target nor the session (RFC 3261
/// section 14.2).
#[tokio::test]
async fn a_reinvite_refreshes_the_target_at_its_2xx() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let moved = Peer::new().await;
    let elsewhere = Peer::new().await;
    let (ok, session) = call_from(&peer, udp, &mut ua.events, "moving").await;

    let offer = offer_named("moved");
    let request =
        reinvite_of(&ok, peer.address(), "moving", 2, moved.address(), &offer);
    peer.send(&request, udp).await;
    let incoming = reinvite(&mut ua.events).await;
    assert_eq!(incoming.session(), Some(&session));
    assert_eq!(incoming.offer(), Some(&described(&offer)));
    let before = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!((before.session_revision, before.target_revision), (1, 0));
    let answer = described(&offer_named("answer"));
    let accepted = incoming.try_accept(answer.clone()).unwrap().await;
    assert_eq!(accepted, Ok(session.clone()));
    let (reok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&reok, "CSeq"), ["2 INVITE"]);
    assert_eq!(body(&reok), offer_named("answer"));
    peer.send(&ack_numbered(&reok, peer.address(), "moving", 2, ""), udp)
        .await;

    let after = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(after.phase, SessionPhase::Established);
    assert_eq!((after.session_revision, after.target_revision), (2, 1));
    assert_eq!(after.remote_description, Some(described(&offer)));

    let request = reinvite_of(
        &ok,
        peer.address(),
        "moving",
        3,
        elsewhere.address(),
        &offer_named("video"),
    );
    peer.send(&request, udp).await;
    let incoming = reinvite(&mut ua.events).await;
    let rejected = StatusCode::from_u16(488).unwrap();
    incoming.try_reject(rejected).unwrap().await.unwrap();
    let (refusal, _) = peer.recv_starting("SIP/2.0 488").await;
    assert_eq!(header(&refusal, "CSeq"), ["3 INVITE"]);
    assert_eq!(ua.handle.snapshot(&session).await.unwrap().unwrap(), after);

    let bye = ua.handle.try_terminate(&session).unwrap();
    let (request, from) = moved.recv_starting("BYE").await;
    assert_eq!(header(&request, "CSeq").len(), 1);
    moved.send(&ok_to(&request), from).await;
    assert_eq!(bye.await, Ok(()));
    peer.quiet("BYE", Duration::from_millis(100)).await;
    elsewhere.quiet("BYE", Duration::from_millis(100)).await;
}

/// A re-INVITE that arrives before the application answered the last one
/// gets a 500 with a Retry-After of 0 to 10 seconds (RFC 3261 section
/// 14.2). A CANCEL of the pending one gets it a 487, and the session goes
/// on as it was.
#[tokio::test]
async fn an_overlapping_reinvite_gets_a_500_and_a_cancelled_one_a_487() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let (ok, session) = call_from(&peer, udp, &mut ua.events, "overlap").await;
    let me = peer.address();

    let offer = offer_named("first");
    peer.send(&reinvite_of(&ok, me, "overlap", 2, me, &offer), udp).await;
    let pending = reinvite(&mut ua.events).await;
    let offer = offer_named("second");
    peer.send(&reinvite_of(&ok, me, "overlap", 3, me, &offer), udp).await;
    let (refusal, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&refusal, "CSeq"), ["3 INVITE"]);
    let retry: u32 = header(&refusal, "Retry-After")[0].parse().unwrap();
    assert!(retry <= 10);

    peer.send(&cancel_of_reinvite(&ok, me, "overlap", 2), udp).await;
    let (cancelled, _) = peer.recv_starting("SIP/2.0 487").await;
    assert_eq!(header(&cancelled, "CSeq"), ["2 INVITE"]);
    assert_eq!(header(&cancelled, "To"), header(&ok, "To"));
    let late = pending.try_accept(sdp()).unwrap().await;
    assert!(
        matches!(late, Err(Error::AlreadyFinalized | Error::StaleDecision)),
        "{late:?}",
    );
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);
    assert_eq!(snapshot.session_revision, 1);
}

/// The UA's re-INVITE crosses the peer's. The peer's gets a 491, since the
/// UA's has no final yet (RFC 3261 section 14.2). The peer answers the UA's
/// with a 491 as well, and the UA, which took the call and so does not own
/// the Call-ID, tries once more within 2 seconds, with the next CSeq number
/// and a new branch (section 14.1). A 2xx to that completes the operation,
/// and the UA acknowledges it.
#[tokio::test]
async fn glare_on_the_wire_retries_with_a_new_transaction() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let (ok, session) = call_from(&peer, udp, &mut ua.events, "glare").await;
    let me = peer.address();

    let hold = described(&offer_named("hold"));
    let operation = ua
        .handle
        .try_reinvite(&session, ReinvitePlan::new(hold.clone()))
        .unwrap();
    let (first, from) = peer.recv_starting("INVITE").await;
    assert_eq!(body(&first), offer_named("hold"));
    let offer = offer_named("crossing");
    peer.send(&reinvite_of(&ok, me, "glare", 2, me, &offer), udp).await;
    let (pending, _) = peer.recv_starting("SIP/2.0 491").await;
    assert_eq!(header(&pending, "CSeq"), ["2 INVITE"]);

    let start = tokio::time::Instant::now();
    peer.send(&reply_with(&first, 491, "unused"), from).await;
    let (second, from) =
        peer.recv_starting_within("INVITE", Duration::from_secs(3)).await;
    assert!(start.elapsed() <= Duration::from_millis(2_300));
    let number = |request: &str| -> u32 {
        header(request, "CSeq")[0].split(' ').next().unwrap().parse().unwrap()
    };
    assert_eq!(number(&second), number(&first) + 1);
    assert_ne!(branch(&second), branch(&first));
    assert_eq!(body(&second), offer_named("hold"));

    let contact = format!("sip:peer@{me}");
    peer.send(&answer(&second, "200", "unused", &contact), from).await;
    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(header(&ack, "CSeq")[0], format!("{} ACK", number(&second)));
    assert_eq!(operation.await, Ok(()));
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.session_revision, 2);
}

/// Two UAs change a session with re-INVITEs over UDP and TCP. The caller's
/// re-INVITE is accepted, and both sessions move to their next revision.
/// The callee's own re-INVITE is then rejected with a 488, and both stay
/// as they were. The session goes on, and the caller ends it.
#[tokio::test]
async fn two_uas_renegotiate_over_udp_and_tcp() {
    for transport in ["udp", "tcp"] {
        let (Ua { handle: caller, events: mut caller_events, driver }, _) =
            ua_on(transport);
        tokio::spawn(driver);
        let (
            Ua { handle: callee, events: mut callee_events, driver },
            address,
        ) = ua_on(transport);
        tokio::spawn(driver);

        let plan = InvitePlan::new(
            format!("sip:ua@{address};transport={transport}").parse().unwrap(),
            "sip:caller@127.0.0.1".parse().unwrap(),
            sdp(),
        );
        caller.try_invite(plan).unwrap().await.unwrap();
        let answered = invite(&mut callee_events)
            .await
            .try_accept(sdp())
            .unwrap()
            .await
            .unwrap();
        let calling = event(&mut caller_events, |event| match event {
            Event::Confirmed { session, .. } => Some(session),
            _ => None,
        })
        .await;
        // The callee takes no re-INVITE of its own before the ACK.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let hold = described(&offer_named("hold"));
        let changing = caller
            .try_reinvite(&calling, ReinvitePlan::new(hold.clone()))
            .unwrap();
        let incoming = reinvite(&mut callee_events).await;
        assert_eq!(incoming.session(), Some(&answered), "{transport}");
        assert_eq!(incoming.offer(), Some(&hold));
        let held = described(&offer_named("held"));
        incoming.try_accept(held.clone()).unwrap().await.unwrap();
        assert_eq!(changing.await, Ok(()), "{transport}");
        let snapshot = caller.snapshot(&calling).await.unwrap().unwrap();
        assert_eq!(snapshot.remote_description, Some(held));
        assert_eq!(snapshot.session_revision, 2);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let snapshot = callee.snapshot(&answered).await.unwrap().unwrap();
        assert_eq!(snapshot.remote_description, Some(hold.clone()));
        assert_eq!(snapshot.session_revision, 2);

        let video = described(&offer_named("video"));
        let refused =
            callee.try_reinvite(&answered, ReinvitePlan::new(video)).unwrap();
        let incoming = reinvite(&mut caller_events).await;
        assert_eq!(incoming.session(), Some(&calling));
        let not_here = StatusCode::from_u16(488).unwrap();
        incoming.try_reject(not_here).unwrap().await.unwrap();
        assert_eq!(refused.await, Err(Error::RemoteFailure(not_here)));
        let snapshot = callee.snapshot(&answered).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established);
        assert_eq!(snapshot.remote_description, Some(hold));
        assert_eq!(snapshot.negotiation, NegotiationState::Settled);
        assert_eq!(snapshot.session_revision, 2);

        assert_eq!(caller.try_terminate(&calling).unwrap().await, Ok(()));
    }
}

/// A re-INVITE without an offer gets the peer's offer in the 2xx, and the
/// answer that the UA's negotiator prepares goes in the ACK (RFC 3261
/// section 13.2.1). A UA without a negotiator refuses such a plan.
#[tokio::test]
async fn a_reinvite_without_an_offer_answers_in_the_ack() {
    let (mut ua, udp, sdp_calls) = negotiating(WAIT);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let (_, session) = call_from(&peer, udp, &mut ua.events, "late").await;

    let operation = ua
        .handle
        .try_reinvite(&session, ReinvitePlan::without_offer())
        .unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    assert_eq!(body(&request), "");
    let contact = format!("sip:peer@{}", peer.address());
    let offer = offer_named("refresh");
    peer.send(&ok_offering(&request, "unused", &contact, &offer), from).await;
    let (ack, _) = peer.recv_starting("ACK").await;
    assert!(body(&ack).contains("m=audio 49170"), "{ack}");
    assert_eq!(operation.await, Ok(()));
    assert_eq!(sdp_calls.calls.load(Ordering::SeqCst), 1);
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.remote_description, Some(described(&offer)));
    assert_eq!(snapshot.session_revision, 2);

    let (Ua { handle, driver, .. }, _) = start(config());
    tokio::spawn(driver);
    let refused = handle.try_reinvite(&session, ReinvitePlan::without_offer());
    assert_eq!(refused.unwrap_err().error(), Error::InvalidInput);
}
