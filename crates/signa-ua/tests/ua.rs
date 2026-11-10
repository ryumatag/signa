/*!
The UA's runtime through its public API, against raw UDP and TCP peers.

Each test drives a UA attached to a loopback endpoint and plays the other
side by hand, so that what goes on the wire is what the test checks.
*/

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use signa_core::{
    HeaderValue, Request, Response, StatusCode,
    endpoint::{Endpoint, Incoming, Reception, Target},
    message::header::SUBJECT,
    transaction::Timers,
};
use signa_ua::{
    AttachError, AttemptResult, Config, Description, Error, Event, InvitePlan,
    Query, Resolve, ResolveError, StaticResolver, Ua, UaEvents, attach,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
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
fn start_fast_with(config: Config) -> (Ua, SocketAddr, SocketAddr) {
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
Content-Length: 4

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
    assert_eq!(header(&ok, "Allow"), ["INVITE, ACK"]);
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
    assert_eq!(
        header(&ack, "To"),
        [format!("<sip:peer@{}>;tag=peer", peer.address())]
    );
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

/// The application does not read events, and the queue of two overflows.
/// The end of the attempt still gets through, since its place was set aside
/// when the INVITE went out, and the queue reports the loss before the next
/// notification that fits.
#[tokio::test]
async fn terminal_outcome_survives_notification_overflow() {
    let (mut ua, _, _) = start_fast_with(config().event_capacity(2));
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
        Event::AttemptEnded { attempt: ended, result, complete } => {
            assert_eq!(ended, attempt.id());
            assert_eq!(result, AttemptResult::Answered);
            assert!(complete);
        }
        other => panic!("expected the end of the attempt, got {other:?}"),
    }

    ua.handle.try_invite(plan_to(&to, "after")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "q", &format!("sip:peer@{to}")), from)
        .await;
    peer.recv_starting("ACK").await;
    match timeout(WAIT, ua.events.recv()).await.unwrap().unwrap() {
        Event::Lagged { missed } => assert!(missed >= 1),
        other => panic!("expected the loss to be reported, got {other:?}"),
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
/// with `DriverStopped`, the handle takes nothing more, and the endpoint
/// shuts down with it.
#[tokio::test]
async fn driver_drop_is_forced_stop_not_graceful_shutdown() {
    let (endpoint, incoming) = bind();
    let gate = Arc::new(Notify::new());
    let ua = attach(endpoint.clone(), incoming, config().resolver(Gate(gate)))
        .unwrap();
    let driver = tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let pending = ua.handle.try_invite(plan_to(&to, "stuck")).unwrap();
    tokio::task::yield_now().await;
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

/// An ACK with another CSeq is not the 2xx's, and the copies go on. The
/// ACK that matches stops them.
#[tokio::test]
async fn matching_ack_stops_retransmission_unrelated_ack_does_not() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "ack"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;

    peer.send(&ack_for(&ok, peer.address(), "ack", 2), udp).await;
    peer.recv_starting("SIP/2.0 200").await;
    peer.recv_starting("SIP/2.0 200").await;

    peer.send(&ack_for(&ok, peer.address(), "ack", 1), udp).await;
    peer.drain(Duration::from_millis(50)).await;
    // Neither a copy of the 200 nor any response to the ACKs.
    peer.quiet("SIP/2.0", Duration::from_millis(400)).await;
}

/// Without an ACK, the copies stop 64 T1 after the first 2xx, and the
/// session ends, with the reason before the end.
#[tokio::test]
async fn an_unacknowledged_2xx_ends_its_session() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "no-ack"), udp).await;
    let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
    let session = accepted.await.unwrap();

    let mut ends = Vec::new();
    while ends.len() < 2 {
        match timeout(WAIT, ua.events.recv()).await.unwrap().unwrap() {
            Event::AckTimeout { session: ended } => {
                ends.push(("timeout", ended))
            }
            Event::Ended { session: ended } => ends.push(("ended", ended)),
            _ => {}
        }
    }
    assert_eq!(
        ends,
        [("timeout", session.clone()), ("ended", session.clone())]
    );
    peer.drain(Duration::from_millis(50)).await;
    peer.quiet("SIP/2.0 200", Duration::from_millis(300)).await;
    assert_eq!(ua.handle.snapshot(&session).await.unwrap(), None);
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

/// An INVITE without an offer gets a 488 before the application sees it,
/// since this UA cannot check the answer its ACK would carry yet. One that
/// requires an extension gets a 420 that lists it as unsupported.
#[tokio::test]
async fn an_offerless_or_extended_invite_is_refused() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let offerless = invite_to_ua(peer.address(), "offerless").replace(
        "Content-Type: application/sdp\nContent-Length: 4\n\nv=0\n",
        "Content-Length: 0\n\n",
    );
    let extended = invite_to_ua(peer.address(), "extended").replace(
        "Max-Forwards: 70\n",
        "Max-Forwards: 70\nRequire: 100rel, timer\n",
    );

    peer.send(&offerless, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 488").await;
    assert_eq!(header(&refused, "Call-ID"), ["offerless"]);
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
