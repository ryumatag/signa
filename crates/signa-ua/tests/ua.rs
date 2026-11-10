/*!
The UA's runtime through its public API, against raw UDP peers.

Each test drives a UA attached to a loopback endpoint and plays the other
side by hand, so that what goes on the wire is what the test checks.
*/

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, Response, StatusCode,
    endpoint::{Endpoint, Incoming, Reception, Target},
    message::header::CALL_ID,
};
use signa_ua::{
    AttachError, Config, Error, Event, Query, Resolve, ResolveError,
    StaticResolver, Ua, UaEvents, attach,
};
use tokio::{net::UdpSocket, sync::Notify, time::timeout};

const WAIT: Duration = Duration::from_secs(2);

fn bind() -> (Endpoint, Incoming) {
    Endpoint::builder().udp("127.0.0.1:0".parse().unwrap()).bind().unwrap()
}

fn config() -> Config {
    Config::new("sip:ua@127.0.0.1").unwrap()
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
}

fn invite_to_ua(peer: SocketAddr, call: &str) -> String {
    format!(
        "INVITE sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-{call}
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

/// An INVITE from the UA to `to`, with an offer.
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
fn answer(request: &str, status: &str, tag: &str, contact: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(StatusCode::from_bytes(status.as_bytes()).unwrap())
        .to_tag(tag)
        .header("Contact", format!("<{contact}>").as_str())
        .body(Bytes::new())
        .unwrap();
    String::from_utf8(response.to_bytes().to_vec()).unwrap()
}

fn header<'a>(message: &'a str, name: &str) -> Vec<&'a str> {
    message
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
        .collect()
}

async fn invite(events: &mut UaEvents) -> signa_ua::IncomingInvite {
    loop {
        match timeout(WAIT, events.recv()).await.unwrap().unwrap() {
            Event::Invite(invite) => return invite,
            _ => continue,
        }
    }
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
    drop(invite.try_accept().unwrap());

    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert!(header(&ok, "To")[0].contains(";tag="));
    assert_eq!(header(&ok, "Contact"), ["<sip:ua@127.0.0.1>"]);
    assert_eq!(header(&ok, "Record-Route"), ["<sip:proxy.example.com;lr>"]);
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
    let _ = invite.try_accept().unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.quiet("SIP/2.0 500", Duration::from_millis(300)).await;

    // So does the attempt handle, and the events with it.
    let _ = ua
        .handle
        .try_invite(invite_from_ua(&peer.address().to_string(), "drop-uac"))
        .unwrap()
        .await
        .unwrap();
    drop(ua.events);

    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{}", peer.address());
    peer.send(&answer(&request, "200", "peer", &contact), from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(header(&ack, "CSeq"), ["1 ACK"]);
    assert_eq!(header(&ack, "Call-ID"), ["drop-uac"]);
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
        ua.handle
            .try_invite(invite_from_ua(&to, call))
            .unwrap()
            .await
            .unwrap();
    }
    let (first, from) = peer.recv_starting("INVITE").await;
    let (second, _) = peer.recv_starting("INVITE").await;
    let (slow, fast) = if header(&first, "Call-ID") == ["slow"] {
        (first, second)
    } else {
        (second, first)
    };

    peer.send(&answer(&slow, "200", "s", "sip:peer@slow.invalid"), from).await;
    peer.send(&answer(&fast, "200", "f", &format!("sip:peer@{to}")), from)
        .await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(header(&ack, "Call-ID"), ["fast"]);
}

/// With a command queue of one and the driver not yet running, a second
/// INVITE is refused and handed back. Nothing goes out for it, then or later.
#[tokio::test]
async fn command_queue_full_returns_busy_without_state_mutation() {
    let (ua, _) = start(config().command_capacity(1));
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let first = ua.handle.try_invite(invite_from_ua(&to, "first")).unwrap();
    let refused =
        ua.handle.try_invite(invite_from_ua(&to, "second")).unwrap_err();

    assert_eq!(refused.error(), Error::Busy);
    let returned = refused.into_inner();
    assert_eq!(returned.headers().get(CALL_ID).unwrap(), "second");

    tokio::spawn(ua.driver);
    first.await.unwrap();
    let (request, _) = peer.recv_starting("INVITE").await;
    assert_eq!(header(&request, "Call-ID"), ["first"]);
    peer.quiet("INVITE", Duration::from_millis(300)).await;
}

/// The application does not read events, and the queue of one overflows.
/// Operations still deliver their outcomes, and the queue reports the loss.
#[tokio::test]
async fn terminal_outcome_survives_notification_overflow() {
    let (mut ua, _) = start(config().event_capacity(1));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    ua.handle.try_invite(invite_from_ua(&to, "fills")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "p", &format!("sip:peer@{to}")), from)
        .await;
    peer.recv_starting("ACK").await;

    let attempt =
        ua.handle.try_invite(invite_from_ua(&to, "after")).unwrap().await;
    assert!(attempt.is_ok());

    let session = match ua.events.recv().await.unwrap() {
        Event::Confirmed { session, .. } => session,
        other => panic!("expected the confirmation, got {other:?}"),
    };
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, signa_ua::SessionPhase::Established);

    // The next notification that fits is preceded by the count of those
    // that did not.
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

    let pending = ua.handle.try_invite(invite_from_ua(&to, "stuck")).unwrap();
    tokio::task::yield_now().await;
    driver.abort();

    assert_eq!(
        timeout(WAIT, pending).await.unwrap().unwrap_err(),
        Error::DriverStopped
    );
    let refused =
        ua.handle.try_invite(invite_from_ua(&to, "late")).unwrap_err();
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

    refused.into_inner().try_accept().unwrap().await.unwrap();
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

    let hung = ua.handle.try_invite(invite_from_ua("slow.invalid", "hung"));
    peer.send(&invite_to_ua(peer.address(), "behind"), address).await;
    let invite = invite(&mut ua.events).await;
    let accepted = invite.try_accept().unwrap();

    assert_eq!(
        timeout(WAIT, hung.unwrap()).await.unwrap().unwrap_err(),
        Error::Unroutable,
    );
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ok, "Call-ID"), ["behind"]);
    timeout(WAIT, accepted).await.unwrap().unwrap();
}
