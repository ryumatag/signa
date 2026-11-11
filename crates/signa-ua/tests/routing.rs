/*!
Where the UA's requests go: the transport for a request near the UDP limit
(RFC 3261 section 18.1.1), the hop a strict router in the route set makes
(section 8.1.2), and a SIPS target that needs TLS on the way (section
26.2.2).
*/

use std::time::Duration;

use bytes::Bytes;
use signa_core::HeaderValue;
use signa_ua::{Description, Error, InvitePlan};
use tokio::{net::TcpListener, time::timeout};

use crate::support::{
    WAIT,
    message::{header, plan_to, sdp},
    peer::{Peer, TcpPeer},
    start_fast,
};

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
