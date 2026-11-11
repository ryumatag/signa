/*!
What comes back to an INVITE of the UA's: the ACK of a 2xx, which the UA
builds from the dialog (RFC 3261 section 13.2.2.4), the ACK of another final,
which is the endpoint's, and the failures an attempt ends with.
*/

use std::time::Duration;

use signa_core::{StatusCode, endpoint::Endpoint};
use signa_ua::{AttemptResult, Error, attach};

use crate::{
    support::{
        config,
        events::attempt_end,
        fast,
        message::{answer, branch, header, plan_to, reply_with},
        peer::Peer,
        stand_in::Hosts,
        start_fast, start_fast_with,
    },
    uac::ending,
};

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
