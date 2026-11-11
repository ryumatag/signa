/*!
re-INVITEs in either direction (RFC 3261 section 14): the remote target a 2xx
refreshes (RFC 6141 section 4.6), re-INVITEs that overlap or cross (RFC 3261
section 14.2), and one without an offer.
*/

use std::{net::SocketAddr, sync::atomic::Ordering, time::Duration};

use signa_core::StatusCode;
use signa_ua::{
    Error, Event, InvitePlan, NegotiationState, ReinvitePlan, SessionPhase, Ua,
};

use crate::support::{
    WAIT, call_from, config,
    events::{event, invite, reinvite},
    message::{
        answer, body, branch, described, header, offer_named, ok_offering,
        ok_to, reinvite_of, reply_with, sdp,
    },
    negotiating,
    peer::Peer,
    start, start_fast, ua_on,
};

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
