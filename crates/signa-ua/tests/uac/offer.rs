/*!
An INVITE of the UA's without an offer. Its 2xx brings the offer, and the
ACK the answer the application's negotiator prepares (RFC 3261 section
13.2.1), within the answer timeout.
*/

use std::{sync::atomic::Ordering, time::Duration};

use signa_ua::{
    CancelResult, EndReason, Error, Event, InvitePlan, NegotiationState, Ua,
};

use crate::support::{
    WAIT,
    events::{event, invite},
    message::{
        answer, body, described, header, offer_named, ok_offering, plan_to,
        reply_with,
    },
    negotiating, negotiating_with,
    peer::Peer,
    start_fast, ua_on,
};

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

/// An answer timeout too long to add to the clock sets no deadline, rather
/// than stop the driver, and the answer still goes in the ACK.
#[tokio::test]
async fn an_answer_timeout_past_the_clock_sets_no_deadline() {
    let (mut ua, _, _) = negotiating(Duration::MAX);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let plan = InvitePlan::without_offer(
        format!("sip:peer@{to}").parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
    );

    ua.handle.try_invite(plan).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{to}");
    let ok = ok_offering(&request, "late", &contact, &offer_named("call"));
    peer.send(&ok, from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert!(body(&ack).contains("m=audio 49170 RTP/AVP 0"));
    event(&mut ua.events, |event| match event {
        Event::Negotiated { .. } => Some(()),
        _ => None,
    })
    .await;
}
