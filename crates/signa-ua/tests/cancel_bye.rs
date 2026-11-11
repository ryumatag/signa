/*!
CANCEL and BYE in either direction (RFC 3261 sections 9 and 15), and the
races of RFC 5407 between them and the INVITE: a 2xx that crosses a CANCEL,
which ends neither the INVITE nor its session (section 3.1.2), a BYE that
crosses a 2xx or its ACK (sections 3.1.3, 3.1.6 and 3.2.4), and two BYEs
that cross (section 3.2.1).
*/

use std::time::Duration;

use signa_core::StatusCode;
use signa_ua::{
    AttemptResult, CancelResult, EndReason, Error, Event, InvitePlan,
    SessionPhase, Ua,
};

use crate::support::{
    events::{attempt_end, event, events_for, invite},
    message::{
        ack_answering, ack_for, answer, branch, cancel_of, direct_invite,
        header, in_dialog, invite_over, invite_to_ua, offerless_invite, ok_to,
        plan_to, reinvite_of, reply_with, sdp,
    },
    peer::{Peer, Raw, TcpPeer},
    start_fast, ua_on,
};

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
/// the sessions it formed. Over UDP and TCP.
#[tokio::test]
async fn cancel_200_does_not_imply_invite_terminated() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let contact = format!("sip:peer@{}", peer.address());

        let plan = plan_to(&peer.target(), "race");
        let attempt = ua.handle.try_invite(plan).unwrap().await.unwrap();
        let request = peer.recv_starting("INVITE").await;
        peer.send(&reply_with(&request, 180, "callee")).await;
        let cancelled = ua.handle.try_cancel(&attempt).unwrap();
        let cancel = peer.recv_starting("CANCEL").await;
        peer.send(&answer(&request, "200", "callee", &contact)).await;
        peer.send(&reply_with(&cancel, 200, "callee")).await;

        peer.recv_starting("ACK").await;
        assert_eq!(cancelled.await.unwrap(), CancelResult::Sent);
        let session = event(&mut ua.events, |event| match event {
            Event::Confirmed { session, .. } => Some(session),
            _ => None,
        })
        .await;
        peer.quiet("BYE", Duration::from_millis(200)).await;
        let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established, "{transport}");
        driver.abort();
    }
}

/// The callee's side of the same race (RFC 5407 section 3.1.2). A CANCEL
/// that arrives after the UA's 2xx still matches the INVITE's transaction,
/// so it gets a 200 with the 2xx's To tag, and it changes nothing (RFC 3261
/// section 9.2). No 487 follows, and the ACK makes the session as it would
/// without the CANCEL. Over UDP and TCP.
#[tokio::test]
async fn a_cancel_that_crosses_the_2xx_cancels_nothing() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let me = peer.address();

        peer.send(&direct_invite(me, "crossed")).await;
        let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        peer.send(&cancel_of("UDP", me, "crossed")).await;
        let cancelled = peer.recv_answer("SIP/2.0 200", "1 CANCEL").await;
        peer.send(&ack_for(&ok, me, "crossed", 1)).await;
        let session = accepted.await.unwrap();

        assert_eq!(header(&cancelled, "To"), header(&ok, "To"), "{transport}");
        peer.quiet("SIP/2.0 487", Duration::from_millis(200)).await;
        let seen = events_for(&mut ua.events, Duration::from_millis(50)).await;
        assert!(
            !seen.iter().any(|event| matches!(event, Event::Cancelled { .. })),
            "{transport}: {seen:?}",
        );
        let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established, "{transport}");
        driver.abort();
    }
}

/// The peer hangs up while the UA's 2xx still waits for its ACK, as when
/// the ACK is lost (RFC 5407 section 3.1.6), or when the caller sent the
/// BYE in the early dialog and it arrives after the 2xx (section 3.1.3).
/// The BYE gets a 200 and ends the session once. The ACK that comes after
/// it stops the copies of the 2xx and forms nothing, so no BYE of the UA's
/// follows. Over UDP and TCP.
#[tokio::test]
async fn a_bye_before_the_ack_ends_the_session_once() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let me = peer.address();

        peer.send(&direct_invite(me, "unacked")).await;
        let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        peer.send(&in_dialog("BYE", "UDP", &ok, me, "unacked", 2)).await;
        peer.recv_answer("SIP/2.0 200", "2 BYE").await;
        let session = accepted.await.unwrap();
        peer.send(&ack_for(&ok, me, "unacked", 1)).await;

        // A copy of the 2xx may still be on its way, and later ones would
        // come at most T2 (80 ms) apart.
        peer.drain(Duration::from_millis(50)).await;
        let copy_or_bye = |message: &str| {
            message.starts_with("BYE")
                || (message.starts_with("SIP/2.0 200")
                    && header(message, "CSeq") == ["1 INVITE"])
        };
        peer.quiet_where(copy_or_bye, Duration::from_millis(300)).await;
        let seen = events_for(&mut ua.events, Duration::from_millis(50)).await;
        let ends = seen
            .iter()
            .filter(|event| matches!(event, Event::Ended { .. }))
            .count();
        assert_eq!(ends, 1, "{transport}: {seen:?}");
        let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Ended, "{transport}");
        assert!(
            matches!(snapshot.end_reason, Some(EndReason::RemoteBye { .. })),
            "{transport}: {snapshot:?}",
        );
        driver.abort();
    }
}

/// The callee hangs up before the ACK of its 2xx, whose offer the ACK
/// answers. RFC 5407 section 3.2.4 has the ACK and the BYE cross then. The
/// UA avoids the race instead: it holds the BYE until the ACK, which a
/// callee waits for (RFC 3261 section 15), and the session shows as ending
/// meanwhile. The BYE goes once the ACK is in, and ends the session. Over
/// UDP and TCP.
#[tokio::test]
async fn the_callees_bye_waits_for_the_ack() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let me = peer.address();

        peer.send(&offerless_invite(me, "hangup")).await;
        let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        let session = accepted.await.unwrap();
        let ending = ua.handle.try_terminate(&session).unwrap();
        // Well past T2, and well before the ACK deadline of 64 T1 (1.28 s).
        peer.quiet("BYE", Duration::from_millis(300)).await;
        let waiting = ua.handle.snapshot(&session).await.unwrap().unwrap();
        peer.send(&ack_answering(&ok, me, "hangup", 1)).await;
        let bye = peer.recv_starting("BYE").await;
        peer.send(&ok_to(&bye)).await;

        assert_eq!(waiting.phase, SessionPhase::Ending, "{transport}");
        assert_eq!(ending.await, Ok(()), "{transport}");
        let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Ended, "{transport}");
        driver.abort();
    }
}

/// Both sides hang up at once (RFC 5407 section 3.2.1). Once the UA's BYE
/// is out, its dialog is Mortal: the peer's BYE gets a 200 and ends nothing
/// twice, and the peer's re-INVITE a 481 (section 3.2.2). The 200 to the
/// UA's BYE completes its operation. Over UDP and TCP.
#[tokio::test]
async fn crossed_byes_end_the_session_once() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let me = peer.address();

        peer.send(&direct_invite(me, "both")).await;
        let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        peer.send(&ack_for(&ok, me, "both", 1)).await;
        let session = accepted.await.unwrap();
        let ending = ua.handle.try_terminate(&session).unwrap();
        let bye = peer.recv_starting("BYE").await;
        peer.send(&in_dialog("BYE", "UDP", &ok, me, "both", 2)).await;
        let crossed = peer.recv_final("2 BYE").await;
        peer.send(&reinvite_of(&ok, me, "both", 3, me, "v=0\r\n")).await;
        let refused = peer.recv_final("3 INVITE").await;
        peer.send(&ok_to(&bye)).await;

        assert!(crossed.starts_with("SIP/2.0 200"), "{transport}: {crossed}");
        assert!(refused.starts_with("SIP/2.0 481"), "{transport}: {refused}");
        assert_eq!(ending.await, Ok(()), "{transport}");
        let seen =
            events_for(&mut ua.events, Duration::from_millis(100)).await;
        let ends = seen
            .iter()
            .filter(|event| matches!(event, Event::Ended { .. }))
            .count();
        assert_eq!(ends, 1, "{transport}: {seen:?}");
        assert!(
            !seen.iter().any(|event| matches!(event, Event::Reinvite(_))),
            "{transport}: {seen:?}",
        );
        driver.abort();
    }
}

/// The caller sends a BYE in the early dialog of one callee (RFC 5407
/// appendix A). A 2xx of that callee that crossed the BYE gets its ACK and
/// a BYE of its own, numbered after the first (section 3.1.3), and a 2xx of
/// another callee still forms a session, which stays up. Over UDP and TCP.
#[tokio::test]
async fn an_early_bye_leaves_the_other_forks() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let contact = format!("sip:peer@{}", peer.address());

        let plan = plan_to(&peer.target(), "early");
        ua.handle.try_invite(plan).unwrap().await.unwrap();
        let request = peer.recv_starting("INVITE").await;
        peer.send(&answer(&request, "180", "bob", &contact)).await;
        let early = event(&mut ua.events, |event| match event {
            Event::Early { session, .. } => Some(session),
            _ => None,
        })
        .await;
        let ending = ua.handle.try_terminate(&early).unwrap();
        let first = peer.recv_starting("BYE").await;
        peer.send(&answer(&request, "200", "bob", &contact)).await;
        let ack = peer.recv_starting("ACK").await;
        // Over UDP the first BYE goes again until its 200.
        let second = peer
            .recv_where(|message| {
                message.starts_with("BYE") && branch(message) != branch(&first)
            })
            .await;
        peer.send(&ok_to(&first)).await;
        peer.send(&ok_to(&second)).await;
        peer.send(&answer(&request, "200", "carol", &contact)).await;
        let carol = event(&mut ua.events, |event| match event {
            Event::Confirmed { session, .. } => Some(session),
            _ => None,
        })
        .await;
        let carols_ack = peer
            .recv_where(|message| {
                message.starts_with("ACK")
                    && header(message, "To")[0].ends_with(";tag=carol")
            })
            .await;

        let number = |request: &str| -> u32 {
            let cseq = header(request, "CSeq")[0];
            cseq.split(' ').next().unwrap().parse().unwrap()
        };
        let tag =
            |message: &str| header(message, "To")[0].ends_with(";tag=bob");
        assert!(tag(&first) && tag(&ack) && tag(&second), "{transport}");
        assert_eq!(number(&second), number(&first) + 1, "{transport}");
        assert_eq!(ending.await, Ok(()), "{transport}");
        assert_eq!(number(&carols_ack), number(&request), "{transport}");
        let byes = [branch(&first).to_owned(), branch(&second).to_owned()];
        let another_bye = |message: &str| {
            message.starts_with("BYE")
                && !byes.iter().any(|known| known == branch(message))
        };
        peer.quiet_where(another_bye, Duration::from_millis(200)).await;
        let snapshot = ua.handle.snapshot(&carol).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established, "{transport}");
        driver.abort();
    }
}

/// The caller hangs up in the early dialog of an INVITE the application has
/// not decided (RFC 5407 section 3.1.3, appendix A). The BYE gets a 200
/// and the INVITE a 487 (RFC 3261 section 15.1.2), and an accept after that
/// sends nothing. Over UDP and TCP.
#[tokio::test]
async fn the_peers_early_bye_ends_its_invite() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp) = start_fast();
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let me = peer.address();

        peer.send(&direct_invite(me, "ringing")).await;
        let incoming = invite(&mut ua.events).await;
        let ringing = StatusCode::from_u16(180).unwrap();
        incoming.try_provisional(ringing).unwrap().await.unwrap();
        let early = peer.recv_answer("SIP/2.0 180", "1 INVITE").await;
        peer.send(&in_dialog("BYE", "UDP", &early, me, "ringing", 2)).await;
        let bye = peer.recv_final("2 BYE").await;
        let terminated = peer.recv_final("1 INVITE").await;
        let late = incoming.try_accept(sdp()).unwrap().await;

        assert!(bye.starts_with("SIP/2.0 200"), "{transport}: {bye}");
        assert!(terminated.starts_with("SIP/2.0 487"), "{transport}");
        assert_eq!(
            header(&terminated, "To"),
            header(&early, "To"),
            "{transport}"
        );
        assert!(
            matches!(
                late,
                Err(Error::AlreadyFinalized | Error::StaleDecision)
            ),
            "{transport}: {late:?}",
        );
        let accepted = |message: &str| {
            message.starts_with("SIP/2.0 200")
                && header(message, "CSeq") == ["1 INVITE"]
        };
        peer.quiet_where(accepted, Duration::from_millis(200)).await;
        driver.abort();
    }
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
