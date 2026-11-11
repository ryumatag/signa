/*!
CANCEL and BYE in either direction (RFC 3261 sections 9 and 15), and a 2xx
that crosses a CANCEL, which ends neither the INVITE nor its session (RFC
3261 section 9.1, RFC 5407 section 3.1.2).
*/

use std::time::Duration;

use signa_core::StatusCode;
use signa_ua::{
    AttemptResult, CancelResult, EndReason, Error, Event, InvitePlan,
    SessionPhase, Ua,
};

use crate::support::{
    events::{attempt_end, event, invite},
    message::{
        ack_for, answer, branch, cancel_of, direct_invite, header, in_dialog,
        invite_over, invite_to_ua, plan_to, reply_with, sdp,
    },
    peer::{Peer, TcpPeer},
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
