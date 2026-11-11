/*!
Each limit of the configuration, and a flood of requests. The limits are
signa-ua policy. What does not fit gets a 503 (RFC 3261 section 21.5.4), and
an offer too large a 413 (section 21.4.11).
*/

use std::{net::SocketAddr, sync::Arc, time::Duration};

use signa_core::{StatusCode, endpoint::Endpoint};
use signa_ua::{
    AttemptResult, Config, EndReason, Error, Event, InvitePlan, ReinvitePlan,
    SessionPhase, Ua, attach,
};
use tokio::{sync::Notify, time::timeout};

use crate::support::{
    LOADED, WAIT, config,
    events::{attempt_end, event, invite, invite_within, reinvite_event},
    flood::{FLOODING, flood},
    message::{
        answer, cancel_of, header, in_dialog, invite_over, invite_to_ua,
        plan_to, reinvite_of, sdp,
    },
    peer::{Peer, Wire},
    stand_in::Slow,
    start, start_fast_with,
};

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

/// The INVITEs the UA and the application keep share a byte limit. One that
/// does not fit gets a 503, after the checks that give other statuses, and
/// room comes back once both let go of an INVITE.
#[tokio::test]
async fn invites_beyond_their_byte_limit_get_a_503() {
    let peer = Peer::new().await;
    // The endpoint adds `received` and `rport` to the top Via, which the
    // allowance per INVITE covers.
    let size = invite_to_ua(peer.address(), "bytes-0").len() + 64;
    let (mut ua, address) = start(config().max_invite_bytes(3 * size));
    tokio::spawn(ua.driver);
    let mut held = Vec::new();

    for call in ["bytes-0", "bytes-1", "bytes-2"] {
        peer.send(&invite_to_ua(peer.address(), call), address).await;
        held.push(invite(&mut ua.events).await);
    }
    peer.send(&invite_to_ua(peer.address(), "bytes-3"), address).await;
    let (busy, _) = peer.recv_starting("SIP/2.0 503").await;
    assert_eq!(header(&busy, "Call-ID"), ["bytes-3"]);
    assert!(!invite_within(&mut ua.events, Duration::from_millis(100)).await);

    let busy_here = StatusCode::from_u16(486).unwrap();
    held.pop().unwrap().try_reject(busy_here).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 486").await;
    peer.send(&invite_to_ua(peer.address(), "bytes-4"), address).await;
    let invite = invite(&mut ua.events).await;
    assert_eq!(invite.request().headers().get("Call-ID").unwrap(), "bytes-4");
}

/// An offer larger than the UA keeps of a session description gets a 413,
/// and the application never sees the INVITE.
#[tokio::test]
async fn an_offer_beyond_the_description_limit_gets_a_413() {
    let (mut ua, address) = start(config().max_description_bytes(4));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "large"), address).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 413").await;
    assert_eq!(header(&refused, "Call-ID"), ["large"]);
    assert!(header(&refused, "To")[0].contains(";tag="));
    assert!(!invite_within(&mut ua.events, Duration::from_millis(100)).await);
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

/// While a peer floods the UA with ACKs that match nothing and with new
/// INVITEs, and the INVITEs the application may hold undecided are all held,
/// the ACKs, the CANCEL and the BYE of another peer still get through, over
/// UDP and over TCP, and the UA's 2xx retransmissions still run. The new
/// INVITEs get a 503. Nothing here is a lane of its own. The UA takes each
/// message in turn and refuses new work quickly, and a peer that resends its
/// ACK for each copy of a 2xx gets it through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_queue_full_does_not_starve_ack_cancel_bye() {
    let _alone = FLOODING.lock().await;
    for transport in ["UDP", "TCP"] {
        let local = "127.0.0.1:0".parse().unwrap();
        let (endpoint, incoming) = Endpoint::builder()
            .udp(local)
            .tcp(local)
            .timers(*LOADED)
            .bind()
            .unwrap();
        let (udp, tcp) =
            (endpoint.udp_addr().unwrap(), endpoint.tcp_addr().unwrap());
        // Four jobs at once, which the answers to the flood fill.
        let config =
            config().timers(*LOADED).max_pending_invites(1).max_jobs(4);
        let mut ua = attach(endpoint, incoming, config).unwrap();
        let handle = ua.handle.clone();
        tokio::spawn(ua.driver);
        let mut peer = Wire::connect(transport, udp, tcp).await;
        let me = peer.address();

        // An initial INVITE and a re-INVITE, each accepted, whose 2xx
        // responses wait for their ACK.
        peer.send(&invite_over(transport, me, "callee")).await;
        let incoming = invite(&mut ua.events).await;
        let session = incoming.try_accept(sdp()).unwrap().await.unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        let reinvite = reinvite_of(&ok, me, "callee", 2, me, "v=0")
            .replace("SIP/2.0/UDP", &format!("SIP/2.0/{transport}"));
        peer.send(&reinvite).await;
        let accepting = reinvite_event(&mut ua.events).await.try_accept(sdp());
        accepting.unwrap().await.unwrap();
        let reok = peer.recv_answer("SIP/2.0 200", "2 INVITE").await;
        // An INVITE the application holds, which takes the only room for
        // an undecided one.
        peer.send(&invite_over(transport, me, "held")).await;
        let held = invite(&mut ua.events).await;

        let stop = Arc::new(Notify::new());
        let flooding = flood(transport, udp, tcp, stop.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A copy of each 2xx still goes out, and its ACK stops the copies
        // before the deadline of 64 T1 ends the session.
        peer.recv_answer("SIP/2.0 200", "2 INVITE").await;
        peer.acknowledge(&ok, "callee", 1).await;
        peer.acknowledge(&reok, "callee", 2).await;
        let snapshot = handle.snapshot(&session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established, "{transport}");

        // The 200 and the 487 go in jobs of their own, either first.
        let cancel = cancel_of(transport, me, "held");
        let (mut ok_to_cancel, mut terminated) = (false, false);
        while !(ok_to_cancel && terminated) {
            let answer = timeout(Duration::from_millis(100), async {
                if !ok_to_cancel {
                    peer.send(&cancel).await;
                }
                loop {
                    let message = match &mut peer {
                        Wire::Udp { peer, .. } => peer.recv().await.0,
                        Wire::Tcp(peer) => peer.recv().await,
                    };
                    match (
                        message.split(' ').nth(1),
                        header(&message, "CSeq")[..].first(),
                    ) {
                        (Some("200"), Some(&"1 CANCEL")) => return true,
                        (Some("487"), Some(&"1 INVITE")) => return false,
                        _ => {}
                    }
                }
            })
            .await;
            match answer {
                Ok(true) => ok_to_cancel = true,
                Ok(false) => terminated = true,
                Err(_) => {}
            }
        }

        let bye = in_dialog("BYE", transport, &ok, me, "callee", 3);
        peer.request(&bye, "SIP/2.0 200", "3 BYE").await;
        let snapshot = handle.snapshot(&session).await.unwrap().unwrap();
        assert!(
            matches!(snapshot.end_reason, Some(EndReason::RemoteBye { .. })),
            "{transport}: {snapshot:?}",
        );

        stop.notify_one();
        let sent = flooding.await.unwrap();
        assert!(sent > 200, "{transport}: only {sent} flooded");
        drop(held);
    }
}

/// A UA whose application reads no more events, flooded as in
/// [`ordinary_queue_full_does_not_starve_ack_cancel_bye`], still does what it
/// owes another UA, over UDP and over TCP: it sends an INVITE and its ACK, a
/// re-INVITE and its ACK, answers a CANCEL with a 200 and its INVITE with a
/// 487, and takes and sends a BYE. A re-INVITE of the other UA, which would
/// need the application, gets a 503 and leaves the session as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ua_that_stops_reading_events_still_answers_its_peer() {
    let _alone = FLOODING.lock().await;
    for transport in ["udp", "tcp"] {
        let loaded = |transport: &str| {
            let local = "127.0.0.1:0".parse().unwrap();
            let builder = Endpoint::builder().timers(*LOADED);
            let builder = if transport == "tcp" {
                builder.tcp(local)
            } else {
                builder.udp(local)
            };
            let (endpoint, incoming) = builder.bind().unwrap();
            let address =
                endpoint.tcp_addr().or_else(|| endpoint.udp_addr()).unwrap();
            let contact = format!("sip:ua@{address};transport={transport}");
            let config = Config::new(&contact).unwrap().timers(*LOADED);
            (endpoint, incoming, address, config)
        };
        let (endpoint, incoming, address, config) = loaded(transport);
        let config =
            config.event_capacity(1).max_pending_invites(1).max_jobs(4);
        let mut ua = attach(endpoint, incoming, config).unwrap();
        let handle = ua.handle.clone();
        tokio::spawn(ua.driver);
        let (endpoint, incoming, far_address, config) = loaded(transport);
        let Ua { handle: far, events: mut far_events, driver } =
            attach(endpoint, incoming, config).unwrap();
        tokio::spawn(driver);
        let plan_to = |address: SocketAddr| {
            InvitePlan::new(
                format!("sip:ua@{address};transport={transport}")
                    .parse()
                    .unwrap(),
                "sip:ua@127.0.0.1".parse().unwrap(),
                sdp(),
            )
        };

        // A session each way, and an INVITE of the far UA that the
        // application holds.
        far.try_invite(plan_to(address)).unwrap().await.unwrap();
        let answered = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
        let answered = answered.await.unwrap();
        let far_calling = event(&mut far_events, |event| match event {
            Event::Confirmed { attempt: Some(_), session, .. } => {
                Some(session)
            }
            _ => None,
        })
        .await;
        let attempt =
            handle.try_invite(plan_to(far_address)).unwrap().await.unwrap();
        let far_answered = invite(&mut far_events)
            .await
            .try_accept(sdp())
            .unwrap()
            .await
            .unwrap();
        // The event queue holds one event, so the session comes from the
        // attempt's snapshot rather than its notification.
        let calling = loop {
            let snapshot =
                handle.attempt_snapshot(&attempt).await.unwrap().unwrap();
            if let Some(session) = snapshot.sessions.first() {
                break session.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let held = far.try_invite(plan_to(address)).unwrap().await.unwrap();
        let undecided = invite(&mut ua.events).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // From here on the application reads no event.
        let stop = Arc::new(Notify::new());
        let wire = if transport == "udp" { "UDP" } else { "TCP" };
        let flooding = flood(wire, address, address, stop.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;

        let another =
            handle.try_invite(plan_to(far_address)).unwrap().await.unwrap();
        let far_another = invite(&mut far_events)
            .await
            .try_accept(sdp())
            .unwrap()
            .await
            .unwrap();
        let changing =
            handle.try_reinvite(&calling, ReinvitePlan::new(sdp())).unwrap();
        let accepting =
            reinvite_event(&mut far_events).await.try_accept(sdp());
        accepting.unwrap().await.unwrap();
        assert_eq!(changing.await, Ok(()), "{transport}");

        let refused = far.try_reinvite(&far_calling, ReinvitePlan::new(sdp()));
        let unavailable = StatusCode::from_u16(503).unwrap();
        assert_eq!(
            refused.unwrap().await,
            Err(Error::RemoteFailure(unavailable)),
            "{transport}",
        );

        far.try_cancel(&held).unwrap().await.unwrap();
        let (result, _) = attempt_end(&mut far_events).await;
        let terminated = StatusCode::from_u16(487).unwrap();
        assert_eq!(
            result,
            AttemptResult::Failed(Error::RemoteFailure(terminated))
        );

        assert_eq!(
            far.try_terminate(&far_calling).unwrap().await,
            Ok(()),
            "{transport}"
        );
        assert_eq!(
            handle.try_terminate(&calling).unwrap().await,
            Ok(()),
            "{transport}"
        );

        // The far UA got the ACK of the INVITE sent under the flood, or it
        // would have ended the session at its ACK deadline of 64 T1.
        tokio::time::sleep(LOADED.t1() * 70).await;
        let snapshot = far.snapshot(&far_another).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established, "{transport}");
        let snapshot = far.snapshot(&far_answered).await.unwrap().unwrap();
        assert_eq!(
            snapshot
                .end_reason
                .map(|reason| matches!(reason, EndReason::RemoteBye { .. })),
            Some(true)
        );

        stop.notify_one();
        let sent = flooding.await.unwrap();
        assert!(sent > 200, "{transport}: only {sent} flooded");
        drop((undecided, answered, another));
    }
}

/// A resolver that hangs holds up only the requests the UA sends, and each
/// of them fails with `Unroutable` once its resolution times out. Meanwhile,
/// with the one send the UA may run taken, a BYE gets its 200 and ends its
/// session, and a CANCEL gets its INVITE a 487, over UDP and over TCP.
/// Responses run apart from sends, so neither waits for the resolution.
#[tokio::test]
async fn bounded_control_budget_exhaustion_is_explicit() {
    for transport in ["UDP", "TCP"] {
        let config = config()
            .resolver(Slow)
            .max_jobs(1)
            .resolve_timeout(Duration::from_secs(3));
        let (mut ua, udp, tcp) = start_fast_with(config);
        tokio::spawn(ua.driver);
        let mut peer = Wire::connect(transport, udp, tcp).await;
        let me = peer.address();

        peer.send(&invite_over(transport, me, "callee")).await;
        let session =
            invite(&mut ua.events).await.try_accept(sdp()).unwrap().await;
        let session = session.unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        peer.acknowledge(&ok, "callee", 1).await;
        peer.send(&invite_over(transport, me, "held")).await;
        let held = invite(&mut ua.events).await;
        // Two INVITEs whose next hop never resolves. One runs, and one waits
        // for the only send.
        let hung = ua.handle.try_invite(plan_to("slow.invalid", "hung"));
        let waiting = ua.handle.try_invite(plan_to("slow.invalid", "waiting"));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let bye = in_dialog("BYE", transport, &ok, me, "callee", 2);
        timeout(
            Duration::from_secs(1),
            peer.request(&bye, "SIP/2.0 200", "2 BYE"),
        )
        .await
        .expect("the BYE's 200 while every send waits");
        let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
        assert!(
            matches!(snapshot.end_reason, Some(EndReason::RemoteBye { .. })),
            "{transport}: {snapshot:?}",
        );
        peer.send(&cancel_of(transport, me, "held")).await;
        let terminated = timeout(
            Duration::from_secs(1),
            peer.recv_answer("SIP/2.0 487", "1 INVITE"),
        )
        .await
        .expect("the 487 while every send waits");
        assert_eq!(header(&terminated, "Call-ID"), ["held"], "{transport}");

        let unroutable = Err(Error::Unroutable);
        assert_eq!(hung.unwrap().await.map(drop), unroutable, "{transport}");
        assert_eq!(
            waiting.unwrap().await.map(drop),
            unroutable,
            "{transport}"
        );
        drop(held);
    }
}

/// Dropping an undecided INVITE reaches the driver through the slot set
/// aside for it when the INVITE arrived, not through the command queue, so
/// the INVITE gets its 500 while no operation can be admitted.
#[tokio::test]
async fn decision_drop_is_observed_even_when_command_queue_is_full() {
    let config = config()
        .resolver(Slow)
        .max_operations(1)
        .command_capacity(1)
        .resolve_timeout(Duration::from_secs(60));
    let (mut ua, address) = start(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    // An INVITE whose next hop never resolves holds the only operation.
    let hung = ua.handle.try_invite(plan_to("slow.invalid", "hung")).unwrap();

    peer.send(&invite_to_ua(peer.address(), "dropped"), address).await;
    let invite = invite(&mut ua.events).await;
    let busy_here = StatusCode::from_u16(486).unwrap();
    let refused = invite.try_reject(busy_here).unwrap_err();
    assert_eq!(refused.error(), Error::Busy);
    drop(refused.into_inner());

    let (response, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&response, "Call-ID"), ["dropped"]);
    drop(hung);
}

/// A request without an RFC 3261 branch, as an RFC 2543 element sends, has
/// no transaction in signa-core, and the UA keeps nothing for it: no
/// dialog, no event and no response. Its retransmissions change nothing
/// either.
#[tokio::test]
async fn legacy_untracked_request_does_not_create_dialog() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let legacy = invite_to_ua(peer.address(), "legacy")
        .replace("branch=z9hG4bK-legacy", "branch=legacy");

    for _ in 0..3 {
        peer.send(&legacy, address).await;
    }
    let bye = in_dialog(
        "BYE",
        "UDP",
        &legacy.replace(
            "To: <sip:ua@127.0.0.1>",
            "To: <sip:ua@127.0.0.1>;tag=made-up",
        ),
        peer.address(),
        "legacy",
        2,
    )
    .replace("branch=z9hG4bK-BYE", "branch=BYE");
    peer.send(&bye, address).await;

    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
    peer.quiet("SIP/2.0", Duration::from_millis(200)).await;
}
