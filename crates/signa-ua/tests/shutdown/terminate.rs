/*!
`ShutdownMode::Terminate`. The UA ends its calls as a user hanging up would
(RFC 3261 section 15), with a BYE, a CANCEL or a 503 for each kind of work.
*/

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use signa_core::StatusCode;
use signa_ua::{
    EndReason, Error, Event, InvitePlan, ReinvitePlan, ShutdownMode,
    ShutdownOutcome, Ua,
};
use tokio::{sync::Notify, time::timeout};

use crate::{
    shutdown::{brisk, brisk_with, report_within, two_ua_call, ua_timed},
    support::{
        LOADED, WAIT, call_from, config,
        events::{event, invite},
        flood::{FLOODING, flood},
        message::{answer, plan_to, reply_with, sdp},
        peer::Peer,
    },
};

/// Two UAs over UDP and over TCP, and either one terminates. The caller
/// with an answered call and one the callee holds undecided: the call gets
/// a BYE, and the INVITE a CANCEL, whose 487 the callee's application learns
/// of. The callee with an answered call and an INVITE it holds: the call
/// gets a BYE, and the INVITE a 503. Each side sees the end of the call as
/// the peer's BYE, and none is left.
#[tokio::test]
async fn a_terminating_ua_ends_its_calls_either_way() {
    for transport in ["udp", "tcp"] {
        for terminating in ["caller", "callee"] {
            let (Ua { handle: caller, events: mut caller_events, driver }, _) =
                ua_timed(transport, brisk());
            tokio::spawn(driver);
            let (
                Ua { handle: callee, events: mut callee_events, driver },
                address,
            ) = ua_timed(transport, brisk());
            tokio::spawn(driver);
            let (calling, answered) = two_ua_call(
                &caller,
                &mut caller_events,
                &mut callee_events,
                address,
                transport,
            )
            .await;
            let plan = InvitePlan::new(
                format!("sip:ua@{address};transport={transport}")
                    .parse()
                    .unwrap(),
                "sip:caller@127.0.0.1".parse().unwrap(),
                sdp(),
            );
            let pending = caller.try_invite(plan).unwrap().await.unwrap();
            let held = invite(&mut callee_events).await;
            // The callee rings, so that the CANCEL may go.
            held.try_provisional(StatusCode::from_u16(180).unwrap())
                .unwrap()
                .await
                .unwrap();
            event(&mut caller_events, |event| match event {
                Event::Early { .. } => Some(()),
                _ => None,
            })
            .await;

            let (stopping, other_events, other_session) =
                if terminating == "caller" {
                    (&caller, &mut callee_events, &answered)
                } else {
                    (&callee, &mut caller_events, &calling)
                };
            let shutdown = stopping
                .shutdown(ShutdownMode::Terminate, Duration::from_secs(3));
            // The other side's events come in either order, so each is
            // taken as it comes: the end of the call, and for the INVITE
            // that rang, its 487 at the callee or its 503 at the caller.
            let (mut ended, mut refused) = (None, false);
            while ended.is_none() || !refused {
                match timeout(WAIT, other_events.recv())
                    .await
                    .unwrap()
                    .unwrap()
                {
                    Event::Ended { session, reason, .. }
                        if &session == other_session =>
                    {
                        ended = Some(reason);
                    }
                    Event::Cancelled { .. } => refused = true,
                    Event::Failed { attempt, error, .. } => {
                        assert_eq!(attempt, pending.id());
                        let unavailable = StatusCode::from_u16(503).unwrap();
                        assert_eq!(error, Error::RemoteFailure(unavailable));
                        refused = true;
                    }
                    _ => {}
                }
            }
            assert!(
                matches!(ended, Some(EndReason::RemoteBye { .. })),
                "{transport} {terminating}"
            );
            drop(held);

            // Over UDP the caller's INVITE that got its 487 keeps Timer D,
            // at least 32 s (RFC 3261 section 17.1.1.2), which holds the
            // UA's attempt and the endpoint's drain alike.
            let report = report_within(shutdown, Duration::from_secs(5)).await;
            let outcome = if (transport, terminating) == ("udp", "caller") {
                ShutdownOutcome::DeadlineExpired
            } else {
                ShutdownOutcome::Drained
            };
            assert_eq!(report.outcome, outcome, "{transport} {terminating}");
            assert_eq!(report.sessions_left, 0, "{transport} {terminating}");
            assert_eq!(report.terminated, 1, "{transport} {terminating}");
            assert_eq!(report.failed_byes, 0, "{transport} {terminating}");
        }
    }
}

/// A UA that terminates while its INVITE rings sends the CANCEL. A 2xx that
/// crosses the CANCEL gets its ACK, and only then a BYE (RFC 3261 sections
/// 13.2.2.4 and 15), and the UA drains once the BYE is answered and Timer M
/// is over.
#[tokio::test]
async fn terminate_cancel_late_2xx_ack_bye_sequence() {
    let (ua, _, _, _) = brisk_with(config());
    let Ua { handle, mut events, driver } = ua;
    tokio::spawn(driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");
    handle.try_invite(plan_to(&to, "hangup")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "180", "callee", &contact), from).await;
    event(&mut events, |event| match event {
        Event::Early { .. } => Some(()),
        _ => None,
    })
    .await;

    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(10));
    let (cancel, cancel_from) = peer.recv_starting("CANCEL").await;
    peer.send(&answer(&request, "200", "callee", &contact), from).await;
    peer.send(&reply_with(&cancel, 200, "callee"), cancel_from).await;
    let mut seen = Vec::new();
    let bye = loop {
        let (message, from) = peer.recv().await;
        let method = message.split(' ').next().unwrap().to_owned();
        seen.push(method.clone());
        if method == "BYE" {
            break (message, from);
        }
    };
    peer.send(&reply_with(&bye.0, 200, "callee"), bye.1).await;

    let ack = seen.iter().position(|method| method == "ACK");
    assert!(ack.is_some_and(|ack| ack < seen.len() - 1), "{seen:?}");
    assert!(!seen.contains(&"INVITE".to_owned()), "{seen:?}");
    let report = report_within(shutdown, Duration::from_secs(5)).await;
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert_eq!((report.ended, report.terminated), (1, 1));
    assert_eq!(report.invites_left, 0);
}

/// A UA that terminates under a flood, as in
/// [`ordinary_queue_full_does_not_starve_ack_cancel_bye`], over UDP and over
/// TCP, still ends each call with a BYE that the other UA takes, and stops
/// by its deadline. The endpoint may not drain while the transactions of
/// the flood's INVITEs wait for the ACK of their 503, so the outcome may be
/// the deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_under_flood_ends_its_calls_by_its_deadline() {
    let _alone = FLOODING.lock().await;
    for (transport, upper) in [("udp", "UDP"), ("tcp", "TCP")] {
        let (Ua { handle: caller, events: mut caller_events, driver }, _) =
            ua_timed(transport, *LOADED);
        tokio::spawn(driver);
        let (
            Ua { handle: callee, events: mut callee_events, driver },
            address,
        ) = ua_timed(transport, *LOADED);
        tokio::spawn(driver);
        for _ in 0..2 {
            two_ua_call(
                &caller,
                &mut caller_events,
                &mut callee_events,
                address,
                transport,
            )
            .await;
        }
        let stop = Arc::new(Notify::new());
        let flooding = flood(upper, address, address, stop.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = Instant::now();
        let deadline = Duration::from_secs(3);
        let shutdown = callee.shutdown(ShutdownMode::Terminate, deadline);
        for _ in 0..2 {
            let reason = event(&mut caller_events, |event| match event {
                Event::Ended { reason, .. } => Some(reason),
                _ => None,
            })
            .await;
            assert!(matches!(reason, EndReason::RemoteBye { .. }));
        }
        // The flood stops before the endpoint does, which closes its
        // connection. The 503s it got still hold the endpoint's drain.
        stop.notify_one();
        flooding.await.unwrap();
        let report = report_within(shutdown, deadline * 2).await;

        assert!(started.elapsed() < deadline + Duration::from_secs(1));
        assert_ne!(
            report.outcome,
            ShutdownOutcome::EndpointLost,
            "{transport}"
        );
        assert_eq!(report.terminated, 2, "{transport}");
        assert_eq!(report.failed_byes, 0, "{transport}");
        assert_eq!(report.sessions_left, 0, "{transport}");
    }
}

/// The BYEs of a termination take no operation of the application's, so
/// they go while every one is in use, here by a CANCEL that waits for a
/// provisional response that never comes.
#[tokio::test]
async fn terminate_needs_no_operation_of_the_application() {
    let (mut ua, udp, _, _) = brisk_with(config().max_operations(1));
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let (_, session) = call_from(&peer, udp, &mut ua.events, "busy").await;
    let silent = Peer::new().await;
    let to = silent.address().to_string();
    let attempt =
        handle.try_invite(plan_to(&to, "silent")).unwrap().await.unwrap();
    let _cancel = handle.try_cancel(&attempt).unwrap();
    let full = handle.try_terminate(&session).unwrap_err().error();
    assert_eq!(full, Error::Busy);

    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_millis(500));
    let (bye, from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&bye, 200, "x"), from).await;
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    assert_eq!(report.terminated, 1);
    assert_eq!(report.failed_byes, 0);
}

/// The UA does not cancel a re-INVITE of its own, so one the peer answers
/// only with a 180 goes on after a termination ended its session, and holds
/// the shutdown until its deadline. The report counts it.
#[tokio::test]
async fn an_unanswered_reinvite_holds_a_termination_until_its_deadline() {
    let (ua, _, _, _) = brisk_with(config());
    let Ua { handle, mut events, driver } = ua;
    tokio::spawn(driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");
    handle.try_invite(plan_to(&to, "pending")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "callee", &contact), from).await;
    peer.recv_starting("ACK").await;
    let session = event(&mut events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    let _reinviting =
        handle.try_reinvite(&session, ReinvitePlan::new(sdp())).unwrap();
    let (reinvite, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&reinvite, "180", "callee", &contact), from).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = Instant::now();
    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(2));
    let (bye, bye_from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&bye, 200, "callee"), bye_from).await;
    let report = report_within(shutdown, Duration::from_secs(4)).await;

    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!((report.terminated, report.sessions_left), (1, 0));
    assert_eq!(report.invites_left, 1);
}
