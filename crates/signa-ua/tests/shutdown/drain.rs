/*!
`ShutdownMode::DrainExisting`. The work under way goes on, the peer's
requests in a dialog still reach the UA, and the endpoint shuts down once
the UA has nothing left, after the Accepted states of RFC 6026 sections 8.4
and 8.7.
*/

use std::time::{Duration, Instant};

use signa_ua::{ReinvitePlan, ShutdownMode, ShutdownOutcome, Ua};
use tokio::time::timeout;

use crate::{
    shutdown::{brisk, brisk_with, report_within, two_ua_call, ua_timed},
    support::{
        call_from, config,
        events::{invite, reinvite, reinvite_event},
        flood::FLOODING,
        message::{
            answer, header, in_dialog, invite_over, plan_to, reinvite_of,
            reply_with, sdp,
        },
        peer::{Peer, Wire},
    },
};

/// A UA that drains keeps its endpoint taking requests, so a BYE of the
/// peer gets the UA's 200 rather than the 503 of an endpoint that shut down
/// too early. So does the peer's re-INVITE, which the application takes, over
/// UDP and over TCP. Only a new INVITE gets a 503, and once the session has
/// ended the UA and its endpoint drain.
#[tokio::test]
async fn peer_bye_during_ua_drain_is_not_rejected_by_premature_core_shutdown()
{
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp, _) = brisk_with(config());
        let handle = ua.handle.clone();
        tokio::spawn(ua.driver);
        let mut peer = Wire::connect(transport, udp, tcp).await;
        let me = peer.address();
        peer.send(&invite_over(transport, me, "draining")).await;
        let incoming = invite(&mut ua.events).await;
        incoming.try_accept(sdp()).unwrap().await.unwrap();
        let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
        peer.acknowledge(&ok, "draining", 1).await;

        let shutdown = handle
            .shutdown(ShutdownMode::DrainExisting, Duration::from_secs(10));
        peer.send(&invite_over(transport, me, "late")).await;
        peer.recv_answer("SIP/2.0 503", "1 INVITE").await;
        let reinvite = reinvite_of(&ok, me, "draining", 2, me, "v=0")
            .replace("SIP/2.0/UDP", &format!("SIP/2.0/{transport}"));
        peer.send(&reinvite).await;
        let accepting = reinvite_event(&mut ua.events).await.try_accept(sdp());
        accepting.unwrap().await.unwrap();
        let reok = peer.recv_answer("SIP/2.0 200", "2 INVITE").await;
        peer.acknowledge(&reok, "draining", 2).await;
        let bye = in_dialog("BYE", transport, &ok, me, "draining", 3);
        peer.send(&bye).await;
        let answered = peer.recv_answer("SIP/2.0 ", "3 BYE").await;

        assert!(
            answered.starts_with("SIP/2.0 200"),
            "{transport}: {answered}"
        );
        let report = report_within(shutdown, Duration::from_secs(5)).await;
        assert_eq!(report.outcome, ShutdownOutcome::Drained, "{transport}");
        assert_eq!((report.ended, report.terminated), (1, 0), "{transport}");
        assert_eq!(report.sessions_left, 0, "{transport}");
    }
}

/// Two UAs over UDP and over TCP, and either one drains, the caller or the
/// callee. The other's re-INVITE reaches the draining one's application,
/// which takes it, and the other's BYE gets its 200, so both operations
/// succeed. Then the draining UA stops.
#[tokio::test]
async fn a_draining_ua_takes_its_peers_reinvite_and_bye_either_way() {
    for transport in ["udp", "tcp"] {
        for draining in ["caller", "callee"] {
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
            let (stopping, mut stopping_events, other, session) =
                if draining == "caller" {
                    (caller, caller_events, callee, answered)
                } else {
                    (callee, callee_events, caller, calling)
                };

            let shutdown = stopping.shutdown(
                ShutdownMode::DrainExisting,
                Duration::from_secs(10),
            );
            let reinviting = other
                .try_reinvite(&session, ReinvitePlan::new(sdp()))
                .unwrap();
            let incoming = reinvite(&mut stopping_events).await;
            incoming.try_accept(sdp()).unwrap().await.unwrap();
            assert_eq!(reinviting.await, Ok(()), "{transport} {draining}");
            tokio::time::sleep(Duration::from_millis(100)).await;
            let bye = other.try_terminate(&session).unwrap().await;

            assert_eq!(bye, Ok(()), "{transport} {draining}");
            let report = report_within(shutdown, Duration::from_secs(5)).await;
            assert_eq!(
                report.outcome,
                ShutdownOutcome::Drained,
                "{transport} {draining}"
            );
            assert_eq!(report.ended, 1, "{transport} {draining}");
        }
    }
}

/// Once the peer's BYE leaves the UA nothing to do, it lets go of its work
/// guard before it shuts the endpoint down, so the endpoint drains as soon
/// as its own transactions end, not at the deadline.
#[tokio::test]
async fn work_guard_is_released_before_waiting_for_core_drain() {
    let (mut ua, udp, _, _) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let (ok, _) = call_from(&peer, udp, &mut ua.events, "guarded").await;

    let shutdown =
        handle.shutdown(ShutdownMode::DrainExisting, Duration::from_secs(10));
    let bye = in_dialog("BYE", "UDP", &ok, peer.address(), "guarded", 2);
    peer.send(&bye, udp).await;
    peer.recv_starting("SIP/2.0 200").await;
    let report = report_within(shutdown, Duration::from_secs(4)).await;

    assert_eq!(report.outcome, ShutdownOutcome::Drained);
}

/// The two Accepted states hold a shutdown each in their own way (RFC 6026
/// sections 8.4 and 8.7). The endpoint keeps the callee's INVITE until
/// Timer L, absorbing a copy of the INVITE, and its drain waits for that.
/// The UA keeps the caller's INVITE until Timer M, since a fork's 2xx can
/// still come, and needs an ACK and a BYE, a new transaction the endpoint
/// would refuse once shut down. So the UA waits before it shuts the endpoint
/// down.
#[tokio::test]
async fn timer_l_m_retention_is_accounted_for() {
    let accepted_states = 64 * brisk().t1();

    // Over TCP, which keeps no non-INVITE transaction after its final, so
    // that only Timer L holds the drain.
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let mut peer = Wire::connect("TCP", udp, tcp).await;
    let me = peer.address();
    let invite_request = invite_over("TCP", me, "timer-l");
    peer.send(&invite_request).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
    let first_2xx = Instant::now();
    peer.acknowledge(&ok, "timer-l", 1).await;
    let bye = in_dialog("BYE", "TCP", &ok, me, "timer-l", 2);
    peer.send(&bye).await;
    peer.recv_answer("SIP/2.0 200", "2 BYE").await;
    let shutdown =
        handle.shutdown(ShutdownMode::DrainExisting, Duration::from_secs(10));
    peer.send(&invite_request).await;
    let absorbed = timeout(
        Duration::from_millis(200),
        peer.recv_answer("SIP/2.0 ", "1 INVITE"),
    )
    .await;
    assert!(absorbed.is_err(), "{absorbed:?}");
    let report = report_within(shutdown, Duration::from_secs(5)).await;
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert!(
        first_2xx.elapsed() >= accepted_states,
        "{:?}",
        first_2xx.elapsed()
    );

    let (ua, _, _, _) = brisk_with(config());
    let Ua { handle, driver, .. } = ua;
    tokio::spawn(driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");
    handle.try_invite(plan_to(&to, "timer-m")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "first", &contact), from).await;
    let first_2xx = Instant::now();
    peer.recv_starting("ACK").await;
    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(10));
    let (bye, bye_from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&bye, 200, "first"), bye_from).await;
    tokio::time::sleep(accepted_states / 2).await;
    peer.send(&answer(&request, "200", "fork", &contact), from).await;
    let (fork_ack, _) = peer.recv_starting("ACK").await;
    let (fork_bye, fork_from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&fork_bye, 200, "fork"), fork_from).await;

    assert!(header(&fork_ack, "To")[0].ends_with(";tag=fork"));
    assert!(header(&fork_bye, "To")[0].ends_with(";tag=fork"));
    let report = report_within(shutdown, Duration::from_secs(5)).await;
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert!(
        first_2xx.elapsed() >= accepted_states,
        "{:?}",
        first_2xx.elapsed()
    );
}

/// A shutdown whose deadline has passed when the driver first sees it still
/// drains a UA with nothing to do, as the endpoint does with a zero timeout,
/// rather than report the deadline. Which input the driver takes first
/// varies, so it runs many times, on two threads, alone as a flood is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_ua_drains_with_no_time_left() {
    let _alone = FLOODING.lock().await;
    for _ in 0..50 {
        let (ua, _, _, _) = brisk_with(config());
        let Ua { handle, driver, .. } = ua;
        tokio::spawn(driver);

        let shutdown =
            handle.shutdown(ShutdownMode::DrainExisting, Duration::ZERO);
        let report = report_within(shutdown, Duration::from_secs(2)).await;

        assert_eq!(report.outcome, ShutdownOutcome::Drained);
    }
}
