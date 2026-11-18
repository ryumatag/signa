/*!
Settlement: when the work of a session, an attempt or an incoming INVITE has
ended, apart from when the session or the INVITE did.

Each test runs on [`brisk`] timers, so that 64 T1 is 1.28 s and a UDP
transaction ends soon after its final response. Timer D of an INVITE that
got an error response stays at 32 s over UDP, so the tests of such an
INVITE run over TCP.
*/

use std::time::{Duration, Instant};

use signa_core::StatusCode;
use signa_ua::{
    AttemptResult, Error, Event, InviteAttempt, Session, Settled, Settlement,
    ShutdownMode, ShutdownOutcome, UaEvents, UaHandle,
};
use tokio::time::timeout;

use crate::support::{
    brisk_with, called_by, config,
    events::{attempt_end, event, invite, report_within},
    message::{
        ack_for, answer, cancel_of, direct_invite, in_dialog, ok_to, plan_to,
        reply_with, sdp,
    },
    peer::Raw,
};

/// 64 T1 of [`brisk`] timers.
///
/// [`brisk`]: crate::support::brisk
const T1_64: Duration = Duration::from_millis(64 * 20);

/// Waits for `settlement`, which must come within `wait`, and says when it
/// came.
async fn settles_within(
    settlement: Settlement,
    wait: Duration,
) -> (Settled, Instant) {
    let settled = timeout(wait, settlement.wait()).await.expect("settled");
    (settled, Instant::now())
}

/// Has the UA call the raw `peer`, which answers with a 2xx and takes the
/// ACK, and returns the attempt, the session and when the 2xx went.
async fn call(
    handle: &UaHandle,
    events: &mut UaEvents,
    peer: &mut Raw,
    call: &str,
) -> (InviteAttempt, Session, Instant) {
    let contact = format!("sip:peer@{}", peer.address());
    let plan = plan_to(&peer.target(), call);
    let attempt = handle.try_invite(plan).unwrap().await.unwrap();
    let request = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "callee", &contact)).await;
    let answered = Instant::now();
    peer.recv_starting("ACK").await;
    let session = event(events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    (attempt, session, answered)
}

/// A caller that hangs up before Timer M has its session end at once, and
/// settle only with its INVITE, 64 T1 after the 2xx, since another fork's
/// 2xx could still need an ACK and a BYE through that transaction (RFC 6026
/// section 8.4). The session counts its own writes, the ACK and the BYE,
/// and the attempt those of the INVITE. Over UDP and TCP.
#[tokio::test]
async fn a_session_ended_before_timer_m_settles_after_its_invite() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp, _) = brisk_with(config());
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let (attempt, session, answered) =
            call(&ua.handle, &mut ua.events, &mut peer, "early-bye").await;

        let ending = ua.handle.try_terminate(&session).unwrap();
        let bye = peer.recv_starting("BYE").await;
        peer.send(&ok_to(&bye)).await;
        ending.await.unwrap();

        assert_eq!(session.settlement().get(), None, "{transport}");
        let (settled, settled_at) =
            settles_within(session.settlement(), 2 * T1_64).await;
        let invite = attempt.settlement().get();
        let invite = invite.expect("the INVITE settled first");
        assert!(settled_at - answered >= T1_64 - T1_64 / 8, "{transport}");
        assert!(invite.is_drained() && settled.is_drained(), "{transport}");
        assert!(invite.written() >= 1, "{transport}: {invite:?}");
        assert!(settled.written() >= 2, "{transport}: {settled:?}");
        driver.abort();
    }
}

/// An attempt the application cancels forms no session, and settles once
/// the INVITE's transaction and the CANCEL's have. It counts the writes of
/// both: the INVITE, the CANCEL and the endpoint's ACK of the 487. Over TCP,
/// where nothing is sent again and Timer D is zero.
#[tokio::test]
async fn a_cancelled_attempt_settles_with_its_cancel() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("TCP", udp, tcp).await;

    let plan = plan_to(&peer.target(), "cancelled");
    let attempt = ua.handle.try_invite(plan).unwrap().await.unwrap();
    let request = peer.recv_starting("INVITE").await;
    peer.send(&reply_with(&request, 180, "callee")).await;
    let cancelled = ua.handle.try_cancel(&attempt).unwrap();
    let cancel = peer.recv_starting("CANCEL").await;
    peer.send(&reply_with(&cancel, 200, "callee")).await;
    peer.send(&reply_with(&request, 487, "callee")).await;
    peer.recv_starting("ACK").await;
    cancelled.await.unwrap();

    let terminated = StatusCode::from_u16(487).unwrap();
    let ended = attempt_end(&mut ua.events).await;
    let failed = AttemptResult::Failed(Error::RemoteFailure(terminated));
    assert_eq!(ended.0, failed);
    let (settled, _) = settles_within(attempt.settlement(), T1_64).await;
    assert!(settled.is_drained());
    assert_eq!(
        (settled.written(), settled.not_written()),
        (3, 0),
        "{settled:?}",
    );
    driver.abort();
}

/// A 2xx of a fork beyond `max_forks` forms no session. The UA acknowledges
/// it and ends its dialog with a BYE, and the attempt counts both, with the
/// INVITE, and settles once the BYE's transaction has. The ACK of the kept
/// 2xx is its session's. Over TCP, where nothing is sent again.
#[tokio::test]
async fn an_attempt_counts_the_cleanup_of_a_fork() {
    let (ua, udp, tcp, _) = brisk_with(config().max_forks(1));
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("TCP", udp, tcp).await;
    let contact = format!("sip:peer@{}", peer.address());

    let plan = plan_to(&peer.target(), "forked");
    let attempt = ua.handle.try_invite(plan).unwrap().await.unwrap();
    let request = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "kept", &contact)).await;
    peer.recv_starting("ACK").await;
    peer.send(&answer(&request, "200", "beyond", &contact)).await;
    peer.recv_starting("ACK").await;
    let bye = peer.recv_starting("BYE").await;
    peer.send(&ok_to(&bye)).await;

    let (settled, _) = settles_within(attempt.settlement(), 2 * T1_64).await;
    assert!(settled.is_drained());
    assert_eq!(settled.written(), 3, "{settled:?}");
    driver.abort();
}

/// A rejected INVITE settles once the endpoint's ACK of the rejection ends
/// its transaction, with the 100 and the 486 as its writes. Over TCP, where
/// Timer I is zero.
#[tokio::test]
async fn a_rejected_invite_settles_with_its_ack() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("TCP", udp, tcp).await;
    let me = peer.address();

    peer.send(&direct_invite(me, "rejected")).await;
    let incoming = invite(&mut ua.events).await;
    let settlement = incoming.settlement();
    let busy = StatusCode::from_u16(486).unwrap();
    incoming.try_reject(busy).unwrap().await.unwrap();
    let rejection = peer.recv_answer("SIP/2.0 486", "1 INVITE").await;
    assert_eq!(settlement.get(), None);
    let ack = ack_for(&rejection, me, "rejected", 1)
        .replace("branch=z9hG4bK-ack-", "branch=z9hG4bK-");
    peer.send(&ack).await;

    let (settled, _) = settles_within(settlement, T1_64).await;
    assert!(settled.is_drained());
    assert_eq!(settled.written(), 2, "{settled:?}");
    driver.abort();
}

/// A BYE the peer never answers ends its session at once, as RFC 3261
/// section 15.1.1 has it, and fails later, at Timer F. The session settles
/// only then, with every retransmission of the BYE counted, and drains,
/// since a timeout is how a transaction ends, not a stop. The attempt
/// settled long before.
#[tokio::test]
async fn a_late_failure_settles_the_session_after_its_end() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("UDP", udp, tcp).await;
    let (attempt, session, _) =
        call(&ua.handle, &mut ua.events, &mut peer, "unanswered").await;
    let (invite, _) = settles_within(attempt.settlement(), 2 * T1_64).await;

    let ending = ua.handle.try_terminate(&session).unwrap();
    peer.recv_starting("BYE").await;
    event(&mut ua.events, |event| match event {
        Event::Ended { .. } => Some(()),
        _ => None,
    })
    .await;
    assert_eq!(session.settlement().get(), None);
    let failed = timeout(2 * T1_64, ending).await.unwrap();
    let (settled, _) = settles_within(session.settlement(), T1_64).await;

    assert!(invite.is_drained());
    assert_eq!(failed, Err(Error::Timeout));
    assert!(settled.is_drained());
    assert!(settled.written() > 2, "{settled:?}");
    driver.abort();
}

/// A callee's session that the peer's BYE ends settles once its INVITE's
/// transaction does, at Timer L, 64 T1 after the 2xx (RFC 6026 section
/// 8.7), and the BYE's. It counts the writes of the INVITE it was accepted
/// from, the 2xx among them, with the 200 of the BYE. Over UDP and TCP.
#[tokio::test]
async fn a_callees_session_waits_for_its_invite_after_the_peers_bye() {
    for transport in ["UDP", "TCP"] {
        let (mut ua, udp, tcp, _) = brisk_with(config());
        let driver = tokio::spawn(ua.driver);
        let mut peer = Raw::start(transport, udp, tcp).await;
        let me = peer.address();
        let (ok, session) =
            called_by(&mut peer, &mut ua.events, "hangup").await;
        let answered = Instant::now();

        let bye = in_dialog("BYE", "UDP", &ok, me, "hangup", 2);
        peer.send(&bye).await;
        peer.recv_answer("SIP/2.0 200", "2 BYE").await;
        event(&mut ua.events, |event| match event {
            Event::Ended { .. } => Some(()),
            _ => None,
        })
        .await;

        assert_eq!(session.settlement().get(), None, "{transport}");
        let (settled, settled_at) =
            settles_within(session.settlement(), 2 * T1_64).await;
        assert!(
            settled_at - answered >= T1_64 - T1_64 / 4,
            "{transport}: {:?}",
            settled_at - answered,
        );
        assert!(settled.is_drained(), "{transport}");
        assert!(settled.written() >= 2, "{transport}: {settled:?}");
        driver.abort();
    }
}

/// An incoming INVITE settles whether or not anything waits for it or keeps
/// its handle. A waiter dropped before it settled, the INVITE dropped once
/// the caller cancelled it and the clone given up change nothing. A clone
/// taken before resolves once the endpoint's ACK of the 487 ends the
/// INVITE's transaction, and the CANCEL's has ended, with the 200 of the
/// CANCEL and the 487 among their writes. Over TCP, where nothing is sent
/// again and Timer I is zero.
#[tokio::test]
async fn a_settlement_needs_no_waiter_and_no_handle() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("TCP", udp, tcp).await;
    let me = peer.address();

    peer.send(&direct_invite(me, "withdrawn")).await;
    let incoming = invite(&mut ua.events).await;
    let settlement = incoming.settlement();
    let kept = settlement.clone();
    let waiting = timeout(Duration::from_millis(20), settlement.wait()).await;
    assert!(waiting.is_err(), "settled before a final");
    drop(settlement);
    peer.send(&cancel_of("UDP", me, "withdrawn")).await;
    peer.recv_answer("SIP/2.0 200", "1 CANCEL").await;
    let terminated = peer.recv_answer("SIP/2.0 487", "1 INVITE").await;
    event(&mut ua.events, |event| match event {
        Event::Cancelled { .. } => Some(()),
        _ => None,
    })
    .await;
    drop(incoming);
    let ack = ack_for(&terminated, me, "withdrawn", 1)
        .replace("branch=z9hG4bK-ack-", "branch=z9hG4bK-");
    peer.send(&ack).await;

    let (settled, _) = settles_within(kept, T1_64).await;
    assert!(settled.is_drained());
    assert_eq!(settled.written(), 3, "{settled:?}");
    driver.abort();
}

/// The peer's BYE holds its session until the BYE's transaction ends,
/// which over UDP is Timer J, 64 T1 after the 200 (RFC 3261 section
/// 17.2.2), so that a copy of the BYE still finds its 200. The INVITE's
/// Timer L has passed by then.
#[tokio::test]
async fn the_peers_bye_holds_its_session_to_timer_j() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("UDP", udp, tcp).await;
    let me = peer.address();
    let (ok, session) = called_by(&mut peer, &mut ua.events, "late").await;
    tokio::time::sleep(T1_64 + T1_64 / 4).await;

    let bye = in_dialog("BYE", "UDP", &ok, me, "late", 2);
    peer.send(&bye).await;
    peer.recv_answer("SIP/2.0 200", "2 BYE").await;
    let answered = Instant::now();

    let (settled, settled_at) =
        settles_within(session.settlement(), 2 * T1_64).await;
    assert!(
        settled_at - answered >= T1_64 - T1_64 / 8,
        "{:?}",
        settled_at - answered,
    );
    assert!(settled.is_drained());
    driver.abort();
}

/// A termination that drains leaves every settlement drained: a session
/// either way, the INVITE the UA sent and the one it took. Each has
/// settled by the time the report comes. Over TCP, where the endpoint's
/// drain ends with Timer M of the UA's INVITE.
#[tokio::test]
async fn a_drained_shutdown_settles_everything_drained() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("TCP", udp, tcp).await;
    let me = peer.address();
    let (attempt, calling, _) =
        call(&ua.handle, &mut ua.events, &mut peer, "outgoing").await;
    peer.send(&direct_invite(me, "incoming")).await;
    let incoming = invite(&mut ua.events).await;
    let taken = incoming.settlement();
    let called = incoming.try_accept(sdp()).unwrap();
    let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
    peer.send(&ack_for(&ok, me, "incoming", 1)).await;
    let called = called.await.unwrap();

    let shutdown =
        ua.handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(5));
    for _ in 0..2 {
        let bye = peer.recv_starting("BYE").await;
        peer.send(&ok_to(&bye)).await;
    }
    let report = report_within(shutdown, Duration::from_secs(5)).await;

    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    let settlements = [
        attempt.settlement(),
        calling.settlement(),
        taken,
        called.settlement(),
    ];
    for settlement in settlements {
        let settled = settlement.get().expect("settled by the report");
        assert!(settled.is_drained(), "{settled:?}");
    }
    driver.await.unwrap();
}

/// A session still up at a shutdown's deadline did not drain, and its
/// settlement says so once the UA stops. So does the INVITE that formed it,
/// which the endpoint kept to Timer L.
#[tokio::test]
async fn work_left_at_the_deadline_settles_undrained() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("UDP", udp, tcp).await;
    let me = peer.address();
    peer.send(&direct_invite(me, "left")).await;
    let incoming = invite(&mut ua.events).await;
    let invite = incoming.settlement();
    let accepted = incoming.try_accept(sdp());
    let session = accepted.unwrap().await.unwrap();

    let shutdown = ua
        .handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_millis(200));
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    let (settled, _) = settles_within(session.settlement(), WAITING).await;
    let (invite, _) = settles_within(invite, WAITING).await;
    assert!(!settled.is_drained() && !invite.is_drained());
    assert!(invite.written() >= 1, "{invite:?}");
    driver.await.unwrap();
}

/// A dropped driver stops the UA at once, and each settlement still
/// resolves, as one that did not drain.
#[tokio::test]
async fn a_dropped_driver_settles_what_it_had_undrained() {
    let (mut ua, udp, tcp, _) = brisk_with(config());
    let driver = tokio::spawn(ua.driver);
    let mut peer = Raw::start("TCP", udp, tcp).await;
    let (_, session) = called_by(&mut peer, &mut ua.events, "dropped").await;

    driver.abort();

    let (settled, _) = settles_within(session.settlement(), WAITING).await;
    assert!(!settled.is_drained());
}

/// How long a settlement may take once the UA has stopped.
const WAITING: Duration = Duration::from_millis(500);
