/*!
The deadline of a shutdown and its report: what later calls and a dropped
future do to it, what the UA lets go of when it comes, and that `Drained`
claims only the work of the UA and its endpoint.
*/

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use signa_core::{StatusCode, endpoint::Target};
use signa_ua::{
    Description, Error, InvitePlan, Negotiate, Offer, Query, Resolve,
    ResolveError, ShutdownMode, ShutdownOutcome, StaticResolver, Ua,
};
use tokio::time::timeout;

use crate::{
    shutdown::{brisk_with, report_within},
    support::{
        WAIT, call_from, config,
        events::invite,
        message::{
            ack_for, direct_invite, in_dialog, invite_over, offer_named,
            ok_offering, plan_to, reply_with, sdp,
        },
        peer::{Peer, Wire},
    },
};

/// Dropping the future of a shutdown leaves the shutdown going: the UA
/// sends its BYE, stops once that is answered, and its driver returns. A
/// later call gets the same report.
#[tokio::test]
async fn shutdown_future_drop_does_not_cancel_shutdown() {
    let (mut ua, udp, _, _) = brisk_with(config());
    let handle = ua.handle.clone();
    let driver = tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    call_from(&peer, udp, &mut ua.events, "dropped").await;

    drop(handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(10)));
    let (bye, from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&bye, 200, "x"), from).await;

    timeout(Duration::from_secs(5), driver).await.unwrap().unwrap();
    let report = handle
        .shutdown(ShutdownMode::DrainExisting, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert_eq!(report.terminated, 1);
}

/// A second call cannot move the deadline of the first. A drain with 400 ms,
/// which the driver takes first, becomes a termination with a minute, so the
/// UA sends its BYE, but the peer never answers it, and the UA stops at
/// 400 ms all the same.
#[tokio::test]
async fn second_shutdown_call_does_not_extend_deadline() {
    let (mut ua, udp, _, _) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    call_from(&peer, udp, &mut ua.events, "deadline").await;

    let started = Instant::now();
    let first = handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_millis(400));
    tokio::time::sleep(Duration::from_millis(50)).await;
    peer.quiet("BYE", Duration::from_millis(50)).await;
    let second =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(60));
    peer.recv_starting("BYE").await;
    let report = report_within(second, Duration::from_secs(2)).await;

    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1200), "{elapsed:?}");
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    // The BYE reached the endpoint, which ended the session, though no
    // answer came.
    assert_eq!((report.ended, report.terminated), (1, 1));
    assert_eq!(first.await.unwrap(), report);
}

/// A [`Negotiate`] that never answers, and counts the answers it holds.
#[derive(Clone, Default)]
struct Stalled(Arc<()>);

impl Negotiate for Stalled {
    fn answer(
        &self,
        _offer: &Offer,
    ) -> impl Future<Output = Option<Description>> + Send {
        let held = self.0.clone();
        async move {
            let _held = held;
            std::future::pending().await
        }
    }
}

/// A negotiator that never answers holds the ACK of a 2xx with an offer for
/// good when its answers have no deadline. The shutdown still ends at its
/// own, with the session and the attempt counted as left, and the stalled
/// answer is dropped.
#[tokio::test]
async fn provider_stall_hits_shared_deadline() {
    let stalled = Stalled::default();
    let config =
        config().negotiator(stalled.clone()).answer_timeout(Duration::MAX);
    let (ua, _, _, _) = brisk_with(config);
    let Ua { handle, driver, .. } = ua;
    let driver = tokio::spawn(driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let plan = InvitePlan::without_offer(
        format!("sip:peer@{to}").parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
    );
    handle.try_invite(plan).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{to}");
    let ok = ok_offering(&request, "stall", &contact, &offer_named("call"));
    peer.send(&ok, from).await;
    while Arc::strong_count(&stalled.0) < 3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let started = Instant::now();
    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_millis(300));
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!((report.sessions_left, report.invites_left), (1, 1));
    // The answer in preparation is gone by the report. The driver may
    // still hold its negotiator, until it returns.
    assert!(Arc::strong_count(&stalled.0) <= 2);
    peer.quiet("ACK", Duration::from_millis(100)).await;
    timeout(WAIT, driver).await.unwrap().unwrap();
    assert_eq!(Arc::strong_count(&stalled.0), 1);
}

/// A [`Resolve`] that never resolves, and counts the resolutions it holds.
#[derive(Clone, Default)]
struct Hung(Arc<()>);

impl Resolve for Hung {
    async fn resolve(&self, _query: &Query) -> Result<Target, ResolveError> {
        let _held = self.0.clone();
        std::future::pending().await
    }
}

/// A resolver that hangs without a timeout holds the BYE of a termination
/// for good. The shutdown still ends at its deadline, with the session
/// counted as left, and the resolution is dropped.
#[tokio::test]
async fn a_hung_resolver_hits_the_shared_deadline() {
    let hung = Hung::default();
    let config =
        config().resolver(hung.clone()).resolve_timeout(Duration::MAX);
    let (mut ua, udp, _, _) = brisk_with(config);
    let handle = ua.handle.clone();
    let driver = tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    call_from(&peer, udp, &mut ua.events, "hung").await;

    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_millis(300));
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!(report.sessions_left, 1);
    // The resolution is gone by the report. The driver may still hold its
    // resolver, until it returns.
    assert!(Arc::strong_count(&hung.0) <= 2);
    timeout(WAIT, driver).await.unwrap().unwrap();
    assert_eq!(Arc::strong_count(&hung.0), 1);
}

/// Every operation still running at the deadline ends, with
/// [`Error::DriverStopped`]: a BYE the peer never answers, and a CANCEL that
/// waits for a provisional response that never comes. The report counts
/// them.
#[tokio::test]
async fn all_operation_waiters_get_terminal_result() {
    let (mut ua, udp, _, _) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let (_, session) = call_from(&peer, udp, &mut ua.events, "waiters").await;
    let silent = Peer::new().await;
    let to = silent.address().to_string();
    let attempt =
        handle.try_invite(plan_to(&to, "silent")).unwrap().await.unwrap();
    silent.recv_starting("INVITE").await;

    let bye = handle.try_terminate(&session).unwrap();
    let cancel = handle.try_cancel(&attempt).unwrap();
    peer.recv_starting("BYE").await;
    let shutdown = handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_millis(300));
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!(timeout(WAIT, bye).await.unwrap(), Err(Error::DriverStopped));
    assert_eq!(
        timeout(WAIT, cancel).await.unwrap(),
        Err(Error::DriverStopped)
    );
    assert_eq!(report.operations_failed, 2);
    assert_eq!(report.invites_left, 1);
}

/// A [`Resolve`] of the peer's literal addresses that counts the
/// resolutions it holds.
#[derive(Clone, Default)]
struct Counted(Arc<()>);

impl Resolve for Counted {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        let _held = self.0.clone();
        StaticResolver::new().resolve(query).await
    }
}

/// Once the UA has drained, nothing of it is left: its driver has returned
/// with every task, the resolver goes with it, and nothing more goes on the
/// wire. The callee's 2xx, never acknowledged, went again every 80 ms until
/// its ACK deadline let the BYE of the termination go. The handles refuse
/// what they are asked.
#[tokio::test]
async fn drained_has_no_live_tasks_timers_or_post_return_writes() {
    let counted = Counted::default();
    let (mut ua, udp, _, _) = brisk_with(config().resolver(counted.clone()));
    let handle = ua.handle.clone();
    let driver = tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    peer.send(&direct_invite(peer.address(), "clean"), udp).await;
    let incoming = invite(&mut ua.events).await;
    let session = incoming.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;

    let shutdown =
        handle.shutdown(ShutdownMode::Terminate, Duration::from_secs(10));
    peer.recv_starting("SIP/2.0 200").await;
    let (bye, from) = peer.recv_starting("BYE").await;
    peer.send(&reply_with(&bye, 200, "x"), from).await;
    let report = report_within(shutdown, Duration::from_secs(5)).await;

    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert_eq!(report.terminated, 1);
    timeout(Duration::from_millis(100), driver).await.unwrap().unwrap();
    assert_eq!(Arc::strong_count(&counted.0), 1);
    peer.quiet("", Duration::from_millis(500)).await;
    let refused = handle.try_invite(plan_to("127.0.0.1:9", "after"));
    assert_eq!(refused.unwrap_err().error(), Error::Closed);
    assert_eq!(handle.snapshot(&session).await, Err(Error::Closed));
    // The events still queued arrive, and then none.
    while timeout(WAIT, ua.events.recv()).await.unwrap().is_some() {}
}

/// A deadline that comes first is not a drain, whether the UA or the
/// endpoint still had work: a session the application never ends and an
/// INVITE it never decides, or the INVITE transaction the endpoint keeps
/// until Timer L. Nothing goes out for what the deadline cuts short.
#[tokio::test]
async fn deadline_expired_is_not_reported_as_drained() {
    let (mut ua, udp, _, _) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    call_from(&peer, udp, &mut ua.events, "kept").await;
    peer.send(&direct_invite(peer.address(), "undecided"), udp).await;
    let held = invite(&mut ua.events).await;
    let shutdown = handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_millis(300));
    let report = report_within(shutdown, Duration::from_secs(2)).await;
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!((report.sessions_left, report.invites_left), (1, 1));
    // The endpoint stopped before the UA let go of the INVITE, so it got no
    // 500 for it, and the decision finds the UA gone.
    peer.quiet("SIP/2.0 500", Duration::from_millis(300)).await;
    let late = held.try_reject(StatusCode::from_u16(486).unwrap());
    assert_eq!(late.unwrap_err().error(), Error::Closed);

    let (mut ua, udp, tcp, _) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let mut peer = Wire::connect("TCP", udp, tcp).await;
    let me = peer.address();
    peer.send(&invite_over("TCP", me, "timer-l")).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
    peer.send(
        &ack_for(&ok, me, "timer-l", 1).replace("SIP/2.0/UDP", "SIP/2.0/TCP"),
    )
    .await;
    let bye = in_dialog("BYE", "TCP", &ok, me, "timer-l", 2);
    peer.send(&bye).await;
    peer.recv_answer("SIP/2.0 200", "2 BYE").await;
    let shutdown = handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_millis(300));
    let report = report_within(shutdown, Duration::from_secs(2)).await;
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!((report.sessions_left, report.invites_left), (0, 0));

    // The same, with the endpoint's deadline brought closer by another of
    // its handles once the UA has shut it down.
    let (mut ua, udp, tcp, endpoint) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let mut peer = Wire::connect("TCP", udp, tcp).await;
    let me = peer.address();
    peer.send(&invite_over("TCP", me, "closer")).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let ok = peer.recv_answer("SIP/2.0 200", "1 INVITE").await;
    peer.send(
        &ack_for(&ok, me, "closer", 1).replace("SIP/2.0/UDP", "SIP/2.0/TCP"),
    )
    .await;
    let bye = in_dialog("BYE", "TCP", &ok, me, "closer", 2);
    peer.send(&bye).await;
    peer.recv_answer("SIP/2.0 200", "2 BYE").await;
    let shutdown =
        handle.shutdown(ShutdownMode::DrainExisting, Duration::from_secs(10));
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(endpoint.shutdown(Duration::from_millis(100)));
    let report = report_within(shutdown, Duration::from_secs(1)).await;
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
}

/// An endpoint that another of its handles stops at once leaves the UA
/// before it is done, which its report says, with the session it still had.
#[tokio::test]
async fn an_endpoint_stopped_elsewhere_is_reported_as_lost() {
    let (mut ua, udp, _, endpoint) = brisk_with(config());
    let handle = ua.handle.clone();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    call_from(&peer, udp, &mut ua.events, "lost").await;

    let shutdown =
        handle.shutdown(ShutdownMode::DrainExisting, Duration::from_secs(10));
    endpoint.shutdown(Duration::ZERO).await;
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    assert_eq!(report.outcome, ShutdownOutcome::EndpointLost);
    assert_eq!(report.sessions_left, 1);
}

/// A timeout too long to add to the clock sets no deadline, rather than
/// panic, and a UA with nothing to do drains at once. An INVITE asked for
/// once the UA shuts down is refused with nothing sent.
#[tokio::test]
async fn a_shutdown_timeout_past_the_clock_sets_no_deadline() {
    let (ua, _, _, _) = brisk_with(config());
    let Ua { handle, driver, .. } = ua;
    tokio::spawn(driver);

    let shutdown = handle.shutdown(ShutdownMode::Terminate, Duration::MAX);
    let refused = handle.try_invite(plan_to("127.0.0.1:9", "late"));
    let report = report_within(shutdown, Duration::from_secs(2)).await;

    assert_eq!(refused.unwrap_err().error(), Error::Closed);
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
}
