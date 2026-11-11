/*!
The lifetime of a handler is not that of anything in SIP. Its end is not the
final response, the ACK or the end of the dialog (RFC 3261 sections 13.3.1.4
and 15), and dropping it, by a Tower timeout or a panic, is neither a CANCEL
(section 9.1) nor a 487. An INVITE dropped with it undecided gets the UA's
500, and an INVITE the UA sent goes on.
*/

use std::{convert::Infallible, time::Duration};

use signa_ua::{
    EndReason, Error, Event, IncomingInvite, InvitePlan, Session, SessionPhase,
};
use tokio::{sync::mpsc, time::timeout};
use tower::{
    Service, ServiceBuilder, ServiceExt, service_fn, timeout::error::Elapsed,
};

use crate::{
    support::{
        WAIT, config,
        message::{
            ack_for, answer, direct_invite, header, in_dialog, invite_to_ua,
            offer_named, plan_to, reinvite_of, sdp,
        },
        peer::Peer,
        stand_in::Hosts,
        start_fast, start_fast_with,
    },
    tower::{Running, Serving},
};

/// Receives datagrams until the 200 that answers `cseq` comes.
async fn ok_for(peer: &Peer, cseq: &str) -> String {
    loop {
        let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
        if header(&ok, "CSeq") == [cseq] {
            return ok;
        }
    }
}

/// A handler accepts and ends, and the session goes on without it. Its 2xx
/// goes again until the ACK, a re-INVITE reaches a handler of its own, which
/// accepts it as well, and the peer's BYE ends the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_completion_does_not_end_dialog() {
    let (ua, udp, _) = start_fast();
    let (done, mut handled) = mpsc::unbounded_channel::<Session>();
    let running = Running::default();
    let handlers = running.clone();
    let handler = service_fn(move |invite: IncomingInvite| {
        let (done, running) = (done.clone(), handlers.clone());
        async move {
            let _running = running.enter();
            let session = invite.try_accept(sdp()).unwrap().await.unwrap();
            done.send(session).unwrap();
            Ok::<(), Infallible>(())
        }
    });
    let mut serving = Serving::start(ua, handler);
    let peer = Peer::new().await;
    let me = peer.address();

    peer.send(&direct_invite(me, "lasting"), udp).await;
    let ok = ok_for(&peer, "1 INVITE").await;
    let session = timeout(WAIT, handled.recv()).await.unwrap().unwrap();
    // Once the handler has ended, and what came before is read, the copies
    // of the 2xx go on.
    let started = tokio::time::Instant::now();
    while running.now() > 0 {
        assert!(started.elapsed() < WAIT, "the handler's end in time");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    peer.drain(Duration::from_millis(5)).await;
    assert_eq!(ok_for(&peer, "1 INVITE").await, ok);
    peer.send(&ack_for(&ok, me, "lasting", 1), udp).await;
    peer.drain(Duration::from_millis(60)).await;

    let offer = offer_named("again");
    peer.send(&reinvite_of(&ok, me, "lasting", 2, me, &offer), udp).await;
    let changed = timeout(WAIT, handled.recv()).await.unwrap().unwrap();
    let reok = ok_for(&peer, "2 INVITE").await;
    peer.send(&ack_for(&reok, me, "lasting", 2), udp).await;
    assert_eq!(changed, session);
    let snapshot = serving.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);
    assert_eq!(snapshot.session_revision, 2);

    peer.send(&in_dialog("BYE", "UDP", &ok, me, "lasting", 3), udp).await;
    ok_for(&peer, "3 BYE").await;
    let (ended, reason) = serving
        .notified(|event| match event {
            Event::Ended { session, reason, .. } => Some((session, reason)),
            _ => None,
        })
        .await;
    assert_eq!(ended, session);
    assert!(matches!(reason, EndReason::RemoteBye { .. }), "{reason:?}");
    let served = serving.stop().await;
    assert_eq!((served.calls, served.completed), (2, 2));
}

/// A Tower timeout drops a handler that holds an INVITE undecided. That is
/// a dropped decision, which gets the UA's 500, and no 487, which would say
/// the caller cancelled. The other way round, a timeout that drops the
/// operation of an INVITE the UA sends, or a handler that holds its attempt,
/// cancels nothing. Each INVITE goes out, the first once its next hop
/// resolves, the callee's 180 gets no CANCEL, and its 2xx gets the ACK.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_timeout_is_not_protocol_cancel() {
    let callee = Peer::new().await;
    let hosts = Hosts::new(callee.address());
    let resolved = hosts.gate.clone();
    let (ua, udp, _) = start_fast_with(config().resolver(hosts));
    let handler = ServiceBuilder::new()
        .timeout(Duration::from_millis(100))
        .service(service_fn(|invite: IncomingInvite| async move {
            let _undecided = invite;
            std::future::pending::<Result<(), Infallible>>().await
        }));
    let mut serving = Serving::start(ua, handler);
    let caller = Peer::new().await;

    caller.send(&invite_to_ua(caller.address(), "slow"), udp).await;
    let (dropped, _) = caller.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&dropped, "Call-ID"), ["slow"]);
    assert!(header(&dropped, "To")[0].contains(";tag="));
    caller.quiet("SIP/2.0 487", Duration::from_millis(300)).await;

    // The first INVITE's next hop waits for the gate, so its operation is
    // still under way when the timeout drops it. The second goes out at
    // once, and the timeout drops the handler that holds its attempt.
    let handle = serving.handle.clone();
    let mut calling = ServiceBuilder::new()
        .timeout(Duration::from_millis(100))
        .service(service_fn(move |plan: InvitePlan| {
            let handle = handle.clone();
            async move {
                let started = handle
                    .try_invite(plan)
                    .map_err(|refused| refused.error())?;
                let _attempt = started.await?;
                std::future::pending::<Result<(), Error>>().await
            }
        }));
    let contact = format!("sip:peer@{}", callee.address());
    for (to, call) in [
        ("gated.invalid".to_owned(), "given-up"),
        (callee.address().to_string(), "held"),
    ] {
        let calls = calling.ready().await.unwrap();
        let given_up = calls.call(plan_to(&to, call)).await;
        assert!(given_up.unwrap_err().is::<Elapsed>(), "{call}");
        resolved.notify_waiters();
        let (request, from) = callee.recv_starting("INVITE").await;
        assert_eq!(header(&request, "Subject"), [call]);
        callee.send(&answer(&request, "180", "callee", &contact), from).await;
        callee.quiet("CANCEL", Duration::from_millis(300)).await;
        callee.send(&answer(&request, "200", "callee", &contact), from).await;
        callee.recv_starting("ACK").await;
        let session = serving
            .notified(|event| match event {
                Event::Confirmed { session, .. } => Some(session),
                _ => None,
            })
            .await;
        let snapshot =
            serving.handle.snapshot(&session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established, "{call}");
        callee.quiet("CANCEL", Duration::from_millis(200)).await;
    }

    let served = serving.stop().await;
    assert_eq!((served.calls, served.failed), (1, 1));
}

/// A handler that panics while it holds an INVITE drops it as it unwinds,
/// which gets the UA's 500. The adapter counts the panic, and the UA and the
/// adapter go on with the next INVITE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_handler_is_a_dropped_decision() {
    let (ua, udp, _) = start_fast();
    let handler = service_fn(|invite: IncomingInvite| async move {
        if invite.request().headers().get("Call-ID").unwrap() == "panics" {
            panic!("a handler that fails as badly as it can");
        }
        invite.try_accept(sdp()).unwrap().await.unwrap();
        Ok::<(), Infallible>(())
    });
    let serving = Serving::start(ua, handler);
    let peer = Peer::new().await;
    let me = peer.address();

    peer.send(&invite_to_ua(me, "panics"), udp).await;
    let (dropped, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&dropped, "Call-ID"), ["panics"]);
    peer.send(&invite_to_ua(me, "after"), udp).await;
    let ok = ok_for(&peer, "1 INVITE").await;
    assert_eq!(header(&ok, "Call-ID"), ["after"]);
    peer.send(&ack_for(&ok, me, "after", 1), udp).await;

    assert!(!serving.driver.is_finished());
    let served = serving.stop().await;
    assert_eq!((served.calls, served.completed, served.panicked), (2, 1, 1));
}
