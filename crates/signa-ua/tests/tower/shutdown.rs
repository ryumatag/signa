/*!
A shutdown of the UA and the work of the adapter. The UA's drain waits for
the decisions the handlers hold, a termination takes them, and once the UA
has stopped the adapter aborts its handlers and returns. Nothing reaches the
wire after the UA's report.
*/

use std::{convert::Infallible, sync::Arc, time::Duration};

use signa_ua::{Error, IncomingInvite, ShutdownMode, ShutdownOutcome};
use tokio::{sync::mpsc, time::timeout};
use tower::{Service, service_fn};

use crate::{
    support::{
        WAIT, brisk_with, config,
        events::report_within,
        message::{ack_for, direct_invite, header, in_dialog, sdp},
        peer::Peer,
    },
    tower::{Gate, Serving},
};

/// A handler that holds each INVITE until the gate opens, then accepts it,
/// and sends what came of that.
fn gated(
    gate: Gate,
    decided: mpsc::UnboundedSender<Result<(), Error>>,
) -> impl Service<IncomingInvite, Response = (), Error = Infallible, Future: Send>
+ Send
+ 'static {
    service_fn(move |invite: IncomingInvite| {
        let (gate, decided) = (gate.clone(), decided.clone());
        async move {
            gate.passed().await;
            let decision = match invite.try_accept(sdp()) {
                Ok(accepted) => accepted.await.map(drop),
                Err(refused) => Err(refused.error()),
            };
            decided.send(decision).unwrap();
            Ok(())
        }
    })
}

/// A drain waits for the decision a handler holds, and the session it
/// makes, which the peer then ends. The UA drains, and the adapter ends with
/// it, with no handler left to abort. At the deadline instead, with a
/// handler that never decides, the endpoint stops first, then the UA lets
/// go of the INVITE and the adapter aborts the handler. Nothing goes on the
/// wire after the report, the 500 of a dropped decision included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_waits_for_or_aborts_tracked_adapter_work() {
    let (ua, udp, _, _) = brisk_with(config());
    let (gate, (decided, mut decisions)) =
        (Gate::new(), mpsc::unbounded_channel());
    let serving = Serving::start(ua, gated(gate.clone(), decided));
    let peer = Peer::new().await;
    let me = peer.address();
    peer.send(&direct_invite(me, "decided"), udp).await;
    peer.recv_starting("SIP/2.0 100").await;

    let mut shutdown = serving
        .handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_secs(10));
    let waiting = timeout(Duration::from_millis(300), &mut shutdown).await;
    assert!(waiting.is_err(), "{waiting:?}");
    gate.open();
    assert_eq!(timeout(WAIT, decisions.recv()).await.unwrap(), Some(Ok(())));
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, me, "decided", 1), udp).await;
    peer.send(&in_dialog("BYE", "UDP", &ok, me, "decided", 2), udp).await;
    let report = report_within(shutdown, Duration::from_secs(5)).await;
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    let served = timeout(WAIT, serving.adapter).await.unwrap().unwrap();
    assert_eq!((served.calls, served.completed, served.aborted), (1, 1, 0));

    let (ua, udp, _, _) = brisk_with(config());
    let held = Arc::new(());
    let handler = {
        let held = held.clone();
        service_fn(move |invite: IncomingInvite| {
            let held = held.clone();
            async move {
                let _undecided = (invite, held);
                std::future::pending::<Result<(), Infallible>>().await
            }
        })
    };
    let serving = Serving::start(ua, handler);
    let peer = Peer::new().await;
    peer.send(&direct_invite(peer.address(), "never"), udp).await;
    peer.recv_starting("SIP/2.0 100").await;
    while Arc::strong_count(&held) < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let shutdown = serving
        .handle
        .shutdown(ShutdownMode::DrainExisting, Duration::from_millis(300));
    let report = report_within(shutdown, Duration::from_secs(2)).await;
    assert_eq!(report.outcome, ShutdownOutcome::DeadlineExpired);
    assert_eq!(report.invites_left, 1);
    let served = timeout(WAIT, serving.adapter).await.unwrap().unwrap();
    assert_eq!((served.calls, served.aborted), (1, 1));
    // The handler's future is gone, which is the adapter's abort. The
    // endpoint stopped first, so nothing it held could reach the wire.
    assert_eq!(Arc::strong_count(&held), 1);
    peer.quiet("SIP/2.0", Duration::from_millis(500)).await;
}

/// A termination answers the INVITE a handler holds with a 503, so the
/// decision the handler makes after that is refused, and sends nothing. The UA
/// drains, and the adapter's handler has ended by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_termination_takes_the_decision_a_handler_holds() {
    let (ua, udp, _, _) = brisk_with(config());
    let (gate, (decided, mut decisions)) =
        (Gate::new(), mpsc::unbounded_channel());
    let serving = Serving::start(ua, gated(gate.clone(), decided));
    let peer = Peer::new().await;
    peer.send(&direct_invite(peer.address(), "taken"), udp).await;
    peer.recv_starting("SIP/2.0 100").await;

    let shutdown = serving
        .handle
        .shutdown(ShutdownMode::Terminate, Duration::from_secs(10));
    let (unavailable, _) = peer.recv_starting("SIP/2.0 503").await;
    assert_eq!(header(&unavailable, "Call-ID"), ["taken"]);
    gate.open();
    // The 503 is out, so the UA is done with the INVITE. A decision while
    // the 503 was still on its way would have found it under way instead.
    let late = timeout(WAIT, decisions.recv()).await.unwrap().unwrap();
    assert!(
        matches!(late, Err(Error::StaleDecision | Error::AlreadyFinalized)),
        "{late:?}"
    );

    let report = report_within(shutdown, Duration::from_secs(5)).await;
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    let served = timeout(WAIT, serving.adapter).await.unwrap().unwrap();
    assert_eq!((served.calls, served.completed, served.aborted), (1, 1, 0));
    peer.quiet("SIP/2.0 200", Duration::from_millis(200)).await;
}
