/*!
The sender wrappers see every response the TU submits and none signa sends
on its own.
*/

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use signa_core::endpoint::{ResponseSubmission, ShutdownOutcome, SubmitError};
use tokio::time::timeout;
use tower::ServiceBuilder;

use crate::tower::{
    Harness, LIMITS,
    adapter::{CountLayer, Log, ObserveLayer, Observing, Outcome},
    observe_end,
};

#[tokio::test]
async fn wrappers_see_every_submission_and_no_protocol_output() {
    let log = Log::default();
    let count = Arc::new(AtomicUsize::new(0));
    let layers = ServiceBuilder::new()
        .layer(ObserveLayer(log.clone()))
        .layer(CountLayer(count.clone()));
    let (mut harness, dispatching) = Harness::start(LIMITS, layers);
    let uac = harness.uac().await;
    let invite = uac.request("INVITE", "answer", "observed", "-inv", None);

    uac.send(&invite).await;
    assert_eq!(uac.until(180).await, [100]);
    // A retransmission gets the 180 again, from the transaction.
    uac.send(&invite).await;
    assert_eq!(uac.status().await, 180);
    let mut tags = Vec::new();
    while tags.len() < 2 {
        let ok = uac.next(Duration::from_secs(2)).await.expect("a 2xx");
        assert_eq!(ok.status().as_u16(), 200);
        tags.push(ok.headers().get("To").unwrap().as_str().to_owned());
    }
    assert_ne!(tags[0], tags[1], "two dialogs");
    uac.send(&uac.request("ACK", "answer", "observed", "-ack", Some("a")))
        .await;
    let events = timeout(Duration::from_secs(2), harness.finished.recv())
        .await
        .unwrap()
        .unwrap();

    // The 100 and the retransmitted 180 never went through the wrappers.
    // The 183 after the 2xx was refused, and the observer saw that too.
    assert_eq!(
        log.entries(),
        [
            (180, Outcome::Accepted),
            (200, Outcome::Accepted),
            (200, Outcome::Accepted),
            (183, Outcome::Refused(SubmitError::FinalAlreadySent)),
        ]
    );
    assert_eq!(count.load(Ordering::SeqCst), 4);
    assert_eq!(harness.acks.load(Ordering::SeqCst), 1);

    // The handler has returned, and the transaction is still in Accepted
    // until Timer L.
    assert!(
        timeout(Duration::from_millis(200), observe_end(events))
            .await
            .is_err()
    );
    let outcome = harness.endpoint.shutdown(Duration::from_secs(10)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    let stats = dispatching.await.unwrap();
    assert_eq!(stats.handler_errors, 0);
}

/// The submission futures a wrapper composes are `Send` and `Unpin`.
#[test]
fn submissions_are_send_and_unpin() {
    fn check<T: Send + Unpin>() {}
    check::<ResponseSubmission<'static>>();
    check::<Observing<ResponseSubmission<'static>>>();
}
