/*!
A handler's end is not its transaction's end.
*/

use std::time::Duration;

use tokio::time::{Instant, timeout};
use tower::{ServiceBuilder, layer::util::Identity};

use crate::tower::{Harness, LIMITS, observe_end};

#[tokio::test]
async fn handler_end_comes_before_transaction_end() {
    let (mut harness, dispatching) = Harness::start(LIMITS, Identity::new());
    let uac = harness.uac().await;

    uac.send(&uac.request("INVITE", "answer", "lifetimes", "-l", None)).await;
    uac.until(200).await;
    uac.send(&uac.request("ACK", "answer", "lifetimes", "-l-ack", Some("a")))
        .await;
    let events = timeout(Duration::from_secs(2), harness.finished.recv())
        .await
        .unwrap()
        .unwrap();
    let returned = Instant::now();

    timeout(Duration::from_secs(5), observe_end(events)).await.unwrap();

    // Timer L is 64 T1 after the 2xx, about 1.2 s after the handler returned.
    assert!(returned.elapsed() > Duration::from_millis(500));
    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    dispatching.await.unwrap();
}

#[tokio::test]
async fn a_tower_timeout_drops_the_handler_but_cancels_nothing() {
    // The timeout ends the handler's future. Its responder drops unanswered,
    // which is signa's 500, not a CANCEL and not the end of the transaction.
    let layers = ServiceBuilder::new().timeout(Duration::from_millis(100));
    let (harness, dispatching) = Harness::start(LIMITS, layers);
    let uac = harness.uac().await;

    uac.send(&uac.request("INVITE", "stall", "timeout", "-t", None)).await;

    assert_eq!(uac.until(500).await, [100]);
    uac.send(&uac.request("ACK", "stall", "timeout", "-t", Some("x"))).await;
    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    let stats = dispatching.await.unwrap();
    assert_eq!(stats.handler_errors, 1);
}
