/*!
The control lane keeps ACK and CANCEL moving while ordinary handlers wait,
and the dispatcher keeps its handlers and buffered calls within its limits.
*/

use std::{sync::atomic::Ordering, time::Duration};

use tokio::time::{sleep, timeout};
use tower::layer::util::Identity;

use crate::tower::{Harness, LIMITS, cseq_method, dispatch::Limits};

#[tokio::test]
async fn acks_progress_while_every_handler_waits_for_one() {
    let limits = Limits { handlers: 2, ..LIMITS };
    let (mut harness, dispatching) = Harness::start(limits, Identity::new());
    let uacs = [harness.uac().await, harness.uac().await, harness.uac().await];

    // Two handlers take the only two slots and wait for their ACKs. The third
    // INVITE waits in the queue.
    for (n, uac) in uacs.iter().enumerate() {
        uac.send(&uac.request(
            "INVITE",
            "answer",
            &format!("busy-{n}"),
            &format!("-b{n}"),
            None,
        ))
        .await;
    }
    for uac in &uacs[..2] {
        uac.until(200).await;
    }
    assert_eq!(uacs[2].until(100).await, Vec::<u16>::new());
    assert!(uacs[2].next(Duration::from_millis(300)).await.is_none());
    assert_eq!(harness.usage.running.load(Ordering::SeqCst), 2);

    // Their ACKs go through the control lane and free the slots.
    for (n, uac) in uacs[..2].iter().enumerate() {
        uac.send(&uac.request(
            "ACK",
            "answer",
            &format!("busy-{n}"),
            &format!("-b{n}-ack"),
            Some("a"),
        ))
        .await;
    }
    uacs[2].until(200).await;
    uacs[2]
        .send(&uacs[2].request(
            "ACK",
            "answer",
            "busy-2",
            "-b2-ack",
            Some("a"),
        ))
        .await;
    for _ in 0..3 {
        timeout(Duration::from_secs(2), harness.finished.recv())
            .await
            .unwrap();
    }

    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    let stats = dispatching.await.unwrap();
    assert_eq!(stats.most_handlers, 2);
    assert_eq!(harness.usage.most_running.load(Ordering::SeqCst), 2);
    let usage = &harness.usage;
    assert_eq!(usage.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        usage.readies.load(Ordering::SeqCst),
        3,
        "one readiness per call"
    );
    assert_eq!(harness.acks.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_cancel_is_answered_while_the_request_service_is_not_ready() {
    let (mut harness, dispatching) = Harness::start(LIMITS, Identity::new());
    harness.gate.closed.store(true, Ordering::SeqCst);
    let uac = harness.uac().await;

    uac.send(&uac.request("INVITE", "ring", "gated", "-g", None)).await;
    assert_eq!(uac.status().await, 100);
    uac.send(&uac.request("CANCEL", "ring", "gated", "-g", None)).await;
    let ok = uac.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!((ok.status().as_u16(), cseq_method(&ok)), (200, "CANCEL"));
    assert_eq!(
        harness.usage.calls.load(Ordering::SeqCst),
        0,
        "the INVITE waits"
    );

    harness.gate.open();
    let terminated = uac.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!(
        (terminated.status().as_u16(), cseq_method(&terminated)),
        (487, "INVITE")
    );
    uac.send(&uac.request("ACK", "ring", "gated", "-g", Some("a"))).await;
    timeout(Duration::from_secs(2), harness.finished.recv()).await.unwrap();

    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    dispatching.await.unwrap();
    let calls = harness.calls.lock();
    assert!(calls.cancels.is_empty() && calls.cancelled.is_empty());
}

#[tokio::test]
async fn buffered_calls_are_bounded_and_overflow_gets_a_503() {
    let limits = Limits { handlers: 1, queued: 1, ..LIMITS };
    let (mut harness, dispatching) = Harness::start(limits, Identity::new());
    let uacs = [harness.uac().await, harness.uac().await, harness.uac().await];

    for (n, uac) in uacs.iter().enumerate() {
        uac.send(&uac.request(
            "INVITE",
            "hold",
            &format!("hold-{n}"),
            &format!("-h{n}"),
            None,
        ))
        .await;
        // One at a time, so the first runs and the second waits in the queue
        // before the third arrives.
        assert_eq!(uac.status().await, 100);
        sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(uacs[2].status().await, 503);
    for uac in &uacs[..2] {
        harness.release.notify_one();
        assert_eq!(uac.until(200).await, Vec::<u16>::new());
        timeout(Duration::from_secs(2), harness.finished.recv())
            .await
            .unwrap();
    }

    harness.endpoint.shutdown(Duration::from_secs(10)).await;
    let stats = dispatching.await.unwrap();
    assert_eq!(
        (stats.most_handlers, stats.most_queued, stats.rejected),
        (1, 1, 1)
    );
}
