/*!
A graceful shutdown waits for the writes on the wire, then closes it, and at
its deadline fails what is left and drops a backend that does not close.
*/

use std::{pin::pin, sync::Arc, time::Duration};

use signa_core::{
    endpoint::{ShutdownOutcome, Target, ViaMode},
    transport::Transport,
};
use tokio::time::timeout;

use crate::datagram::{
    PEER, bind, outgoing,
    wire::{Wire, Writes},
};

// A graceful shutdown waits for the writes on the wire to complete, then
// closes the backend.
#[tokio::test]
async fn shutdown_drains_the_wire_then_closes_it() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    wire.writes(Writes::Delay);
    let target = Target::new(Transport::Udp, PEER);
    let mut send = pin!(endpoint.send_request(
        outgoing("drain"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut send => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }

    let mut shutdown = pin!(endpoint.clone().shutdown(Duration::from_secs(5)));
    assert!(timeout(Duration::from_millis(50), &mut shutdown).await.is_err());
    assert!(!wire.closed());
    wire.finish(Ok(()));

    let outcome = timeout(Duration::from_secs(2), shutdown).await.unwrap();
    assert_eq!(outcome, ShutdownOutcome::Drained);
    assert!(wire.closed());
    send.await.unwrap();
}

// At the deadline, a write the wire never took fails as closed, and one it
// took fails as the backend reports it on close.
#[tokio::test]
async fn the_deadline_fails_what_is_left_and_closes_the_wire() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);
    wire.writes(Writes::Delay);
    let mut taken = pin!(endpoint.send_request(
        outgoing("taken"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut taken => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }
    wire.writes(Writes::Hold);
    let held = endpoint.send_request(
        outgoing("held"),
        target.clone(),
        ViaMode::Fresh,
    );
    let mut held = pin!(held);
    assert!(timeout(Duration::from_millis(50), &mut held).await.is_err());

    let outcome = timeout(
        Duration::from_secs(2),
        endpoint.clone().shutdown(Duration::from_millis(100)),
    )
    .await
    .unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(wire.closed());
    assert!(held.await.unwrap_err().is_closed());
    assert!(taken.await.unwrap_err().is_transport());
}

// A backend that never finishes closing cannot hold the shutdown past its
// deadline. The endpoint drops it, and the write it held fails as closed.
#[tokio::test]
async fn a_stuck_close_is_dropped_at_the_deadline() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);
    wire.writes(Writes::Delay);
    wire.state.lock().unwrap().stuck = true;
    let mut send = pin!(endpoint.send_request(
        outgoing("stuck"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut send => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }

    let outcome = timeout(
        Duration::from_secs(2),
        endpoint.clone().shutdown(Duration::from_millis(100)),
    )
    .await
    .unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(wire.closed());
    assert_eq!(Arc::strong_count(&wire.state), 1, "the backend is dropped");
    assert!(send.await.unwrap_err().is_closed());
}
