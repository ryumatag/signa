/*!
Each write on a port learns how it ended, by the port's sequence of writes.
*/

use std::{io, time::Duration};

use bytes::Bytes;
use signa_core::endpoint::{Endpoint, Error, ShutdownOutcome};
use tokio::{task::JoinHandle, time::timeout};

use crate::datagram::{
    port::{intercept, upstream},
    send_options, unknown,
    wire::{Wire, Writes},
};

// The port numbers every write, the endpoints' and its raw sends, in one
// sequence of its own, and sends each outcome back to the write that made it.
// The wire here reports three writes in reverse order and fails the middle
// one, and only its sender sees the failure.
#[tokio::test]
async fn each_write_outcome_goes_back_to_its_own_write() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);

    let raw = port.send_bytes(Bytes::from_static(b"raw"), &upstream).unwrap();
    wire.sent(1).await;
    let from_a = send_options(&a, "a");
    wire.sent(2).await;
    let from_b = send_options(&b, "b");
    wire.sent(3).await;
    wire.finish_newest(Ok(()));
    wire.finish_newest(Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "down",
    )));
    wire.finish_newest(Ok(()));

    assert!(from_b.await.unwrap().is_ok());
    assert!(from_a.await.unwrap().unwrap_err().is_transport());
    raw.await.unwrap();
}

// What a raw write's waiter learns, for each way it can end. A write the
// wire reports written is `Ok`. One it reports failed, and one the port
// never offered before a forced close, did not go out. One the wire reports
// unknown, and one it held unreported through a forced close, may have.
#[tokio::test]
async fn a_raw_write_tells_a_failure_from_an_unknown_outcome() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);
    let send = || port.send_bytes(Bytes::from_static(b"raw"), &upstream);

    let written = send().unwrap();
    let failed = send().unwrap();
    let unknown_write = send().unwrap();
    wire.sent(3).await;
    wire.finish(Ok(()));
    wire.finish(Err(io::Error::new(io::ErrorKind::NotConnected, "link down")));
    wire.finish(unknown());

    written.await.unwrap();
    let error = failed.await.unwrap_err();
    assert!(error.is_transport() && !error.is_outcome_unknown());
    let error = unknown_write.await.unwrap_err();
    assert!(error.is_outcome_unknown() && !error.is_transport());

    let taken = send().unwrap();
    wire.sent(4).await;
    wire.writes(Writes::Hold);
    let held = send().unwrap();
    wire.until(|state| state.submit.is_some()).await;
    wire.state.lock().unwrap().stuck = true;
    let close = port.close(Duration::from_millis(50));
    let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(taken.await.unwrap_err().is_outcome_unknown());
    assert!(held.await.unwrap_err().is_transport());
}

// An endpoint on a port learns the same of its writes as over a wire of its
// own: written, failed, or unknown, as the port's wire reported them.
#[tokio::test]
async fn an_endpoint_on_a_port_learns_each_write_outcome() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);

    let written = send_options(&endpoint, "written");
    wire.sent(1).await;
    let failed = send_options(&endpoint, "failed");
    wire.sent(2).await;
    let unknown_write = send_options(&endpoint, "unknown");
    wire.sent(3).await;
    wire.finish(Ok(()));
    wire.finish(Err(io::Error::new(io::ErrorKind::NotConnected, "link down")));
    wire.finish(unknown());

    async fn outcome(
        write: JoinHandle<Result<(), Error>>,
    ) -> Result<(), Error> {
        timeout(Duration::from_secs(2), write).await.unwrap().unwrap()
    }
    outcome(written).await.unwrap();
    let error = outcome(failed).await.unwrap_err();
    assert!(error.is_transport() && !error.is_outcome_unknown());
    let error = outcome(unknown_write).await.unwrap_err();
    assert!(error.is_outcome_unknown() && !error.is_transport());
}
