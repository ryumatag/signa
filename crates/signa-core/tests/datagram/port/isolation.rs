/*!
Endpoints on one port keep their own transactions and paths, a port refuses
the endpoints and paths of another, and an endpoint that stops leaves the
port to the others.
*/

use std::time::Duration;

use bytes::Bytes;
use signa_core::{
    Request,
    endpoint::{
        Endpoint, PathSelection, ShutdownOutcome, Target, port::DatagramPort,
    },
};
use tokio::{task::yield_now, time::timeout};

use crate::{
    datagram::{
        LOCAL, PEER, datagram, ok, options, outgoing,
        port::{intercept, next, upstream},
        send_options, short_timers, status,
        wire::{Wire, Writes},
    },
    support::request,
};

// Two endpoints on one port are two network domains. The same request
// delivered to each makes a transaction in each, and each answers it. A path
// one endpoint prepared is refused by the other. When one stops, the other
// goes on, and the stopped one refuses a delivery and hands it back.
#[tokio::test]
async fn endpoints_on_one_port_stay_apart() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let bind =
        || Endpoint::builder().timers(short_timers()).bind_on(&port).unwrap();
    let (a, mut a_incoming, to_a) = bind();
    let (b, mut b_incoming, to_b) = bind();

    for (to, incoming) in [(&to_a, &mut a_incoming), (&to_b, &mut b_incoming)]
    {
        wire.deliver(datagram(options("both")));
        next(&mut ingress).await.try_deliver(to).unwrap();
        let request = request(incoming).await;
        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request)).await.unwrap();
    }
    let sent = wire.sent(2).await;
    assert_eq!(sent.iter().map(status).collect::<Vec<_>>(), [200, 200]);

    let path = a.prepare_path(PathSelection::new(LOCAL, PEER)).await.unwrap();
    let refused =
        b.start(outgoing("stale"), Target::on_path(path)).await.unwrap_err();
    assert!(refused.is_stale_path());

    let outcome = a.shutdown(Duration::from_secs(2)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    wire.deliver(datagram(options("after")));
    let refused = next(&mut ingress).await.try_deliver(&to_a).unwrap_err();
    assert!(refused.error().is_closed());
    refused.into_datagram().try_deliver(&to_b).unwrap();
    let request = request(&mut b_incoming).await;
    assert_eq!(request.request.headers().get("Call-ID").unwrap(), "after");
}

// A datagram goes only to an endpoint or along a path of the port that
// received it. One of another port is foreign, and the datagram comes back
// with its disposition, so it can still go where it belongs.
#[tokio::test]
async fn a_port_refuses_the_targets_of_another_port() {
    let (wire, other_wire) = (Wire::default(), Wire::default());
    let (port, mut ingress) = intercept(&wire);
    let (other, _other_ingress) = intercept(&other_wire);
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let (_stranger, _, to_stranger) =
        Endpoint::builder().bind_on(&other).unwrap();
    let foreign_path = upstream(&other).await;
    wire.deliver(datagram(options("foreign")));
    let held = next(&mut ingress).await;

    let refused = held.try_deliver(&to_stranger).unwrap_err();
    assert!(refused.error().is_foreign());
    let refused = refused.into_datagram().try_forward(&foreign_path);
    let refused = refused.unwrap_err();
    assert!(refused.error().is_foreign());
    assert_eq!(
        refused.error().to_string(),
        "the endpoint ingress or path belongs to another port"
    );
    let raw = Bytes::from_static(b"raw");
    let error = port.send_bytes(raw, &foreign_path).unwrap_err();
    assert!(error.is_foreign());

    refused.into_datagram().try_deliver(&to_endpoint).unwrap();
    let taken = request(&mut incoming).await;
    assert_eq!(taken.request.headers().get("Call-ID").unwrap(), "foreign");
    assert_eq!(port.stats().delivered, 1);
    assert_eq!(other_wire.count(), 0);
}

// An endpoint that stops at its deadline leaves unsent the writes the port
// still queues for it, and its outcome is an expiry. A write the backend had
// taken could not be taken back, but this one never reached it. The other
// endpoint's writes go out once the wire takes them.
#[tokio::test]
async fn an_endpoint_that_stops_withdraws_its_queued_writes() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Hold);

    let from_a = send_options(&a, "a");
    wire.until(|state| state.submit.is_some()).await;
    let outcome = a.shutdown(Duration::from_millis(50)).await;
    let from_b = send_options(&b, "b");
    yield_now().await;
    wire.writes(Writes::Complete);

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    assert!(from_a.await.unwrap().is_err());
    assert!(from_b.await.unwrap().is_ok());
    let sent = wire.sent(1).await;
    assert_eq!(sent.len(), 1);
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(request.headers().get("Call-ID").unwrap(), "b");
}

// A port takes as many endpoints as it is configured for, and one more once
// an endpoint has stopped and ended its registration.
#[tokio::test]
async fn registrations_are_bounded() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire)
        .max_registrations(1)
        .intercept()
        .unwrap();
    let (first, _first_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();

    assert!(Endpoint::builder().bind_on(&port).unwrap_err().is_busy());
    let outcome = first.shutdown(Duration::from_secs(1)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    yield_now().await;
    assert!(Endpoint::builder().bind_on(&port).is_ok());
}

// An endpoint stopped at its deadline leaves the port to the others. A write
// of its that the wire took before may still go out, and the wire's late
// report of it reaches nobody: not the sibling still running, and not an
// endpoint registered after the stop, whose own first write has the same
// local ID as the stopped endpoint's.
#[tokio::test]
async fn a_forced_stop_leaves_the_port_to_the_other_endpoints() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (stopping, _stopping_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    let (sibling, _sibling_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);
    let from_stopping = send_options(&stopping, "stopping");
    wire.sent(1).await;

    let stopped =
        timeout(Duration::from_secs(2), stopping.shutdown(Duration::ZERO))
            .await
            .unwrap();

    assert_eq!(stopped, ShutdownOutcome::DeadlineExpired);
    let (late, _late_incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    let mut from_late = send_options(&late, "late");
    wire.sent(2).await;
    let from_sibling = send_options(&sibling, "sibling");
    wire.sent(3).await;
    wire.finish(Ok(()));
    assert!(
        timeout(Duration::from_millis(50), &mut from_late).await.is_err(),
        "the stopped endpoint's outcome reached a later one"
    );
    wire.finish(Ok(()));
    wire.finish(Ok(()));
    let outcome = |write| timeout(Duration::from_secs(2), write);
    assert!(outcome(from_late).await.unwrap().unwrap().is_ok());
    assert!(outcome(from_sibling).await.unwrap().unwrap().is_ok());
    assert!(outcome(from_stopping).await.unwrap().unwrap().is_err());
}
