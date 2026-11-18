/*!
A transaction settles once its machine has terminated and every write it
started has ended, apart from the end of its observation, and when the
endpoint stops first.
*/

use std::{io, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, ServerEvent, ShutdownOutcome, Target},
    transport::{
        Limits, Transport,
        datagram::{Datagram, RecvError},
    },
};
use tokio::time::timeout;

use crate::{
    datagram::{
        LOCAL, PEER, bind, datagram, invite, method, ok, options, outgoing,
        outgoing_invite, short_timers,
        wire::{Wire, Writes},
    },
    support::request,
};

/// A response from `PEER` to `request`, which the wire sent.
fn reply(request: &[u8], status: u16) -> Result<Datagram, RecvError> {
    let request = Request::from_bytes(request).unwrap();
    let response = Response::reply_to(&request)
        .status(status)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    Ok(Datagram::new(response.to_bytes(), PEER, LOCAL))
}

// Timer J ends the machine while the wire still holds the final's write.
// The settlement waits for that write and counts its failure, which the
// observation reports after `Terminated`.
#[tokio::test(start_paused = true)]
async fn a_server_settles_after_a_write_that_fails_late() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .bind()
        .unwrap();
    wire.deliver(datagram(options("late")));
    let request = request(&mut incoming).await;
    let settlement = request.transaction.settlement();
    let (responder, mut events) = request.transaction.into_parts();

    let before = wire.count();
    wire.writes(Writes::Delay);
    responder.respond(ok(&request.request)).await.unwrap();
    wire.sent(before + 1).await;

    assert!(matches!(events.next().await, Some(ServerEvent::Terminated)));
    assert_eq!(settlement.get(), None);
    let pending = timeout(Duration::from_secs(60), settlement.wait()).await;
    assert!(pending.is_err(), "the write is still out");

    let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
    wire.finish(Err(refused));
    let settled = settlement.wait().await;

    assert!(settled.is_drained());
    assert_eq!(settled.not_written(), 1);
    assert_eq!(settled.abandoned(), 0);
    assert_eq!(settled.written() as usize, before);
    assert!(matches!(
        events.next().await,
        Some(ServerEvent::TransportFailure { .. })
    ));
    assert!(events.next().await.is_none());
    assert_eq!(settlement.get(), Some(settled));
}

// A response stream that ends, with its final or an overflow, leaves the
// machine to retransmit and acknowledge. The settlement resolves after
// Timer K, or after Timer D with the ACK counted.
#[tokio::test(start_paused = true)]
async fn a_client_settles_after_its_responses_end() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .client_response_limits(Limits { count: 1, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, PEER);

    let options = endpoint.start(outgoing("k"), target.clone()).await.unwrap();
    let settlement = options.settlement();
    let (_control, mut responses) = options.into_parts();
    let sent = wire.sent(1).await;
    wire.deliver(reply(&sent[0].payload, 200));
    responses.next().await.unwrap().unwrap();
    assert!(responses.next().await.is_none());
    assert_eq!(settlement.get(), None, "Timer K keeps the machine");

    let settled = settlement.wait().await;
    assert!(settled.is_drained());
    assert!(settled.written() >= 1);
    assert_eq!(settled.not_written(), 0);

    // Two provisionals overflow a stream that holds one, and the stream ends
    // while the INVITE goes on to its final and its ACK.
    let before = wire.count();
    let invite = endpoint.start(outgoing_invite("d"), target).await.unwrap();
    let settlement = invite.settlement();
    let (_control, mut responses) = invite.into_parts();
    let sent = wire.sent(before + 1).await;
    let request = sent[before].payload.clone();
    wire.deliver(reply(&request, 180));
    wire.deliver(reply(&request, 183));
    assert_eq!(
        responses.next().await.unwrap().unwrap().response.status().as_u16(),
        180
    );
    let overflow = responses.next().await.unwrap().unwrap_err();
    assert!(overflow.is_delivery_overflow());
    assert!(responses.next().await.is_none());

    wire.deliver(reply(&request, 486));
    assert_eq!(settlement.get(), None, "Timer D keeps the machine");
    let settled = settlement.wait().await;
    assert!(settled.is_drained());
    assert_eq!(settled.written(), 2, "the INVITE and its ACK");
    let ack = wire.sent(wire.count()).await.into_iter().skip(before);
    assert_eq!(
        ack.filter(|sent| method(sent).as_deref() == Some("ACK")).count(),
        1
    );
}

// Waiting is not the transaction's business. A dropped wait, and dropped
// handles, leave the machine to end on its own, and another settlement
// still sees it drain.
#[tokio::test(start_paused = true)]
async fn a_dropped_waiter_cancels_nothing() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let transaction = endpoint.start(outgoing("drop"), target).await.unwrap();
    let settlement = transaction.settlement();
    let other = settlement.clone();
    drop(transaction);

    let waited = timeout(Duration::from_millis(1), settlement.wait()).await;
    assert!(waited.is_err());
    drop(settlement);
    let sent = wire.sent(1).await;
    wire.deliver(reply(&sent[0].payload, 200));

    let settled = other.wait().await;
    assert!(settled.is_drained());
    assert_eq!(settled.abandoned(), 0);
}

// A shutdown deadline drops an INVITE in Accepted, gives up on a final the
// wire took and never reported, since its close is stuck, and on a request
// the wire never took. All settle as closed, with the two writes abandoned,
// and the observation ends with the endpoint closed.
#[tokio::test(start_paused = true)]
async fn a_forced_close_settles_what_is_left() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    wire.deliver(datagram(invite("accepted")));
    let accepted = request(&mut incoming).await;
    let server = accepted.transaction.settlement();
    let (responder, _) = accepted.transaction.into_parts();
    responder.respond(ok(&accepted.request)).await.unwrap();
    wire.sent(2).await; // The automatic 100 and the 2xx.

    wire.writes(Writes::Delay);
    wire.deliver(datagram(options("unreported")));
    let options = request(&mut incoming).await;
    let unreported = options.transaction.settlement();
    let (responder, mut events) = options.transaction.into_parts();
    responder.respond(ok(&options.request)).await.unwrap();
    wire.sent(3).await;

    wire.writes(Writes::Hold);
    let target = Target::new(Transport::Udp, PEER);
    let held = endpoint.start(outgoing("held"), target).await.unwrap();
    let client = held.settlement();
    wire.until(|state| state.submit.is_some()).await;

    wire.state.lock().unwrap().stuck = true;
    let outcome = endpoint.shutdown(Duration::from_millis(10)).await;

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    let server = server.wait().await;
    assert!(!server.is_drained());
    assert_eq!((server.written(), server.abandoned()), (2, 0));
    let client = client.wait().await;
    assert!(!client.is_drained());
    assert_eq!((client.written(), client.abandoned()), (0, 1));
    let unreported = unreported.wait().await;
    assert!(!unreported.is_drained());
    assert_eq!((unreported.written(), unreported.abandoned()), (0, 1));
    assert!(matches!(events.next().await, Some(ServerEvent::EndpointClosed)));
}
