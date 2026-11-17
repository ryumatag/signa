/*!
An endpoint's observer, which sees each arrival before parsing and every
write with its stages.
*/

use std::{
    task::{Context, Waker},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{
        CancelOutcome, Endpoint, Target, ViaMode,
        observe::{
            self, Observed, Observer, Record, WriteEnd, WriteOrigin, WriteRef,
        },
    },
    message::header::Tag,
    transport::{
        Limits, Transport,
        datagram::{Datagram, TransportContext},
    },
};
use tokio::time::{sleep, timeout};

use crate::{
    datagram::{
        LOCAL, PEER, arriving, bind, datagram, invite, ok, options, outgoing,
        outgoing_invite, short_timers, status, unknown,
        wire::{Wire, Writes},
    },
    support::request,
};

/// The next record, which must come within two seconds.
pub(crate) async fn record(observer: &mut Observer) -> Record {
    timeout(Duration::from_secs(2), observer.recv())
        .await
        .expect("a record within two seconds")
        .expect("an attached observer")
}

/// The next record, which must be a write stage, with its write.
async fn stage(observer: &mut Observer) -> (WriteRef, Observed) {
    let record = record(observer).await;
    let write = match record.observed() {
        Observed::WriteStarted { write, .. }
        | Observed::WriteAccepted { write, .. }
        | Observed::WriteEnded { write, .. } => *write,
        other => panic!("a write stage, got {other:?}"),
    };
    (write, record.observed().clone())
}

/// Checks that the next three records are one write that started with an
/// origin `origin` accepts and with `cause`, was taken, and was written, and
/// returns its payload.
async fn written(
    observer: &mut Observer,
    origin: impl Fn(&WriteOrigin) -> bool,
    cause: Option<signa_core::transport::ReceiveId>,
) -> Bytes {
    let started = record(observer).await;
    let Observed::WriteStarted { write, origin: seen, cause: why, .. } =
        started.observed()
    else {
        panic!("a started write, got {started:?}");
    };
    assert!(origin(seen), "{seen:?}");
    assert_eq!(*why, cause);
    assert!(write.datagram().is_some());
    let (accepted, taken) = stage(observer).await;
    assert_eq!(accepted, *write);
    assert!(matches!(taken, Observed::WriteAccepted { .. }), "{taken:?}");
    let (ended, end) = stage(observer).await;
    assert_eq!(ended, *write);
    let Observed::WriteEnded { end, accepted, .. } = end else {
        panic!("an ended write, got {end:?}");
    };
    assert_eq!((end, accepted), (WriteEnd::Written, true));
    started.payload().cloned().unwrap_or_default()
}

// An observer sees each datagram as it arrived, before parsing, with the ID
// its envelope carries, and every write the endpoint makes of it: the
// automatic 100 and the cached response resent for a retransmission, which
// name the arrival they answer, and the TU's own response.
#[tokio::test]
async fn an_observer_sees_arrivals_and_every_write_they_cause() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let config = observe::Config::new().payload(4096).context(true);
    let mut observer = endpoint.observe(config).await.unwrap();
    // Compact names and extra spaces, which a re-encoding would change.
    let text = invite("observed")
        .replace("Call-ID:", "i:")
        .replace("CSeq: 1 INVITE", "CSeq:  1   INVITE");

    wire.deliver(arriving(text.clone(), "nic0"));
    let request = request(&mut incoming).await;
    let arrival = record(&mut observer).await;
    let Observed::Received { id, flow, .. } = arrival.observed() else {
        panic!("an arrival, got {arrival:?}");
    };
    assert_eq!(*id, request.received.id());
    assert_eq!(arrival.at(), request.received.received_at());
    assert_eq!((flow.remote, flow.local), (PEER, LOCAL));
    assert_eq!(arrival.payload().unwrap(), text.as_bytes());
    assert_eq!(arrival.context().unwrap().as_bytes(), "nic0");
    let (responder, _) = request.transaction.into_parts();
    let transaction = responder.id();
    let trying = written(
        &mut observer,
        |origin| {
            matches!(
                origin,
                WriteOrigin::Response { transaction: t, operation: None, .. }
                    if *t == transaction
            )
        },
        Some(*id),
    )
    .await;
    assert!(trying.starts_with(b"SIP/2.0 100 "));

    let busy = Response::reply_to(&request.request)
        .status(486)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap();
    let submission = responder.respond(busy);
    let operation = Some(submission.id());
    submission.await.unwrap();
    let final_response = written(
        &mut observer,
        |origin| {
            matches!(
                origin,
                WriteOrigin::Response { transaction: t, operation: o, .. }
                    if (*t, *o) == (transaction, operation)
            )
        },
        None,
    )
    .await;
    assert!(final_response.starts_with(b"SIP/2.0 486 "));

    wire.deliver(arriving(text, "nic1"));
    let again = record(&mut observer).await;
    let Observed::Received { id: again_id, .. } = again.observed() else {
        panic!("an arrival, got {again:?}");
    };
    assert_ne!(again_id, id);
    let resent = written(
        &mut observer,
        |origin| {
            matches!(
                origin,
                WriteOrigin::ResponseRetransmission { transaction: t, .. }
                    if *t == transaction
            )
        },
        Some(*again_id),
    )
    .await;
    assert_eq!(resent, final_response);
    assert_eq!(observer.stats(), observe::Stats::default());
}

// A client transaction's writes name it by the number its control gives:
// the request, its retransmissions, the ACK of its non-2xx final and its
// CANCEL's own transaction. A response that matches nothing is still seen
// arriving.
#[tokio::test(start_paused = true)]
async fn an_observer_names_client_writes_by_their_transaction() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .bind()
        .unwrap();
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (control, mut responses) = endpoint
        .start(outgoing_invite("client"), target)
        .await
        .unwrap()
        .into_parts();
    let transaction = control.number();

    let request_of = |number| {
        move |origin: &WriteOrigin| {
            matches!(origin, WriteOrigin::Request { transaction: t, .. }
                if *t == number)
        }
    };
    written(&mut observer, request_of(transaction), None).await;
    let retransmission = |origin: &WriteOrigin| {
        matches!(origin, WriteOrigin::RequestRetransmission { transaction: t, .. }
            if *t == transaction)
    };
    written(&mut observer, retransmission, None).await;

    let invite = Request::from_bytes(&wire.sent(1).await[0].payload).unwrap();
    let ringing = Response::reply_to(&invite)
        .status(180)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    wire.deliver(Ok(Datagram::new(ringing.to_bytes(), PEER, LOCAL)));
    let Observed::Received { id: ringing_id, .. } =
        *record(&mut observer).await.observed()
    else {
        panic!("an arrival");
    };
    let received = responses.next().await.unwrap().unwrap();
    assert_eq!(received.received.id(), ringing_id);

    let outcome = control.cancel().await.unwrap();
    let CancelOutcome::Sent(cancel) = outcome else {
        panic!("a CANCEL, got {outcome:?}");
    };
    let (cancel, _) = cancel.into_parts();
    assert_ne!(cancel.number(), transaction);
    written(&mut observer, request_of(cancel.number()), None).await;

    let declined = Response::reply_to(&invite)
        .status(487)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    wire.deliver(Ok(Datagram::new(declined.to_bytes(), PEER, LOCAL)));
    let Observed::Received { id: final_id, .. } =
        *record(&mut observer).await.observed()
    else {
        panic!("an arrival");
    };
    let ack = written(
        &mut observer,
        |origin| {
            matches!(origin, WriteOrigin::Ack { transaction: t, .. }
                if *t == transaction)
        },
        Some(final_id),
    )
    .await;
    assert!(ack.is_empty(), "no payload is copied by default");
}

// A full observer loses records, never what the protocol delivers. The
// response channel and the endpoint go on, the losses show in the stats and
// in the gap before the next record that fits, and a record keeps its share
// of the limits until the application drops it.
#[tokio::test]
async fn a_full_observer_loses_records_but_nothing_else() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let config = observe::Config::new().records(2).payload(64);
    let mut observer = endpoint.observe(config).await.unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) =
        endpoint.start(outgoing("full"), target).await.unwrap().into_parts();
    let request = Request::from_bytes(&wire.sent(1).await[0].payload).unwrap();

    // The request's three stages and the response's arrival, with room for
    // two records. The lost end of the write carries no message, so the
    // response is all the lost bytes.
    let ok = ok(&request).to_bytes();
    wire.deliver(Ok(Datagram::new(ok.clone(), PEER, LOCAL)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.response.status().as_u16(), 200);
    let stats = observer.stats();
    assert_eq!((stats.lost, stats.lost_bytes), (2, ok.len() as u64));

    let held = [record(&mut observer).await, record(&mut observer).await];
    let sequences: Vec<_> = held.iter().map(Record::sequence).collect();
    assert_eq!(sequences, [0, 1]);
    // The held records still fill the limits, so all three stages of this
    // write are lost.
    endpoint
        .send_request(
            outgoing("lost"),
            Target::new(Transport::Udp, PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap();
    let lost = wire.sent(2).await[1].payload.len();
    drop(held);
    endpoint
        .send_request(
            outgoing("seen"),
            Target::new(Transport::Udp, PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap();
    let seen = wire.sent(3).await[2].payload.len();
    let next = record(&mut observer).await;
    assert!(matches!(next.observed(), Observed::WriteStarted { .. }));
    assert_eq!((next.sequence(), next.lost_before()), (7, 5));
    // The write's end, behind its start and acceptance, is lost too.
    let stats = observer.stats();
    assert_eq!(stats.lost, 6);
    assert_eq!(stats.lost_bytes, (ok.len() + lost) as u64);
    // Each delivered start copied the first 64 bytes of its message.
    let full = wire.sent(1).await[0].payload.len();
    assert_eq!(stats.truncated_bytes, (full - 64 + seen - 64) as u64);
}

// An overflowing response stream is its own explicit error, however much
// room the observer has, and the observer goes on seeing the responses the
// stream could not take.
#[tokio::test]
async fn response_overflow_does_not_depend_on_the_observer() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .client_response_limits(Limits { count: 1, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing_invite("overflow"), target)
        .await
        .unwrap()
        .into_parts();
    let invite = Request::from_bytes(&wire.sent(1).await[0].payload).unwrap();
    for status in [180, 183] {
        let response = Response::reply_to(&invite)
            .status(status)
            .to_tag("alice")
            .body(Bytes::new())
            .unwrap();
        wire.deliver(Ok(Datagram::new(response.to_bytes(), PEER, LOCAL)));
    }
    sleep(Duration::from_millis(100)).await;

    let first = responses.next().await.unwrap().unwrap();
    assert_eq!(first.response.status().as_u16(), 180);
    assert!(
        responses.next().await.unwrap().unwrap_err().is_delivery_overflow()
    );
    let mut arrivals = Vec::new();
    while arrivals.len() < 2 {
        if let Observed::Received { id, .. } =
            *record(&mut observer).await.observed()
        {
            arrivals.push(id);
        }
    }
    assert_eq!(arrivals[0], first.received.id());
    assert_eq!(observer.stats(), observe::Stats::default());
}

// One observer at a time. Dropping it changes nothing on the wire, and
// another can attach.
#[tokio::test]
async fn one_observer_at_a_time_and_dropping_it_changes_nothing() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let first = endpoint.observe(observe::Config::new()).await.unwrap();
    let busy = endpoint.observe(observe::Config::new()).await.unwrap_err();
    assert!(busy.is_busy());

    drop(first);
    wire.deliver(datagram(options("dropped")));
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();
    assert_eq!(status(&wire.sent(1).await[0]), 200);

    let mut second = endpoint.observe(observe::Config::new()).await.unwrap();
    wire.deliver(datagram(options("second")));
    let record = record(&mut second).await;
    assert!(matches!(record.observed(), Observed::Received { .. }));
    assert_eq!(record.sequence(), 0);
}

// An `observe` dropped after it asked the driver to attach leaves nothing
// behind. Another observer attaches, and only it sees what comes next, from
// the first number on.
#[tokio::test]
async fn an_observe_dropped_while_attaching_lets_another_attach() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    // One poll sends the request, and the driver has not answered yet.
    let mut dropped = Box::pin(endpoint.observe(observe::Config::new()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(dropped.as_mut().poll(&mut cx).is_pending());
    drop(dropped);

    let mut second = endpoint.observe(observe::Config::new()).await.unwrap();
    wire.deliver(datagram(options("second")));

    let record = record(&mut second).await;
    assert!(matches!(record.observed(), Observed::Received { .. }));
    assert_eq!((record.sequence(), record.lost_before()), (0, 0));
    assert_eq!(second.stats(), observe::Stats::default());
}

// The write stages keep the backend's word apart: a write it holds is taken
// once it can, a refused one ends without being taken, an unknown outcome
// stays unknown, and a write the limits refuse ends before the backend sees
// it.
#[tokio::test]
async fn write_records_keep_each_stage_and_outcome() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .udp_write_limits(Limits { count: 1, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let target = || Target::new(Transport::Udp, PEER);
    let send = |call: &'static str| {
        endpoint.send_request(outgoing(call), target(), ViaMode::Fresh)
    };

    wire.writes(Writes::Hold);
    let held = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            endpoint
                .send_request(
                    outgoing("held"),
                    Target::new(Transport::Udp, PEER),
                    ViaMode::Fresh,
                )
                .await
        }
    });
    let (write, started) = stage(&mut observer).await;
    assert!(matches!(started, Observed::WriteStarted { .. }));
    // The limits hold one write, so the next ends before the backend.
    assert!(send("refused").await.is_err());
    let (refused, _) = stage(&mut observer).await;
    let (ended, stage_seen) = stage(&mut observer).await;
    assert_eq!(ended, refused);
    assert!(matches!(
        stage_seen,
        Observed::WriteEnded {
            accepted: false,
            end: WriteEnd::NotWritten(_),
            ..
        }
    ));
    wire.writes(Writes::Complete);
    assert!(held.await.unwrap().is_ok());
    let (taken, stage_seen) = stage(&mut observer).await;
    assert_eq!(taken, write);
    assert!(matches!(stage_seen, Observed::WriteAccepted { .. }));
    let (_, stage_seen) = stage(&mut observer).await;
    assert!(matches!(stage_seen, Observed::WriteEnded { accepted: true, .. }));

    wire.writes(Writes::Reject);
    assert!(send("rejected").await.is_err());
    let (_, started) = stage(&mut observer).await;
    assert!(matches!(started, Observed::WriteStarted { .. }));
    let (_, stage_seen) = stage(&mut observer).await;
    assert!(matches!(
        stage_seen,
        Observed::WriteEnded { accepted: false, .. }
    ));

    wire.writes(Writes::Delay);
    let unknown_write = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let target = Target::new(Transport::Udp, PEER);
            endpoint
                .send_request(outgoing("unknown"), target, ViaMode::Fresh)
                .await
        }
    });
    stage(&mut observer).await;
    stage(&mut observer).await;
    wire.finish(unknown());
    let outcome = unknown_write.await.unwrap();
    assert!(outcome.unwrap_err().is_outcome_unknown());
    let (_, stage_seen) = stage(&mut observer).await;
    assert!(matches!(
        stage_seen,
        Observed::WriteEnded { accepted: true, end: WriteEnd::Unknown(_), .. }
    ));
}

// A record copies what it shows, so it keeps no received buffer alive, and
// a payload beyond the configured length is cut and counted.
#[tokio::test]
async fn records_copy_their_bytes_and_cut_long_ones() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let config = observe::Config::new().payload(16).context(true);
    let mut observer = endpoint.observe(config).await.unwrap();
    let text = options("copied");
    // The datagram is a slice of a much larger capture buffer.
    let mut capture = vec![0u8; 64 * 1024];
    capture[..text.len()].copy_from_slice(text.as_bytes());
    let capture = Bytes::from(capture);
    let payload = capture.slice(..text.len());
    let context =
        TransportContext::new(capture.slice(text.len()..text.len() + 8))
            .unwrap();

    wire.deliver(
        Ok(Datagram::new(payload, PEER, LOCAL).with_context(context)),
    );
    let _request = request(&mut incoming).await;
    let arrival = record(&mut observer).await;
    let copy = arrival.payload().unwrap();
    assert_eq!(&copy[..], &text.as_bytes()[..16]);
    assert_eq!(arrival.message_len(), text.len());
    let range = capture.as_ptr_range();
    assert!(!range.contains(&copy.as_ptr()));
    assert!(!range.contains(&arrival.context().unwrap().as_bytes().as_ptr()));
    assert_eq!(observer.stats().truncated_bytes, (text.len() - 16) as u64);
}

// A response the endpoint makes without a transaction names the arrival it
// answers too, here a 400 for a request without a Call-ID.
#[tokio::test]
async fn a_stateless_refusal_names_the_arrival_it_answers() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let mut observer = endpoint.observe(observe::Config::new()).await.unwrap();
    let text = options("refused").replace("Call-ID: refused\r\n", "");

    // What is not SIP at all arrives too, and nothing answers it.
    wire.deliver(datagram("not SIP\r\n\r\n".to_owned()));
    let garbage = record(&mut observer).await;
    assert!(matches!(garbage.observed(), Observed::Received { .. }));
    assert_eq!(garbage.message_len(), 11);
    wire.deliver(datagram(text));
    let arrival = record(&mut observer).await;
    let Observed::Received { id, .. } = *arrival.observed() else {
        panic!("an arrival, got {arrival:?}");
    };
    written(&mut observer, |o| *o == WriteOrigin::Stateless, Some(id)).await;
    assert_eq!(status(&wire.sent(1).await[0]), 400);
}
