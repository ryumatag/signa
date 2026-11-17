/*!
A port's observer, which sees each datagram as the port takes it and each
write as the backend gets it.
*/

use std::time::Duration;

use bytes::Bytes;
use signa_core::{
    endpoint::{
        Endpoint, ShutdownOutcome,
        observe::{
            self, Observed, Observer, Record, WriteEnd, WriteOrigin, WriteRef,
        },
        port::DatagramPort,
    },
    transport::Limits,
};
use tokio::time::timeout;

use crate::{
    datagram::{
        arriving,
        observe::record,
        options,
        port::{intercept, next, stats_until, upstream},
        send_options, unknown,
        wire::{Wire, Writes},
    },
    support::request,
};

/// Records until `n` of them satisfy `keep`, which are returned.
async fn records_where(
    observer: &mut Observer,
    n: usize,
    keep: impl Fn(&Record) -> bool,
) -> Vec<Record> {
    let mut kept = Vec::new();
    while kept.len() < n {
        let record = record(observer).await;
        if keep(&record) {
            kept.push(record);
        }
    }
    kept
}

fn started(record: &Record) -> Option<(WriteRef, WriteOrigin)> {
    match record.observed() {
        Observed::WriteStarted { write, origin, .. } => {
            Some((*write, *origin))
        }
        _ => None,
    }
}

// A port's observer sees each endpoint write once, as the backend gets it,
// and names the endpoint's own record of it. Two endpoints number their
// writes alike, each in a domain of its own, so the port never mixes them,
// and it numbers the physical writes in its own domain.
#[tokio::test]
async fn a_port_observer_ties_each_backend_write_to_its_endpoint() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let mut on_port = port.observe(observe::Config::new()).await.unwrap();
    let mut endpoints = Vec::new();
    for _ in 0..2 {
        let (endpoint, incoming, _) =
            Endpoint::builder().bind_on(&port).unwrap();
        let observer = endpoint.observe(observe::Config::new()).await.unwrap();
        endpoints.push((endpoint, incoming, observer));
    }

    let mut local = Vec::new();
    for (endpoint, _, observer) in &mut endpoints {
        send_options(endpoint, "tied").await.unwrap().unwrap();
        let records =
            records_where(observer, 1, |r| started(r).is_some()).await;
        let (write, origin) = started(&records[0]).unwrap();
        assert_eq!(origin, WriteOrigin::Send);
        local.push(write);
    }
    assert_eq!(local[0].number(), local[1].number());
    assert_ne!(local[0].domain(), local[1].domain());

    let physical =
        records_where(&mut on_port, 2, |r| started(r).is_some()).await;
    let physical: Vec<_> =
        physical.iter().map(|r| started(r).unwrap()).collect();
    let origins: Vec<_> = physical
        .iter()
        .map(|(_, origin)| match origin {
            WriteOrigin::Endpoint { write, .. } => *write,
            other => panic!("an endpoint's write, got {other:?}"),
        })
        .collect();
    assert_eq!(origins, local);
    let (first, second) = (physical[0].0, physical[1].0);
    assert_eq!(first.domain(), second.domain());
    assert!(!local.iter().any(|write| write.domain() == first.domain()));
    assert_eq!(second.number(), first.number() + 1);
    assert_eq!(wire.count(), 2);
}

// A port's observer sees each datagram as its task takes it, under the ID
// the endpoint it is delivered to keeps, and before the ingress limits drop
// one. A forward names the datagram it sends on, and a raw send nothing.
#[tokio::test]
async fn a_port_observer_sees_arrivals_raw_sends_and_forwards() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .ingress_limits(Limits { count: 1, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    let config = observe::Config::new().payload(1500);
    let mut on_port = port.observe(config).await.unwrap();

    wire.deliver(arriving(options("held"), "nic0"));
    wire.deliver(arriving(options("dropped"), "nic0"));
    let arrivals = records_where(&mut on_port, 2, |r| {
        matches!(r.observed(), Observed::Received { .. })
    })
    .await;
    stats_until(&port, |stats| stats.overflow == 1).await;
    let held = next(&mut ingress).await;
    let Observed::Received { id: held_id, .. } = *arrivals[0].observed()
    else {
        unreachable!()
    };
    assert_eq!(held.received().id(), held_id);
    assert_eq!(arrivals[1].payload().unwrap(), options("dropped").as_bytes());

    held.try_forward(&upstream).unwrap().await.unwrap();
    let forwarded =
        records_where(&mut on_port, 1, |r| started(r).is_some()).await;
    let Observed::WriteStarted { origin, cause, .. } =
        *forwarded[0].observed()
    else {
        unreachable!()
    };
    assert_eq!((origin, cause), (WriteOrigin::Raw, Some(held_id)));

    port.send_bytes(Bytes::from_static(b"raw"), &upstream)
        .unwrap()
        .await
        .unwrap();
    let raw = records_where(&mut on_port, 1, |r| started(r).is_some()).await;
    let Observed::WriteStarted { write, origin, cause, .. } =
        *raw[0].observed()
    else {
        unreachable!()
    };
    assert_eq!((origin, cause), (WriteOrigin::Raw, None));
    let Observed::WriteStarted { write: first, .. } = *forwarded[0].observed()
    else {
        unreachable!()
    };
    assert_eq!(write.domain(), first.domain());
    assert_ne!(write.number(), first.number());

    wire.deliver(arriving(options("delivered"), "nic0"));
    let arrival = records_where(&mut on_port, 1, |r| {
        matches!(r.observed(), Observed::Received { .. })
    })
    .await;
    next(&mut ingress).await.try_deliver(&to_endpoint).unwrap();
    let request = request(&mut incoming).await;
    let Observed::Received { id, .. } = *arrival[0].observed() else {
        unreachable!()
    };
    assert_eq!(request.received.id(), id);
}

// The backend's stages reach the port's observer as they happen: a write it
// takes and later reports unknown, and an endpoint write the port held when
// the endpoint stopped, which the port withdrew before the backend took it.
#[tokio::test]
async fn a_port_observer_sees_late_unknown_and_withdrawn_writes() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let mut on_port = port.observe(observe::Config::new()).await.unwrap();
    let end = |record: &Record| match record.observed() {
        Observed::WriteEnded { end, accepted, .. } => Some((*end, *accepted)),
        _ => None,
    };

    wire.writes(Writes::Delay);
    let late = send_options(&endpoint, "late");
    wire.sent(1).await;
    wire.finish(unknown());
    assert!(late.await.unwrap().unwrap_err().is_outcome_unknown());
    let ended = records_where(&mut on_port, 1, |r| end(r).is_some()).await;
    assert!(matches!(end(&ended[0]), Some((WriteEnd::Unknown(_), true))));

    wire.writes(Writes::Hold);
    let held = send_options(&endpoint, "held");
    wire.until(|state| state.submit.is_some()).await;
    let stopped =
        timeout(Duration::from_secs(2), endpoint.shutdown(Duration::ZERO))
            .await
            .unwrap();
    assert_eq!(stopped, ShutdownOutcome::DeadlineExpired);
    let ended = records_where(&mut on_port, 1, |r| end(r).is_some()).await;
    assert!(matches!(end(&ended[0]), Some((WriteEnd::NotWritten(_), false))));
    wire.writes(Writes::Complete);
    assert!(held.await.unwrap().is_err());
    assert_eq!(wire.count(), 1, "nothing went out after the stop");
}
