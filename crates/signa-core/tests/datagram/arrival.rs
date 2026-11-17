/*!
What each received message keeps of how it arrived: an ID and a time from
where it first arrived, and for a client response its own source and
context.
*/

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{
        Endpoint, ReceivedResponse, Target,
        observe::{self, Observed},
        port::Capture,
    },
    message::header::Tag,
    transport::{
        Limits, Transport,
        datagram::{Datagram, MAX_CONTEXT_LEN, TransportContext},
    },
};
use tokio::time::{advance, sleep, timeout};

use crate::{
    datagram::{
        LOCAL, PEER, arriving, bind, context, datagram, invite, method,
        observe::record,
        ok, options, outgoing, outgoing_invite,
        port::{intercept, next},
        wire::{Way, Wire},
    },
    support::request,
};

// A datagram on a shared port gets its ID and time when the port's task
// takes it from the backend. The endpoint it is delivered to keeps both,
// however long the application held it before deciding.
#[tokio::test(start_paused = true)]
async fn a_held_datagram_keeps_its_id_and_arrival_time() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();

    wire.deliver(arriving(options("held"), "nic0"));
    let datagram = next(&mut ingress).await;
    let (id, arrived) =
        (datagram.received().id(), datagram.received().received_at());
    assert_eq!(datagram.deadline(), arrived + Duration::from_secs(1));
    advance(Duration::from_millis(300)).await;
    datagram.try_deliver(&to_endpoint).unwrap();

    let request = request(&mut incoming).await;
    assert_eq!(request.received.id(), id);
    assert_eq!(request.received.received_at(), arrived);
    assert_eq!(request.received.context().as_bytes(), "nic0");
    let held = tokio::time::Instant::now().into_std() - arrived;
    assert!(held >= Duration::from_millis(300), "{held:?}");

    wire.deliver(arriving(options("after"), "nic0"));
    let after = next(&mut ingress).await;
    assert_eq!(after.received().id().domain(), id.domain());
    assert_eq!(after.received().id().sequence(), id.sequence() + 1);
}

/// A second peer of the wire, which a response may come from.
const OTHER_PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 21)),
    5070,
);

// Each response of a client transaction comes with its own arrival, not the
// transaction's: the address and context it came with, its ID and its time.
// The responses of two forks, and of one fork along two ways, keep theirs
// apart, and the transaction still sends the way it chose.
#[tokio::test]
async fn each_response_keeps_how_it_arrived() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing_invite("forks"), target)
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(1).await;
    let invite = Request::from_bytes(&sent[0].payload).unwrap();
    let reply = |status: u16, tag: &str| {
        Response::reply_to(&invite)
            .status(status)
            .to_tag(tag)
            .body(Bytes::new())
            .unwrap()
            .to_bytes()
    };
    let arrivals = [
        (180, "a", PEER, "nic0"),
        (183, "a", OTHER_PEER, "nic1"),
        (200, "a", PEER, "nic0"),
        (200, "b", OTHER_PEER, "nic2"),
    ];

    for (status, tag, source, on) in arrivals {
        let datagram = Datagram::new(reply(status, tag), source, LOCAL)
            .with_context(context(on));
        wire.deliver(Ok(datagram));
    }

    let mut ids = Vec::new();
    for (status, tag, source, on) in arrivals {
        let ReceivedResponse { response, received } =
            timeout(Duration::from_secs(2), responses.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(response.status().as_u16(), status);
        let to = response.headers().get("To").unwrap().as_str();
        assert!(to.ends_with(&format!(";tag={tag}")), "{to}");
        assert_eq!(
            (received.flow().remote, received.flow().local),
            (source, LOCAL)
        );
        assert_eq!(received.context().as_bytes(), on);
        ids.push((received.id(), received.received_at()));

        // Code that keeps the response longer can let the context go and
        // keep the rest.
        let kept = received.clone().without_context();
        assert!(kept.context().is_empty());
        assert_eq!(
            (kept.id(), kept.received_at(), kept.flow()),
            (received.id(), received.received_at(), received.flow())
        );
    }
    for pair in ids.windows(2) {
        let ((before, at), (after, then)) = (pair[0], pair[1]);
        assert_eq!(after.domain(), before.domain());
        assert_eq!(after.sequence(), before.sequence() + 1);
        assert!(at <= then);
    }
    assert!(wire.sent(1).await.iter().all(|sent| sent.path == Way::Default));
}

// A 2xx and its retransmission reach the TU apart (RFC 6026 section 8.4),
// each with its own ID and context. Each is charged to the stream's limits
// with its context, so a retransmission that cannot keep its context ends
// the stream rather than arriving without it.
#[tokio::test]
async fn each_2xx_retransmission_arrives_with_its_own_id_and_charge() {
    let target = Target::new(Transport::Udp, PEER);
    // The limits hold two 200s with small contexts, whose copies take well
    // under 128 bytes each, and not with the large one. The 200's length
    // comes from one exchange.
    let ok_len = {
        let wire = Wire::default();
        let (endpoint, _incoming) = bind(&wire);
        let call = outgoing_invite("retransmitted");
        let _call = endpoint.start(call, target.clone()).await.unwrap();
        let sent = wire.sent(1).await;
        ok(&Request::from_bytes(&sent[0].payload).unwrap()).to_bytes().len()
    };
    let limit = 2 * ok_len + 2 * 128;
    let large =
        TransportContext::new(Bytes::from(vec![b'x'; MAX_CONTEXT_LEN]))
            .unwrap();

    for again in [context("nic1"), large] {
        let wire = Wire::default();
        let (endpoint, _incoming) = Endpoint::builder()
            .udp_io(wire.clone())
            .client_response_limits(Limits { count: 8, bytes: limit })
            .bind()
            .unwrap();
        let (_control, mut responses) = endpoint
            .start(outgoing_invite("retransmitted"), target.clone())
            .await
            .unwrap()
            .into_parts();
        let sent = wire.sent(1).await;
        let invite = Request::from_bytes(&sent[0].payload).unwrap();
        let ok = ok(&invite).to_bytes();
        assert_eq!(ok.len(), ok_len);
        let first = Datagram::new(ok.clone(), PEER, LOCAL)
            .with_context(context("nic0"));
        let second =
            Datagram::new(ok, PEER, LOCAL).with_context(again.clone());

        wire.deliver(Ok(first));
        wire.deliver(Ok(second));
        // Both wait in the stream before it is read.
        sleep(Duration::from_millis(100)).await;

        let mut next = async || {
            timeout(Duration::from_secs(2), responses.next())
                .await
                .unwrap()
                .unwrap()
        };
        let first = next().await.unwrap();
        assert_eq!(first.received.context().as_bytes(), "nic0");
        let second = next().await;
        if again.len() == MAX_CONTEXT_LEN {
            assert!(second.unwrap_err().is_delivery_overflow());
            continue;
        }
        let second = second.unwrap();
        assert_eq!(second.response.status().as_u16(), 200);
        assert_eq!(second.received.context().as_bytes(), "nic1");
        let (before, after) = (first.received.id(), second.received.id());
        assert_eq!(after.domain(), before.domain());
        assert_eq!(after.sequence(), before.sequence() + 1);
    }
}

// A non-2xx final that overflows its stream still gets its ACK. The
// transaction acknowledges the response whatever becomes of its delivery
// (RFC 3261 section 17.1.1.3).
#[tokio::test]
async fn a_final_that_overflows_its_stream_still_gets_its_ack() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .client_response_limits(Limits { count: 8, bytes: 1 })
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing_invite("overflowed"), target)
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(1).await;
    let invite = Request::from_bytes(&sent[0].payload).unwrap();
    let busy = Response::reply_to(&invite)
        .status(486)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap();

    wire.deliver(Ok(Datagram::new(busy.to_bytes(), PEER, LOCAL)));

    let ended = timeout(Duration::from_secs(2), responses.next()).await;
    assert!(ended.unwrap().unwrap().unwrap_err().is_delivery_overflow());
    let sent = wire.sent(2).await;
    assert_eq!(method(&sent[1]).as_deref(), Some("ACK"));
}

// Each receive point numbers what it receives in a domain of its own: two
// endpoints, an endpoint and a shared port, and a capture never share one.
// An endpoint's own backend numbers its arrivals in the domain of its
// writes, as a shared port does, so an observer's records of one backend
// name one domain.
#[tokio::test]
async fn each_receive_point_numbers_in_a_domain_of_its_own() {
    let wires: [Wire; 4] = Default::default();
    let (first, mut first_incoming) = bind(&wires[0]);
    let (_second, mut second_incoming) = bind(&wires[1]);
    let (_port, mut ingress) = intercept(&wires[2]);
    let mut capture =
        Capture::builder().udp_io(wires[3].clone()).open().unwrap();
    let mut observer = first.observe(observe::Config::new()).await.unwrap();

    wires[0].deliver(datagram(invite("first")));
    wires[1].deliver(datagram(options("second")));
    wires[2].deliver(datagram(options("port")));
    wires[3].deliver(datagram(options("capture")));
    let first_request = request(&mut first_incoming).await;
    let second_request = request(&mut second_incoming).await;
    let held = next(&mut ingress).await;
    let captured =
        timeout(Duration::from_secs(2), capture.recv()).await.unwrap();

    let ids = [
        first_request.received.id(),
        second_request.received.id(),
        held.received().id(),
        captured.received().id(),
    ];
    for (n, id) in ids.iter().enumerate() {
        for other in &ids[n + 1..] {
            assert_ne!(id.domain(), other.domain(), "{ids:?}");
        }
    }
    let arrival = record(&mut observer).await;
    assert!(matches!(arrival.observed(), Observed::Received { .. }));
    let trying = record(&mut observer).await;
    let Observed::WriteStarted { write, .. } = trying.observed() else {
        panic!("the 100 Trying's write, got {trying:?}");
    };
    assert_eq!(write.domain(), ids[0].domain());
}

// A response's context counts against its stream's limits with its bytes.
// One that cannot keep its context ends the stream with the overflow error,
// after the responses already queued, rather than arriving without it.
#[tokio::test]
async fn a_response_never_arrives_without_its_context() {
    const LIMIT: usize = 500;
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .client_response_limits(Limits { count: 8, bytes: LIMIT })
        .bind()
        .unwrap();
    let large =
        TransportContext::new(Bytes::from(vec![b'x'; MAX_CONTEXT_LEN]))
            .unwrap();

    for (call, context) in [("small", None), ("large", Some(large))] {
        let target = Target::new(Transport::Udp, PEER);
        let (_control, mut responses) =
            endpoint.start(outgoing(call), target).await.unwrap().into_parts();
        let sent = wire.sent(wire.count() + 1).await;
        let request =
            Request::from_bytes(&sent.last().unwrap().payload).unwrap();
        let trying = Response::reply_to(&request)
            .status(100)
            .body(Bytes::new())
            .unwrap()
            .to_bytes();
        let ok = ok(&request).to_bytes();
        // Both fit without the context and not with it.
        assert!(trying.len() + ok.len() <= LIMIT);
        assert!(trying.len() + ok.len() + MAX_CONTEXT_LEN > LIMIT);

        wire.deliver(Ok(Datagram::new(trying, PEER, LOCAL)));
        let mut final_response = Datagram::new(ok, PEER, LOCAL);
        if let Some(context) = context.clone() {
            final_response = final_response.with_context(context);
        }
        wire.deliver(Ok(final_response));
        // Both wait in the stream before it is read.
        sleep(Duration::from_millis(100)).await;

        let mut next = async || {
            timeout(Duration::from_secs(2), responses.next())
                .await
                .unwrap()
                .unwrap()
        };
        let first = next().await.unwrap();
        assert_eq!(first.response.status().as_u16(), 100);
        let second = next().await;
        match context {
            None => {
                assert_eq!(second.unwrap().response.status().as_u16(), 200)
            }
            Some(_) => assert!(second.unwrap_err().is_delivery_overflow()),
        }
    }
}
