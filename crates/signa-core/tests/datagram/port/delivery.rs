/*!
The application delivers a port's datagrams to its endpoints, forwards them
or sends its own raw, within the port's ingress limits and each datagram's
deadline. A capture only receives.
*/

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use quickcheck::{Arbitrary, Gen, QuickCheck};
use signa_core::{
    Message,
    endpoint::{
        Endpoint, ShutdownOutcome, Target, ViaMode,
        port::{Capture, DatagramPort},
    },
    message::header::VIA,
    transport::{
        Limits, Transport,
        datagram::{Datagram, TransportContext},
    },
};
use tokio::time::{advance, sleep, timeout};

use crate::{
    datagram::{
        LOCAL, PEER, PUBLIC, arriving, datagram, invite, ok, options,
        outgoing,
        port::{intercept, next, stats_until, upstream},
        status,
        wire::{Way, Wire},
    },
    support::request,
};

// A datagram the application delivers to an endpoint on the port is received
// as from the endpoint's own socket. Its envelope shows how it arrived, the
// endpoint fills in `received` in its own copy, and its response goes out
// through the port with the request's context (RFC 3261 section 18.2.2).
#[tokio::test]
async fn a_delivered_datagram_is_received_and_answered_by_its_endpoint() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    assert_eq!(endpoint.udp_addr(), Some(LOCAL));
    // The Via names another host, so the endpoint marks its copy with
    // `received`, and without `rport` the response goes to that address at
    // the Via's port.
    let text = options("port")
        .replace("192.0.2.20:5060", "192.0.2.99:5060")
        .replace(";rport", "");

    wire.deliver(arriving(text.clone(), "nic0"));
    let datagram = next(&mut ingress).await;
    assert_eq!(datagram.payload(), text.as_bytes());
    assert_eq!(
        (datagram.received().flow().remote, datagram.received().flow().local),
        (PEER, LOCAL)
    );
    assert_eq!(datagram.received().context().as_bytes(), "nic0");
    datagram.try_deliver(&to_endpoint).unwrap();

    let request = request(&mut incoming).await;
    assert_eq!(request.received.flow().remote, PEER);
    assert_eq!(request.received.context().as_bytes(), "nic0");
    let via = request.request.headers().get(VIA).unwrap().as_str();
    assert!(via.contains("received=192.0.2.20"), "{via}");
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    let via_port = SocketAddr::new(PEER.ip(), 5060);
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, via_port));
    assert_eq!(sent[0].path, Way::reply("nic0"));
    assert_eq!(status(&sent[0]), 200);
    let stats = port.stats();
    assert_eq!((stats.received, stats.delivered), (1, 1));
}

// Forwarding sends the payload once, byte for byte, whether or not it parses
// as SIP. Compact and mixed-case headers stay as they came, and a payload that
// is not SIP goes too. Nothing else goes out: an INVITE forwarded this way
// gets no 100 Trying, no transaction and no retransmission, and the endpoint
// on the port sees nothing.
#[tokio::test]
async fn forwarding_sends_the_bytes_once_and_nothing_else() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (_endpoint, mut incoming, _) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    let compact = Bytes::from_static(
        b"INVITE sip:bob@192.0.2.10 SIP/2.0\r\n\
          v: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bKcompact\r\n\
          f: <sip:alice@192.0.2.20>;tag=a\r\n\
          t: <sip:bob@192.0.2.10>\r\n\
          i: compact\r\n\
          cSeQ: 1 INVITE\r\n\
          mAX-fORWARDS: 70\r\n\
          l: 0\r\n\r\n",
    );
    let malformed = Bytes::from_static(b"INVITE this is not SIP\r\n\r\n\xff");

    for payload in [&compact, &malformed] {
        wire.deliver(Ok(Datagram::new(payload.clone(), PEER, LOCAL)));
        let datagram = next(&mut ingress).await;
        assert_eq!(datagram.parse().is_ok(), payload == &compact);
        datagram.try_forward(&upstream).unwrap().await.unwrap();
    }

    let sent = wire.sent(2).await;
    for (sent, payload) in sent.iter().zip([&compact, &malformed]) {
        assert_eq!(&sent.payload, payload);
        assert_eq!((sent.source, sent.destination), (LOCAL, PUBLIC));
        assert_eq!(sent.path, Way::prepared("nic1"));
    }
    assert!(
        timeout(Duration::from_millis(100), incoming.recv()).await.is_err()
    );
    assert_eq!(wire.count(), 2);
    assert_eq!(port.stats().forwarded, 2);
}

// A request the endpoint generates must go over a congestion-controlled
// transport once it is over 1300 bytes with no known path MTU (RFC 3261
// section 18.1.1), so the endpoint refuses it over UDP. A raw send is not a
// generated request and has only the backend's limit, so the same size goes.
// One over the backend's maximum is refused before anything is sent.
#[tokio::test]
async fn a_raw_send_has_only_the_backend_s_size_limit() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    let mut large = outgoing("large");
    *large.body_mut() = Bytes::from(vec![b'x'; 1250]);

    let generated = endpoint
        .send_request(
            large.clone(),
            Target::new(Transport::Udp, PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap_err();
    let raw = large.to_bytes();
    port.send_bytes(raw.clone(), &upstream).unwrap().await.unwrap();
    let over =
        port.send_bytes(Bytes::from(vec![0; 1473]), &upstream).unwrap_err();

    assert!(generated.is_too_large());
    assert!(raw.len() > 1300 && raw.len() <= 1472, "{}", raw.len());
    assert!(over.is_too_large());
    let sent = wire.sent(1).await;
    assert_eq!(sent[0].payload, raw);
    assert_eq!(wire.count(), 1);
}

// Delivery commits when the endpoint's queue takes the datagram. A full queue
// refuses it before then and hands it back with its disposition, so it can be
// tried again, go elsewhere or be discarded. It is never processed twice.
#[tokio::test]
async fn a_full_endpoint_queue_hands_the_datagram_back() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .delivery_queue(1)
        .intercept()
        .unwrap();
    let (_endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    wire.deliver(datagram(options("first")));
    wire.deliver(datagram(options("second")));
    let first = next(&mut ingress).await;
    let second = next(&mut ingress).await;

    // Nothing awaits between the two, so the endpoint's driver has not run.
    first.try_deliver(&to_endpoint).unwrap();
    let refused = second.try_deliver(&to_endpoint).unwrap_err();

    assert!(refused.error().is_busy());
    assert_eq!(
        refused.error().to_string(),
        "the endpoint's delivery queue is full"
    );
    let second = refused.into_datagram();
    assert_eq!(second.payload(), options("second").as_bytes());
    let taken = request(&mut incoming).await;
    assert_eq!(taken.request.headers().get("Call-ID").unwrap(), "first");
    second.try_deliver(&to_endpoint).unwrap();
    let taken = request(&mut incoming).await;
    assert_eq!(taken.request.headers().get("Call-ID").unwrap(), "second");
    assert!(
        timeout(Duration::from_millis(50), incoming.recv()).await.is_err()
    );
    assert_eq!(port.stats().delivered, 2);
}

// After its deadline a datagram can no longer be delivered or forwarded, and
// it comes back from either. It still holds its share of the ingress limits
// until it drops, since the application still holds its bytes, so a datagram
// that arrives meanwhile finds them full. The clock is paused, so the
// deadline passes exactly when the test says.
#[tokio::test(start_paused = true)]
async fn an_expired_datagram_is_refused_but_still_counted() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .ingress_limits(Limits { count: 1, bytes: 64 * 1024 })
        .decision_deadline(Duration::from_millis(500))
        .intercept()
        .unwrap();
    let (_endpoint, _incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.deliver(datagram(options("late")));
    let held = next(&mut ingress).await;

    advance(Duration::from_millis(500)).await;
    let refused = held.try_deliver(&to_endpoint).unwrap_err();
    assert!(refused.error().is_expired());
    let refused = refused.into_datagram().try_forward(&upstream).unwrap_err();
    assert!(refused.error().is_expired());
    let held = refused.into_datagram();

    wire.deliver(datagram(options("meanwhile")));
    stats_until(&port, |stats| stats.overflow == 1).await;
    drop(held);
    wire.deliver(datagram(options("after")));
    let after = next(&mut ingress).await;
    assert_eq!(after.payload(), options("after").as_bytes());
    let stats = port.stats();
    assert_eq!((stats.received, stats.expired, stats.overflow), (3, 1, 1));
    assert_eq!(wire.count(), 0);
}

// An application that reads slowly loses traffic. The datagrams beyond the
// ingress limits are dropped on receipt and counted, and no SIP goes out for
// them. ACK and CANCEL progress is the endpoint's to guarantee once a
// datagram reaches it, not the port's.
#[tokio::test]
async fn a_slow_classifier_loses_what_is_beyond_the_ingress_limits() {
    let wire = Wire::default();
    let (port, mut ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .ingress_limits(Limits { count: 2, bytes: 64 * 1024 })
        .intercept()
        .unwrap();

    for n in 0..5 {
        wire.deliver(datagram(options(&format!("slow{n}"))));
    }
    stats_until(&port, |stats| stats.received == 5).await;

    assert_eq!(port.stats().overflow, 3);
    for n in 0..2 {
        let kept = next(&mut ingress).await;
        assert_eq!(kept.payload(), options(&format!("slow{n}")).as_bytes());
        kept.discard();
    }
    assert!(timeout(Duration::from_millis(50), ingress.recv()).await.is_err());
    assert_eq!(port.stats().discarded, 2);
    assert_eq!(wire.count(), 0);
}

// A capture only receives. Its datagrams carry no disposition and it has no
// send, so an INVITE it captures gets no 100 Trying and nothing else goes out.
#[tokio::test]
async fn a_capture_receives_and_sends_nothing() {
    let wire = Wire::default();
    let mut capture = Capture::builder().udp_io(wire.clone()).open().unwrap();

    wire.deliver(arriving(invite("captured"), "tap0"));
    let captured =
        timeout(Duration::from_secs(2), capture.recv()).await.unwrap();

    assert_eq!(capture.local_addr(), LOCAL);
    assert_eq!(capture.capabilities().max_payload, 1472);
    assert_eq!(captured.payload(), invite("captured").as_bytes());
    assert_eq!(captured.received().context().as_bytes(), "tap0");
    assert!(matches!(captured.parse(), Ok(Message::Request(_))));
    sleep(Duration::from_millis(50)).await;
    assert_eq!(wire.count(), 0);
    let outcome = capture.close(Duration::from_secs(1)).await;
    assert_eq!(outcome, ShutdownOutcome::Drained);
    assert!(wire.closed());
}

// A captured datagram keeps a copy of its context, so holding it does not
// keep alive the buffer the backend sliced the context out of.
#[tokio::test]
async fn a_captured_datagram_does_not_hold_the_capture_buffer() {
    let wire = Wire::default();
    let mut capture = Capture::builder().udp_io(wire.clone()).open().unwrap();
    let buffer =
        Bytes::from(b"nic0 vlan 100, then the rest of a frame".to_vec());
    let context = TransportContext::new(buffer.slice(..13)).unwrap();

    wire.deliver(
        datagram(options("buffer"))
            .map(|datagram| datagram.with_context(context)),
    );
    let captured =
        timeout(Duration::from_secs(2), capture.recv()).await.unwrap();

    assert_eq!(captured.received().context().as_bytes(), "nic0 vlan 100");
    assert!(buffer.is_unique(), "the captured datagram holds the buffer");
}

/// What becomes of one datagram in the disposition property.
#[derive(Clone, Copy, Debug)]
enum Fate {
    Deliver,
    Forward,
    Discard,
    Drop,
    /// Held until the end, so that later datagrams may find the limits full.
    Hold,
    /// Tried after its deadline, then dropped.
    Expire,
}

impl Arbitrary for Fate {
    fn arbitrary(g: &mut Gen) -> Fate {
        *g.choose(&[
            Fate::Deliver,
            Fate::Forward,
            Fate::Discard,
            Fate::Drop,
            Fate::Hold,
            Fate::Expire,
        ])
        .unwrap()
    }
}

// Whatever the application does, each datagram ends exactly once: delivered,
// forwarded, discarded, abandoned, expired, or dropped on receipt when the
// ingress limits are full. Once none is held, the limits are whole again.
// The clock is paused, so expiry is exact.
#[test]
fn every_datagram_ends_once_and_gives_back_its_share() {
    const LIMIT: usize = 3;

    fn property(fates: Vec<Fate>) -> bool {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async move {
            let wire = Wire::default();
            let (port, mut ingress) = DatagramPort::builder()
                .udp_io(wire.clone())
                .ingress_limits(Limits { count: LIMIT, bytes: 64 * 1024 })
                .decision_deadline(Duration::from_millis(500))
                .intercept()
                .unwrap();
            let (_endpoint, _incoming, to_endpoint) =
                Endpoint::builder().bind_on(&port).unwrap();
            let upstream = upstream(&port).await;
            let mut held = Vec::new();

            for (n, fate) in fates.iter().take(12).enumerate() {
                wire.deliver(datagram(options(&format!("q{n}"))));
                stats_until(&port, |stats| stats.received == n as u64 + 1)
                    .await;
                let stats = port.stats();
                let ended = stats.overflow
                    + stats.delivered
                    + stats.forwarded
                    + stats.discarded
                    + stats.abandoned
                    + stats.expired;
                if ended + held.len() as u64 == stats.received {
                    continue; // Dropped on receipt.
                }
                let datagram = next(&mut ingress).await;
                match fate {
                    Fate::Deliver => {
                        datagram.try_deliver(&to_endpoint).unwrap();
                    }
                    Fate::Forward => {
                        datagram
                            .try_forward(&upstream)
                            .unwrap()
                            .await
                            .unwrap();
                    }
                    Fate::Discard => datagram.discard(),
                    Fate::Drop => drop(datagram),
                    Fate::Hold => held.push(datagram),
                    Fate::Expire => {
                        advance(Duration::from_millis(500)).await;
                        let refused =
                            datagram.try_deliver(&to_endpoint).unwrap_err();
                        assert!(refused.error().is_expired());
                    }
                }
            }
            drop(held);

            let stats = port.stats();
            let ended = stats.overflow
                + stats.delivered
                + stats.forwarded
                + stats.discarded
                + stats.abandoned
                + stats.expired;
            let mut whole = true;
            for n in 0..LIMIT {
                wire.deliver(datagram(options(&format!("after{n}"))));
            }
            let received = stats.received + LIMIT as u64;
            stats_until(&port, |stats| stats.received == received).await;
            whole &= port.stats().overflow == stats.overflow;
            ended == stats.received && whole
        })
    }

    QuickCheck::new().tests(40).quickcheck(property as fn(Vec<Fate>) -> bool);
}

// A port can intercept the endpoint's own kind of socket too. A request from
// an ordinary endpoint reaches the endpoint on the port through the
// application, and its response comes back through the port's socket.
#[tokio::test]
async fn a_socket_port_carries_a_round_trip() {
    let (port, mut ingress) = DatagramPort::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .intercept()
        .unwrap();
    let (_server, mut incoming, to_server) =
        Endpoint::builder().bind_on(&port).unwrap();
    let (client, _client_incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, port.local_addr());

    let (_control, mut responses) =
        client.start(outgoing("socket"), target).await.unwrap().into_parts();
    next(&mut ingress).await.try_deliver(&to_server).unwrap();
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);
}
