/*!
A response goes back with the context its request arrived with, whatever
sends it (RFC 3261 section 18.2.2), and the same request on two wires makes a
transaction on each. The endpoint counts the contexts it keeps against its
limits for as long as anything holds them.
*/

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, IncomingEvent, Reception},
    message::header::Tag,
    transaction::Timers,
    transport::{Limits, datagram::Datagram},
};
use tokio::{task::yield_now, time::timeout};

use crate::{
    datagram::{
        LOCAL, PEER, arriving, bind, context, datagram, invite, ok, options,
        status, stray_ack,
        wire::{Way, Wire},
    },
    support::request,
};

// Each response of a server transaction goes back with the context its
// request arrived with: the automatic 100, the final, and the final again
// for a retransmission. A request that came without context is answered
// without one. An ACK the TU gets comes up with its own context.
#[tokio::test]
async fn server_output_goes_back_with_the_request_s_context() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);

    wire.deliver(arriving(invite("busy"), "nic0"));
    let busy_invite = request(&mut incoming).await;
    assert_eq!(busy_invite.received.context().as_bytes(), "nic0");
    assert_eq!(busy_invite.received.flow().remote, PEER);
    assert_eq!(busy_invite.received.flow().local, LOCAL);
    let (responder, _) = busy_invite.transaction.into_parts();
    let busy = Response::reply_to(&busy_invite.request)
        .status(486)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap();
    responder.respond(busy).await.unwrap();
    wire.deliver(arriving(invite("busy"), "nic0"));

    let sent = wire.sent(3).await;
    assert_eq!(sent.iter().map(status).collect::<Vec<_>>(), [100, 486, 486]);
    for sent in &sent {
        assert_eq!((sent.source, sent.destination), (LOCAL, PEER));
        assert_eq!(sent.path, Way::reply("nic0"));
    }

    wire.deliver(datagram(options("bare")));
    let bare = request(&mut incoming).await;
    assert!(bare.received.context().is_empty());
    let (responder, _) = bare.transaction.into_parts();
    responder.respond(ok(&bare.request)).await.unwrap();
    assert_eq!(wire.sent(4).await[3].path, Way::Default);

    wire.deliver(arriving(stray_ack(), "nic2"));
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::Ack(ack)) = event.unwrap() else {
        panic!("expected the ACK");
    };
    assert_eq!(ack.received.context().as_bytes(), "nic2");
}

// Without `rport` a response goes to the port of the Via, not to the one its
// request came from (RFC 3261 section 18.2.2). The backend gets that
// destination with the request's context, and works out the way back from
// both. It does not swap the request's addresses.
#[tokio::test]
async fn a_response_without_rport_goes_to_the_via_port_with_the_context() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);
    let text = options("plain").replace(";rport", "");

    wire.deliver(arriving(text, "nic0"));
    let request = request(&mut incoming).await;
    assert_eq!(request.received.flow().remote, PEER);
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    let via_port = SocketAddr::new(PEER.ip(), 5060);
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, via_port));
    assert_eq!(sent[0].path, Way::reply("nic0"));
}

// Two endpoints on two wires with the same addresses stand for two network
// domains. The same request, branch and addresses in both makes a
// transaction in each, and each answers on its own wire with its own
// context. Within one domain the same request over another NIC is a
// retransmission, since the NIC is no part of the matching key of RFC 3261
// section 17.2.3. Its cached response goes back the way the first copy came.
#[tokio::test]
async fn identical_tuples_in_separate_domains_stay_apart() {
    let (a_wire, b_wire) = (Wire::default(), Wire::default());
    let (_a, mut a_incoming) = bind(&a_wire);
    let (_b, mut b_incoming) = bind(&b_wire);

    a_wire.deliver(arriving(options("same"), "domain a"));
    b_wire.deliver(arriving(options("same"), "domain b"));
    for (incoming, domain) in
        [(&mut a_incoming, "domain a"), (&mut b_incoming, "domain b")]
    {
        let request = request(incoming).await;
        assert_eq!(request.received.context().as_bytes(), domain);
        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request)).await.unwrap();
    }
    assert_eq!(a_wire.sent(1).await[0].path, Way::reply("domain a"));
    assert_eq!(b_wire.sent(1).await[0].path, Way::reply("domain b"));

    a_wire.deliver(arriving(options("same"), "domain a nic1"));
    let sent = a_wire.sent(2).await;
    assert_eq!(sent[1].payload, sent[0].payload);
    assert_eq!(sent[1].path, Way::reply("domain a"));
    let again = timeout(Duration::from_millis(50), a_incoming.recv()).await;
    assert!(again.is_err(), "a retransmission reaches no TU");
    assert_eq!(b_wire.count(), 1);
}

// The 503 a request gets when the endpoint is full goes back with the
// request's context, though nothing keeps that context afterwards.
#[tokio::test]
async fn a_stateless_refusal_goes_back_with_the_context() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .max_pending_requests(1)
        .bind()
        .unwrap();

    wire.deliver(arriving(options("held"), "nic0"));
    let _held = request(&mut incoming).await;
    wire.deliver(arriving(options("refused"), "nic1"));

    let sent = wire.sent(1).await;
    assert_eq!(status(&sent[0]), 503);
    assert_eq!(sent[0].path, Way::reply("nic1"));
}

// The endpoint counts the contexts it keeps for as long as anything holds
// them, which for a server transaction lasts until Timer J. New requests get
// three quarters of the limits and a 503 past them. A request without
// context takes nothing.
#[tokio::test]
async fn kept_contexts_are_bounded_for_their_lifetime() {
    let wire = Wire::default();
    let timers =
        Timers::builder().t1(Duration::from_millis(5)).build().unwrap();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(timers)
        .context_limits(Limits { count: 4, bytes: 64 * 1024 })
        .bind()
        .unwrap();

    let mut held = Vec::new();
    for call in ["one", "two", "three"] {
        wire.deliver(arriving(options(call), "nic0"));
        held.push(request(&mut incoming).await);
    }
    wire.deliver(arriving(options("four"), "nic0"));
    let sent = wire.sent(1).await;
    assert_eq!(status(&sent[0]), 503);
    wire.deliver(datagram(options("bare")));
    let bare = request(&mut incoming).await;
    assert!(bare.received.context().is_empty());

    // Their 500s go out when the responders drop, and Timer J of 64 T1 ends
    // the transactions that kept the contexts. Until then a request with
    // context gets a 503.
    drop(held);
    wire.sent(4).await;
    let admitted = timeout(Duration::from_secs(5), async {
        for attempt in 0.. {
            wire.deliver(arriving(options(&format!("late{attempt}")), "nic0"));
            let event = timeout(Duration::from_millis(50), incoming.recv());
            if let Ok(Some(IncomingEvent::Request(request))) = event.await {
                return request;
            }
        }
        unreachable!()
    })
    .await
    .expect("Timer J frees the contexts");
    assert_eq!(admitted.received.context().as_bytes(), "nic0");
}

fn cancel_of(branch: &str) -> String {
    format!(
        "CANCEL sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@192.0.2.20>;tag=alice\r\n\
         To: <sip:bob@192.0.2.10>\r\n\
         Call-ID: {branch}\r\n\
         CSeq: 1 CANCEL\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

// A stateless endpoint keeps a request's context for its reply route and
// shows a response's in its envelope.
#[tokio::test]
async fn a_stateless_endpoint_keeps_contexts_too() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .reception(Reception::Stateless)
        .bind()
        .unwrap();

    wire.deliver(arriving(options("stateless"), "nic0"));
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::StatelessRequest(received)) = event.unwrap()
    else {
        panic!("expected a stateless request");
    };
    assert_eq!(received.received.context().as_bytes(), "nic0");
    received.reply.send(ok(&received.request)).await.unwrap();
    assert_eq!(wire.sent(1).await[0].path, Way::reply("nic0"));

    let request = Request::from_bytes(options("upstream").as_bytes()).unwrap();
    wire.deliver(
        Ok(Datagram::new(ok(&request).to_bytes(), PEER, LOCAL))
            .map(|datagram| datagram.with_context(context("nic1"))),
    );
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::StatelessResponse(response)) = event.unwrap()
    else {
        panic!("expected a stateless response");
    };
    assert_eq!(response.received.context().as_bytes(), "nic1");
}

// ACKs and matched CANCELs may use the quarter of the context limits that
// new requests leave. An ACK past all of it is discarded and counted, as one
// past the control event limits is.
#[tokio::test]
async fn control_messages_keep_a_share_of_the_context_limits() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .context_limits(Limits { count: 4, bytes: 64 * 1024 })
        .bind()
        .unwrap();

    let mut held = Vec::new();
    for branch in ["one", "two", "three"] {
        wire.deliver(arriving(invite(branch), "nic0"));
        held.push(request(&mut incoming).await);
    }
    wire.deliver(arriving(cancel_of("one"), "nic9"));
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    let Some(IncomingEvent::Cancel(cancel)) = event.unwrap() else {
        panic!("expected the CANCEL");
    };
    assert_eq!(cancel.received.context().as_bytes(), "nic9");

    wire.deliver(arriving(stray_ack(), "nic2"));
    timeout(Duration::from_secs(2), async {
        while endpoint.reception_stats().dropped_acks == 0 {
            yield_now().await;
        }
    })
    .await
    .expect("the ACK is counted");
    let event = timeout(Duration::from_millis(50), incoming.recv()).await;
    assert!(event.is_err(), "the ACK reaches no TU");
}
