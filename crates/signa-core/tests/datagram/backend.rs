/*!
What an endpoint asks of its backend. A request and its response cross the
wire with the addresses the wire reports. A write counts against the
endpoint's limits until the wire reports how it ended, and the endpoint tells
a failed write from one whose outcome is unknown. What the wire cannot
deliver whole is never parsed.
*/

use std::{
    io,
    net::SocketAddr,
    pin::pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, ServerEvent, Target, ViaMode},
    message::header::{Tag, VIA},
    transport::{
        Flow, Limits, Transport,
        datagram::{
            Capabilities, Datagram, DatagramIo, DatagramWrite,
            MAX_CONTEXT_LEN, RecvError, Submit, TransportContext, WriteId,
            WriteOutcome,
        },
    },
};
use tokio::time::timeout;

use crate::{
    datagram::{
        LOCAL, PEER, bind, datagram, invite, ok, options, outgoing,
        send_options, short_timers, status, unknown,
        wire::{Way, Wire, Writes},
    },
    support::request,
};

// A request that arrives on the wire comes up with the addresses the wire
// reported, and its response goes back down from the address it came to. The
// Via names port 5060 and `rport` asks for the port it came from, which is
// where the response goes (RFC 3581 section 4).
#[tokio::test]
async fn a_request_and_its_response_cross_the_wire() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    assert_eq!(endpoint.udp_addr(), Some(LOCAL));

    let context = TransportContext::new(Bytes::from_static(b"nic0 vlan 100"));
    wire.deliver(
        datagram(options("uas"))
            .map(|datagram| datagram.with_context(context.unwrap())),
    );
    let request = request(&mut incoming).await;
    assert_eq!(
        request.received.flow(),
        Flow { transport: Transport::Udp, local: LOCAL, remote: PEER }
    );
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, PEER));
    let response = Response::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(sent[0].path, Way::reply("nic0 vlan 100"));
}

// A client transaction sends from the backend's address and names it in its
// Via. Its response arrives through the backend too.
#[tokio::test]
async fn a_client_transaction_runs_over_the_wire() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);

    let target = Target::new(Transport::Udp, PEER);
    let (control, mut responses) = endpoint
        .start(outgoing("uac"), target.clone())
        .await
        .unwrap()
        .into_parts();
    assert_eq!(control.flow().local, LOCAL);

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LOCAL, PEER));
    assert_eq!(sent[0].path, Way::Default);
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    let via = request.headers().get(VIA).unwrap().as_str();
    assert!(via.starts_with("SIP/2.0/UDP 192.0.2.10:5060;rport;branch="));

    wire.deliver(Ok(Datagram::new(ok(&request).to_bytes(), PEER, LOCAL)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);
}

// A one-shot send resolves when the wire reports the datagram written, not
// when it takes it.
#[tokio::test]
async fn a_send_waits_for_its_completion() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    wire.writes(Writes::Delay);
    let target = Target::new(Transport::Udp, PEER);

    let mut send = pin!(endpoint.send_request(
        outgoing("delay"),
        target.clone(),
        ViaMode::Fresh
    ));
    tokio::select! {
        _ = &mut send => panic!("the write has not completed"),
        _ = wire.sent(1) => {}
    }
    assert!(
        timeout(Duration::from_millis(50), &mut send).await.is_err(),
        "the write has not completed"
    );
    wire.finish(Ok(()));

    let sent = timeout(Duration::from_secs(2), send).await.unwrap().unwrap();
    assert_eq!(sent.flow().local, LOCAL);
}

// A write the wire takes and then fails is a transport error, for a one-shot
// send and for a client transaction's request alike. A transaction whose
// request fails at once is never started, and one whose request fails later
// ends with the error.
#[tokio::test]
async fn a_failed_write_is_reported() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    wire.writes(Writes::Fail);
    let target = Target::new(Transport::Udp, PEER);

    let error = endpoint
        .send_request(outgoing("fail"), target.clone(), ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_transport());
    let error = endpoint
        .start(outgoing("fail-at-once"), target.clone())
        .await
        .unwrap_err();
    assert!(error.is_transport());

    wire.writes(Writes::Delay);
    let (_control, mut responses) = endpoint
        .start(outgoing("fail-later"), target.clone())
        .await
        .unwrap()
        .into_parts();
    wire.sent(3).await;
    wire.finish(Err(io::Error::new(io::ErrorKind::NotConnected, "link down")));
    let error = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is_transport());
}

// A backend may refuse a write with `WouldBlock`, as one whose own queue is
// full would. That is the backend's refusal, not the endpoint's limits, so a
// one-shot send, a client transaction's request and a reply all fail as
// transport errors, and none is told that the endpoint is busy.
#[tokio::test]
async fn a_backend_refusing_with_would_block_is_a_transport_error() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    wire.deliver(datagram(options("refused-reply")));
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    let route = responder.reply_route();
    let target = Target::new(Transport::Udp, PEER);
    wire.writes(Writes::Busy);

    let sent = endpoint
        .send_request(outgoing("refused-send"), target.clone(), ViaMode::Fresh)
        .await
        .unwrap_err();
    let started =
        endpoint.start(outgoing("refused-start"), target).await.unwrap_err();
    let replied = route.send(ok(&request.request)).await;

    assert!(sent.is_transport() && !sent.is_busy(), "{sent}");
    assert!(started.is_transport() && !started.is_busy(), "{started}");
    assert!(
        matches!(replied, Err(signa_core::endpoint::ReplyError::Transport(_))),
        "{replied:?}"
    );
    assert_eq!(wire.state.lock().unwrap().refused, 3);
    drop(responder);
}

// A retransmission the backend refuses with `WouldBlock` is a transport
// error, which ends the client transaction (RFC 3261 section 17.1.2.2). Only
// a full limit of the endpoint's own skips a retransmission as if UDP had
// lost it.
#[tokio::test]
async fn a_refused_retransmission_ends_its_transaction() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(short_timers())
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing("retransmission"), target)
        .await
        .unwrap()
        .into_parts();
    wire.sent(1).await;

    wire.writes(Writes::Busy);

    let ended = timeout(Duration::from_secs(2), responses.next()).await;
    let ended = ended.unwrap().unwrap().unwrap_err();
    assert!(ended.is_transport() && !ended.is_timeout(), "{ended}");
    assert_eq!(wire.count(), 1);
}

// A write the wire took and cannot account for may have gone out, so it is
// not a failure. A one-shot send and a one-shot reply report the outcome
// unknown, and a client transaction goes on until its response. Only a
// request that did not go out ends a transaction (RFC 3261 sections 17.1.1.2
// and 17.1.2.2).
#[tokio::test]
async fn an_unknown_write_outcome_is_not_a_failure() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    wire.writes(Writes::Delay);

    let send = send_options(&endpoint, "unknown");
    wire.sent(1).await;
    wire.finish(unknown());
    let error = timeout(Duration::from_secs(2), send)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is_outcome_unknown());
    assert!(!error.is_transport() && !error.is_closed());

    let target = Target::new(Transport::Udp, PEER);
    let (_control, mut responses) = endpoint
        .start(outgoing("uac-unknown"), target)
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(2).await;
    wire.finish(unknown());
    assert!(
        timeout(Duration::from_millis(50), responses.next()).await.is_err(),
        "the transaction ended on an unknown outcome"
    );
    let sent_request = Request::from_bytes(&sent[1].payload).unwrap();
    let response = ok(&sent_request).to_bytes();
    wire.deliver(Ok(Datagram::new(response, PEER, LOCAL)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);

    wire.writes(Writes::Complete);
    wire.deliver(datagram(options("reply-unknown")));
    let request = request(&mut incoming).await;
    // The responder stays alive, so that its drop sends no 500 meanwhile.
    let (responder, _) = request.transaction.into_parts();
    let route = responder.reply_route();
    wire.writes(Writes::Delay);
    let reply = tokio::spawn({
        let response = ok(&request.request);
        async move { route.send(response).await }
    });
    wire.until(|state| !state.delayed.is_empty()).await;
    wire.finish(unknown());
    let reply = timeout(Duration::from_secs(2), reply).await.unwrap();
    assert!(matches!(
        reply.unwrap(),
        Err(signa_core::endpoint::ReplyError::OutcomeUnknown(_))
    ));
    drop(responder);
}

// A final the wire cannot account for is observed as an unknown outcome, not
// as a transport failure, and the transaction keeps its state as it does
// after one (RFC 6026 section 8.8). A retransmission of the request is
// absorbed and gets the cached final.
#[tokio::test]
async fn an_unknown_final_is_observed_apart_from_failures() {
    for is_invite in [false, true] {
        let branch =
            if is_invite { "unknown-invite" } else { "unknown-options" };
        let text = if is_invite { invite(branch) } else { options(branch) };
        let code = if is_invite { 486 } else { 200 };
        let wire = Wire::default();
        let (_endpoint, mut incoming) = bind(&wire);
        wire.deliver(datagram(text.clone()));
        let request = request(&mut incoming).await;
        if is_invite {
            wire.sent(1).await; // The automatic 100.
        }
        let (responder, mut events) = request.transaction.into_parts();
        let response = Response::reply_to(&request.request)
            .status(code)
            .to_tag(Tag::random())
            .body(Bytes::new())
            .unwrap();

        wire.writes(Writes::Delay);
        responder.respond(response).await.unwrap();
        wire.until(|state| !state.delayed.is_empty()).await;
        wire.finish(unknown());

        let event =
            timeout(Duration::from_secs(2), events.next()).await.unwrap();
        assert!(
            matches!(
                event,
                Some(ServerEvent::OutcomeUnknown { operation: Some(_), .. })
            ),
            "{is_invite}: {event:?}"
        );
        wire.writes(Writes::Complete);
        let before = wire.count();
        wire.deliver(datagram(text));
        let sent = wire.sent(before + 1).await;
        assert_eq!(status(&sent[before]), code, "{is_invite}");
        assert!(
            timeout(Duration::from_millis(50), incoming.recv()).await.is_err(),
            "{is_invite}: the retransmission reached the TU"
        );
    }
}

// Writes the wire cannot take wait in the endpoint, within its UDP write
// limits, and go out in order once the wire can take them.
#[tokio::test]
async fn a_held_wire_fills_the_write_limits() {
    let wire = Wire::default();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .udp_write_limits(Limits { count: 2, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    wire.writes(Writes::Hold);
    let target = Target::new(Transport::Udp, PEER);

    let first =
        endpoint.send_request(outgoing("1"), target.clone(), ViaMode::Fresh);
    let second =
        endpoint.send_request(outgoing("2"), target.clone(), ViaMode::Fresh);
    let mut both = pin!(async { tokio::join!(first, second) });
    assert!(timeout(Duration::from_millis(50), &mut both).await.is_err());
    let error = endpoint
        .send_request(outgoing("3"), target.clone(), ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_busy());

    wire.writes(Writes::Complete);
    let (first, second) = timeout(Duration::from_secs(2), both).await.unwrap();
    first.unwrap();
    second.unwrap();
    let sent = wire.sent(2).await;
    let calls: Vec<_> = sent
        .iter()
        .map(|sent| {
            let request = Request::from_bytes(&sent.payload).unwrap();
            request.headers().get("Call-ID").unwrap().as_str().to_owned()
        })
        .collect();
    assert_eq!(calls, ["1", "2"]);
}

// What the wire cannot deliver whole is counted and never parsed.
#[tokio::test]
async fn undeliverable_datagrams_are_counted_and_dropped() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);

    wire.deliver(Err(RecvError::Truncated));
    wire.deliver(Err(RecvError::Io(io::Error::other("nic reset"))));
    wire.deliver(datagram(options("after")));

    let request = request(&mut incoming).await;
    assert_eq!(request.request.headers().get("Call-ID").unwrap(), "after");
    let stats = endpoint.reception_stats();
    assert_eq!(stats.truncated_datagrams, 1);
    assert_eq!(stats.receive_errors, 1);
}

#[test]
fn a_context_is_bounded_when_it_is_made() {
    let longest = Bytes::from(vec![0; MAX_CONTEXT_LEN]);
    let longer = Bytes::from(vec![0; MAX_CONTEXT_LEN + 1]);

    assert_eq!(TransportContext::new(longest).unwrap().len(), MAX_CONTEXT_LEN);
    assert_eq!(
        TransportContext::new(longer).unwrap_err().context_len(),
        MAX_CONTEXT_LEN + 1
    );
}

#[test]
fn a_backend_must_name_its_address_and_send_something() {
    struct Misnamed {
        local: &'static str,
        max_payload: usize,
        wire: Wire,
    }

    impl DatagramIo for Misnamed {
        fn local_addr(&self) -> SocketAddr {
            self.local.parse().unwrap()
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::new(self.max_payload)
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Datagram, RecvError>> {
            self.wire.poll_recv(cx)
        }

        fn poll_submit(
            &mut self,
            cx: &mut Context<'_>,
            write: DatagramWrite,
        ) -> Submit {
            self.wire.poll_submit(cx, write)
        }

        fn poll_complete(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<(WriteId, WriteOutcome)> {
            self.wire.poll_complete(cx)
        }

        fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            self.wire.poll_close(cx)
        }
    }

    for (local, max_payload) in [
        ("0.0.0.0:5060", 1472),
        ("192.0.2.10:0", 1472),
        ("192.0.2.10:5060", 0),
    ] {
        let backend = Misnamed { local, max_payload, wire: Wire::default() };

        let error = Endpoint::builder().udp_io(backend).bind().unwrap_err();

        assert!(error.is_invalid_config(), "{local} {max_payload}");
    }
}
