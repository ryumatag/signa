/*!
Requests on a prepared path, which carry its source, context and `sent-by`
for their whole transaction, and the paths an endpoint takes.
*/

use std::{io, net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, PathSelection, Target, ViaMode},
    message::header::VIA,
    transaction::Timers,
    transport::{Limits, Transport, datagram::Datagram},
};
use tokio::{task::yield_now, time::timeout};

use crate::{
    datagram::{
        ALTERNATE, LOCAL, PEER, PUBLIC, bind, context, datagram, method,
        options, outgoing, outgoing_invite,
        wire::{Way, Wire},
    },
    support::request,
};

// A request on a prepared path goes from the path's source with its
// context, names the path's `sent-by` in its Via, and keeps the path for its
// retransmissions and its CANCEL. A response must name that `sent-by`,
// as RFC 3261 section 18.1.2 checks, not the source address.
#[tokio::test]
async fn a_prepared_path_carries_a_whole_transaction() {
    let wire = Wire::default();
    let timers =
        Timers::builder().t1(Duration::from_millis(20)).build().unwrap();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(timers)
        .bind()
        .unwrap();
    assert_eq!(endpoint.timers(), timers);

    let selection = PathSelection::new(ALTERNATE, PEER)
        .context(context("vlan 200"))
        .sent_by(PUBLIC);
    let path = endpoint.prepare_path(selection).await.unwrap();
    assert_eq!(
        (path.source(), path.destination(), path.sent_by()),
        (ALTERNATE, PEER, PUBLIC)
    );
    assert_eq!(path.context().as_bytes(), "vlan 200");
    let (control, mut responses) = endpoint
        .start(outgoing_invite("path"), Target::on_path(path))
        .await
        .unwrap()
        .into_parts();
    assert_eq!(control.flow().local, ALTERNATE);

    // The INVITE and at least one retransmission after T1.
    let sent = wire.sent(2).await;
    let invite = Request::from_bytes(&sent[0].payload).unwrap();
    let via = invite.headers().get(VIA).unwrap().clone();
    assert!(via.as_str().starts_with("SIP/2.0/UDP 203.0.113.5:5060;rport;"));

    let ringing = Response::reply_to(&invite)
        .status(180)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    let mut misnamed = ringing.clone();
    let source_via = via.as_str().replace("203.0.113.5", "198.51.100.10");
    misnamed.headers_mut().insert(VIA, source_via.parse().unwrap());
    wire.deliver(Ok(Datagram::new(misnamed.to_bytes(), PEER, ALTERNATE)));
    wire.deliver(Ok(Datagram::new(ringing.to_bytes(), PEER, ALTERNATE)));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 180);
    assert_eq!(response.headers().get(VIA), Some(&via));

    let outcome = control.cancel().await.unwrap();
    assert!(matches!(outcome, signa_core::endpoint::CancelOutcome::Sent(_)));
    let cancel = timeout(Duration::from_secs(2), async {
        loop {
            let sent = wire.sent(wire.count() + 1).await;
            if let Some(cancel) = sent
                .into_iter()
                .find(|sent| method(sent).as_deref() == Some("CANCEL"))
            {
                return cancel;
            }
        }
    })
    .await
    .unwrap();

    // The 487 is acknowledged by the transaction, on the INVITE's path
    // (RFC 3261 section 17.1.1.3).
    let terminated = Response::reply_to(&invite)
        .status(487)
        .to_tag("alice")
        .body(Bytes::new())
        .unwrap();
    wire.deliver(Ok(Datagram::new(terminated.to_bytes(), PEER, ALTERNATE)));
    timeout(Duration::from_secs(2), async {
        while !wire
            .sent(wire.count())
            .await
            .iter()
            .any(|sent| method(sent).as_deref() == Some("ACK"))
        {
            wire.sent(wire.count() + 1).await;
        }
    })
    .await
    .unwrap();

    let sent = wire.sent(wire.count()).await;
    for sent in sent.iter().filter(|sent| method(sent).is_some()) {
        assert_eq!((sent.source, sent.destination), (ALTERNATE, PEER));
        assert_eq!(sent.path, Way::prepared("vlan 200"));
    }
    let cancel = Request::from_bytes(&cancel.payload).unwrap();
    assert_eq!(cancel.headers().get(VIA), Some(&via));
}

// A path belongs to the endpoint that prepared it, and so does a prepared
// request. Another endpoint refuses both before anything is sent. The
// backend refuses a source it may not send from when the path is prepared,
// and a path that has turned stale since when a request is sent on it.
#[tokio::test]
async fn paths_are_checked_before_anything_is_sent() {
    let (a_wire, b_wire) = (Wire::default(), Wire::default());
    let (a, _a_incoming) = bind(&a_wire);
    let (b, _b_incoming) = bind(&b_wire);
    let path = a.prepare_path(PathSelection::new(LOCAL, PEER)).await.unwrap();

    let on_path = || Target::on_path(path.clone());
    assert!(
        b.start(outgoing("1"), on_path()).await.unwrap_err().is_stale_path()
    );
    let error = b
        .send_request(outgoing("2"), on_path(), ViaMode::Fresh)
        .await
        .unwrap_err();
    assert!(error.is_stale_path());
    assert!(
        b.prepare(outgoing("3"), on_path()).await.unwrap_err().is_stale_path()
    );
    let prepared = a
        .prepare(outgoing("4"), Target::new(Transport::Udp, PEER))
        .await
        .unwrap();
    assert!(b.start_prepared(prepared).await.unwrap_err().is_stale_path());
    assert_eq!((a_wire.count(), b_wire.count()), (0, 0));

    let multicast: SocketAddr = "224.0.1.75:5060".parse().unwrap();
    let no_port = SocketAddr::new(PEER.ip(), 0);
    let unspecified: SocketAddr = "0.0.0.0:5060".parse().unwrap();
    for selection in [
        PathSelection::new(LOCAL, multicast),
        PathSelection::new(LOCAL, no_port),
        PathSelection::new(LOCAL, PEER).sent_by(unspecified),
        PathSelection::new(unspecified, PEER),
    ] {
        let error = a.prepare_path(selection).await.unwrap_err();
        assert!(error.is_path_refused(), "{error}");
    }

    let error =
        a.prepare_path(PathSelection::new(PUBLIC, PEER)).await.unwrap_err();
    assert!(error.is_path_refused());
    assert_eq!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::AddrNotAvailable)
    );

    let selection =
        PathSelection::new(ALTERNATE, PEER).context(context("pppoe 7"));
    let path = a.prepare_path(selection).await.unwrap();
    a_wire.stale("pppoe 7");
    let error =
        a.start(outgoing("5"), Target::on_path(path)).await.unwrap_err();
    assert!(error.is_transport());
}

// `prepare` measures a request with the Via it will go out with, and
// `start_prepared` sends exactly those bytes. A UDP request over 1300 bytes
// is refused when started, not when measured, so the caller can take it to
// TCP instead (RFC 3261 section 18.1.1). That limit is for requests the
// endpoint generates. A response goes up to what the backend sends.
#[tokio::test]
async fn prepared_sizes_are_exact_and_only_requests_have_the_udp_limit() {
    let wire = Wire::default();
    let (endpoint, mut incoming) = bind(&wire);
    let target = Target::new(Transport::Udp, PEER);

    let prepared =
        endpoint.prepare(outgoing("size"), target.clone()).await.unwrap();
    let (len, via) = (prepared.encoded_len(), prepared.via().clone());
    assert_eq!(prepared.request().headers().get(VIA), Some(&via));
    assert_eq!(prepared.flow().local, LOCAL);
    endpoint.start_prepared(prepared).await.unwrap();
    let sent = wire.sent(1).await;
    assert_eq!(sent[0].payload.len(), len);
    let sent_request = Request::from_bytes(&sent[0].payload).unwrap();
    assert_eq!(sent_request.headers().get(VIA), Some(&via));

    let mut large = outgoing("large");
    *large.body_mut() = Bytes::from(vec![b'x'; 1200]);
    let prepared = endpoint.prepare(large, target.clone()).await.unwrap();
    assert!(prepared.encoded_len() > 1300);
    let large = prepared.into_request();
    assert!(large.headers().get(VIA).is_none());
    let prepared = endpoint.prepare(large, target.clone()).await.unwrap();
    assert!(
        endpoint.start_prepared(prepared).await.unwrap_err().is_too_large()
    );
    assert_eq!(wire.count(), 1);

    wire.deliver(datagram(options("large")));
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    let route = responder.reply_route();
    let response = |body: usize| {
        Response::reply_to(&request.request)
            .status(200)
            .to_tag("bob")
            .body(Bytes::from(vec![b'x'; body]))
            .unwrap()
    };
    responder.respond(response(1200)).await.unwrap();
    let sent = wire.sent(2).await;
    assert!(sent[1].payload.len() > 1300);
    let Err(signa_core::endpoint::ReplyError::Transport(error)) =
        route.send(response(1500)).await
    else {
        panic!("a response over the backend's maximum fails");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

// The endpoint's own socket accepts a path from its own address without
// context, and sends on it.
#[tokio::test]
async fn the_socket_takes_paths_from_its_own_address() {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let local = endpoint.udp_addr().unwrap();

    let other_port = SocketAddr::new(local.ip(), local.port().wrapping_add(1));
    let error = endpoint
        .prepare_path(PathSelection::new(other_port, peer_addr))
        .await
        .unwrap_err();
    assert!(error.is_path_refused());
    let error = endpoint
        .prepare_path(
            PathSelection::new(local, peer_addr).context(context("x")),
        )
        .await
        .unwrap_err();
    assert!(error.is_path_refused());

    let path = endpoint
        .prepare_path(PathSelection::new(local, peer_addr))
        .await
        .unwrap();
    endpoint
        .send_request(
            outgoing("socket"),
            Target::on_path(path),
            ViaMode::Fresh,
        )
        .await
        .unwrap();
    let mut buffer = [0; 2048];
    let (_, source) =
        timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source, local);
}

// A path counts against the context limits until its last clone and the
// last transaction sent on it drop. New paths get three quarters.
#[tokio::test]
async fn a_path_is_counted_until_nothing_holds_it() {
    let wire = Wire::default();
    let timers =
        Timers::builder().t1(Duration::from_millis(5)).build().unwrap();
    let (endpoint, _incoming) = Endpoint::builder()
        .udp_io(wire.clone())
        .timers(timers)
        .context_limits(Limits { count: 4, bytes: 64 * 1024 })
        .bind()
        .unwrap();
    let prepare = || {
        let selection =
            PathSelection::new(LOCAL, PEER).context(context("vlan"));
        endpoint.prepare_path(selection)
    };

    let mut paths = Vec::new();
    for _ in 0..3 {
        paths.push(prepare().await.unwrap());
    }
    assert!(prepare().await.unwrap_err().is_busy());
    let clone = paths[1].clone();
    drop(paths.remove(1));
    assert!(prepare().await.unwrap_err().is_busy(), "a clone holds it");
    drop(clone);
    paths.push(prepare().await.unwrap());

    // The transaction keeps its path until Timer F ends it, 64 T1 later.
    let (_control, mut responses) = endpoint
        .start(outgoing("held"), Target::on_path(paths.remove(0)))
        .await
        .unwrap()
        .into_parts();
    assert!(
        prepare().await.unwrap_err().is_busy(),
        "the transaction holds it"
    );
    let end = timeout(Duration::from_secs(2), responses.next()).await;
    assert!(end.unwrap().unwrap().unwrap_err().is_timeout());
    let freed = timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(path) = prepare().await {
                return path;
            }
            yield_now().await;
        }
    })
    .await;
    assert!(freed.is_ok(), "the ended transaction frees its path");
}
