/*!
IPv4-mapped and link-local addresses. An endpoint names an IPv4 peer in its
IPv4 form, and keeps a link-local peer on the interface its scope names.
*/

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, PathSelection, Target, ViaMode},
    message::header::VIA,
    transport::{Transport, datagram::Datagram},
};
use tokio::time::timeout;

use crate::{
    datagram::{
        LINK_LOCAL, LINK_PEER, LOCAL, PEER, bind, ok, options, outgoing,
        wire::Wire,
    },
    support::request,
};

// A backend that reports an IPv4 peer by its IPv4-mapped IPv6 address gets
// it named in its IPv4 form, as a Via names it, so a request whose Via
// names that address and asks for no `rport` gets no `received`.
#[tokio::test]
async fn mapped_ipv4_addresses_are_named_in_their_own_form() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);
    let mapped = |addr: SocketAddr| match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            SocketAddr::new(ip.to_ipv6_mapped().into(), addr.port())
        }
        std::net::IpAddr::V6(_) => addr,
    };

    let text = options("mapped")
        .replace("192.0.2.20:5060", "192.0.2.20:5070")
        .replace(";rport", "");
    wire.deliver(Ok(Datagram::new(
        Bytes::from(text),
        mapped(PEER),
        mapped(LOCAL),
    )));

    let request = request(&mut incoming).await;
    assert_eq!(request.received.flow().remote, PEER);
    assert_eq!(request.received.flow().local, LOCAL);
    let via = request.request.headers().get(VIA).unwrap().as_str();
    assert!(!via.contains("received="), "{via}");
}

// A dual-stack socket sends to an IPv4 peer at its mapped address, so it
// takes an IPv4 path from an address of this host too, where the platform
// sends from a named source. Elsewhere, as on Windows, the kernel picks the
// source of a wildcard socket, a path could not fix it, and the socket
// refuses the path. A socket bound to the address takes it there too, see
// `the_socket_takes_paths_from_its_own_address`.
#[tokio::test]
async fn a_dual_stack_socket_takes_ipv4_paths() {
    let Ok((endpoint, _incoming)) =
        Endpoint::builder().udp("[::]:0".parse().unwrap()).bind()
    else {
        return; // No IPv6 here.
    };
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let port = endpoint.udp_addr().unwrap().port();
    let source = SocketAddr::new([127, 0, 0, 1].into(), port);

    let prepared =
        endpoint.prepare_path(PathSelection::new(source, peer_addr)).await;
    let names_source = cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ));
    if !names_source {
        assert!(prepared.unwrap_err().is_path_refused());
        return;
    }
    let path = prepared.unwrap();
    endpoint
        .send_request(outgoing("dual"), Target::on_path(path), ViaMode::Fresh)
        .await
        .unwrap();

    let mut buffer = [0; 2048];
    let (_, from) =
        timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(from, source);
}

// A link-local peer is reachable only through the interface its scope names.
// The request comes up with the scope and flow label the wire reported, and
// the response goes back with them, to the source port with `rport` and to
// the Via port without it (RFC 3581 section 4, RFC 3261 section 18.2.2), and
// so does the response a retransmission gets.
#[tokio::test]
async fn a_link_local_peer_is_answered_on_its_interface() {
    let wire = Wire::default();
    let (_endpoint, mut incoming) = bind(&wire);
    let scoped =
        |branch| options(branch).replace("192.0.2.20:5060", "[fe80::20]:5060");
    let mut via_port = LINK_PEER;
    via_port.set_port(5060);

    for (text, destination) in [
        (scoped("rport"), LINK_PEER),
        (scoped("plain").replace(";rport", ""), via_port),
    ] {
        let sent = wire.count();
        let text = Bytes::from(text);
        wire.deliver(Ok(Datagram::new(text.clone(), LINK_PEER, LINK_LOCAL)));
        let request = request(&mut incoming).await;
        assert_eq!(request.received.flow().remote, LINK_PEER);
        assert_eq!(request.received.flow().local, LINK_LOCAL);

        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request)).await.unwrap();

        let response = &wire.sent(sent + 1).await[sent];
        assert_eq!(
            (response.source, response.destination),
            (LINK_LOCAL, destination)
        );

        // A retransmission gets the cached response the same way.
        wire.deliver(Ok(Datagram::new(text, LINK_PEER, LINK_LOCAL)));
        let resent = &wire.sent(sent + 2).await[sent + 1];
        assert_eq!(
            (resent.source, resent.destination),
            (LINK_LOCAL, destination)
        );
        assert_eq!(resent.payload, response.payload);
    }
}

// A path keeps the scope of its addresses, which the wire checks, and its
// requests go out with it. The `sent-by` has none, since a Via cannot name
// one (RFC 3261 section 25.1), and the response is matched against it.
#[tokio::test]
async fn a_scoped_path_keeps_its_scope_and_advertises_none() {
    let wire = Wire::default();
    let (endpoint, _incoming) = bind(&wire);
    let mut elsewhere = LINK_LOCAL;
    if let SocketAddr::V6(addr) = &mut elsewhere {
        addr.set_scope_id(8);
    }

    let refused = endpoint
        .prepare_path(PathSelection::new(elsewhere, LINK_PEER))
        .await
        .unwrap_err();
    let path = endpoint
        .prepare_path(PathSelection::new(LINK_LOCAL, LINK_PEER))
        .await
        .unwrap();

    assert!(refused.is_path_refused());
    assert_eq!((path.source(), path.destination()), (LINK_LOCAL, LINK_PEER));
    assert_eq!(path.sent_by(), "[fe80::10]:5060".parse().unwrap());

    let (_control, mut responses) = endpoint
        .start(outgoing("scoped-path"), Target::on_path(path))
        .await
        .unwrap()
        .into_parts();
    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LINK_LOCAL, LINK_PEER));
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    let via = request.headers().get(VIA).unwrap().as_str();
    assert!(
        via.starts_with("SIP/2.0/UDP [fe80::10]:5060;rport;branch="),
        "{via}"
    );

    wire.deliver(Ok(Datagram::new(
        ok(&request).to_bytes(),
        LINK_PEER,
        LINK_LOCAL,
    )));
    let response = timeout(Duration::from_secs(2), responses.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(response.status().as_u16(), 200);
}

// A dual-stack socket reports an IPv4 peer by its mapped address, and the
// endpoint names it in its IPv4 form, as a Via does. An IPv6 socket takes
// IPv4 by default on Linux, Android and Apple's systems, which also report
// the address a datagram came to. Windows and some BSDs bind it to IPv6 only
// unless told otherwise, and a Linux host can be set up so too.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
))]
#[tokio::test]
async fn a_dual_stack_socket_names_ipv4_peers_in_their_own_form() {
    let Ok((endpoint, mut incoming)) =
        Endpoint::builder().udp("[::]:0".parse().unwrap()).bind()
    else {
        return; // No IPv6 here.
    };
    let port = endpoint.udp_addr().unwrap().port();
    let local = SocketAddr::new([127, 0, 0, 1].into(), port);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let text =
        options("dual").replace("192.0.2.20:5060", &peer_addr.to_string());

    peer.send_to(text.as_bytes(), local).await.unwrap();

    let request = request(&mut incoming).await;
    assert_eq!(request.received.flow().remote, peer_addr);
    assert_eq!(request.received.flow().local, local);

    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();
    let mut buffer = [0; 2048];
    let (n, _) = timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let response = Response::from_bytes(&buffer[..n]).unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

// A request to a link-local peer goes from the wire's link-local address on
// the peer's interface, which the peer's scope names. The Via names the
// address without one.
#[tokio::test]
async fn a_request_to_a_link_local_peer_goes_out_on_its_interface() {
    let mut unscoped = LINK_LOCAL;
    if let SocketAddr::V6(addr) = &mut unscoped {
        addr.set_scope_id(0);
    }
    let wire = Wire::at(unscoped);
    let (endpoint, _incoming) = bind(&wire);

    endpoint
        .send_request(
            outgoing("link-local"),
            Target::new(Transport::Udp, LINK_PEER),
            ViaMode::Fresh,
        )
        .await
        .unwrap();

    let sent = wire.sent(1).await;
    assert_eq!((sent[0].source, sent[0].destination), (LINK_LOCAL, LINK_PEER));
    let request = Request::from_bytes(&sent[0].payload).unwrap();
    let via = request.headers().get(VIA).unwrap().as_str();
    assert!(via.starts_with("SIP/2.0/UDP [fe80::10]:5060;rport;"), "{via}");
}
