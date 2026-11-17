/*!
An endpoint whose UDP datagrams travel over a backend of the application's
own.

The backend here is an in-memory packet wire, standing in for an adapter that
reads and writes frames on a NIC. The test decides when each write completes,
fails or waits, which a socket cannot be made to do on demand. Its contexts
are text such as `nic0 vlan 100`, which the endpoint never reads, and two
wires with the same addresses stand for two network domains.

`wire` holds the wire, and this module the addresses and messages the tests
share. The other modules hold the tests:

* `backend`: what the endpoint asks of a backend, and how each write it
  submits ends.
* `shutdown`: a shutdown drains the writes on the backend, then closes it.
* `failure`: a server transaction keeps its state after a transport failure
  (RFC 6026 section 8.8).
* `context`: a response goes back with the context its request came with,
  and the contexts the endpoint keeps are bounded.
* `path`: requests on a prepared path, and the paths an endpoint takes.
* `address`: IPv4-mapped and link-local addresses.
* `arrival`: what each received message keeps of how it arrived.
* `observe`: an endpoint's observer.
* `port`: ports that several endpoints share.
*/

mod address;
mod arrival;
mod backend;
mod context;
mod failure;
mod observe;
mod path;
mod port;
mod shutdown;
mod wire;

use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, Error, Incoming, Target, ViaMode},
    message::header::Tag,
    transaction::Timers,
    transport::{
        Transport,
        datagram::{Datagram, RecvError, TransportContext, WriteOutcome},
    },
};
use tokio::task::JoinHandle;

use crate::datagram::wire::{Sent, Wire};

/// The address the endpoint owns on the wire. Nothing binds it on this host.
const LOCAL: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
    5060,
);

const PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20)),
    5070,
);

/// A second address the wire may send from, as on a second VLAN.
const ALTERNATE: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10)),
    5060,
);

/// A link-local address of the wire on interface 7. The scope says which
/// interface, and nothing else in the endpoint reads it.
const LINK_LOCAL: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x10),
    5060,
    0,
    7,
));

/// A link-local peer on the same interface, with a flow label.
const LINK_PEER: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x20),
    5070,
    0x12345,
    7,
));

/// A public address that a static NAT maps onto `ALTERNATE`.
const PUBLIC: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)),
    5060,
);

fn bind(wire: &Wire) -> (Endpoint, Incoming) {
    Endpoint::builder().udp_io(wire.clone()).bind().unwrap()
}

fn options(branch: &str) -> String {
    format!(
        "OPTIONS sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@192.0.2.20>;tag=alice\r\n\
         To: <sip:bob@192.0.2.10>\r\n\
         Call-ID: {branch}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

fn outgoing(call: &str) -> Request<Bytes> {
    Request::builder()
        .method("OPTIONS")
        .uri("sip:alice@192.0.2.20")
        .header("From", "<sip:bob@192.0.2.10>;tag=bob")
        .header("To", "<sip:alice@192.0.2.20>")
        .header("Call-ID", call)
        .header("CSeq", "1 OPTIONS")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap()
}

fn datagram(text: String) -> Result<Datagram, RecvError> {
    Ok(Datagram::new(Bytes::from(text), PEER, LOCAL))
}

fn context(text: &'static str) -> TransportContext {
    TransportContext::new(Bytes::from_static(text.as_bytes())).unwrap()
}

/// A datagram from `PEER` with `text` and the context `on`.
fn arriving(text: String, on: &'static str) -> Result<Datagram, RecvError> {
    datagram(text).map(|datagram| datagram.with_context(context(on)))
}

fn ok(request: &Request<Bytes>) -> Response<Bytes> {
    Response::reply_to(request)
        .status(200)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .unwrap()
}

/// What a wire reports for a write it took and can no longer account for.
fn unknown() -> WriteOutcome {
    WriteOutcome::Unknown(io::Error::other("the writer stopped"))
}

fn invite(branch: &str) -> String {
    format!(
        "INVITE sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@192.0.2.20>;tag=alice\r\n\
         To: <sip:bob@192.0.2.10>\r\n\
         Call-ID: {branch}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@192.0.2.20:5070>\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

/// An ACK that matches no transaction, which goes to the TU.
fn stray_ack() -> String {
    "ACK sip:bob@192.0.2.10 SIP/2.0\r\n\
     Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bKstray;rport\r\n\
     Max-Forwards: 70\r\n\
     From: <sip:alice@192.0.2.20>;tag=alice\r\n\
     To: <sip:bob@192.0.2.10>;tag=bob\r\n\
     Call-ID: stray\r\n\
     CSeq: 1 ACK\r\n\
     Content-Length: 0\r\n\r\n"
        .to_owned()
}

fn outgoing_invite(call: &str) -> Request<Bytes> {
    Request::builder()
        .method("INVITE")
        .uri("sip:alice@192.0.2.20")
        .header("From", "<sip:bob@203.0.113.5>;tag=bob")
        .header("To", "<sip:alice@192.0.2.20>")
        .header("Call-ID", call)
        .header("CSeq", "1 INVITE")
        .header("Max-Forwards", "70")
        .header("Contact", "<sip:bob@203.0.113.5>")
        .body(Bytes::new())
        .unwrap()
}

fn status(sent: &Sent) -> u16 {
    Response::from_bytes(&sent.payload).unwrap().status().as_u16()
}

fn method(sent: &Sent) -> Option<String> {
    let request = Request::from_bytes(&sent.payload).ok()?;
    Some(request.method().as_str().to_owned())
}

/// Short timers, so that a transaction ends at Timer J within a test.
fn short_timers() -> Timers {
    Timers::builder().t1(Duration::from_millis(5)).build().unwrap()
}

/// Sends a one-shot OPTIONS from `endpoint` in a task of its own, which
/// resolves with the write's local outcome.
fn send_options(
    endpoint: &Endpoint,
    call: &'static str,
) -> JoinHandle<Result<(), Error>> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        endpoint
            .send_request(
                outgoing(call),
                Target::new(Transport::Udp, PEER),
                ViaMode::Fresh,
            )
            .await
            .map(|_| ())
    })
}
