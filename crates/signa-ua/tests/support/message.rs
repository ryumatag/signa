/*!
The messages of a peer, written out as text, and what a test reads from the
UA's.
*/

use std::net::SocketAddr;

use bytes::Bytes;
use signa_core::{
    HeaderValue, Request, Response, StatusCode, message::header::SUBJECT,
};
use signa_ua::{Description, InvitePlan};

/// The answer the application gives to the peer's offer.
pub(crate) fn sdp() -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(b"v=0\r\n"),
    )
}

pub(crate) fn invite_to_ua(peer: SocketAddr, call: &str) -> String {
    invite_over("UDP", peer, call)
}

pub(crate) fn invite_over(
    transport: &str,
    peer: SocketAddr,
    call: &str,
) -> String {
    format!(
        "INVITE sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 INVITE
Contact: <sip:peer@{peer}>
Record-Route: <sip:proxy.example.com;lr>
Content-Type: application/sdp
Content-Length: 5

v=0
"
    )
}

/// A plan for an INVITE from the UA to `to`, with an offer. `call` goes in
/// its Subject, so that a test can tell its INVITEs apart, since the UA
/// picks each Call-ID.
pub(crate) fn plan_to(to: &str, call: &str) -> InvitePlan {
    InvitePlan::new(
        format!("sip:peer@{to}").parse().unwrap(),
        "sip:ua@127.0.0.1".parse().unwrap(),
        sdp(),
    )
    .header(SUBJECT, HeaderValue::try_from(call).unwrap())
}

/// The response of the peer to an INVITE it received as `request`.
/// A 2xx carries the answer to the INVITE's offer.
pub(crate) fn answer(
    request: &str,
    status: &str,
    tag: &str,
    contact: &str,
) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let status = StatusCode::from_bytes(status.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(status)
        .to_tag(tag)
        .header("Contact", format!("<{contact}>").as_str());
    let response = if status.is_success() {
        response
            .header("Content-Type", "application/sdp")
            .body(Bytes::from_static(b"v=0\r\n"))
    } else {
        response.body(Bytes::new())
    };
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

pub(crate) fn header<'a>(message: &'a str, name: &str) -> Vec<&'a str> {
    message
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
        .collect()
}

/// The ACK of the peer for the 2xx `ok` it received for its INVITE `call`,
/// with `cseq` as its CSeq number.
pub(crate) fn ack_for(
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
) -> String {
    format!(
        "ACK sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-ack-{call}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} ACK
Content-Length: 0

",
        to = header(ok, "To")[0],
    )
}

/// An INVITE from `peer` straight to the UA, with no proxy on the way, so
/// that the dialog's requests go to the peer.
pub(crate) fn direct_invite(peer: SocketAddr, call: &str) -> String {
    invite_to_ua(peer, call)
        .replace("Record-Route: <sip:proxy.example.com;lr>\n", "")
}

/// [`direct_invite`] without its offer.
pub(crate) fn offerless_invite(peer: SocketAddr, call: &str) -> String {
    let invite = direct_invite(peer, call)
        .replace("Content-Type: application/sdp\n", "")
        .replace("Content-Length: 5\n\nv=0\n", "Content-Length: 0\n\n");
    assert!(!invite.contains("application/sdp") && invite.ends_with("\n\n"));
    invite
}

/// [`ack_for`] with an SDP answer, for a 2xx that carried an offer.
pub(crate) fn ack_answering(
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
) -> String {
    let ack = ack_for(ok, peer, call, cseq).replace(
        "Content-Length: 0\n",
        "Content-Type: application/sdp\nContent-Length: 5\n",
    );
    assert!(ack.contains("application/sdp"));
    ack + "v=0\n"
}

/// The value of the `branch` parameter of the top Via of `message`.
pub(crate) fn branch(message: &str) -> &str {
    let via = header(message, "Via")[0];
    let start = via.find("branch=").unwrap() + "branch=".len();
    via[start..].split(';').next().unwrap()
}

/// The 200 of the peer to a request it received as `request`.
pub(crate) fn ok_to(request: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response =
        Response::reply_to(&request).status(StatusCode::OK).body(Bytes::new());
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

/// A response of the peer to `request`, with `tag` on its To unless it has
/// one, and nothing else.
pub(crate) fn reply_with(request: &str, status: u16, tag: &str) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(status)
        .to_tag(tag)
        .body(Bytes::new());
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

/// The CANCEL of the INVITE [`invite_over`] made for `call` (RFC 3261
/// section 9.1): its Request-URI, top Via, From, To, Call-ID and CSeq
/// number.
pub(crate) fn cancel_of(
    transport: &str,
    peer: SocketAddr,
    call: &str,
) -> String {
    format!(
        "CANCEL sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 CANCEL
Content-Length: 0

"
    )
}

/// A request of the peer in the dialog its INVITE `call` formed with the
/// 2xx `ok`, numbered `cseq`.
pub(crate) fn in_dialog(
    method: &str,
    transport: &str,
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
) -> String {
    format!(
        "{method} sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{method}-{call}-{cseq}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} {method}
Content-Length: 0

",
        to = header(ok, "To")[0],
    )
}

/// An SDP offer whose session name is `name`.
pub(crate) fn offer_named(name: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns={name}\r\n\
         c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
    )
}

pub(crate) fn described(text: &str) -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from(text.to_owned()),
    )
}

/// The 2xx of the peer to an INVITE it received as `request`, carrying
/// `body` as an SDP offer, as one without an offer gets it.
pub(crate) fn ok_offering(
    request: &str,
    tag: &str,
    contact: &str,
    body: &str,
) -> String {
    let request = Request::from_bytes(request.as_bytes()).unwrap();
    let response = Response::reply_to(&request)
        .status(StatusCode::OK)
        .to_tag(tag)
        .header("Contact", format!("<{contact}>").as_str())
        .header("Content-Type", "application/sdp")
        .body(Bytes::from(body.to_owned()));
    String::from_utf8(response.unwrap().to_bytes().to_vec()).unwrap()
}

/// The body of a message, after its head.
pub(crate) fn body(message: &str) -> &str {
    message.split_once("\r\n\r\n").unwrap().1
}

/// A re-INVITE of the peer in the dialog its INVITE `call` formed with the
/// 2xx `ok`, numbered `cseq`, with `contact` as its Contact and `offer` as
/// its SDP offer. `branch` names its transaction.
pub(crate) fn reinvite_of(
    ok: &str,
    peer: SocketAddr,
    call: &str,
    cseq: u32,
    contact: SocketAddr,
    offer: &str,
) -> String {
    format!(
        "INVITE sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-reinvite-{call}-{cseq}
Max-Forwards: 70
To: {to}
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: {cseq} INVITE
Contact: <sip:peer@{contact}>
Content-Type: application/sdp
Content-Length: {length}

{offer}",
        to = header(ok, "To")[0],
        length = offer.len(),
    )
}
