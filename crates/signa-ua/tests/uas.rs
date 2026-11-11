/*!
The initial INVITE the UA receives (RFC 3261 sections 8.2 and 13.3): what it
refuses before the application sees it, the responses that carry the
application's decision, the copies of a 2xx until its ACK, and an INVITE
without an offer, whose answer comes in the ACK.
*/

use std::{net::SocketAddr, time::Duration};

use signa_core::StatusCode;
use signa_ua::{
    EndReason, Error, Event, IncomingInvite, ReinvitePlan, SessionPhase,
    UaEvents,
};
use tokio::time::timeout;

use crate::support::{
    WAIT, call_from, config,
    events::{event, invite, invite_within, reinvite},
    message::{
        ack_for, body, cancel_of, described, direct_invite, header, in_dialog,
        invite_over, invite_to_ua, offer_named, plan_to, reinvite_of, sdp,
    },
    peer::{Peer, TcpPeer},
    start_fast, start_fast_with,
};

/// Every response to an INVITE carries the To tag of its first one: the
/// 180, the 200 and each copy of the 200. The 180 forms an early dialog at
/// the caller, so it carries the Contact and Record-Route as the 200 does.
#[tokio::test]
async fn uas_to_tag_is_stable() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "tag"), udp).await;
    let invite = invite(&mut ua.events).await;
    let ringing = StatusCode::from_u16(180).unwrap();
    invite.try_provisional(ringing).unwrap().await.unwrap();
    let (ringing, _) = peer.recv_starting("SIP/2.0 180").await;
    invite.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    let (copy, _) = peer.recv_starting("SIP/2.0 200").await;

    let to = header(&ringing, "To");
    assert!(to[0].contains(";tag="));
    assert_eq!(header(&ok, "To"), to);
    assert_eq!(header(&copy, "To"), to);
    assert_eq!(header(&ringing, "Contact"), ["<sip:ua@127.0.0.1>"]);
    assert_eq!(
        header(&ringing, "Record-Route"),
        ["<sip:proxy.example.com;lr>"]
    );
}

/// The 2xx goes out again until its ACK, over TCP as over UDP. A reliable
/// transport does not excuse it, since a proxy on the way may forward over
/// UDP (RFC 3261 section 13.3.1.4).
#[tokio::test]
async fn uas_2xx_retransmits_on_udp_and_tcp() {
    let (mut ua, udp, tcp) = start_fast();
    tokio::spawn(ua.driver);

    let peer = Peer::new().await;
    peer.send(&invite_to_ua(peer.address(), "over-udp"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    for _ in 0..3 {
        let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Call-ID"), ["over-udp"]);
    }

    let mut stream = TcpPeer::connect(tcp).await;
    let request = invite_over("TCP", stream.address(), "over-tcp");
    stream.send(&request).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    for _ in 0..3 {
        let ok = stream.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Call-ID"), ["over-tcp"]);
    }
}

/// Each copy of the 2xx is the message that first went out, answer and
/// all, from the address the INVITE reached. It goes through the INVITE's
/// reply route, which takes nothing but the request's Via, From, Call-ID and
/// CSeq as they were received.
#[tokio::test]
async fn response_replay_preserves_reply_route_identity() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "replay"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, first) = peer.recv_starting("SIP/2.0 200").await;
    let (copy, second) = peer.recv_starting("SIP/2.0 200").await;

    assert_eq!(copy, ok);
    assert_eq!((first, second), (udp, udp));
    assert_eq!(header(&ok, "Content-Type"), ["application/sdp"]);
    assert!(ok.ends_with("\r\n\r\nv=0\r\n"));
}

/// An ACK with another CSeq, another To tag or another From tag is not the
/// 2xx's, and the copies go on. The ACK that matches stops them.
#[tokio::test]
async fn matching_ack_stops_retransmission_unrelated_ack_does_not() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "ack"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    let matching = ack_for(&ok, peer.address(), "ack", 1);
    let to = header(&ok, "To")[0];
    let other_to = matching.replace(to, "<sip:ua@127.0.0.1>;tag=other");
    let other_from = matching.replace("tag=peer-ack", "tag=other");

    for ack in [ack_for(&ok, peer.address(), "ack", 2), other_to, other_from] {
        peer.send(&ack, udp).await;
        peer.recv_starting("SIP/2.0 200").await;
        peer.recv_starting("SIP/2.0 200").await;
    }

    peer.send(&ack_for(&ok, peer.address(), "ack", 1), udp).await;
    peer.drain(Duration::from_millis(50)).await;
    // Neither a copy of the 200 nor any response to the ACKs.
    peer.quiet("SIP/2.0", Duration::from_millis(400)).await;
}

/// Without an ACK, the copies stop 64 T1 after the first 2xx, and the
/// session ends with a BYE (RFC 3261 section 13.3.1.4), with the reason
/// before the end. The session's snapshot still says why afterwards.
#[tokio::test]
async fn an_unacknowledged_2xx_ends_its_session() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&direct_invite(peer.address(), "no-ack"), udp).await;
    let accepted = invite(&mut ua.events).await.try_accept(sdp()).unwrap();
    let session = accepted.await.unwrap();

    let mut ends = Vec::new();
    while ends.len() < 2 {
        match timeout(WAIT, ua.events.recv()).await.unwrap().unwrap() {
            Event::AckTimeout { session: ended, .. } => {
                ends.push(("timeout", ended))
            }
            Event::Ended { session: ended, reason, .. } => {
                assert_eq!(reason, EndReason::AckTimeout);
                ends.push(("ended", ended));
            }
            _ => {}
        }
    }
    assert_eq!(
        ends,
        [("timeout", session.clone()), ("ended", session.clone())]
    );
    let (bye, _) = peer.recv_starting("BYE").await;
    assert!(bye.starts_with(&format!("BYE sip:peer@{} ", peer.address())));
    assert_eq!(header(&bye, "Call-ID"), ["no-ack"]);
    peer.quiet("SIP/2.0 200", Duration::from_millis(300)).await;
    let snapshot = ua.handle.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Ended);
    assert_eq!(snapshot.end_reason, Some(EndReason::AckTimeout));
}

/// A retransmission of the INVITE is the core's to absorb, before and after
/// the 2xx, so the application sees one INVITE and one session. A copy that
/// came by another path, with another branch, gets a 482 (RFC 3261 section
/// 8.2.2.2).
#[tokio::test]
async fn retransmitted_invite_does_not_create_second_usage() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let request = invite_to_ua(peer.address(), "again");
    let merged =
        request.replace("branch=z9hG4bK-again", "branch=z9hG4bK-other");

    peer.send(&request, udp).await;
    let invite = invite(&mut ua.events).await;
    peer.send(&request, udp).await;
    peer.send(&merged, udp).await;

    // The 482 answers the merged copy, and the copy on the same branch gets
    // none. The core sends the 482 again until its ACK, which this peer
    // does not send, so each failure that arrives is that 482.
    let (loop_detected, _) = peer.recv_starting("SIP/2.0 482").await;
    assert_eq!(header(&loop_detected, "Call-ID"), ["again"]);
    peer.only_failures_for("z9hG4bK-other", Duration::from_millis(200)).await;
    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);

    invite.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.send(&request, udp).await;
    peer.only_failures_for("z9hG4bK-other", Duration::from_millis(200)).await;
    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
}

/// An INVITE the application holds past the decision timeout gets a 500,
/// and the accept that comes after it sends nothing.
#[tokio::test]
async fn the_decision_timeout_answers_an_undecided_invite() {
    let config = config().decision_timeout(Duration::from_millis(100));
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "slow"), udp).await;
    let invite = invite(&mut ua.events).await;
    let (error, _) = peer.recv_starting("SIP/2.0 500").await;
    let late = invite.try_accept(sdp()).unwrap().await.unwrap_err();

    assert_eq!(header(&error, "Call-ID"), ["slow"]);
    assert!(matches!(late, Error::AlreadyFinalized | Error::StaleDecision));
    peer.quiet("SIP/2.0 200", Duration::from_millis(200)).await;
}

/// An INVITE whose body may hold its offer where the UA cannot take it out,
/// as a multipart body, gets a 415 that says what the UA takes (RFC 3261
/// section 21.4.13), before the application sees it. One that requires an
/// extension gets a 420 that lists it as unsupported.
#[tokio::test]
async fn a_multipart_or_extended_invite_is_refused() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let multipart = invite_to_ua(peer.address(), "multipart").replace(
        "Content-Type: application/sdp\n",
        "Content-Type: multipart/mixed;boundary=x\n",
    );
    let extended = invite_to_ua(peer.address(), "extended").replace(
        "Max-Forwards: 70\n",
        "Max-Forwards: 70\nRequire: 100rel, timer\n",
    );

    peer.send(&multipart, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 415").await;
    assert_eq!(header(&refused, "Call-ID"), ["multipart"]);
    assert_eq!(header(&refused, "Accept"), ["application/sdp"]);
    assert!(header(&refused, "To")[0].contains(";tag="));

    peer.send(&extended, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 420").await;
    assert_eq!(header(&refused, "Call-ID"), ["extended"]);
    assert_eq!(header(&refused, "Unsupported"), ["100rel, timer"]);

    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
}

/// Without TLS, a SIPS Request-URI gets a 416 (RFC 3261 section 8.2.2.1),
/// and a SIPS Record-Route a 480 with the warning 380 (RFC 5630 section
/// 5.1.2). Neither reaches the application.
#[tokio::test]
async fn a_sips_invite_is_refused_without_tls() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let secure = invite_to_ua(peer.address(), "secure")
        .replace("INVITE sip:ua@", "INVITE sips:ua@");
    let routed = invite_to_ua(peer.address(), "routed")
        .replace("<sip:proxy.example.com;lr>", "<sips:proxy.example.com;lr>");

    peer.send(&secure, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 416").await;
    assert_eq!(header(&refused, "Call-ID"), ["secure"]);

    peer.send(&routed, udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 480").await;
    assert_eq!(header(&refused, "Call-ID"), ["routed"]);
    assert_eq!(
        header(&refused, "Warning"),
        ["380 127.0.0.1 \"SIPS Not Allowed\""]
    );

    assert!(!invite_within(&mut ua.events, Duration::from_millis(200)).await);
}

/// An INVITE whose Expires passes before the application decides gets a
/// 487 (RFC 3261 section 13.3.1), and the accept after it sends nothing.
#[tokio::test]
async fn an_expired_invite_gets_a_487() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let expiring = invite_to_ua(peer.address(), "expiring")
        .replace("Max-Forwards: 70\n", "Max-Forwards: 70\nExpires: 1\n");

    peer.send(&expiring, udp).await;
    let invite = invite(&mut ua.events).await;
    let read = async {
        loop {
            let (message, _) = peer.recv().await;
            if message.starts_with("SIP/2.0 487") {
                return message;
            }
        }
    };
    let terminated = timeout(Duration::from_secs(3), read).await.unwrap();
    assert_eq!(header(&terminated, "Call-ID"), ["expiring"]);

    let late = invite.try_accept(sdp()).unwrap().await.unwrap_err();
    assert!(matches!(late, Error::AlreadyFinalized | Error::StaleDecision));
    peer.quiet("SIP/2.0 200", Duration::from_millis(200)).await;
}

/// A request outside a dialog other than INVITE gets an answer of its own
/// (RFC 3261 section 8.2.1): OPTIONS a 200 with the methods the UA takes, a
/// method the UA knows but does not take a 405 with them, one it does not
/// know a 501, and a BYE a 481 (section 15.1.2).
#[tokio::test]
async fn requests_outside_a_dialog_get_their_own_answers() {
    let (ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let request = |method: &str, call: &str| {
        format!(
            "{method} sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 {method}
Content-Length: 0

",
            peer = peer.address(),
        )
    };

    for (method, status, allow) in [
        ("OPTIONS", "200", true),
        ("MESSAGE", "405", true),
        ("FROBNICATE", "501", false),
        ("BYE", "481", false),
    ] {
        peer.send(&request(method, method), udp).await;
        let (response, _) =
            peer.recv_starting(&format!("SIP/2.0 {status}")).await;
        assert_eq!(header(&response, "Call-ID"), [method]);
        assert!(header(&response, "To")[0].contains(";tag="), "{method}");
        let expected: &[&str] =
            if allow { &["INVITE, ACK, CANCEL, BYE, OPTIONS"] } else { &[] };
        assert_eq!(header(&response, "Allow"), expected, "{method}");
    }
}

/// A request outside a dialog from `peer`, with `headers` after its CSeq and
/// `body` as its body. An INVITE needs a Contact, which `headers` gives.
fn request_from(
    peer: SocketAddr,
    method: &str,
    call: &str,
    headers: &str,
    body: &str,
) -> String {
    // `Peer::send` ends each line with CRLF, the body's included.
    let length = body.replace('\n', "\r\n").len();
    format!(
        "{method} sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP {peer};branch=z9hG4bK-{call}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>
From: <sip:peer@{peer}>;tag=peer-{call}
Call-ID: {call}
CSeq: 1 {method}
{headers}Content-Length: {length}

{body}"
    )
}

/// The first response other than a 100 that `peer` gets for `call`,
/// skipping those of earlier calls, such as a retransmitted final.
async fn response_to(peer: &Peer, call: &str) -> String {
    loop {
        let (message, _) = peer.recv_starting("SIP/2.0").await;
        if header(&message, "Call-ID") == [call]
            && !message.starts_with("SIP/2.0 100")
        {
            return message;
        }
    }
}

/// The INVITE `call` as it reaches the application. A response to it comes
/// first only when the UA refused it, which fails the test with it.
async fn taken(
    events: &mut UaEvents,
    peer: &Peer,
    call: &str,
) -> IncomingInvite {
    let incoming = tokio::select! {
        incoming = invite(events) => incoming,
        response = response_to(peer, call) => panic!("{call} refused: {response}"),
    };
    assert_eq!(call_id(&incoming), call);
    incoming
}

/// The Call-ID of the INVITE `invite` hands over.
fn call_id(invite: &IncomingInvite) -> String {
    let request = invite.request().to_bytes();
    let request = std::str::from_utf8(&request).unwrap();
    header(request, "Call-ID")[0].to_owned()
}

/// The status code of `response`.
fn status(response: &str) -> &str {
    &response["SIP/2.0 ".len().."SIP/2.0 ".len() + 3]
}

/// The values of every row of `name` in `message`, split at the commas.
fn listed<'a>(message: &'a str, name: &str) -> Vec<&'a str> {
    header(message, name)
        .into_iter()
        .flat_map(|row| row.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect()
}

/// The methods of RFC 3261 and its extensions that the UA knows, which get
/// a 405 when it does not take them.
const KNOWN: [&str; 9] = [
    "REGISTER",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE",
];

/// What the 200 to OPTIONS advertises, the UA takes (RFC 3261 section
/// 11.2). An INVITE reaches the application and a CANCEL cancels it, a BYE
/// outside a dialog gets a 481 and one in a dialog a 200, and OPTIONS gets
/// the same 200 in a dialog as outside one. A method outside the Allow gets
/// a 405 with the same Allow, or a 501 when the UA does not know it. An
/// INVITE whose body has a type of the Accept and a coding of the
/// Accept-Encoding reaches the application with its offer. A tag of the
/// Supported passes the Require check, and any other gets a 420 that lists
/// it. So a value added to what the UA advertises, without the UA taking
/// it, fails here.
#[tokio::test]
async fn the_ua_takes_what_it_advertises() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let me = peer.address();
    let contact = format!("Contact: <sip:peer@{me}>\n");
    let sdp = "Content-Type: application/sdp\n";

    peer.send(&request_from(me, "OPTIONS", "ask", "", ""), udp).await;
    let outside = response_to(&peer, "ask").await;
    assert_eq!(status(&outside), "200");
    let allow = listed(&outside, "Allow");
    let accept = listed(&outside, "Accept");
    let encodings = listed(&outside, "Accept-Encoding");
    let supported = listed(&outside, "Supported");

    // An ACK gets no response. `call_from` sends the ACK of a 2xx below, and
    // `matching_ack_stops_retransmission_unrelated_ack_does_not` shows what
    // it does.
    let mut methods = vec!["INVITE", "CANCEL", "BYE", "OPTIONS", "FROBNICATE"];
    methods.extend(KNOWN);
    let extra: Vec<&str> =
        allow.iter().copied().filter(|m| !methods.contains(m)).collect();
    methods.extend(extra);
    methods.retain(|method| *method != "ACK");
    for method in methods {
        let call = format!("method-{method}");
        if !allow.contains(&method) {
            peer.send(&request_from(me, method, &call, "", ""), udp).await;
            let response = response_to(&peer, &call).await;
            if KNOWN.contains(&method) {
                assert_eq!(status(&response), "405", "{method}");
                assert_eq!(listed(&response, "Allow"), allow, "{method}");
            } else {
                assert_eq!(status(&response), "501", "{method}");
                assert!(header(&response, "Allow").is_empty(), "{method}");
            }
            continue;
        }
        match method {
            "INVITE" => {
                let invite = request_from(me, method, &call, &contact, "");
                peer.send(&invite, udp).await;
                let incoming = taken(&mut ua.events, &peer, &call).await;
                drop(incoming.try_reject(StatusCode::BUSY_HERE).unwrap());
            }
            "CANCEL" => {
                let invite = request_from(me, "INVITE", &call, &contact, "");
                peer.send(&invite, udp).await;
                let _incoming = taken(&mut ua.events, &peer, &call).await;
                peer.send(&cancel_of("UDP", me, &call), udp).await;
                let mut statuses = Vec::new();
                for _ in 0..2 {
                    let response = response_to(&peer, &call).await;
                    let cseq = header(&response, "CSeq")[0].to_owned();
                    statuses.push((cseq, status(&response).to_owned()));
                }
                statuses.sort();
                assert_eq!(
                    statuses,
                    [
                        ("1 CANCEL".to_owned(), "200".to_owned()),
                        ("1 INVITE".to_owned(), "487".to_owned()),
                    ],
                );
            }
            "BYE" | "OPTIONS" => {
                peer.send(&request_from(me, method, &call, "", ""), udp).await;
                let response = response_to(&peer, &call).await;
                let expected = if method == "BYE" { "481" } else { "200" };
                assert_eq!(status(&response), expected, "{method}");
            }
            // A method added to the Allow that this test does not know yet
            // must at least not be refused as one the UA does not take.
            _ => {
                peer.send(&request_from(me, method, &call, "", ""), udp).await;
                let response = response_to(&peer, &call).await;
                assert!(
                    !["405", "501"].contains(&status(&response)),
                    "{method}"
                );
            }
        }
    }

    for (n, (kind, coding)) in accept
        .iter()
        .flat_map(|kind| encodings.iter().map(move |coding| (kind, coding)))
        .enumerate()
    {
        let call = format!("accept-{n}");
        let headers = format!(
            "{contact}Content-Type: {kind}\nContent-Encoding: {coding}\n"
        );
        peer.send(&request_from(me, "INVITE", &call, &headers, "v=0\n"), udp)
            .await;
        let incoming = taken(&mut ua.events, &peer, &call).await;
        assert!(incoming.offer().is_some(), "{kind} {coding}");
        drop(incoming.try_reject(StatusCode::BUSY_HERE).unwrap());
    }

    // The UA lists no option tag today, so this loop waits for the first.
    for (n, tag) in supported.iter().enumerate() {
        let call = format!("supported-{n}");
        let headers = format!("{contact}{sdp}Require: {tag}\n");
        peer.send(&request_from(me, "INVITE", &call, &headers, "v=0\n"), udp)
            .await;
        let incoming = taken(&mut ua.events, &peer, &call).await;
        drop(incoming.try_reject(StatusCode::BUSY_HERE).unwrap());
    }
    let unlisted = "x-not-listed";
    let headers = format!("{contact}{sdp}Require: {unlisted}\n");
    peer.send(&request_from(me, "INVITE", "unlisted", &headers, "v=0\n"), udp)
        .await;
    let refused = response_to(&peer, "unlisted").await;
    assert_eq!(status(&refused), "420");
    assert_eq!(listed(&refused, "Unsupported"), [unlisted]);

    let (ok, _session) = call_from(&peer, udp, &mut ua.events, "dialog").await;
    peer.send(&in_dialog("OPTIONS", "UDP", &ok, me, "dialog", 2), udp).await;
    let options = response_to(&peer, "dialog").await;
    peer.send(&in_dialog("MESSAGE", "UDP", &ok, me, "dialog", 3), udp).await;
    let message = response_to(&peer, "dialog").await;
    peer.send(&in_dialog("BYE", "UDP", &ok, me, "dialog", 4), udp).await;
    let bye = response_to(&peer, "dialog").await;

    assert_eq!(status(&options), "200");
    for name in ["Allow", "Accept", "Accept-Encoding", "Supported"] {
        assert_eq!(listed(&options, name), listed(&outside, name));
    }
    assert_eq!(status(&message), "405");
    assert_eq!(listed(&message, "Allow"), allow);
    assert_eq!(status(&bye), "200");
    assert_eq!(header(&bye, "CSeq"), ["4 BYE"]);
}

/// Each response and request that advertises what the UA takes says the
/// same as the 200 to OPTIONS: the Allow of a 405, of the 2xx of an INVITE
/// and of a re-INVITE, and of the UA's INVITE and re-INVITE, and the Accept
/// and Accept-Encoding of a 415. None carries a Supported, since the UA has
/// no extension.
#[tokio::test]
async fn every_advertisement_says_the_same() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let me = peer.address();
    let contact = format!("Contact: <sip:peer@{me}>\n");

    peer.send(&request_from(me, "OPTIONS", "ask", "", ""), udp).await;
    let ok = response_to(&peer, "ask").await;
    peer.send(&request_from(me, "MESSAGE", "message", "", ""), udp).await;
    let not_allowed = response_to(&peer, "message").await;
    let multipart =
        format!("{contact}Content-Type: multipart/mixed;boundary=x\n");
    let invite =
        request_from(me, "INVITE", "multipart", &multipart, "--x--\n");
    peer.send(&invite, udp).await;
    let unsupported = response_to(&peer, "multipart").await;
    let (accepted, session) =
        call_from(&peer, udp, &mut ua.events, "accepted").await;
    peer.send(&reinvite_of(&accepted, me, "accepted", 2, me, "v=0\r\n"), udp)
        .await;
    let incoming = reinvite(&mut ua.events).await;
    drop(incoming.try_accept(sdp()).unwrap());
    let (reaccepted, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&reaccepted, me, "accepted", 2), udp).await;
    peer.drain(Duration::from_millis(60)).await;
    drop(ua.handle.try_reinvite(&session, ReinvitePlan::new(sdp())).unwrap());
    let (reinvite, _) = peer.recv_starting("INVITE").await;
    let to = me.to_string();
    drop(ua.handle.try_invite(plan_to(&to, "outgoing")).unwrap());
    let outgoing = loop {
        let (request, _) = peer.recv_starting("INVITE").await;
        if header(&request, "Subject") == ["outgoing"] {
            break request;
        }
    };

    assert_eq!(status(&not_allowed), "405");
    assert_eq!(status(&unsupported), "415");
    assert_eq!(header(&reaccepted, "CSeq"), ["2 INVITE"]);
    let allow = listed(&ok, "Allow");
    assert!(!allow.is_empty());
    for message in [&not_allowed, &accepted, &reaccepted, &reinvite, &outgoing]
    {
        assert_eq!(listed(message, "Allow"), allow, "{message}");
    }
    for name in ["Accept", "Accept-Encoding"] {
        assert!(!listed(&ok, name).is_empty(), "{name}");
        assert_eq!(listed(&unsupported, name), listed(&ok, name), "{name}");
    }
    let all =
        [&ok, &not_allowed, &unsupported, &accepted, &reaccepted, &reinvite];
    for message in all.into_iter().chain([&outgoing]) {
        assert!(header(message, "Supported").is_empty(), "{message}");
    }
}

/// The ACK of the peer for the 2xx `ok` to its INVITE `call`, carrying
/// `answer` as its body.
fn ack_with(ok: &str, peer: SocketAddr, call: &str, answer: &str) -> String {
    ack_for(ok, peer, call, 1).replace(
        "Content-Length: 0\n",
        &format!(
            "Content-Type: application/sdp\nContent-Length: {}\n",
            answer.len()
        ),
    ) + answer
}

/// An INVITE without an offer reaches the application, whose 2xx carries
/// the offer. The ACK brings the answer, which completes the exchange, and
/// the session keeps it. An ACK without the answer still stops the 2xx's
/// retransmissions, but fails the exchange, and the UA ends the session with
/// a BYE.
#[tokio::test]
async fn an_offerless_invite_gets_its_answer_in_the_ack() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    // Without a Record-Route, so that the BYE goes straight to the peer.
    let offerless = |call: &str| {
        direct_invite(peer.address(), call).replace(
            "Content-Type: application/sdp\nContent-Length: 5\n\nv=0\n",
            "Content-Length: 0\n\n",
        )
    };
    let mine = described(&offer_named("ua"));

    for call in ["answered", "unanswered"] {
        peer.send(&offerless(call), udp).await;
        let incoming = invite(&mut ua.events).await;
        assert_eq!(incoming.offer(), None);
        let session =
            incoming.try_accept(mine.clone()).unwrap().await.unwrap();
        let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Content-Type"), ["application/sdp"]);
        assert_eq!(body(&ok), offer_named("ua"));

        let theirs = "v=0\r\ns=peer\r\n";
        let ack = if call == "answered" {
            ack_with(&ok, peer.address(), call, theirs)
        } else {
            ack_for(&ok, peer.address(), call, 1)
        };
        peer.send(&ack, udp).await;

        if call == "answered" {
            let settled = event(&mut ua.events, |event| match event {
                Event::Negotiated { session, .. } => Some(session),
                _ => None,
            })
            .await;
            assert_eq!(settled, session);
            let snapshot = ua.handle.snapshot(&session).await.unwrap();
            let snapshot = snapshot.unwrap();
            assert_eq!(snapshot.remote_description, Some(described(theirs)));
            assert_eq!(snapshot.phase, SessionPhase::Established);
        } else {
            let failed = event(&mut ua.events, |event| match event {
                Event::NegotiationFailed { session, .. } => Some(session),
                _ => None,
            })
            .await;
            assert_eq!(failed, session);
            let (bye, _) = peer.recv_starting("BYE").await;
            assert_eq!(header(&bye, "Call-ID"), [call]);
            let reason = event(&mut ua.events, |event| match event {
                Event::Ended { reason, .. } => Some(reason),
                _ => None,
            })
            .await;
            assert_eq!(reason, EndReason::NegotiationFailed);
        }
        peer.quiet("SIP/2.0 200", Duration::from_millis(100)).await;
    }
}

/// A provisional response previews the answer, as for early media, and
/// carries it. The 2xx has to carry the same answer, so an accept with
/// another is handed back, and one with the preview goes.
#[tokio::test]
async fn a_provisional_previews_the_answer() {
    let (mut ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let progress = StatusCode::from_u16(183).unwrap();
    let preview = described("v=0\r\ns=preview\r\n");

    peer.send(&invite_to_ua(peer.address(), "preview"), udp).await;
    let mut incoming = invite(&mut ua.events).await;
    assert_eq!(incoming.offer(), Some(&sdp()));
    let sent = incoming.try_provisional_with(progress, preview.clone());
    assert_eq!(sent.unwrap().await, Ok(()));
    let (early, _) = peer.recv_starting("SIP/2.0 183").await;
    assert_eq!(body(&early), "v=0\r\ns=preview\r\n");

    let refused = incoming.try_accept(sdp()).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);
    let (incoming, _) = refused.into_inner();
    incoming.try_accept(preview).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(body(&ok), body(&early));
    assert_eq!(header(&ok, "To"), header(&early, "To"));
}
