/*!
A UDP stateless proxy between a raw UAC and a stateful UAS, on the loopback.

The UAC sends an INVITE, retransmits it, cancels it, and acknowledges the 487.
The proxy forwards each request with a branch it computes, and each response
by its next Via. The UAS is an ordinary stateful signa endpoint, so its own
transaction matching shows whether the proxy kept the branches stable: the
retransmission is absorbed, the CANCEL matches the INVITE, and the ACK confirms
it ([RFC 3261 sections 9.2 and 17.2.3]).

# What the proxy does

Following [RFC 3261 section 16.11]:

* It runs on [`Reception::Stateless`], so every request and response arrives
  as an event, retransmissions included, and nothing is answered for it.
* It picks one downstream target per request from its configuration alone,
  so a retransmission, its CANCEL and its ACK go to the same place.
* It computes the branch from what a retransmission, its CANCEL and the ACK of
  a non-2xx share: the received top Via's branch and `sent-by`, plus a secret
  of this proxy. The method is not part of it. The RFC recommends hashing the
  received branch. The `sent-by` is added because section 17.2.3 identifies a
  transaction by both, and two UACs can pick the same branch.
* It decrements Max-Forwards, which gives the same result for every
  retransmission.
* For a response, it checks that the top Via's `sent-by` is its own, removes
  that one Via value, and passes the rest to
  [`Endpoint::forward_response`], which routes by the next Via. A response
  whose top Via is not the proxy's is dropped.

The secret and the downstream target must not change while a forwarded request
can still be retransmitted, cancelled or acknowledged. An INVITE can ring for
minutes before its CANCEL, so that has no fixed bound. A proxy that restarts
with a new secret breaks the CANCELs and ACKs of calls in progress. The secret
keeps this proxy's branches apart from another proxy running the same code
that sees the same request, and makes them hard to predict.

# What it leaves out

This is not a complete or production SIP proxy. It does not do:

* Request validation ([section 16.3]): syntax, URI scheme, a Max-Forwards of
  zero (which needs a 483 that this example does not send), loop detection,
  Proxy-Require, and authorization.
* Route processing and target determination ([sections 16.4 and 16.5]). Every
  request goes to one configured target, and a 2xx ACK is not routed by its
  dialog's route set.
* Record-Route, strict routing, and the loop-detection part of the branch
  ([section 16.6]).
* Requests without the RFC 3261 magic cookie, which the RFC hashes by other
  fields. This proxy drops them.
* SIPS, TLS, TCP, DNS resolution ([RFC 3263]) and authentication.

Its Via handling is simplified too. It splits a Via row at the first comma
outside a quoted string, and does not handle a quoted parameter that contains
a semicolon. A wildcard-bound proxy would have to compare `sent-by` with every
address it advertises, not with one socket address.

[RFC 3261 sections 9.2 and 17.2.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.3
[RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
[section 16.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.3
[sections 16.4 and 16.5]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.4
[section 16.6]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.6
[RFC 3263]: https://www.rfc-editor.org/rfc/rfc3263.html
[`Reception::Stateless`]: signa::endpoint::Reception::Stateless
[`Endpoint::forward_response`]: signa::endpoint::Endpoint::forward_response
*/

use std::{error::Error, net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa::{
    endpoint::{
        Branch, Endpoint, Incoming, IncomingEvent, Reception, ServerEvent,
        Target, ViaMode,
    },
    message::header::{
        HeaderMap, HeaderValue, Tag, CSEQ, MAX_FORWARDS, TO, VIA,
    },
    transaction::Timers,
    transport::Transport,
    Request, Response,
};
use tokio::{net::UdpSocket, time::timeout};

/// What the proxy's forwarding depends on. None of it may change while a
/// forwarded request can still be retransmitted, cancelled or acknowledged.
#[derive(Clone, Copy)]
struct ProxyConfig {
    /// Mixed into every branch, so that this proxy's branches differ from
    /// those of another proxy that sees the same request.
    secret: u64,
    /// The one next hop for every request.
    downstream: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Short timers end the UAS's transactions quickly.
    let timers = Timers::builder()
        .t1(Duration::from_millis(50))
        .t4(Duration::from_millis(200))
        .build()?;
    let (uas, uas_incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .timers(timers)
        .bind()?;
    let (proxy, proxy_incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .reception(Reception::Stateless)
        .bind()?;
    let proxy_addr = proxy.udp_addr().expect("UDP bound");
    let config = ProxyConfig {
        secret: 0x5eed_0f7e_57a7_e1e5,
        downstream: uas.udp_addr().expect("UDP bound"),
    };

    tokio::spawn(run_proxy(proxy, proxy_incoming, config));
    let uas_done = tokio::spawn(run_uas(uas_incoming));
    run_uac(proxy_addr).await?;

    // The UAS reports how its INVITE ended.
    let confirmed = timeout(Duration::from_secs(5), uas_done).await??;
    assert!(confirmed, "the ACK through the proxy confirmed the INVITE");
    drop(uas);

    Ok(())
}

/// The proxy's receive loop.
async fn run_proxy(
    proxy: Endpoint,
    mut incoming: Incoming,
    config: ProxyConfig,
) {
    let own = proxy.udp_addr().expect("UDP bound");
    let target = Target::new(Transport::Udp, config.downstream);

    while let Some(event) = incoming.recv().await {
        match event {
            IncomingEvent::StatelessRequest(received) => {
                let mut request = received.request;
                let Some(branch) = stable_branch(&request, config.secret)
                else {
                    println!(
                        "proxy: dropped a request without an RFC 3261 branch"
                    );
                    continue;
                };
                if !decrement_max_forwards(request.headers_mut()) {
                    println!("proxy: dropped a request out of Max-Forwards");
                    continue;
                }

                let method = request.method().clone();
                match proxy
                    .send_request(request, target, ViaMode::Branch(branch))
                    .await
                {
                    Ok(sent) => {
                        println!("proxy: {method} -> {}", sent.via().as_str())
                    }
                    Err(error) => {
                        println!("proxy: {method} not sent: {error}")
                    }
                }
            }
            IncomingEvent::StatelessResponse(received) => {
                let mut response = received.response;
                if !remove_own_via(response.headers_mut(), own) {
                    println!("proxy: dropped a response that is not ours");
                    continue;
                }
                let status = response.status();
                if let Err(error) = proxy.forward_response(response).await {
                    println!("proxy: {status} not forwarded: {error}");
                }
            }
            // A stateless endpoint delivers nothing else, but the enum has
            // room for more.
            _ => {}
        }
    }
}

/// The branch for a request, from its top Via's branch and `sent-by` and the
/// proxy's secret, or `None` without an RFC 3261 branch.
///
/// A retransmission has the same top Via, and so do the CANCEL and the ACK of
/// a non-2xx ([RFC 3261 sections 9.1 and 17.1.1.3]), so they all get the same
/// branch. A 2xx ACK has a branch of its own and gets a different one.
///
/// [RFC 3261 sections 9.1 and 17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
fn stable_branch(request: &Request<Bytes>, secret: u64) -> Option<Branch> {
    let row = request.headers().get(VIA)?.as_str();
    let (top, _) = split_first_value(row);
    let via = parse_via(top)?;
    let received =
        via.branch.filter(|branch| branch.starts_with("z9hG4bK"))?;

    // FNV-1a over the inputs, separated so that no two inputs run together.
    // Any hash that gives the same output for the same input across the
    // proxy's lifetime works. Hash the `sent-by` as written, with the host
    // in lowercase.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325 ^ secret;
    for part in [received, "\0", &via.sent_by.to_ascii_lowercase()] {
        for byte in part.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("z9hG4bK-sl-{hash:016x}").parse().ok()
}

/// Decrements Max-Forwards, or adds it with 70 (RFC 3261 section 16.6,
/// step 3). Returns `false` for a value of zero or one that does not parse,
/// which a complete proxy answers with a 483 or a 400 instead.
fn decrement_max_forwards(headers: &mut HeaderMap) -> bool {
    let next = match headers.get(MAX_FORWARDS) {
        None => 70,
        Some(value) => match value.as_str().trim().parse::<u32>() {
            Ok(0) | Err(_) => return false,
            Ok(hops) => hops - 1,
        },
    };
    let value = HeaderValue::from_bytes(next.to_string().as_bytes())
        .expect("digits are a valid value");
    headers.insert(MAX_FORWARDS, value);
    true
}

/// Removes the top Via value if its `sent-by` is `own`, as a stateless proxy
/// must before it forwards a response (RFC 3261 section 16.11).
///
/// The top value is the first value of the first Via row. A row can carry
/// several values separated by commas, so removing the whole row could drop
/// other hops' values. When the first row has more values, the rest of it
/// stays as the new first row.
fn remove_own_via(headers: &mut HeaderMap, own: SocketAddr) -> bool {
    let Some(first) = headers.get(VIA) else { return false };
    let (top, rest) = split_first_value(first.as_str());
    let ours = parse_via(top)
        .and_then(|via| sent_by_address(via.sent_by))
        .is_some_and(|sent_by| sent_by == own);
    if !ours {
        return false;
    }

    match rest {
        Some(rest) => {
            let rest = HeaderValue::from_bytes(rest.as_bytes())
                .expect("a part of a valid value");
            *headers.get_mut(VIA).expect("checked above") = rest;
        }
        None => {
            // HeaderMap removes rows by name, so the rows after the first go
            // back in order. They end up after the other fields, which does
            // not matter for fields of different names (RFC 3261 section
            // 7.3.1).
            let later: Vec<HeaderValue> =
                headers.get_all(VIA).skip(1).cloned().collect();
            headers.remove(VIA);
            for value in later {
                headers.append(VIA, value);
            }
        }
    }
    true
}

/// Splits a Via row at the first comma outside a quoted string, returning the
/// first value and the rest after the comma, if any.
fn split_first_value(row: &str) -> (&str, Option<&str>) {
    let mut quoted = false;
    let mut escaped = false;
    for (at, c) in row.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                let rest = row[at + 1..].trim_start();
                return (
                    row[..at].trim_end(),
                    Some(rest).filter(|r| !r.is_empty()),
                );
            }
            _ => {}
        }
    }
    (row.trim_end(), None)
}

/// The parts of one Via value this proxy reads.
struct ViaValue<'a> {
    sent_by: &'a str,
    branch: Option<&'a str>,
}

/// Reads `SIP/2.0/UDP sent-by;params`. It takes whitespace around the
/// semicolons but not the whitespace the grammar allows around the slashes.
fn parse_via(value: &str) -> Option<ViaValue<'_>> {
    let (_protocol, rest) = value.trim().split_once(char::is_whitespace)?;
    let mut parts = rest.trim_start().split(';');
    let sent_by = parts.next()?.trim();
    let branch = parts.find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim().eq_ignore_ascii_case("branch").then(|| value.trim())
    });
    Some(ViaValue { sent_by, branch })
}

/// The address a numeric `sent-by` names, with 5060 when it has no port.
fn sent_by_address(sent_by: &str) -> Option<SocketAddr> {
    sent_by.parse().ok().or_else(|| format!("{sent_by}:5060").parse().ok())
}

/// The UAS: rings, then takes a CANCEL with a 200 and ends the INVITE with a
/// 487. It returns whether the ACK of the 487 confirmed the INVITE.
async fn run_uas(mut incoming: Incoming) -> bool {
    let mut ringing = None;
    while let Some(event) = incoming.recv().await {
        match event {
            IncomingEvent::Request(envelope) => {
                let (responder, events) = envelope.transaction.into_parts();
                let ring = reply(&envelope.request, 180);
                responder.respond(ring).await.expect("accepted 180");
                println!("uas: INVITE ringing");
                ringing = Some((envelope.request, responder, events));
            }
            IncomingEvent::Cancel(cancel) => {
                let (responder, _) = cancel.transaction.into_parts();
                let ok = reply(&cancel.request, 200);
                responder.respond(ok).await.expect("accepted 200");
                let (invite, invite_responder, mut events) =
                    ringing.take().expect("the CANCEL matched the INVITE");
                let terminated = reply(&invite, 487);
                invite_responder
                    .respond(terminated)
                    .await
                    .expect("accepted 487");
                println!("uas: CANCEL matched the INVITE, which got a 487");

                // Timer I ends a confirmed INVITE. Timer H would report a
                // missing ACK first.
                loop {
                    match events.next().await {
                        Some(ServerEvent::AckTimeout) => {
                            println!("uas: no ACK reached the INVITE");
                            return false;
                        }
                        Some(ServerEvent::Terminated) => {
                            println!("uas: the ACK confirmed the INVITE");
                            return true;
                        }
                        Some(_) => {}
                        None => return false,
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn reply(request: &Request<Bytes>, status: u16) -> Response<Bytes> {
    // A fixed tag for the INVITE's responses, so the 180 and the 487 agree.
    let tag: Tag = "uas-1".parse().expect("a token");
    Response::reply_to(request)
        .status(status)
        .to_tag(tag)
        .body(Bytes::new())
        .expect("a valid response")
}

/// The UAC, as raw datagrams, so that it can send an exact retransmission.
async fn run_uac(proxy: SocketAddr) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local = socket.local_addr()?;
    let via = format!("SIP/2.0/UDP {local};branch=z9hG4bK-uac-1;rport");
    let invite = request("INVITE", &via, None);

    // The UAS's transaction sends a 100 at once and the 180 its TU gives it.
    socket.send_to(&invite, proxy).await?;
    while receive(&socket).await?.status().as_u16() == 100 {}

    // A retransmission gets the latest provisional response again, from the
    // same transaction.
    socket.send_to(&invite, proxy).await?;
    println!("uac: retransmitted the INVITE");
    receive(&socket).await?;

    socket.send_to(&request("CANCEL", &via, None), proxy).await?;
    let mut to = None;
    for _ in 0..2 {
        let response = receive(&socket).await?;
        if response.status().as_u16() == 487 {
            to = response.headers().get(TO).cloned();
        }
    }

    let to = to.ok_or("no 487")?;
    socket.send_to(&request("ACK", &via, Some(to.as_str())), proxy).await?;
    println!("uac: acknowledged the 487");
    Ok(())
}

/// A request of the INVITE transaction. The CANCEL and the ACK reuse its Via,
/// as RFC 3261 sections 9.1 and 17.1.1.3 have them do.
fn request(method: &str, via: &str, to: Option<&str>) -> Vec<u8> {
    let to = to.unwrap_or("<sip:bob@example.com>");
    format!(
        "{method} sip:bob@example.com SIP/2.0\r\n\
         Via: {via}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag=uac-1\r\n\
         To: {to}\r\n\
         Call-ID: stateless-proxy-example\r\n\
         CSeq: 1 {method}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Receives one response from the proxy and prints it.
async fn receive(
    socket: &UdpSocket,
) -> Result<Response<Bytes>, Box<dyn Error>> {
    let mut buf = vec![0; 65536];
    let (len, _) =
        timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await??;
    let response = Response::from_bytes(&buf[..len])?;
    let cseq = response.headers().get(CSEQ).map_or("?", HeaderValue::as_str);
    println!("uac: {} for {cseq}", response.status());
    Ok(response)
}
