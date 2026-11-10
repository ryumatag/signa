/*!
A stateful proxy that forks each INVITE to two UASes, on the loopback.

A signa UAC calls through the proxy, which forks to two signa UASes. Three
calls show the cases a forking proxy has to get right:

1. Both forks answer. The proxy forwards both 2xx upstream as they arrive and
   cancels whatever is still pending. The UAC acknowledges each 2xx straight
   to the UAS that sent it.
2. The UAC cancels while both forks ring. The proxy answers the CANCEL, cancels
   both branches, and forwards the best final response, a 487.
3. Both forks refuse. The proxy waits for both finals and forwards the best.

# What the proxy does

Following [RFC 3261 section 16], with signa's transactions on both sides:

* Each upstream INVITE gets a server transaction, whose 100 Trying signa sends
  on admission. Each branch is a client transaction from
  [`Endpoint::start`], which adds the proxy's Via above the received ones.
* A 100 from a branch is not forwarded ([section 16.7], step 5). Other
  provisional responses and every 2xx are forwarded at once, through the
  upstream [`Responder`], after the proxy removes its own Via. The responder
  takes several 2xx with different To tags while the upstream INVITE is in
  Accepted ([RFC 6026 section 7.3]).
* The first 2xx cancels every branch without a final response yet (step 10).
  A branch that answers anyway still has its 2xx forwarded.
* Without a 2xx, the proxy waits for a final from every branch and forwards
  the best one: a 6xx if there is one, else the lowest status code (step 6).
  A branch that fails without a response counts as a 408.
* A CANCEL that matches the upstream INVITE gets a 200 from the proxy and
  cancels the pending branches ([section 16.10]). Each [`ClientControl::cancel`]
  waits for its branch's provisional response, and the branch's 487 comes back
  as an ordinary final.
* A response can only be forwarded while the upstream transaction allows it.
  `respond` refuses a provisional response after the first 2xx, anything but a
  2xx after a final, and everything after Timer L, and the proxy drops it
  then. It never sends a late response through the reply route, which would
  skip that check ([RFC 6026 section 8.3]).

The fork task that does this ends when the last branch's response stream does,
which for a 2xx is Timer M. The upstream transaction ends at Timer L on its own
schedule, which the proxy observes separately. Neither end means the other.

# What it leaves out

This is not a complete proxy. The two targets are fixed, so there is no
location service, Request-URI rewriting, Route processing, DNS or loop
detection. The proxy adds no Record-Route, so the ACK for a 2xx and later
requests in the dialog go straight to the UAS's Contact. There is no Timer C,
no 3xx recursion, no 483 beyond the Max-Forwards check, no authentication,
and a CANCEL that matches nothing gets a 481 instead of the stateless
forwarding of section 16.10. The UASes are minimal and do not retransmit their
2xx. The `invite_uas` example does that. Its Via removal is simplified, as
noted where it happens.

[RFC 3261 section 16]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16
[section 16.7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.7
[section 16.10]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.10
[RFC 6026 section 7.3]: https://www.rfc-editor.org/rfc/rfc6026.html#section-7.3
[RFC 6026 section 8.3]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.3
[`Endpoint::start`]: signa::endpoint::Endpoint::start
[`Responder`]: signa::endpoint::Responder
[`ClientControl::cancel`]: signa::endpoint::ClientControl::cancel
*/

use std::{
    collections::HashMap,
    env,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use signa::{
    Method, Request, Response,
    endpoint::{
        self, CancelOutcome, ClientControl, Endpoint, Incoming, IncomingEvent,
        Responder, Responses, ServerEvent, ServerTransactionId,
        ShutdownOutcome, SubmitError, Target, ViaMode,
    },
    message::header::{
        CALL_ID, CONTACT, CSEQ, FROM, HeaderMap, HeaderValue, MAX_FORWARDS,
        TO, Tag, VIA,
    },
    transaction::Timers,
    transport::Transport,
};
use tokio::sync::{mpsc, oneshot};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let timers = timers_from_args()?;
    let (uas_a, uas_a_incoming) = bind(timers)?;
    let (uas_b, uas_b_incoming) = bind(timers)?;
    tokio::spawn(run_uas("a", uas_a_incoming, uas_a.clone()));
    tokio::spawn(run_uas("b", uas_b_incoming, uas_b.clone()));
    let branches = [
        Target::new(Transport::Udp, uas_a.udp_addr().expect("UDP")),
        Target::new(Transport::Udp, uas_b.udp_addr().expect("UDP")),
    ];
    let (proxy, proxy_incoming) = bind(timers)?;
    let proxying =
        tokio::spawn(run_proxy(proxy.clone(), proxy_incoming, branches));
    let (uac, _uac_incoming) = bind(timers)?;
    let next_hop = Target::new(Transport::Udp, proxy.udp_addr().expect("UDP"));

    let answers = call(&uac, next_hop, "answer", false).await?;
    assert_eq!(answers, [200, 200], "both forks' 2xx reach the UAC");
    let cancelled = call(&uac, next_hop, "ring", true).await?;
    assert_eq!(cancelled, [487]);
    let refused = call(&uac, next_hop, "refuse", false).await?;
    assert_eq!(refused, [480], "the lower of 486 and 480");

    // The proxy drains once its upstream INVITEs leave Accepted at Timer L
    // and its branches leave Accepted at Timer M or Completed at Timer D.
    let outcome = proxy.shutdown(Duration::from_secs(40)).await;
    println!("proxy: shutdown {outcome:?}");
    assert_eq!(outcome, ShutdownOutcome::Drained);
    proxying.await?;
    Ok(())
}

fn bind(timers: Timers) -> Result<(Endpoint, Incoming), BoxError> {
    Ok(Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .timers(timers)
        .bind()?)
}

/// RFC 3261's timers, or T1 from `--t1-ms` with T2 and T4 scaled alike.
fn timers_from_args() -> Result<Timers, BoxError> {
    let mut args = env::args().skip(1);
    let Some(flag) = args.next() else { return Ok(Timers::default()) };
    let ms: u64 = match (flag.as_str(), args.next()) {
        ("--t1-ms", Some(ms)) => ms.parse()?,
        _ => return Err("usage: fork_proxy [--t1-ms MS]".into()),
    };
    Ok(Timers::builder()
        .t1(Duration::from_millis(ms))
        .t2(Duration::from_millis(ms * 8))
        .t4(Duration::from_millis(ms * 10))
        .build()?)
}

// The proxy.

/// The proxy's receive loop. Each INVITE gets a fork task, and the loop only
/// routes CANCELs to them, so it never waits on a branch.
async fn run_proxy(
    proxy: Endpoint,
    mut incoming: Incoming,
    branches: [Target; 2],
) {
    let forks: Arc<Mutex<HashMap<ServerTransactionId, oneshot::Sender<()>>>> =
        Arc::default();
    while let Some(event) = incoming.recv().await {
        match event {
            IncomingEvent::Request(envelope)
                if envelope.request.method() == Method::INVITE =>
            {
                let (responder, mut events) =
                    envelope.transaction.into_parts();
                let id = responder.id();
                let (cancel, cancelled) = oneshot::channel();
                forks.lock().expect("not poisoned").insert(id, cancel);

                // The transaction's own lifetime, apart from the fork task's.
                tokio::spawn(async move {
                    while let Some(event) = events.next().await {
                        if let ServerEvent::Terminated = event {
                            println!(
                                "proxy: upstream INVITE {id:?} terminated"
                            );
                        }
                    }
                });
                let forks = forks.clone();
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    fork(
                        &proxy,
                        envelope.request,
                        responder,
                        cancelled,
                        branches,
                    )
                    .await;
                    forks.lock().expect("not poisoned").remove(&id);
                    println!("proxy: fork task for {id:?} finished");
                });
            }
            IncomingEvent::Request(envelope) => {
                // Only INVITE is proxied here.
                let (responder, _) = envelope.transaction.into_parts();
                let response = own_response(&envelope.request, 501);
                let _ = responder.respond(response).await;
            }
            IncomingEvent::Cancel(cancel) => {
                // The proxy answers the CANCEL hop by hop (section 16.10).
                let (responder, _) = cancel.transaction.into_parts();
                let ok = own_response(&cancel.request, 200);
                let _ = responder.respond(ok).await;
                let fork =
                    forks.lock().expect("not poisoned").remove(&cancel.target);
                if let Some(fork) = fork {
                    let _ = fork.send(());
                }
            }
            IncomingEvent::UnmatchedCancel(cancel) => {
                let response = own_response(&cancel.request, 481);
                let _ = cancel.reply.send(response).await;
            }
            // An ACK for a non-2xx is absorbed by its transaction, and one for
            // a 2xx goes to the UAS without Record-Route.
            _ => {}
        }
    }
}

/// One branch of a fork, as the fork task tracks it.
struct Branch {
    control: Option<ClientControl>,
    /// Whether the branch has a final response, or failed without one.
    done: bool,
}

/// Forks `request` to `targets` and relays the responses upstream until every
/// branch's response stream has ended.
async fn fork(
    proxy: &Endpoint,
    request: Request<Bytes>,
    upstream: Responder,
    mut cancelled: oneshot::Receiver<()>,
    targets: [Target; 2],
) {
    let Some(downstream) = forwarded(&request) else {
        let _ = upstream.respond(own_response(&request, 483)).await;
        return;
    };

    // Every branch's responses arrive on one channel, tagged by branch.
    let (arrivals, mut arrived) = mpsc::unbounded_channel();
    let mut branches = Vec::new();
    for (index, target) in targets.into_iter().enumerate() {
        match proxy.start(downstream.clone(), target).await {
            Ok(transaction) => {
                let (control, responses) = transaction.into_parts();
                tokio::spawn(relay(index, responses, arrivals.clone()));
                branches.push(Branch { control: Some(control), done: false });
            }
            Err(error) => {
                println!("proxy: branch {index} not started: {error}");
                branches.push(Branch { control: None, done: true });
            }
        }
    }
    drop(arrivals);

    let mut answered = false;
    let mut best: Option<Response<Bytes>> = None;
    let mut cancelling = false;
    loop {
        let (index, arrival) = tokio::select! {
            arrival = arrived.recv() => match arrival {
                Some(arrival) => arrival,
                // Every branch's stream has ended.
                None => break,
            },
            Ok(()) = &mut cancelled, if !cancelling => {
                println!("proxy: upstream CANCEL, cancelling the branches");
                cancelling = true;
                cancel_pending(&mut branches);
                continue;
            }
        };
        // Every response but a 100 goes upstream sooner or later, without the
        // proxy's own Via.
        let arrival = arrival.map(|mut response| {
            remove_top_via(response.headers_mut());
            response
        });
        match arrival {
            Ok(response) if response.status().as_u16() == 100 => {}
            Ok(response) if response.status().is_provisional() => {
                forward(&upstream, response).await;
            }
            Ok(response) if response.status().is_success() => {
                branches[index].done = true;
                forward(&upstream, response).await;
                if !answered {
                    answered = true;
                    cancel_pending(&mut branches);
                }
            }
            Ok(response) => {
                branches[index].done = true;
                best = Some(better(best, response));
            }
            Err(error) => {
                println!("proxy: branch {index} failed: {error}");
                if !branches[index].done {
                    branches[index].done = true;
                    // A branch that failed without a response counts as a
                    // 408 from the proxy.
                    best = Some(better(best, own_response(&request, 408)));
                }
            }
        }

        if !answered && branches.iter().all(|branch| branch.done) {
            if let Some(best) = best.take() {
                forward(&upstream, best).await;
            }
        }
    }
}

/// A branch's index and one item of its response stream.
type Arrival = (usize, Result<Response<Bytes>, endpoint::Error>);

/// Sends every response of a branch to the fork task, then drops its sender.
async fn relay(
    index: usize,
    mut responses: Responses,
    arrivals: mpsc::UnboundedSender<Arrival>,
) {
    while let Some(arrival) = responses.next().await {
        if arrivals.send((index, arrival)).is_err() {
            return;
        }
    }
}

/// Cancels every branch without a final response, each in a task of its own,
/// since `cancel` waits for the branch's provisional response.
fn cancel_pending(branches: &mut [Branch]) {
    for (index, branch) in branches.iter_mut().enumerate() {
        if branch.done {
            continue;
        }
        let Some(control) = branch.control.take() else { continue };
        tokio::spawn(async move {
            match control.cancel().await {
                Ok(CancelOutcome::Sent(cancel)) => {
                    let (_, mut responses) = cancel.into_parts();
                    if let Some(Ok(response)) = responses.next().await {
                        println!(
                            "proxy: CANCEL of branch {index} got {}",
                            response.status()
                        );
                    }
                }
                Ok(_) => println!("proxy: branch {index} needed no CANCEL"),
                Err(error) => println!("proxy: branch {index}: {error}"),
            }
        });
    }
}

/// Forwards a response upstream, once the proxy's own Via is gone.
async fn forward(upstream: &Responder, response: Response<Bytes>) {
    let status = response.status();
    match upstream.respond(response).await {
        Ok(()) => println!("proxy: forwarded {status}"),
        // The upstream transaction no longer takes it. A late response is
        // dropped, not sent around the transaction through its reply route.
        Err(
            error @ (SubmitError::FinalAlreadySent | SubmitError::Terminated),
        ) => {
            println!("proxy: dropped a late {status}: {error}")
        }
        Err(error) => println!("proxy: {status} not forwarded: {error}"),
    }
}

/// The better of two final non-2xx responses: a 6xx if either is one, else
/// the lower status code.
fn better(
    best: Option<Response<Bytes>>,
    new: Response<Bytes>,
) -> Response<Bytes> {
    let Some(best) = best else { return new };
    let rank = |response: &Response<Bytes>| {
        let code = response.status().as_u16();
        (code < 600, code)
    };
    if rank(&new) < rank(&best) { new } else { best }
}

/// A response the proxy makes itself, with a To tag of its own.
fn own_response(request: &Request<Bytes>, status: u16) -> Response<Bytes> {
    Response::reply_to(request)
        .status(status)
        .to_tag(Tag::random())
        .body(Bytes::new())
        .expect("a valid response")
}

/// The request to send on each branch: the received one with Max-Forwards
/// decremented, or `None` when it has run out (section 16.6, step 3).
fn forwarded(request: &Request<Bytes>) -> Option<Request<Bytes>> {
    let hops = match request.headers().get(MAX_FORWARDS) {
        None => 70,
        Some(value) => {
            value.as_str().trim().parse::<u32>().ok()?.checked_sub(1)?
        }
    };
    let mut downstream = request.clone();
    let value = HeaderValue::from_bytes(hops.to_string().as_bytes())
        .expect("digits are a valid value");
    downstream.headers_mut().insert(MAX_FORWARDS, value);
    Some(downstream)
}

/// Removes the first Via row, which `Endpoint::start` added for this proxy as
/// a row of its own. `HeaderMap::remove` takes every row, so the later ones go
/// back in order, after the other fields. A proxy that also receives Via
/// values joined by commas in its own row would split the row instead, as the
/// `stateless_proxy` example does.
fn remove_top_via(headers: &mut HeaderMap) {
    let later: Vec<HeaderValue> =
        headers.get_all(VIA).skip(1).cloned().collect();
    headers.remove(VIA);
    for value in later {
        headers.append(VIA, value);
    }
}

// The UAC and the UASes.

/// Calls through the proxy and returns the final statuses it saw. It
/// acknowledges each 2xx straight to the Contact of the UAS that sent it.
async fn call(
    uac: &Endpoint,
    next_hop: Target,
    user: &str,
    cancel: bool,
) -> Result<Vec<u16>, BoxError> {
    let local = uac.udp_addr().expect("UDP");
    let invite = Request::builder()
        .method("INVITE")
        .uri(format!("sip:{user}@example.com").as_str())
        .header(FROM, "<sip:alice@example.com>;tag=alice")
        .header(TO, format!("<sip:{user}@example.com>").as_str())
        .header(CALL_ID, format!("fork-{user}").as_str())
        .header(CSEQ, "1 INVITE")
        .header(CONTACT, format!("<sip:alice@{local}>").as_str())
        .header("Max-Forwards", "70")
        .body(Bytes::new())?;
    let (control, mut responses) =
        uac.start(invite.clone(), next_hop).await?.into_parts();

    let mut provisional = 0;
    let mut finals = Vec::new();
    // A real UAC reads until the stream ends at Timer M. This one stops after
    // the two 2xx it expects, or after its one non-2xx final.
    while finals.len() < 2 {
        let Some(response) = responses.next().await else { break };
        let response = response?;
        let status = response.status().as_u16();
        println!("uac: {user}: {status}");
        if response.status().is_provisional() {
            provisional += 1;
            // The proxy's 100 and one ringing response from each fork.
            if cancel && provisional == 3 {
                control.cancel().await?;
            }
            continue;
        }
        finals.push(status);
        if !response.status().is_success() {
            break;
        }
        let headers = response.headers();
        let contact = headers.get(CONTACT).ok_or("no Contact")?.as_str();
        let remote: SocketAddr = contact
            .trim_start_matches("<sip:")
            .trim_end_matches('>')
            .split_once('@')
            .ok_or("no host in the Contact")?
            .1
            .parse()?;
        let ack = Request::builder()
            .method("ACK")
            .uri(format!("sip:{user}@{remote}").as_str())
            .header(FROM, invite.headers().get(FROM).ok_or("no From")?.clone())
            .header(TO, headers.get(TO).ok_or("no To")?.clone())
            .header(
                CALL_ID,
                invite.headers().get(CALL_ID).ok_or("no Call-ID")?.clone(),
            )
            .header(CSEQ, "1 ACK")
            .header("Max-Forwards", "70")
            .body(Bytes::new())?;
        let target = Target::new(Transport::Udp, remote);
        uac.send_request(ack, target, ViaMode::Fresh).await?;
    }
    Ok(finals)
}

/// A UAS that does what the Request-URI's user says: `answer` rings and
/// answers at once, `ring` rings until a CANCEL, and `refuse` refuses with a
/// status that differs between the two UASes.
async fn run_uas(
    name: &'static str,
    mut incoming: Incoming,
    endpoint: Endpoint,
) {
    let mut ringing: HashMap<
        ServerTransactionId,
        (Request<Bytes>, Responder, Tag),
    > = HashMap::new();
    let contact =
        format!("<sip:{name}@{}>", endpoint.udp_addr().expect("UDP"));
    while let Some(event) = incoming.recv().await {
        match event {
            IncomingEvent::Request(envelope) => {
                let request = envelope.request;
                let (responder, _) = envelope.transaction.into_parts();
                let tag: Tag = format!("uas-{name}").parse().expect("a token");
                let ring = if name == "a" { 180 } else { 183 };
                let user = request.uri().as_str().to_owned();
                if user.starts_with("sip:refuse@") {
                    let status = if name == "a" { 486 } else { 480 };
                    let _ = responder
                        .respond(reply(&request, status, &tag, None))
                        .await;
                    continue;
                }
                let _ =
                    responder.respond(reply(&request, ring, &tag, None)).await;
                if user.starts_with("sip:answer@") {
                    let ok = reply(&request, 200, &tag, Some(&contact));
                    let _ = responder.respond(ok).await;
                } else {
                    ringing.insert(responder.id(), (request, responder, tag));
                }
            }
            IncomingEvent::Cancel(cancel) => {
                let (responder, _) = cancel.transaction.into_parts();
                let _ = responder
                    .respond(reply(&cancel.request, 200, &Tag::random(), None))
                    .await;
                if let Some((request, invite, tag)) =
                    ringing.remove(&cancel.target)
                {
                    let _ =
                        invite.respond(reply(&request, 487, &tag, None)).await;
                    println!("uas {name}: cancelled, sent 487");
                } else {
                    println!("uas {name}: CANCEL after the final, no effect");
                }
            }
            IncomingEvent::Ack(_) => println!("uas {name}: ACK for its 2xx"),
            _ => {}
        }
    }
}

fn reply(
    request: &Request<Bytes>,
    status: u16,
    tag: &Tag,
    contact: Option<&str>,
) -> Response<Bytes> {
    let mut builder =
        Response::reply_to(request).status(status).to_tag(tag.clone());
    if let Some(contact) = contact {
        builder = builder.header(CONTACT, contact);
    }
    builder.body(Bytes::new()).expect("a valid response")
}
