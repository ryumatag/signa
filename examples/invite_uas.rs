/*!
An INVITE UAS that answers calls and runs the UA core's side of a 2xx.

The example binds a UAS endpoint and a caller endpoint on the loopback and
places three calls:

1. Over UDP. The caller acknowledges the 2xx, and the UAS stops retransmitting
   it.
2. Over TCP. The caller never acknowledges the 2xx, so the UAS retransmits it
   until 64 T1 have passed and then gives up on the session.
3. On a second UAS endpoint, a call whose shutdown deadline comes before the
   UAS has finished, to show a forced shutdown next to the graceful one.

A graceful shutdown starts while call 2 is still retransmitting. It reports
[`ShutdownOutcome::Drained`] once the TU's work guard is gone and both INVITE
transactions have left Accepted at Timer L. The third call's shutdown reports
[`ShutdownOutcome::DeadlineExpired`].

Pass `--t1-ms 50` for a quicker run. Every timer the example uses scales with
T1, and the default is RFC 3261's 500 ms, which makes the run take about 35 s.

# What signa does and what the TU does

signa's INVITE server transaction sends 100 Trying as soon as it admits the
INVITE, before this TU sees it. That 100 never passes through the TU. The TU
submits 180 and 183 and the final response through its [`Responder`]. After a
2xx the transaction stays in Accepted for Timer L, absorbs retransmitted
INVITEs, and passes each ACK to the TU as [`IncomingEvent::Ack`]
([RFC 6026 section 8.7]). It never retransmits the 2xx itself.

The rest is the UA core's job, which this example does:

* Pick one To tag for the dialog and use it on the 180, the 183 and the 200.
* Register an ACK waiter for the dialog before submitting the 2xx, so an ACK
  that arrives right after the 2xx cannot be missed.
* Take a [`WorkGuard`] before the 2xx, so a graceful shutdown waits for the ACK
  wait, and drop it when the wait ends.
* Retransmit the 2xx through the saved [`ReplyRoute`], starting at T1 and
  doubling up to T2, until the ACK arrives or 64 T1 have passed
  ([RFC 3261 section 13.3.1.4]). That holds over TCP too, since the 2xx is
  retransmitted end to end and a later hop can be UDP. If no ACK comes, the
  dialog is confirmed, but the session should be ended with a BYE, which this
  example only reports.
* Match an ACK to its dialog by Call-ID, the From and To tags and the CSeq
  number. An ACK that matches no waiter, such as a copy sent for a
  retransmitted 2xx, is ignored.
* Answer a CANCEL that arrives while the call rings with a 200, and the INVITE
  with a 487 ([RFC 3261 section 9.2]). signa only matches the CANCEL to its
  INVITE.

`Responder::respond` returns once the driver has accepted the response, not
once the caller has it. A later write failure arrives in [`ServerEvents`].

# What it leaves out

This is not a complete UA. It keeps no dialog after the ACK wait, does no
SDP offer/answer (an ACK may carry the answer), sends no BYE, has no PRACK,
session timers, authentication or Record-Route handling, and builds its
Contact from the local address. Its header parsing is simplified, as noted
where it happens.

[RFC 6026 section 8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
[RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
[RFC 3261 section 9.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2
[`ShutdownOutcome::Drained`]: signa::endpoint::ShutdownOutcome::Drained
[`ShutdownOutcome::DeadlineExpired`]: signa::endpoint::ShutdownOutcome::DeadlineExpired
[`Responder`]: signa::endpoint::Responder
[`IncomingEvent::Ack`]: signa::endpoint::IncomingEvent::Ack
[`WorkGuard`]: signa::endpoint::WorkGuard
[`ReplyRoute`]: signa::endpoint::ReplyRoute
[`ServerEvents`]: signa::endpoint::ServerEvents
*/

use std::{
    collections::HashMap,
    env,
    error::Error,
    net::SocketAddr,
    pin::pin,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use bytes::Bytes;
use signa::{
    Method, Request, Response,
    endpoint::{
        Endpoint, Incoming, IncomingEvent, ReplyError, ReplyRoute, Responder,
        Responses, ServerEvent, ServerEvents, ServerTransactionId,
        ShutdownOutcome, Target, ViaMode,
    },
    message::header::{
        CALL_ID, CONTACT, CSEQ, FROM, HeaderMap, HeaderValue, TO, Tag, VIA,
    },
    transaction::Timers,
    transport::Transport,
};
use tokio::{
    sync::oneshot,
    time::{Instant, sleep, sleep_until, timeout},
};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let timers = timers_from_args()?;
    let t1 = timers.t1();

    let (uas, incoming) = bind(timers)?;
    let serving = tokio::spawn(run_uas(uas.clone(), incoming, timers));
    let (caller, _caller_incoming) = bind(timers)?;

    // Call 1, acknowledged.
    let target = Target::new(Transport::Udp, uas.udp_addr().expect("UDP"));
    let (first, responses) = invite(&caller, target, "acked").await?;
    acknowledge(&caller, target, &first).await?;
    println!("caller: acknowledged the 2xx of call 1");
    // The stream stays open until Timer M. A UAS that stopped retransmitting
    // sends no further 2xx, which the caller reads for a while.
    let late = count_2xx(responses, Some(8 * t1)).await;
    assert_eq!(late.len(), 0, "the UAS stopped at the ACK");

    // Call 2, never acknowledged.
    let target = Target::new(Transport::Tcp, uas.tcp_addr().expect("TCP"));
    let (_, responses) = invite(&caller, target, "unacked").await?;
    let retransmissions = tokio::spawn(count_2xx(responses, None));

    // Shut down while call 2 still retransmits. Its work guard and both
    // transactions in Accepted hold the drain, which ends at Timer L.
    let started = Instant::now();
    let outcome = uas.shutdown(64 * t1 + 10 * t1).await;
    println!(
        "uas: shutdown {outcome:?} after {:.1?} (64 T1 is {:.1?})",
        started.elapsed(),
        64 * t1
    );
    assert_eq!(outcome, ShutdownOutcome::Drained);
    serving.await?;

    let arrivals = retransmissions.await?;
    let expected = expected_retransmissions(&timers);
    println!(
        "caller: {} retransmitted 2xx of call 2, {expected} expected, at {:?}",
        arrivals.len(),
        arrivals
    );
    // The last one can fall right at Timer M, where the caller's stream ends.
    assert!(
        (expected - 1..=expected).contains(&arrivals.len()),
        "the UAS retransmitted on the T1 to T2 schedule"
    );

    forced_shutdown(timers).await
}

/// Call 3: a shutdown deadline that comes before the TU is done.
async fn forced_shutdown(timers: Timers) -> Result<(), BoxError> {
    let (uas, incoming) = bind(timers)?;
    let serving = tokio::spawn(run_uas(uas.clone(), incoming, timers));
    let (caller, _caller_incoming) = bind(timers)?;
    let target = Target::new(Transport::Udp, uas.udp_addr().expect("UDP"));
    let (_, _responses) = invite(&caller, target, "forced").await?;

    let outcome = uas.shutdown(timers.t1()).await;

    println!("uas: shutdown {outcome:?} with the 2xx still unacknowledged");
    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    serving.await?;
    Ok(())
}

fn bind(timers: Timers) -> Result<(Endpoint, Incoming), BoxError> {
    Ok(Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .tcp("127.0.0.1:0".parse()?)
        .timers(timers)
        .bind()?)
}

/// RFC 3261's timers, or T1 from `--t1-ms` with T2 and T4 scaled alike.
fn timers_from_args() -> Result<Timers, BoxError> {
    let mut args = env::args().skip(1);
    let Some(flag) = args.next() else { return Ok(Timers::default()) };
    let ms: u64 = match (flag.as_str(), args.next()) {
        ("--t1-ms", Some(ms)) => ms.parse()?,
        _ => return Err("usage: invite_uas [--t1-ms MS]".into()),
    };
    Ok(Timers::builder()
        .t1(Duration::from_millis(ms))
        .t2(Duration::from_millis(ms * 8))
        .t4(Duration::from_millis(ms * 10))
        .build()?)
}

// The UAS.

/// The dialog and CSeq an ACK must carry to end one 2xx wait.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AckKey {
    call_id: String,
    remote_tag: String,
    local_tag: String,
    cseq: u32,
}

impl AckKey {
    /// The key of a 2xx this UAS sends, or of an ACK it receives. Both carry
    /// the dialog's tags in From and To, and the INVITE's CSeq number.
    fn of(headers: &HeaderMap) -> Option<AckKey> {
        Some(AckKey {
            call_id: headers.get(CALL_ID)?.as_str().trim().to_owned(),
            remote_tag: tag_of(headers.get(FROM)?)?.to_owned(),
            local_tag: tag_of(headers.get(TO)?)?.to_owned(),
            cseq: cseq_number(headers.get(CSEQ)?)?,
        })
    }
}

/// What the receive loop shares with the call tasks.
#[derive(Default)]
struct Calls {
    /// One entry for each 2xx waiting for its ACK.
    acks: HashMap<AckKey, oneshot::Sender<()>>,
    /// One entry for each INVITE still ringing.
    ringing: HashMap<ServerTransactionId, oneshot::Sender<()>>,
}

/// The UAS's receive loop. It never waits for a call, so ACKs and CANCELs get
/// through however many calls are ringing or waiting.
async fn run_uas(endpoint: Endpoint, mut incoming: Incoming, timers: Timers) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    while let Some(event) = incoming.recv().await {
        match event {
            IncomingEvent::Request(envelope)
                if envelope.request.method() == Method::INVITE =>
            {
                let (responder, events) = envelope.transaction.into_parts();
                let (cancel, cancelled) = oneshot::channel();
                lock(&calls).ringing.insert(responder.id(), cancel);
                tokio::spawn(observe(events));
                tokio::spawn(answer(
                    endpoint.clone(),
                    envelope.request,
                    responder,
                    cancelled,
                    calls.clone(),
                    timers,
                ));
            }
            IncomingEvent::Request(envelope) => {
                // A UA would handle BYE and the rest within its dialogs.
                let (responder, _) = envelope.transaction.into_parts();
                let _ = responder
                    .respond(reply(&envelope.request, 501, &Tag::random()))
                    .await;
            }
            IncomingEvent::Ack(ack) => {
                let waiter = AckKey::of(ack.request.headers())
                    .and_then(|key| lock(&calls).acks.remove(&key));
                match waiter {
                    Some(waiter) => {
                        let _ = waiter.send(());
                    }
                    None => println!("uas: an ACK for no waiting 2xx"),
                }
            }
            IncomingEvent::Cancel(cancel) => {
                // The CANCEL's own transaction gets a 200 whether or not the
                // INVITE still rings. The call task sends the 487.
                let (responder, _) = cancel.transaction.into_parts();
                let _ = responder
                    .respond(reply(&cancel.request, 200, &Tag::random()))
                    .await;
                if let Some(ringing) =
                    lock(&calls).ringing.remove(&cancel.target)
                {
                    let _ = ringing.send(());
                }
            }
            IncomingEvent::UnmatchedCancel(cancel) => {
                let response = reply(&cancel.request, 481, &Tag::random());
                let _ = cancel.reply.send(response).await;
            }
            _ => {}
        }
    }
}

/// One call, from the first provisional response to the end of its 2xx wait.
async fn answer(
    endpoint: Endpoint,
    request: Request<Bytes>,
    responder: Responder,
    cancelled: oneshot::Receiver<()>,
    calls: Arc<Mutex<Calls>>,
    timers: Timers,
) {
    // One To tag for every response that can create this dialog.
    let tag = Tag::random();
    let mut cancelled = pin!(cancelled);

    for status in [180, 183] {
        if let Err(error) =
            responder.respond(reply(&request, status, &tag)).await
        {
            println!("uas: {status} not accepted: {error}");
            return;
        }
        let ring = sleep(timers.t1());
        tokio::select! {
            _ = ring => {}
            Ok(()) = &mut cancelled => {
                let terminated = reply(&request, 487, &tag);
                let _ = responder.respond(terminated).await;
                println!("uas: cancelled while ringing, sent 487");
                return;
            }
        }
    }
    lock(&calls).ringing.remove(&responder.id());

    let ok = answer_ok(&request, &tag, &endpoint);
    let key = AckKey::of(ok.headers()).expect("the 2xx has a dialog");
    let (ack_waiter, acked) = oneshot::channel();
    lock(&calls).acks.insert(key.clone(), ack_waiter);
    // A shutdown that has already decided to stop refuses the guard. The call
    // goes on unguarded then, and the endpoint's end stops it.
    let guard = endpoint.work_guard().ok();
    let route = responder.reply_route();

    if let Err(error) = responder.respond(ok.clone()).await {
        println!("uas: 2xx not accepted: {error}");
        lock(&calls).acks.remove(&key);
        return;
    }
    let call = key.call_id.clone();
    match retransmit_until_ack(&route, &ok, acked, &timers).await {
        Wait::Acked(sent) => {
            println!("uas: {call}: ACK after {sent} retransmissions")
        }
        Wait::GaveUp(sent) => println!(
            "uas: {call}: no ACK within 64 T1 after {sent} retransmissions. \
             A UA would send a BYE now."
        ),
        Wait::Closed(sent) => println!(
            "uas: {call}: the endpoint closed after {sent} retransmissions"
        ),
    }
    lock(&calls).acks.remove(&key);
    drop(guard);
}

/// How a 2xx wait ended, with the number of retransmissions sent.
enum Wait {
    Acked(usize),
    GaveUp(usize),
    Closed(usize),
}

/// Retransmits `ok` through `route` as RFC 3261 section 13.3.1.4 says: first
/// after T1, then at doubling intervals capped at T2, until the ACK or until
/// 64 T1 after the first 2xx.
async fn retransmit_until_ack(
    route: &ReplyRoute,
    ok: &Response<Bytes>,
    acked: oneshot::Receiver<()>,
    timers: &Timers,
) -> Wait {
    let first = Instant::now();
    let give_up = first + 64 * timers.t1();
    let mut acked = pin!(acked);
    let mut interval = timers.t1();
    let mut next = first + interval;
    let mut sent = 0;
    loop {
        let wake = next.min(give_up);
        tokio::select! {
            _ = &mut acked => return Wait::Acked(sent),
            _ = sleep_until(wake) => {}
        }
        if wake == give_up {
            return Wait::GaveUp(sent);
        }

        match route.send(ok.clone()).await {
            Ok(()) => sent += 1,
            Err(ReplyError::Closed) => return Wait::Closed(sent),
            // A write that failed may succeed next time, as over UDP.
            Err(error) => println!("uas: retransmission failed: {error}"),
        }
        interval = (interval * 2).min(timers.t2());
        next += interval;
    }
}

/// How many retransmissions the schedule of `retransmit_until_ack` makes.
fn expected_retransmissions(timers: &Timers) -> usize {
    let mut interval = timers.t1();
    let mut at = interval;
    let mut count = 0;
    while at < 64 * timers.t1() {
        count += 1;
        interval = (interval * 2).min(timers.t2());
        at += interval;
    }
    count
}

/// Prints what the transaction reports, independently of the call task.
async fn observe(mut events: ServerEvents) {
    let id = events.id();
    while let Some(event) = events.next().await {
        match event {
            ServerEvent::Terminated => {
                println!("uas: transaction {id:?} terminated")
            }
            ServerEvent::EndpointClosed => {
                println!("uas: transaction {id:?} closed with the endpoint")
            }
            other => println!("uas: transaction {id:?}: {other:?}"),
        }
    }
}

fn reply(request: &Request<Bytes>, status: u16, tag: &Tag) -> Response<Bytes> {
    Response::reply_to(request)
        .status(status)
        .to_tag(tag.clone())
        .body(Bytes::new())
        .expect("a valid response")
}

/// The 2xx, with a Contact for this UAS and a stand-in SDP answer.
fn answer_ok(
    request: &Request<Bytes>,
    tag: &Tag,
    endpoint: &Endpoint,
) -> Response<Bytes> {
    let over_tcp = request
        .headers()
        .get(VIA)
        .is_some_and(|via| via.as_str().starts_with("SIP/2.0/TCP"));
    let contact = if over_tcp {
        let addr = endpoint.tcp_addr().expect("TCP");
        format!("<sip:uas@{addr};transport=tcp>")
    } else {
        format!("<sip:uas@{}>", endpoint.udp_addr().expect("UDP"))
    };
    Response::reply_to(request)
        .status(200)
        .to_tag(tag.clone())
        .header(CONTACT, contact.as_str())
        .header("Content-Type", "application/sdp")
        .body(Bytes::from_static(b"v=0\r\n"))
        .expect("a valid response")
}

fn lock(calls: &Mutex<Calls>) -> MutexGuard<'_, Calls> {
    calls.lock().expect("no call task panics while holding the lock")
}

// The caller, a minimal UAC core on its own endpoint.

/// Sends an INVITE and reads its responses up to the first 2xx.
async fn invite(
    caller: &Endpoint,
    target: Target,
    call_id: &str,
) -> Result<(Response<Bytes>, Responses), BoxError> {
    let local = caller.udp_addr().expect("UDP");
    let request = Request::builder()
        .method("INVITE")
        .uri(format!("sip:uas@{}", target.address()).as_str())
        .header(FROM, "<sip:caller@example.com>;tag=caller")
        .header(TO, "<sip:uas@example.com>")
        .header(CALL_ID, call_id)
        .header(CSEQ, "1 INVITE")
        .header(CONTACT, format!("<sip:caller@{local}>").as_str())
        .header("Max-Forwards", "70")
        .body(Bytes::new())?;

    let (_control, mut responses) =
        caller.start(request, target).await?.into_parts();
    loop {
        let response = responses.next().await.ok_or("no final response")??;
        println!("caller: {call_id}: {}", response.status());
        if response.status().is_success() {
            return Ok((response, responses));
        }
        if response.status().is_final() {
            return Err(format!("{call_id} failed").into());
        }
    }
}

/// Sends the ACK for `ok` to the remote target its Contact names.
async fn acknowledge(
    caller: &Endpoint,
    target: Target,
    ok: &Response<Bytes>,
) -> Result<(), BoxError> {
    let headers = ok.headers();
    let contact = headers.get(CONTACT).ok_or("no Contact")?;
    let remote = contact_address(contact).ok_or("an unreadable Contact")?;
    let ack = Request::builder()
        .method("ACK")
        .uri(format!("sip:uas@{remote}").as_str())
        .header(FROM, headers.get(FROM).ok_or("no From")?.clone())
        .header(TO, headers.get(TO).ok_or("no To")?.clone())
        .header(CALL_ID, headers.get(CALL_ID).ok_or("no Call-ID")?.clone())
        .header(CSEQ, "1 ACK")
        .header("Max-Forwards", "70")
        .body(Bytes::new())?;
    let target = Target::new(target.transport(), remote);
    caller.send_request(ack, target, ViaMode::Fresh).await?;
    Ok(())
}

/// Collects the arrival times of further 2xx until the stream ends, which
/// Timer M does, or until `limit`.
async fn count_2xx(
    mut responses: Responses,
    limit: Option<Duration>,
) -> Vec<Duration> {
    let started = Instant::now();
    let mut arrivals = Vec::new();
    loop {
        let next = responses.next();
        let response = match limit {
            Some(limit) => match timeout(limit, next).await {
                Ok(response) => response,
                Err(_) => break,
            },
            None => next.await,
        };
        match response {
            Some(Ok(response)) if response.status().is_success() => {
                arrivals.push(started.elapsed())
            }
            Some(_) => {}
            None => break,
        }
    }
    arrivals
}

// Simplified header reading. A typed-header crate does this properly.

/// The `tag` parameter of a From or To value. It reads parameters after the
/// closing `>` only, so it needs a name-addr, which this example always
/// sends.
fn tag_of(value: &HeaderValue) -> Option<&str> {
    let (_, params) = value.as_str().rsplit_once('>')?;
    params.split(';').find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim().eq_ignore_ascii_case("tag").then(|| value.trim())
    })
}

/// The number of a CSeq value.
fn cseq_number(value: &HeaderValue) -> Option<u32> {
    value.as_str().split_whitespace().next()?.parse().ok()
}

/// The numeric host and port of a Contact such as `<sip:uas@1.2.3.4:5060>`.
fn contact_address(value: &HeaderValue) -> Option<SocketAddr> {
    let value = value.as_str();
    let uri = &value[value.find('<')? + 1..value.find('>')?];
    let host_port = uri.split_once('@')?.1.split(';').next()?;
    host_port.parse().ok()
}
