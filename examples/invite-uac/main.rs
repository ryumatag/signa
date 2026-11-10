/*!
An INVITE UAC that handles forked answers and cancels calls.

The far side is a raw UDP socket that plays a forking proxy with two UASes
behind it, so the example can send exactly the responses each case needs:

1. Forked answers. A 180 and a 183 from two forks, a 2xx from the first fork,
   that 2xx again, and a 2xx from the second fork. The UAC acknowledges every
   2xx, keeps the first dialog, and ends the second with a BYE.
2. A cancelled call. A 180, then the CANCEL. The CANCEL gets its own 200 and
   the INVITE a 487, which signa acknowledges.
3. A CANCEL that loses the race. The far side answers the INVITE with a 2xx
   before the CANCEL reaches it. The CANCEL still gets a 200, the 2xx still
   needs its ACK, and the UAC then ends the call with a BYE.

At the end the UAC endpoint shuts down gracefully. It drains when the INVITEs
of cases 1 and 3 leave Accepted at Timer M and the INVITE of case 2 leaves
Completed at Timer D, which is at least 32 seconds over UDP whatever T1 is.
Pass `--t1-ms 50` to shorten the other timers.

# What signa does and what the TU does

[`Endpoint::start`] runs the INVITE client transaction and returns its
[`ClientControl`] and [`Responses`] separately, so the TU can cancel while it
reads responses. The stream yields each provisional response and either the
one non-2xx final or every 2xx until Timer M, including retransmissions and
other forks' 2xx ([RFC 6026 section 8.4]). signa acknowledges a non-2xx itself
([RFC 3261 section 17.1.1.3]).

The UA core's part, which this example does:

* Acknowledge every 2xx with a new ACK sent by [`Endpoint::send_request`], not
  through a client transaction ([RFC 3261 section 13.2.2.4]). A retransmitted
  2xx gets the ACK again. signa does not merge 2xx by To tag, so the TU tells
  a retransmission (same To tag) from another fork (another To tag).
* Decide which dialogs to keep. This UAC keeps the first and ends any other
  with a BYE after its ACK, as section 13.2.2.4 asks.
* Cancel with [`ClientControl::cancel`]. It waits for a provisional response
  before the CANCEL goes out ([RFC 3261 section 9.1]), and the CANCEL is a
  transaction of its own whose responses do not end the INVITE. Whether the
  call was cancelled is what the INVITE's final says.
* Bound the ringing time. signa has no Timer C or ringing limit of its own.

# What it leaves out

There is no dialog layer beyond picking the To tag and building the ACK and
BYE, no route set (the ACK and BYE go to the Contact), no SDP, PRACK or
authentication. Its header parsing is simplified, as noted where it happens.

[RFC 6026 section 8.4]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
[RFC 3261 section 17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
[RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
[RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
[`Endpoint::start`]: signa::endpoint::Endpoint::start
[`Endpoint::send_request`]: signa::endpoint::Endpoint::send_request
[`ClientControl`]: signa::endpoint::ClientControl
[`ClientControl::cancel`]: signa::endpoint::ClientControl::cancel
[`Responses`]: signa::endpoint::Responses
*/

use std::{
    collections::HashMap, env, error::Error, net::SocketAddr, time::Duration,
};

use bytes::Bytes;
use signa::{
    Method, Request, Response,
    endpoint::{
        CancelOutcome, ClientControl, Endpoint, Responses, ShutdownOutcome,
        Target, ViaMode,
    },
    message::header::{
        CALL_ID, CONTACT, CSEQ, FROM, HeaderName, HeaderValue, TO, VIA,
    },
    transaction::Timers,
    transport::Transport,
};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let timers = timers_from_args()?;
    let (uac, _incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .timers(timers)
        .bind()?;

    let script = FarSide::bind().await?.run();
    let target = Target::new(Transport::Udp, script.addr);

    forked_answers(&uac, target).await?;
    cancelled(&uac, target).await?;
    cancel_loses_the_race(&uac, target).await?;
    script.handle.await??;

    // Timer D keeps the cancelled INVITE for 32 s over UDP, and Timer M keeps
    // the answered ones for 64 T1.
    let outcome = uac.shutdown(Duration::from_secs(40)).await;
    println!("uac: shutdown {outcome:?}");
    assert_eq!(outcome, ShutdownOutcome::Drained);
    Ok(())
}

/// RFC 3261's timers, or T1 from `--t1-ms` with T2 and T4 scaled alike.
fn timers_from_args() -> Result<Timers, BoxError> {
    let mut args = env::args().skip(1);
    let Some(flag) = args.next() else { return Ok(Timers::default()) };
    let ms: u64 = match (flag.as_str(), args.next()) {
        ("--t1-ms", Some(ms)) => ms.parse()?,
        _ => return Err("usage: invite-uac [--t1-ms MS]".into()),
    };
    Ok(Timers::builder()
        .t1(Duration::from_millis(ms))
        .t2(Duration::from_millis(ms * 8))
        .t4(Duration::from_millis(ms * 10))
        .build()?)
}

// The UAC core.

/// One INVITE's dialogs, by the To tag of their 2xx.
struct Call {
    invite: Request<Bytes>,
    target: Target,
    /// The ACK sent for each dialog's 2xx, to send again for a retransmission.
    acks: HashMap<String, (Request<Bytes>, Target)>,
    /// The dialog the UAC keeps, the first to answer.
    kept: Option<String>,
    next_cseq: u32,
}

impl Call {
    async fn start(
        uac: &Endpoint,
        target: Target,
        call_id: &str,
    ) -> Result<(Call, ClientControl, Responses), BoxError> {
        let local = uac.udp_addr().expect("UDP");
        let invite = Request::builder()
            .method("INVITE")
            .uri("sip:bob@example.com")
            .header(FROM, "<sip:alice@example.com>;tag=alice")
            .header(TO, "<sip:bob@example.com>")
            .header(CALL_ID, call_id)
            .header(CSEQ, "1 INVITE")
            .header(CONTACT, format!("<sip:alice@{local}>").as_str())
            .header("Max-Forwards", "70")
            .body(Bytes::new())?;
        let (control, responses) =
            uac.start(invite.clone(), target).await?.into_parts();
        let call = Call {
            invite,
            target,
            acks: HashMap::new(),
            kept: None,
            next_cseq: 2,
        };
        Ok((call, control, responses))
    }

    /// Acknowledges a 2xx. The first 2xx of a dialog gets a new ACK, and a
    /// retransmission gets the same request again, with a fresh Via since
    /// each send is its own. Returns the To tag if this 2xx made a new dialog.
    async fn acknowledge(
        &mut self,
        uac: &Endpoint,
        ok: &Response<Bytes>,
    ) -> Result<Option<String>, BoxError> {
        let tag = tag_of(ok.headers().get(TO).ok_or("no To")?)
            .ok_or("a 2xx without a To tag")?
            .to_owned();
        let new = !self.acks.contains_key(&tag);
        if new {
            let contact = ok.headers().get(CONTACT).ok_or("no Contact")?;
            let remote =
                contact_address(contact).ok_or("unreadable Contact")?;
            let ack = self.in_dialog("ACK", 1, ok, remote)?;
            let target = Target::new(self.target.transport(), remote);
            self.acks.insert(tag.clone(), (ack, target));
            self.kept.get_or_insert_with(|| tag.clone());
        }
        let (ack, target) = &self.acks[&tag];
        uac.send_request(ack.clone(), *target, ViaMode::Fresh).await?;
        println!(
            "uac: ACK for the 2xx with tag {tag}{}",
            if new { "" } else { ", again for its retransmission" }
        );
        Ok(new.then_some(tag))
    }

    /// Ends a dialog that was acknowledged but is not wanted, with a BYE in a
    /// client transaction of its own.
    async fn hang_up(
        &mut self,
        uac: &Endpoint,
        ok: &Response<Bytes>,
    ) -> Result<(), BoxError> {
        let contact = ok.headers().get(CONTACT).ok_or("no Contact")?;
        let remote = contact_address(contact).ok_or("unreadable Contact")?;
        let cseq = self.next_cseq;
        self.next_cseq += 1;
        let bye = self.in_dialog("BYE", cseq, ok, remote)?;
        let target = Target::new(self.target.transport(), remote);

        let (_, mut responses) = uac.start(bye, target).await?.into_parts();
        let status = final_status(&mut responses).await?;
        println!("uac: BYE got {status}");
        Ok(())
    }

    /// A request within the dialog of `ok`: the INVITE's From and Call-ID,
    /// the To of `ok`, and the Request-URI of its Contact.
    fn in_dialog(
        &self,
        method: &str,
        cseq: u32,
        ok: &Response<Bytes>,
        remote: SocketAddr,
    ) -> Result<Request<Bytes>, BoxError> {
        let invite = self.invite.headers();
        Ok(Request::builder()
            .method(method)
            .uri(format!("sip:bob@{remote}").as_str())
            .header(FROM, invite.get(FROM).ok_or("no From")?.clone())
            .header(TO, ok.headers().get(TO).ok_or("no To")?.clone())
            .header(CALL_ID, invite.get(CALL_ID).ok_or("no Call-ID")?.clone())
            .header(CSEQ, format!("{cseq} {method}").as_str())
            .header("Max-Forwards", "70")
            .body(Bytes::new())?)
    }
}

/// Case 1: two forks answer and the first one's 2xx is retransmitted.
async fn forked_answers(
    uac: &Endpoint,
    target: Target,
) -> Result<(), BoxError> {
    let (mut call, _control, mut responses) =
        Call::start(uac, target, "forked").await?;

    let mut answers = 0;
    // A real UAC reads until Timer M ends the stream. The far side sends
    // three 2xx here, so the example stops after them.
    while answers < 3 {
        let response = responses.next().await.ok_or("stream ended")??;
        println!("uac: {}", response.status());
        if response.status().is_success() {
            answers += 1;
            let created = call.acknowledge(uac, &response).await?;
            if created.is_some_and(|tag| Some(&tag) != call.kept.as_ref()) {
                call.hang_up(uac, &response).await?;
            }
        }
    }
    assert_eq!(call.acks.len(), 2, "two dialogs, one of them ended");
    Ok(())
}

/// Case 2: the call rings and the UAC cancels it.
async fn cancelled(uac: &Endpoint, target: Target) -> Result<(), BoxError> {
    let (_call, control, mut responses) =
        Call::start(uac, target, "cancelled").await?;
    let ringing = responses.next().await.ok_or("stream ended")??;
    println!("uac: {}", ringing.status());

    let (_, mut cancel_responses) =
        cancel(&control).await?.ok_or("nothing was sent")?;

    let status = final_status(&mut responses).await?;
    println!("uac: the INVITE ended with {status}, which signa acknowledged");
    assert_eq!(status, 487);
    let status = final_status(&mut cancel_responses).await?;
    println!("uac: CANCEL got {status}");
    Ok(())
}

/// Case 3: the far side answers before the CANCEL reaches it.
async fn cancel_loses_the_race(
    uac: &Endpoint,
    target: Target,
) -> Result<(), BoxError> {
    let (mut call, control, mut responses) =
        Call::start(uac, target, "race").await?;
    let ringing = responses.next().await.ok_or("stream ended")??;
    println!("uac: {}", ringing.status());

    // The CANCEL goes out, but the INVITE's own stream decides the outcome.
    let cancel = cancel(&control).await?;
    let ok = loop {
        let response = responses.next().await.ok_or("stream ended")??;
        println!("uac: {}", response.status());
        if response.status().is_final() {
            break response;
        }
    };
    assert!(ok.status().is_success(), "the 2xx won");
    if let Some((_, mut cancel)) = cancel {
        println!("uac: CANCEL got {}", final_status(&mut cancel).await?);
    }

    // The 2xx is a dialog the UAC did not want any more, so it acknowledges
    // it and hangs up.
    call.acknowledge(uac, &ok).await?;
    call.hang_up(uac, &ok).await?;
    Ok(())
}

/// Asks to cancel, and returns the CANCEL's transaction if one was sent.
async fn cancel(
    control: &ClientControl,
) -> Result<Option<(ClientControl, Responses)>, BoxError> {
    match control.cancel().await? {
        CancelOutcome::Sent(transaction) => {
            println!("uac: CANCEL sent");
            Ok(Some(transaction.into_parts()))
        }
        CancelOutcome::NotNeeded => {
            println!("uac: a final response came before the CANCEL");
            Ok(None)
        }
        _ => Err("an unknown cancel outcome".into()),
    }
}

/// Reads up to the final response and returns its status.
async fn final_status(responses: &mut Responses) -> Result<u16, BoxError> {
    loop {
        let response = responses.next().await.ok_or("stream ended")??;
        if response.status().is_final() {
            return Ok(response.status().as_u16());
        }
    }
}

// The far side, a scripted forking proxy and its two UASes on one socket.

/// The socket the script runs on.
struct FarSide {
    socket: UdpSocket,
}

impl FarSide {
    async fn bind() -> Result<FarSide, BoxError> {
        Ok(FarSide { socket: UdpSocket::bind("127.0.0.1:0").await? })
    }

    fn run(self) -> Script {
        let addr = self.socket.local_addr().expect("bound");
        Script { addr, handle: tokio::spawn(self.script()) }
    }

    async fn script(self) -> Result<(), BoxError> {
        // Case 1.
        let (invite, uac) = self.expect("INVITE").await?;
        self.send(&respond(&invite, 180, "fork-a", None), uac).await?;
        self.send(&respond(&invite, 183, "fork-b", None), uac).await?;
        let ok_a = respond(&invite, 200, "fork-a", Some(self.contact()));
        self.send(&ok_a, uac).await?;
        self.expect("ACK").await?;
        self.send(&ok_a, uac).await?;
        self.expect("ACK").await?;
        let ok_b = respond(&invite, 200, "fork-b", Some(self.contact()));
        self.send(&ok_b, uac).await?;
        self.expect("ACK").await?;
        let (bye, uac) = self.expect("BYE").await?;
        assert!(header(&bye, TO).contains("fork-b"), "the second fork ends");
        self.send(&respond(&bye, 200, "fork-b", None), uac).await?;

        // Case 2.
        let (invite, uac) = self.expect("INVITE").await?;
        self.send(&respond(&invite, 180, "ring", None), uac).await?;
        let (cancel, uac) = self.expect("CANCEL").await?;
        assert_eq!(header(&cancel, VIA), header(&invite, VIA));
        self.send(&respond(&cancel, 200, "ring", None), uac).await?;
        self.send(&respond(&invite, 487, "ring", None), uac).await?;
        let (ack, _) = self.expect("ACK").await?;
        // signa's ACK for a non-2xx reuses the INVITE's branch.
        assert_eq!(header(&ack, VIA), header(&invite, VIA));

        // Case 3.
        let (invite, uac) = self.expect("INVITE").await?;
        self.send(&respond(&invite, 180, "race", None), uac).await?;
        let (cancel, uac) = self.expect("CANCEL").await?;
        // The 2xx was on its way before the CANCEL arrived.
        let ok = respond(&invite, 200, "race", Some(self.contact()));
        self.send(&ok, uac).await?;
        // The CANCEL matched, but the INVITE had its final. It has no effect
        // beyond its own 200 (RFC 3261 section 9.2).
        self.send(&respond(&cancel, 200, "race", None), uac).await?;
        self.expect("ACK").await?;
        let (bye, uac) = self.expect("BYE").await?;
        self.send(&respond(&bye, 200, "race", None), uac).await?;
        Ok(())
    }

    fn contact(&self) -> String {
        format!("<sip:bob@{}>", self.socket.local_addr().expect("bound"))
    }

    /// Receives requests until one with `method` arrives, and returns it.
    async fn expect(
        &self,
        method: &str,
    ) -> Result<(Request<Bytes>, SocketAddr), BoxError> {
        let mut buf = vec![0; 65536];
        loop {
            let (len, from) = timeout(
                Duration::from_secs(5),
                self.socket.recv_from(&mut buf),
            )
            .await??;
            let request = Request::from_bytes(&buf[..len])?;
            if request.method() == Method::from_bytes(method.as_bytes())? {
                println!("far:  got {method}");
                return Ok((request, from));
            }
            println!("far:  ignored a {}", request.method());
        }
    }

    async fn send(
        &self,
        response: &Response<Bytes>,
        to: SocketAddr,
    ) -> Result<(), BoxError> {
        self.socket.send_to(&response.to_bytes(), to).await?;
        Ok(())
    }
}

/// A running script, and the address the UAC sends to.
struct Script {
    addr: SocketAddr,
    handle: JoinHandle<Result<(), BoxError>>,
}

fn respond(
    request: &Request<Bytes>,
    status: u16,
    tag: &str,
    contact: Option<String>,
) -> Response<Bytes> {
    let mut builder = Response::reply_to(request).status(status).to_tag(tag);
    if let Some(contact) = contact {
        builder = builder.header(CONTACT, contact.as_str());
    }
    builder.body(Bytes::new()).expect("a valid response")
}

fn header(request: &Request<Bytes>, name: HeaderName) -> &str {
    request.headers().get(name).map_or("", HeaderValue::as_str)
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

/// The numeric host and port of a Contact such as `<sip:bob@1.2.3.4:5060>`.
fn contact_address(value: &HeaderValue) -> Option<SocketAddr> {
    let value = value.as_str();
    let uri = &value[value.find('<')? + 1..value.find('>')?];
    let host_port = uri.split_once('@')?.1.split(';').next()?;
    host_port.parse().ok()
}
