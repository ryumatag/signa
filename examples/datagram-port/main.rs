/*!
A shared datagram port: the application sees every datagram first, and an
endpoint answers only what it is given.

A [`DatagramPort`] owns one UDP socket. One endpoint is registered on it with
[`Builder::bind_on`], and a classifier reads the port's [`Ingress`]. A phone on
the loopback sends an OPTIONS and a REGISTER to the port. The classifier
delivers the OPTIONS to the endpoint, which answers it through its server
transaction, and forwards the REGISTER unchanged to an upstream registrar
along a [`RawPath`]. An [`Observer`] of the port records both arrivals and the
port's writes. The endpoint then shuts down, and the port closes.

Pass `--t1-ms 50` for a quicker run. With RFC 3261's 500 ms T1, the endpoint's
shutdown waits 32 s for Timer J of the OPTIONS it answered.

# What signa does and what the application does

The port's task alone reads the socket. It gives each datagram an ID and a
time as it takes it, and hands it to the application, which decides once what
becomes of it before the port's decision deadline passes:

* [`ReceivedDatagram::try_deliver`] gives it to an endpoint on the port, which
  receives it as from a socket of its own: it fills in `received` and `rport`,
  matches it to a transaction, and answers through the port.
* [`ReceivedDatagram::try_forward`] sends the payload once, byte for byte, with
  no SIP processing. Nothing retransmits it or waits for a response, so a
  forwarded request is the upstream's to answer and the phone's to resend.
* Dropping it, or [`ReceivedDatagram::discard`], drops it.

The application decides by what it parses, and it keeps whatever state that
needs. Here a REGISTER goes upstream and any other request to the endpoint.
A real classifier also has to send a forwarded transaction's responses back,
and keep its CANCEL, ACK and retransmissions on the same side. signa does not
track that for a forward.

The observer is lossy and bounded. It sees what the port received before any
decision, and each write the backend was offered: the endpoint's response,
under the name the endpoint's own records give it, and the raw forward, with
the arrival that caused it.

[`DatagramPort`]: signa::endpoint::port::DatagramPort
[`Builder::bind_on`]: signa::endpoint::Builder::bind_on
[`Ingress`]: signa::endpoint::port::Ingress
[`RawPath`]: signa::endpoint::port::RawPath
[`Observer`]: signa::endpoint::observe::Observer
[`ReceivedDatagram::try_deliver`]: signa::endpoint::port::ReceivedDatagram::try_deliver
[`ReceivedDatagram::try_forward`]: signa::endpoint::port::ReceivedDatagram::try_forward
[`ReceivedDatagram::discard`]: signa::endpoint::port::ReceivedDatagram::discard
*/

use std::{env, error::Error, net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa::{
    Message, Method, Request, Response,
    endpoint::{
        Endpoint, IncomingEvent, PathSelection, ShutdownOutcome,
        observe::{self, Observed, Observer, WriteOrigin},
        port::{DatagramPort, EndpointIngress, Ingress, RawPath},
    },
    message::header::Tag,
    transaction::Timers,
    transport::ReceiveId,
};
use tokio::{net::UdpSocket, time::timeout};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let timers = timers_from_args()?;
    let (port, ingress) =
        DatagramPort::builder().udp("127.0.0.1:0".parse()?).intercept()?;
    let local = port.local_addr();
    // Attached before any traffic, so that it sees all of it. 64 records and
    // the first 16 bytes of each message are plenty here.
    let mut observer =
        port.observe(observe::Config::new().records(64).payload(16)).await?;
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().timers(timers).bind_on(&port)?;

    // The endpoint answers every request it is given with a 200.
    let serving = tokio::spawn(async move {
        while let Some(event) = incoming.recv().await {
            if let IncomingEvent::Request(envelope) = event {
                let (responder, _events) = envelope.transaction.into_parts();
                let ok = Response::reply_to(&envelope.request)
                    .status(200)
                    .to_tag(Tag::random())
                    .body(Bytes::new())
                    .expect("a valid response");
                if let Err(error) = responder.respond(ok).await {
                    println!("endpoint: 200 not accepted: {error}");
                }
            }
        }
    });

    let upstream = UdpSocket::bind("127.0.0.1:0").await?;
    let to_upstream =
        port.prepare_path(PathSelection::new(local, upstream.local_addr()?));
    let classifying =
        tokio::spawn(classify(ingress, to_endpoint, to_upstream.await?));

    let phone = UdpSocket::bind("127.0.0.1:0").await?;
    let options = request("OPTIONS", phone.local_addr()?, local)?;
    let register = request("REGISTER", phone.local_addr()?, local)?;
    phone.send_to(&options, local).await?;
    phone.send_to(&register, local).await?;

    // The endpoint's 200 comes back to the phone through the port, and the
    // REGISTER reaches the registrar as the phone sent it.
    let answer = receive(&phone).await?;
    let status = Response::from_bytes(&answer)?.status();
    println!("phone: {status} for the OPTIONS");
    assert_eq!(status.as_u16(), 200);
    let forwarded = receive(&upstream).await?;
    println!("registrar: {} bytes, unchanged", forwarded.len());
    assert_eq!(forwarded, register);

    check_records(&mut observer).await?;
    let stats = port.stats();
    println!(
        "port: {} received, {} delivered, {} forwarded",
        stats.received, stats.delivered, stats.forwarded
    );
    assert_eq!((stats.received, stats.delivered, stats.forwarded), (2, 1, 1));

    // Stopping goes endpoint first, then the port, which waits for nothing
    // the endpoint still owes. The drain waits for Timer J over UDP.
    let outcome = endpoint.shutdown(Duration::from_secs(40)).await;
    println!("endpoint: shutdown {outcome:?}");
    assert_eq!(outcome, ShutdownOutcome::Drained);
    serving.await?;
    let outcome = port.close(Duration::from_secs(5)).await;
    println!("port: close {outcome:?}");
    assert_eq!(outcome, ShutdownOutcome::Drained);
    // The ingress ends with the close, and the classifier with it.
    classifying.await?;
    Ok(())
}

/// Delivers every request but a REGISTER to the endpoint, forwards the
/// REGISTERs upstream, and drops whatever does not parse as a request.
async fn classify(
    mut ingress: Ingress,
    to_endpoint: EndpointIngress,
    upstream: RawPath,
) {
    while let Some(datagram) = ingress.recv().await {
        let method = match datagram.parse() {
            Ok(Message::Request(request)) => request.method().clone(),
            Ok(Message::Response(_)) | Err(_) => {
                datagram.discard();
                continue;
            }
        };
        let id = datagram.received().id();
        if method == Method::REGISTER {
            match datagram.try_forward(&upstream) {
                // The write's outcome is local: written, not received.
                Ok(write) => match write.await {
                    Ok(()) => println!("classifier: forwarded {id}"),
                    Err(error) => println!("classifier: {id} lost: {error}"),
                },
                Err(refused) => {
                    println!("classifier: {id} not forwarded: {refused}")
                }
            }
        } else if let Err(refused) = datagram.try_deliver(&to_endpoint) {
            println!("classifier: {id} not delivered: {refused}");
        } else {
            println!("classifier: delivered {id}");
        }
    }
}

/// Reads the port's records until it has seen both arrivals, the endpoint's
/// 200 reaching the backend, and the forward of the REGISTER, named by the
/// REGISTER's own arrival.
async fn check_records(observer: &mut Observer) -> Result<(), BoxError> {
    let mut register: Option<ReceiveId> = None;
    let mut forward: Option<ReceiveId> = None;
    let (mut arrivals, mut response) = (0, false);
    while arrivals < 2 || !response || forward.is_none() {
        let record = timeout(Duration::from_secs(5), observer.recv())
            .await?
            .ok_or("the observer ended early")?;
        match record.observed() {
            Observed::Received { id, .. } => {
                arrivals += 1;
                let head = record.payload().map_or(&b""[..], |p| p.as_ref());
                if head.starts_with(b"REGISTER") {
                    register = Some(*id);
                }
                println!(
                    "observer: {id} arrived, {} bytes",
                    record.message_len()
                );
            }
            Observed::WriteStarted { origin, cause, .. } => match origin {
                WriteOrigin::Endpoint { write, .. } => {
                    let (domain, number) = (write.domain(), write.number());
                    println!(
                        "observer: the endpoint's write {domain}:{number}"
                    );
                    response = true;
                }
                WriteOrigin::Raw => {
                    let cause = cause.ok_or("a forward names its arrival")?;
                    println!("observer: a raw write for {cause}");
                    forward = Some(cause);
                }
                other => println!("observer: {other:?}"),
            },
            _ => {}
        }
    }
    assert!(register.is_some());
    assert_eq!(forward, register);
    Ok(())
}

/// A request from `phone` to `port`, encoded as the phone would send it.
fn request(
    method: &str,
    phone: SocketAddr,
    port: SocketAddr,
) -> Result<Bytes, BoxError> {
    let via = format!("SIP/2.0/UDP {phone};branch=z9hG4bK{method}");
    let request = Request::builder()
        .method(method)
        .uri(format!("sip:{port}").as_str())
        .header("Via", via.as_str())
        .header("Max-Forwards", "70")
        .header("From", "<sip:alice@127.0.0.1>;tag=phone")
        .header("To", "<sip:alice@127.0.0.1>")
        .header("Call-ID", format!("datagram-port-{method}").as_str())
        .header("CSeq", format!("1 {method}").as_str())
        .body(Bytes::new())?;
    Ok(request.to_bytes())
}

/// The next datagram `socket` receives, within five seconds.
async fn receive(socket: &UdpSocket) -> Result<Bytes, BoxError> {
    let mut buffer = vec![0; 65_535];
    let (len, _) =
        timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
            .await??;
    buffer.truncate(len);
    Ok(Bytes::from(buffer))
}

/// RFC 3261's timers, or T1 from `--t1-ms` with T2 and T4 scaled alike.
fn timers_from_args() -> Result<Timers, BoxError> {
    let mut args = env::args().skip(1);
    let Some(flag) = args.next() else { return Ok(Timers::default()) };
    let ms: u64 = match (flag.as_str(), args.next()) {
        ("--t1-ms", Some(ms)) => ms.parse()?,
        _ => return Err("usage: datagram-port [--t1-ms MS]".into()),
    };
    Ok(Timers::builder()
        .t1(Duration::from_millis(ms))
        .t2(Duration::from_millis(ms * 8))
        .t4(Duration::from_millis(ms * 10))
        .build()?)
}
