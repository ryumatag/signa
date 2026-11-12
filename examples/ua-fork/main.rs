/*!
A call that a forking proxy sends to two phones, through signa-ua.

The caller is a UA. The other side is a plain UDP socket that plays a proxy
and the two phones behind it: it answers the INVITE with a 180 from the first
phone, and a 2xx from each, as a forking proxy passes them on (RFC 3261
section 13.2.2.4). Each 2xx forms a dialog of its own.

* The caller's UA acknowledges each 2xx itself, as RFC 3261 has the UAC
  core do, without the application.
* The application learns of each session from a `Confirmed` event. It keeps
  the first and ends the other with a BYE, as a phone that took the call
  from one place would.
* Once the INVITE's transaction stops collecting responses, the attempt
  ends, and its event lists the sessions still up.

The example checks each step and fails otherwise. Pass `--t1-ms 50` for a
quicker run. The default is RFC 3261's T1 of 500 ms, and the attempt ends at
64 T1 after the first 2xx, so the run takes about 40 s.
*/

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa::{
    HeaderValue, Request, Response,
    endpoint::Endpoint,
    transaction::Timers,
    ua::{
        AttemptResult, Config, Description, Event, InvitePlan, ShutdownMode,
        ShutdownOutcome, Ua, UaEvents, attach,
    },
};
use tokio::{net::UdpSocket, time::timeout};

#[tokio::main]
async fn main() {
    let timers = timers();
    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .timers(timers)
        .bind()
        .unwrap();
    let address = endpoint.udp_addr().unwrap();
    let config =
        Config::new(&format!("sip:caller@{address}")).unwrap().timers(timers);
    let Ua { handle, mut events, driver } =
        attach(endpoint, incoming, config).unwrap();
    let driver = tokio::spawn(driver);
    let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let forking = tokio::spawn(fork(proxy));

    let plan = InvitePlan::new(
        format!("sip:bob@{proxy_address}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
        sdp(OFFER),
    );
    let attempt = handle.try_invite(plan).unwrap().await.unwrap();
    let mut sessions = Vec::new();
    while sessions.len() < 2 {
        sessions.push(
            next(&mut events, |event| match event {
                Event::Confirmed { session, .. } => Some(session),
                _ => None,
            })
            .await,
        );
    }
    println!("caller: two phones answered");
    handle.try_terminate(&sessions[1]).unwrap().await.unwrap();
    println!("caller: kept the first, hung up on the second");

    let (result, up) =
        next(&mut events, |event| match event {
            Event::AttemptEnded {
                attempt: ended, result, sessions, ..
            } if ended == attempt.id() => Some((result, sessions)),
            _ => None,
        })
        .await;
    assert_eq!(result, AttemptResult::Answered);
    assert_eq!(up, [sessions[0].clone()]);
    println!("caller: the attempt ended with one session up");

    handle.try_terminate(&sessions[0]).unwrap().await.unwrap();
    let (mut acks, byes) = timeout(LIMIT, forking)
        .await
        .expect("each phone gets its ACK and BYE in time")
        .unwrap();
    // The ACKs go out as separate jobs, in either order.
    acks.sort();
    assert_eq!(acks, ["phone-a", "phone-b"]);
    assert_eq!(byes, ["phone-b", "phone-a"]);
    println!("caller: hung up, each phone got its ACK and its BYE");

    let report =
        handle.shutdown(ShutdownMode::DrainExisting, LIMIT).await.unwrap();
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    println!("caller: shut down");
    driver.await.unwrap();
}

/// Plays the forking proxy and its two phones until each phone has got an
/// ACK and a BYE, and returns the To tags they came to, in order. Copies of
/// a request that cross a response are answered and not counted again.
async fn fork(socket: UdpSocket) -> (Vec<String>, Vec<String>) {
    let address = socket.local_addr().unwrap();
    let (mut acks, mut byes) = (Vec::new(), Vec::new());
    let mut buffer = vec![0; 65_536];
    while acks.len() < 2 || byes.len() < 2 {
        let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
        let request = Request::from_bytes(&buffer[..n]).unwrap();
        let tag = to_tag(&request);
        match request.method().as_str() {
            "INVITE" => {
                send(&socket, from, reply(&request, 180, "phone-a", address))
                    .await;
                for phone in ["phone-a", "phone-b"] {
                    let ok = reply(&request, 200, phone, address)
                        .header("Content-Type", "application/sdp")
                        .body(Bytes::from_static(ANSWER))
                        .unwrap();
                    send_response(&socket, from, ok).await;
                }
            }
            "ACK" => {
                if !acks.contains(&tag) {
                    acks.push(tag);
                }
            }
            "BYE" => {
                let ok = Response::reply_to(&request)
                    .status(200)
                    .body(Bytes::new())
                    .unwrap();
                send_response(&socket, from, ok).await;
                if !byes.contains(&tag) {
                    byes.push(tag);
                }
            }
            method => panic!("the proxy got a {method}"),
        }
    }
    (acks, byes)
}

/// A response of the phone `phone` to `request`, with the phone's Contact.
fn reply(
    request: &Request<Bytes>,
    status: u16,
    phone: &str,
    address: SocketAddr,
) -> signa::message::response::Builder {
    Response::reply_to(request)
        .status(status)
        .to_tag(phone)
        .header("Contact", format!("<sip:{phone}@{address}>").as_str())
}

async fn send(
    socket: &UdpSocket,
    to: SocketAddr,
    response: signa::message::response::Builder,
) {
    send_response(socket, to, response.body(Bytes::new()).unwrap()).await;
}

async fn send_response(
    socket: &UdpSocket,
    to: SocketAddr,
    response: Response<Bytes>,
) {
    socket.send_to(&response.to_bytes(), to).await.unwrap();
}

/// The tag of the To of `request`, which names the phone it is for.
fn to_tag(request: &Request<Bytes>) -> String {
    let to = request.headers().get("To").unwrap().as_str();
    to.split(";tag=").nth(1).unwrap_or_default().to_owned()
}

/// How long the proxy's exchanges and the shutdown may each take: past
/// every timer of RFC 3261's T1.
const LIMIT: Duration = Duration::from_secs(60);

const OFFER: &[u8] = b"v=0\r\no=caller 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=phone 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40002 RTP/AVP 0\r\n";

fn sdp(body: &'static [u8]) -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(body),
    )
}

/// The next event for which `wanted` gives something. The attempt ends at
/// 64 T1, which is 32 s with RFC 3261's T1.
async fn next<T>(
    events: &mut UaEvents,
    wanted: impl Fn(Event) -> Option<T>,
) -> T {
    loop {
        let event = timeout(Duration::from_secs(60), events.recv())
            .await
            .expect("an event in time")
            .expect("the UA runs");
        // The queues here never fill, so a lost event is a failure.
        if let Event::Lagged { missed, .. } = event {
            panic!("{missed} events were lost");
        }
        if let Some(found) = wanted(event) {
            return found;
        }
    }
}

/// RFC 3261's timers, or those of the T1 that `--t1-ms` gives.
fn timers() -> Timers {
    let mut args = std::env::args().skip(1);
    let mut builder = Timers::builder();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--t1-ms" => {
                let ms = args.next().and_then(|ms| ms.parse().ok());
                let t1 = Duration::from_millis(ms.expect("--t1-ms takes ms"));
                builder = builder.t1(t1).t2(t1 * 8).t4(t1 * 10);
            }
            other => panic!("unknown argument {other}"),
        }
    }
    builder.build().unwrap()
}
