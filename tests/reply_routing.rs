/*!
Where a stateful endpoint sends its responses, through the public API only.

A response goes back on the connection or local address its request came in
on ([RFC 3261 section 18.2.2]), which the endpoint keeps in an opaque reply
route instead of working it out from the Via.

[RFC 3261 section 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
*/

use std::time::Duration;

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, Incoming, IncomingEvent, ServerRequest},
    message::header::Tag,
    Request, Response,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

fn options(via: &str, call: &str) -> String {
    format!(
        "OPTIONS sip:bob@example.com SIP/2.0\r\n\
         Via: {via}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag=alice\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {call}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

async fn request(incoming: &mut Incoming) -> ServerRequest {
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    match event.unwrap().unwrap() {
        IncomingEvent::Request(request) => request,
        other => panic!("expected a request, got {other:?}"),
    }
}

fn ok(request: &Request<Bytes>, body: Bytes) -> Response<Bytes> {
    Response::reply_to(request)
        .status(200)
        .to_tag(Tag::random())
        .body(body)
        .unwrap()
}

/// Reads one response off a stream, by its Content-Length.
async fn read_response(stream: &mut TcpStream) -> Response<Bytes> {
    let mut buf = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("a response within two seconds")
            .unwrap();
        assert_ne!(n, 0, "the connection stays open");
        buf.extend_from_slice(&chunk[..n]);
        if let Ok(response) = Response::from_bytes(&buf) {
            return response;
        }
    }
}

// RFC 3261 section 18.2.2. Two connections whose requests advertise the same
// `sent-by` each get their own response. The Via alone cannot tell them
// apart, so the reply route keeps the connection.
#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn two_tcp_connections_with_one_sent_by_get_their_own_responses() {
    let (endpoint, mut incoming) = Endpoint::builder()
        .tcp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let listener = endpoint.tcp_addr().unwrap();
    let mut first = TcpStream::connect(listener).await.unwrap();
    let mut second = TcpStream::connect(listener).await.unwrap();
    let sent_by = "SIP/2.0/TCP client.example.com:5060";

    first
        .write_all(
            options(&format!("{sent_by};branch=z9hG4bK-one"), "one")
                .as_bytes(),
        )
        .await
        .unwrap();
    let one = request(&mut incoming).await;
    second
        .write_all(
            options(&format!("{sent_by};branch=z9hG4bK-two"), "two")
                .as_bytes(),
        )
        .await
        .unwrap();
    let two = request(&mut incoming).await;

    // Answered in the other order, so arrival order cannot explain it.
    for request in [two, one] {
        let (responder, _) = request.transaction.into_parts();
        responder.respond(ok(&request.request, Bytes::new())).await.unwrap();
    }

    let to_first = read_response(&mut first).await;
    let to_second = read_response(&mut second).await;
    assert_eq!(to_first.headers().get("Call-ID").unwrap(), "one");
    assert_eq!(to_second.headers().get("Call-ID").unwrap(), "two");
    let quiet =
        timeout(Duration::from_millis(100), first.read(&mut [0; 1])).await;
    assert!(quiet.is_err(), "nothing more on the first connection");
}

// RFC 3261 section 18.2.2. A response to a UDP request goes back over UDP,
// from the address the request came to, whatever its size. The 1300-byte
// limit of section 18.1.1 is for requests.
#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn a_udp_response_above_1300_bytes_stays_on_udp() {
    let (endpoint, mut incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let server = endpoint.udp_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let via = format!(
        "SIP/2.0/UDP {};branch=z9hG4bK-large;rport",
        client.local_addr().unwrap()
    );

    client.send_to(options(&via, "large").as_bytes(), server).await.unwrap();
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    let body = Bytes::from(vec![b'x'; 3000]);
    responder.respond(ok(&request.request, body.clone())).await.unwrap();

    let mut buf = vec![0; 65536];
    let (n, from) =
        timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(from, server);
    assert!(n > 3000);
    let response = Response::from_bytes(&buf[..n]).unwrap();
    assert_eq!(response.body(), &body);
}
