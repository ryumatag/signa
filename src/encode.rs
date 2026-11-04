/*!
Conversion from messages to the bytes of one complete SIP message.

Every part of a message was checked when it was built or parsed, so writing
it out cannot fail.
*/

use bytes::{BufMut, BytesMut};

use crate::{
    header::{HeaderMap, CONTENT_LENGTH},
    request::Request,
    response::Response,
};

pub(crate) fn request<T: AsRef<[u8]>>(
    request: &Request<T>,
    dst: &mut BytesMut,
) {
    let method = request.method().as_str();
    let uri = request.uri().as_str();
    let version = request.version();
    let version = version.as_str();
    let body = request.body().as_ref();

    // `METHOD SP URI SP VERSION CRLF`
    let line_len = method.len() + uri.len() + version.len() + 4;
    let len = line_len + head_fields_len(request.headers(), body) + body.len();
    let start = dst.len();
    dst.reserve(len);

    dst.put_slice(method.as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(uri.as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(version.as_bytes());
    dst.put_slice(b"\r\n");

    fields_and_body(request.headers(), body, dst);
    debug_assert_eq!(dst.len() - start, len, "reserved length is off");
}

pub(crate) fn response<T: AsRef<[u8]>>(
    response: &Response<T>,
    dst: &mut BytesMut,
) {
    let version = response.version();
    let version = version.as_str();
    let status = response.status();
    // Without a reason of its own, a response uses the one RFC 3261 or the
    // IANA registry gives its code. An extension code with neither gets an
    // empty reason, which the status-line grammar allows.
    let reason = match response.reason() {
        Some(reason) => reason.as_str(),
        None => status.canonical_reason().unwrap_or(""),
    };
    let body = response.body().as_ref();

    // `VERSION SP CODE SP REASON CRLF`, where the code is three digits.
    let line_len = version.len() + reason.len() + 7;
    let len =
        line_len + head_fields_len(response.headers(), body) + body.len();
    let start = dst.len();
    dst.reserve(len);

    dst.put_slice(version.as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(status.as_str().as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(reason.as_bytes());
    dst.put_slice(b"\r\n");

    fields_and_body(response.headers(), body, dst);
    debug_assert_eq!(dst.len() - start, len, "reserved length is off");
}

/// Returns the length of the header fields, the `Content-Length` field, and
/// the empty line, so the whole message can be reserved at once.
fn head_fields_len(headers: &HeaderMap, body: &[u8]) -> usize {
    let fields: usize = headers
        .iter()
        .filter(|(name, _)| **name != CONTENT_LENGTH)
        // `NAME: VALUE CRLF`
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    let content_length =
        "Content-Length: \r\n".len() + Digits::new(body.len()).len();

    fields + content_length + 2
}

/// Writes the header fields, the empty line, and the body.
///
/// `Content-Length` always comes from the body. Any `Content-Length` rows in
/// the map are skipped, so the length on the wire cannot disagree with the
/// body. RFC 3261 section 20.14 requires the field on stream transports, and
/// it does no harm on datagrams.
fn fields_and_body(headers: &HeaderMap, body: &[u8], dst: &mut BytesMut) {
    for (name, value) in headers {
        if *name == CONTENT_LENGTH {
            continue;
        }
        dst.put_slice(name.as_str().as_bytes());
        dst.put_slice(b": ");
        // The value is written as stored, folds included.
        dst.put_slice(value.as_bytes());
        dst.put_slice(b"\r\n");
    }

    dst.put_slice(b"Content-Length: ");
    dst.put_slice(Digits::new(body.len()).as_bytes());
    dst.put_slice(b"\r\n\r\n");
    dst.put_slice(body);
}

/// The decimal digits of a `usize`, formatted on the stack.
struct Digits {
    buf: [u8; 20],
    start: usize,
}

impl Digits {
    fn new(mut n: usize) -> Digits {
        // `usize::MAX` has at most 20 decimal digits.
        let mut buf = [0; 20];
        let mut start = buf.len();
        loop {
            start -= 1;
            buf[start] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        Digits { buf, start }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn len(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{message::Message, ReasonPhrase, StatusCode};

    #[test]
    fn encodes_a_request() {
        let request = Request::builder()
            .method("MESSAGE")
            .uri("sip:bob@biloxi.example.com")
            .header(
                "Via",
                "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds",
            )
            .header("X-Custom", "one")
            .header("i", "a84b4c76e66710")
            .body(Bytes::from_static(b"hello"))
            .unwrap();

        assert_eq!(
            request.to_bytes(),
            &b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
               Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
               x-custom: one\r\n\
               Call-ID: a84b4c76e66710\r\n\
               Content-Length: 5\r\n\
               \r\n\
               hello"[..]
        );
    }

    #[test]
    fn encodes_a_response_with_its_canonical_reason() {
        let response = Response::builder()
            .status(StatusCode::RINGING)
            .body(Bytes::new())
            .unwrap();

        assert_eq!(
            response.to_bytes(),
            &b"SIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n"[..]
        );
    }

    #[test]
    fn keeps_a_reason_of_its_own_or_none_at_all() {
        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .reason("Maintenance until 05:00")
            .body(Bytes::new())
            .unwrap();
        assert!(response
            .to_bytes()
            .starts_with(b"SIP/2.0 503 Maintenance until 05:00\r\n"));

        // An extension code has no canonical reason.
        let response =
            Response::builder().status(299).body(Bytes::new()).unwrap();
        assert!(response.to_bytes().starts_with(b"SIP/2.0 299 \r\n"));
    }

    #[test]
    fn content_length_always_matches_the_body() {
        let request = Request::builder()
            .method("MESSAGE")
            .uri("sip:bob@biloxi.example.com")
            .header("Content-Length", "99")
            .header("l", "1")
            .body(b"hello".to_vec())
            .unwrap();

        let bytes = request.to_bytes();
        let lengths: Vec<_> = bytes
            .split(|&b| b == b'\n')
            .filter(|line| {
                line.to_ascii_lowercase().starts_with(b"content-length")
            })
            .collect();
        assert_eq!(lengths, [&b"Content-Length: 5\r"[..]]);
    }

    #[test]
    fn encode_appends_to_the_buffer() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::new())
            .unwrap();

        let mut dst = BytesMut::from(&b"keep"[..]);
        response.encode(&mut dst);
        assert_eq!(
            dst,
            &b"keepSIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"[..]
        );
    }

    #[test]
    fn round_trips_a_received_message() {
        let src: &[u8] = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
            Max-Forwards: 70\r\n\
            To: Bob <sip:bob@biloxi.example.com>\r\n\
            From: \"Alice\\\x01\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
            Subject: lunch\r\n \tplans\r\n\
            Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
            CSeq: 314159 INVITE\r\n\
            Content-Length: 4\r\n\
            \r\n\
            v=0\n";

        let Message::Request(request) = Message::from_bytes(src).unwrap()
        else {
            panic!("expected a request");
        };
        // The names are already in canonical form, so the bytes come back
        // unchanged.
        assert_eq!(request.to_bytes(), src);

        let again = Request::from_shared(request.to_bytes()).unwrap();
        assert_eq!(again.method(), request.method());
        assert_eq!(again.uri().as_str(), request.uri().as_str());
        assert!(again.headers().iter().eq(request.headers().iter()));
        assert_eq!(again.body(), request.body());
    }

    #[test]
    fn round_trips_a_response_through_message() {
        let mut response = Response::builder()
            .status(StatusCode::BUSY_HERE)
            .header("Call-ID", "a84b4c76e66710")
            .body(Bytes::from_static(b"busy"))
            .unwrap();
        *response.reason_mut() =
            Some(ReasonPhrase::from_static("Busy %22now%22"));

        let message = Message::Response(response);
        let Message::Response(again) =
            Message::from_shared(message.to_bytes()).unwrap()
        else {
            panic!("expected a response");
        };
        assert_eq!(again.reason().unwrap().as_str(), "Busy %22now%22");
        assert_eq!(again.body(), "busy");
    }

    #[test]
    fn digits() {
        for n in [0, 7, 10, 4096, usize::MAX] {
            let digits = Digits::new(n);
            assert_eq!(digits.as_bytes(), n.to_string().as_bytes());
            assert_eq!(digits.len(), n.to_string().len());
        }
    }
}
