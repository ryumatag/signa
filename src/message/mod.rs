/*!
SIP message representation, construction, parsing, and encoding.

[`Request`] and [`Response`] have opaque, generic bodies. [`Message`] holds
either kind. Their fields, builders and errors live in this namespace, while
socket I/O and transaction lifetimes belong to the higher protocol layers.

The crate root also exposes the principal message types. Use [`request`],
[`response`] and [`header`] for parts, builders, header constants and iterators.
[`BuildError`] reports construction failures. Parsing received bytes reports
[`error::InvalidMessage`] instead.

Value implementation modules are private. Use [`Method`] rather than its
implementation path. The following cannot compile because `method` is private:

```compile_fail
use signa::message::method::Method;
```
*/

pub use self::{
    error::BuildError,
    extensions::Extensions,
    header::{HeaderMap, HeaderName, HeaderValue},
    request::Request,
    response::Response,
    start_line::{Method, ReasonPhrase, StatusCode, Uri, Version},
};

mod byte_str;
mod encode;
pub mod error;
mod extensions;
pub mod header;
pub(crate) mod parse;
pub mod request;
pub mod response;
mod start_line;

use bytes::{Bytes, BytesMut};

use self::error::InvalidMessage;

/// A SIP request or response.
///
/// UDP sockets and TCP connections carry both kinds, so a received message may
/// be either. [`Message::from_shared`] parses the head once and decides from
/// its start-line.
///
/// # Example
///
/// ```
/// use bytes::Bytes;
/// use signa::{Message, StatusCode};
///
/// let datagram = Bytes::from_static(b"SIP/2.0 180 Ringing\r\n\r\n");
///
/// match Message::from_shared(datagram)? {
///     Message::Request(request) => println!("request {}", request.method()),
///     Message::Response(response) => {
///         assert_eq!(response.status(), StatusCode::RINGING);
///     }
/// }
/// # Ok::<(), signa::message::error::InvalidMessage>(())
/// ```
#[derive(Clone, Debug)]
pub enum Message<T> {
    /// A request.
    Request(Request<T>),
    /// A response.
    Response(Response<T>),
}

impl Message<Bytes> {
    /// Parses a request or response from the bytes of one complete message,
    /// copying them.
    ///
    /// This is [`Message::from_shared`] on a copy of `src`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Message::from_shared`].
    pub fn from_bytes(src: &[u8]) -> Result<Message<Bytes>, InvalidMessage> {
        Message::from_shared(Bytes::copy_from_slice(src))
    }

    /// Parses a request or response from the bytes of one complete message
    /// without copying them.
    ///
    /// A start-line that begins with `SIP/` is a status-line, and anything
    /// else is a request-line. The message is then parsed like
    /// [`Request::from_shared`] or [`Response::from_shared`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Request::from_shared`] or [`Response::from_shared`], whichever
    /// matches the start-line.
    pub fn from_shared(src: Bytes) -> Result<Message<Bytes>, InvalidMessage> {
        crate::message::parse::message(src)
    }
}

impl<T: AsRef<[u8]>> Message<T> {
    /// Writes the message to the end of `dst`.
    ///
    /// This is [`Request::encode`] or [`Response::encode`], whichever the
    /// message holds.
    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Message::Request(request) => request.encode(dst),
            Message::Response(response) => response.encode(dst),
        }
    }

    /// Returns the message as bytes.
    ///
    /// This is [`Message::encode`] into a new buffer.
    pub fn to_bytes(&self) -> Bytes {
        let mut dst = BytesMut::new();
        self.encode(&mut dst);
        dst.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        error::{InvalidMessage, InvalidMessageKind},
        header::{CALL_ID, VIA},
        parse::MAX_HEADERS,
    };
    use siparse::ErrorKind;

    const OPTIONS: &[u8] = b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
        i: a84b4c76e66710\r\n\
        X-Custom: one\r\n\
        x-custom: two\r\n\
        Content-Length: 4\r\n\
        \r\n\
        body";

    const RINGING: &[u8] = b"SIP/2.0 180 Ringing\r\n\
        Call-ID: a84b4c76e66710\r\n\
        \r\n";

    fn kind(err: InvalidMessage) -> InvalidMessageKind {
        err.kind()
    }

    #[test]
    fn parses_a_request() {
        let request = Request::from_bytes(OPTIONS).unwrap();

        assert_eq!(request.method(), Method::OPTIONS);
        assert_eq!(request.uri().as_str(), "sip:carol@chicago.example.com");
        assert_eq!(
            request.headers().get(VIA).unwrap(),
            "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877"
        );
        // The compact form `i` is `Call-ID`.
        assert_eq!(request.headers().get(CALL_ID).unwrap(), "a84b4c76e66710");

        let custom: Vec<_> = request.headers().get_all("x-custom").collect();
        assert_eq!(custom, ["one", "two"]);
        assert_eq!(request.body(), "body");
    }

    #[test]
    fn parses_a_response() {
        let response = Response::from_bytes(RINGING).unwrap();

        assert_eq!(response.status(), StatusCode::RINGING);
        assert_eq!(response.reason().unwrap().as_str(), "Ringing");
        assert_eq!(response.headers().get(CALL_ID).unwrap(), "a84b4c76e66710");
        assert!(response.body().is_empty());
    }

    #[test]
    fn keeps_an_empty_reason_phrase() {
        let response = Response::from_bytes(b"SIP/2.0 200 \r\n\r\n").unwrap();

        assert_eq!(response.reason().unwrap().as_str(), "");
    }

    #[test]
    fn parses_either_kind_as_a_message() {
        let Message::Request(request) = Message::from_bytes(OPTIONS).unwrap()
        else {
            panic!("expected a request");
        };
        assert_eq!(request.method(), Method::OPTIONS);

        let Message::Response(response) =
            Message::from_bytes(RINGING).unwrap()
        else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::RINGING);
    }

    #[test]
    fn shares_the_input_instead_of_copying() {
        let src = Bytes::from_static(OPTIONS);
        let range = src.as_ptr_range();
        let within = |bytes: &[u8]| range.contains(&bytes.as_ptr());

        let request = Request::from_shared(src.clone()).unwrap();

        assert!(within(request.uri().as_str().as_bytes()));
        assert!(within(request.headers().get(VIA).unwrap().as_bytes()));
        assert!(within(request.body()));
    }

    #[test]
    fn body_without_content_length_is_the_rest() {
        let request = Request::from_bytes(
            b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\r\nhello",
        )
        .unwrap();

        assert_eq!(request.body(), "hello");
    }

    #[test]
    fn content_length_cuts_off_trailing_bytes() {
        let request = Request::from_bytes(
            b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
              l: 3 \r\n\
              \r\n\
              hello",
        )
        .unwrap();

        assert_eq!(request.body(), "hel");
    }

    #[test]
    fn rejects_a_body_shorter_than_content_length() {
        let err = Request::from_bytes(
            b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
              Content-Length: 6\r\n\
              \r\n\
              hello",
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "SIP message body shorter than Content-Length"
        );
    }

    #[test]
    fn content_length_must_be_digits() {
        for value in ["", "+5", "-1", "5 5", "0x5", "99999999999999999999999"]
        {
            let mut src = b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
                Content-Length: "
                .to_vec();
            src.extend_from_slice(value.as_bytes());
            src.extend_from_slice(b"\r\n\r\n");

            let err = Request::from_bytes(&src).unwrap_err();
            assert_eq!(
                kind(err),
                InvalidMessageKind::ContentLength,
                "{value:?}"
            );
        }
    }

    #[test]
    fn repeated_content_length_must_agree() {
        let request = Request::from_bytes(
            b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
              Content-Length: 2\r\n\
              l: 2\r\n\
              \r\n\
              hi",
        )
        .unwrap();
        assert_eq!(request.body(), "hi");

        let err = Request::from_bytes(
            b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
              Content-Length: 2\r\n\
              Content-Length: 1\r\n\
              \r\n\
              hi",
        )
        .unwrap_err();
        assert_eq!(kind(err), InvalidMessageKind::ContentLength);
    }

    #[test]
    fn rejects_an_incomplete_head() {
        let err = Request::from_bytes(&OPTIONS[..40]).unwrap_err();

        assert_eq!(kind(err), InvalidMessageKind::IncompleteHead);
        assert_eq!(
            Request::from_bytes(b"").unwrap_err().to_string(),
            "incomplete SIP message head"
        );
    }

    #[test]
    fn reports_what_siparse_rejected() {
        let err = Request::from_bytes(
            b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
              Call ID: a84b4c76e66710\r\n\
              \r\n",
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "missing colon after SIP header name");

        // A request-line parser sees a status-line as a bad method.
        let err = Request::from_bytes(RINGING).unwrap_err();
        assert_eq!(kind(err), InvalidMessageKind::Head(ErrorKind::Method));

        let err = Response::from_bytes(OPTIONS).unwrap_err();
        assert_eq!(kind(err), InvalidMessageKind::Head(ErrorKind::Version));
    }

    #[test]
    fn rejects_status_codes_outside_the_sip_classes() {
        for code in ["000", "099", "700", "999"] {
            let src = format!("SIP/2.0 {code} Odd\r\n\r\n");
            let err = Response::from_bytes(src.as_bytes()).unwrap_err();
            assert_eq!(kind(err), InvalidMessageKind::StatusCode, "{code}");
        }
    }

    #[test]
    fn limits_the_number_of_header_rows() {
        let head = |rows: usize| {
            let mut src =
                b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n".to_vec();
            for _ in 0..rows {
                src.extend_from_slice(b"X-Row: 1\r\n");
            }
            src.extend_from_slice(b"\r\n");
            src
        };

        let request = Request::from_bytes(&head(MAX_HEADERS)).unwrap();
        assert_eq!(request.headers().len(), MAX_HEADERS);

        let err = Request::from_bytes(&head(MAX_HEADERS + 1)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "more than 100 header fields in SIP message"
        );
    }

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
}
