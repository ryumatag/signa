/*!
Conversion from the bytes of one complete SIP message.

`siparse` parses the head. This module turns its output into a `Request` or
`Response` whose parts share the input `Bytes` instead of copying it, and
picks out the body.
*/

use bytes::Bytes;
use siparse::{
    AnyHead, ErrorKind, Header, HeaderBuf, RequestHead, RequestLine,
    ResponseHead, StartLine, Status, StatusLine,
};

use crate::{
    error::{InvalidMessage, InvalidMessageKind},
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH},
    message::Message,
    method::Method,
    reason::ReasonPhrase,
    request::{self, Request},
    response::{self, Response},
    status::StatusCode,
    uri::Uri,
};

/// The most header rows a message can have.
///
/// The rows live on the stack during parsing. At two `&str` each, 100 rows
/// take about 3 KiB, and hyper uses the same limit for HTTP/1. A configurable
/// limit can come with the transport settings in 0.2.0.
pub(crate) const MAX_HEADERS: usize = 100;

pub(crate) fn request(src: Bytes) -> Result<Request<Bytes>, InvalidMessage> {
    let mut rows = HeaderBuf::<MAX_HEADERS>::new();
    let mut head = RequestHead::new(&mut rows);
    let head_end = head_end(head.parse(&src))?;

    let parts = request_parts(&src, &head.start_line, head.headers)?;
    let body = body(&src, head_end, &parts.headers)?;
    Ok(Request::from_parts(parts, body))
}

pub(crate) fn response(src: Bytes) -> Result<Response<Bytes>, InvalidMessage> {
    let mut rows = HeaderBuf::<MAX_HEADERS>::new();
    let mut head = ResponseHead::new(&mut rows);
    let head_end = head_end(head.parse(&src))?;

    let parts = response_parts(&src, &head.start_line, head.headers)?;
    let body = body(&src, head_end, &parts.headers)?;
    Ok(Response::from_parts(parts, body))
}

pub(crate) fn message(src: Bytes) -> Result<Message<Bytes>, InvalidMessage> {
    let mut rows = HeaderBuf::<MAX_HEADERS>::new();
    let mut head = AnyHead::new(&mut rows);
    let head_end = head_end(head.parse(&src))?;

    match head.start_line.expect(COMPLETE) {
        StartLine::Request(line) => {
            let parts = request_parts(&src, &line, head.headers)?;
            let body = body(&src, head_end, &parts.headers)?;
            Ok(Message::Request(Request::from_parts(parts, body)))
        }
        StartLine::Status(line) => {
            let parts = response_parts(&src, &line, head.headers)?;
            let body = body(&src, head_end, &parts.headers)?;
            Ok(Message::Response(Response::from_parts(parts, body)))
        }
    }
}

// `siparse` fills every start-line field before it reports a complete head.
const COMPLETE: &str = "a complete head has every start-line field";

/// Returns where the head ends, or the error for a head that is invalid or
/// cut short.
///
/// The input is one complete message, so a partial head is an error rather
/// than a request for more bytes.
fn head_end(
    result: Result<Status<usize>, siparse::Error>,
) -> Result<usize, InvalidMessage> {
    let kind = match result {
        Ok(Status::Complete(head_end)) => return Ok(head_end),
        Ok(Status::Partial) => InvalidMessageKind::IncompleteHead,
        Err(err) if err.kind() == ErrorKind::TooManyHeaders => {
            InvalidMessageKind::TooManyHeaders
        }
        Err(err) => InvalidMessageKind::Head(err.kind()),
    };
    Err(InvalidMessage::new(kind))
}

fn request_parts(
    src: &Bytes,
    line: &RequestLine<'_>,
    rows: &[Header<'_>],
) -> Result<request::Parts, InvalidMessage> {
    let method = Method::from_bytes(line.method.expect(COMPLETE).as_bytes())
        .map_err(|_| drifted(ErrorKind::Method))?;
    let uri = Uri::from_parsed(src, line.uri.expect(COMPLETE));

    let mut parts = request::Parts::new(method, uri);
    parts.headers = headers(src, rows)?;
    Ok(parts)
}

fn response_parts(
    src: &Bytes,
    line: &StatusLine<'_>,
    rows: &[Header<'_>],
) -> Result<response::Parts, InvalidMessage> {
    // `siparse` accepts any three digits. `StatusCode` only takes the
    // classes RFC 3261 defines.
    let status =
        StatusCode::from_bytes(line.status_code.expect(COMPLETE).as_bytes())
            .map_err(|_| InvalidMessage::new(InvalidMessageKind::StatusCode))?;
    let reason =
        ReasonPhrase::from_parsed(src, line.reason_phrase.expect(COMPLETE));

    let mut parts = response::Parts::new(status);
    parts.reason = Some(reason);
    parts.headers = headers(src, rows)?;
    Ok(parts)
}

fn headers(
    src: &Bytes,
    rows: &[Header<'_>],
) -> Result<HeaderMap, InvalidMessage> {
    let mut headers = HeaderMap::with_capacity(rows.len());

    for row in rows {
        // `HeaderName` lowercases the name and expands compact forms, so it
        // copies unless the name is a standard one.
        let name = HeaderName::from_parsed(row.name);
        headers.append(name, HeaderValue::from_parsed(src, row.value));
    }

    Ok(headers)
}

// `Method` uses `siparse`'s own check, so it never rejects a parsed method.
// If that ever changed, this reports the method as invalid instead of
// panicking on untrusted input.
fn drifted(kind: ErrorKind) -> InvalidMessage {
    InvalidMessage::new(InvalidMessageKind::Head(kind))
}

/// Returns the body that follows the head.
///
/// Without `Content-Length`, the body is the rest of the input. With it, the
/// body is that many bytes, and anything after them is dropped, as RFC 3261
/// section 18.3 says for datagrams. A `Content-Length` larger than the rest
/// is an error, since the input is the whole message.
fn body(
    src: &Bytes,
    head_end: usize,
    headers: &HeaderMap,
) -> Result<Bytes, InvalidMessage> {
    let rest = src.len() - head_end;
    let len = match content_length(headers)? {
        Some(len) if len > rest => {
            return Err(InvalidMessage::new(InvalidMessageKind::TruncatedBody))
        }
        Some(len) => len,
        None => rest,
    };

    Ok(src.slice(head_end..head_end + len))
}

/// Returns the value of `Content-Length`, or `None` if there is none.
///
/// The field is `1*DIGIT` (RFC 3261 section 20.14). A repeated field is
/// accepted only if every copy has the same value, because a message with
/// two different lengths has no single body.
fn content_length(
    headers: &HeaderMap,
) -> Result<Option<usize>, InvalidMessage> {
    let mut len = None;

    for value in headers.get_all(CONTENT_LENGTH) {
        let this = parse_content_length(value)
            .ok_or(InvalidMessage::new(InvalidMessageKind::ContentLength))?;
        // MSRV(1.70): Write this as `len.is_some_and(|len| len != this)`.
        if matches!(len, Some(len) if len != this) {
            return Err(InvalidMessage::new(
                InvalidMessageKind::ContentLength,
            ));
        }
        len = Some(this);
    }

    Ok(len)
}

fn parse_content_length(value: &HeaderValue) -> Option<usize> {
    // `siparse` keeps trailing whitespace, including a trailing fold.
    let digits = value.as_str().trim_end_matches([' ', '\t', '\r', '\n']);

    // `usize::from_str` also takes a leading `+`, which the grammar does
    // not. It still rejects a value too large for `usize`.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{CALL_ID, VIA};

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
}
