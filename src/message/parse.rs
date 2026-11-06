/*!
Conversion from the bytes of a SIP message.

siparse parses the head. This module turns its output into a `Request` or
`Response` whose parts share the input `Bytes` instead of copying it, and picks
out the body. The public `from_shared` functions take one complete message,
such as a datagram. The stream decoder in `frame` parses the head on its own
through [`head`] and supplies the body once it has arrived.
*/

use bytes::Bytes;
use siparse::{
    AnyHead, ErrorKind, Header, HeaderBuf, RequestHead, RequestLine,
    ResponseHead, StartLine, Status, StatusLine,
};

use crate::message::{
    error::{InvalidMessage, InvalidMessageKind},
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH},
    request::{self, Request},
    response::{self, Response},
    Message, Method, ReasonPhrase, StatusCode, Uri,
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

// This repeats `head` instead of calling it, because building the message
// from a `Head` moved through `Status` measured about ~5% slower on
// `parse/message/typical`.
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

/// The parts of a request or response whose head has been parsed, before its
/// body is known.
#[derive(Debug)]
#[cfg(any(feature = "tokio", feature = "__bench", test))]
pub(crate) enum Head {
    Request(request::Parts),
    Response(response::Parts),
}

#[cfg(any(feature = "tokio", feature = "__bench", test))]
impl Head {
    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Head::Request(parts) => &parts.headers,
            Head::Response(parts) => &parts.headers,
        }
    }

    pub(crate) fn into_message(self, body: Bytes) -> Message<Bytes> {
        match self {
            Head::Request(parts) => {
                Message::Request(Request::from_parts(parts, body))
            }
            Head::Response(parts) => {
                Message::Response(Response::from_parts(parts, body))
            }
        }
    }
}

/// Parses the head at the start of `src` into the parts of a request or
/// response, deciding which from the start-line.
///
/// On `Complete`, the parts share `src`, and the offset is where the head
/// ends, so the body starts there. `Partial` means `src` ends before the head
/// does.
#[cfg(any(feature = "tokio", feature = "__bench", test))]
pub(crate) fn head(
    src: &Bytes,
) -> Result<Status<(Head, usize)>, InvalidMessage> {
    let mut rows = HeaderBuf::<MAX_HEADERS>::new();
    let mut head = AnyHead::new(&mut rows);
    let head_end = match head.parse(src) {
        Ok(Status::Complete(head_end)) => head_end,
        Ok(Status::Partial) => return Ok(Status::Partial),
        Err(err) => return Err(head_error(err)),
    };

    let head = match head.start_line.expect(COMPLETE) {
        StartLine::Request(line) => {
            Head::Request(request_parts(src, &line, head.headers)?)
        }
        StartLine::Status(line) => {
            Head::Response(response_parts(src, &line, head.headers)?)
        }
    };
    Ok(Status::Complete((head, head_end)))
}

// siparse fills every start-line field before it reports a complete head.
const COMPLETE: &str = "a complete head has every start-line field";

/// Returns where the head ends, or the error for a head that is invalid or cut
/// short.
///
/// The input is one complete message, so a partial head is an error rather
/// than a request for more bytes.
fn head_end(
    result: Result<Status<usize>, siparse::Error>,
) -> Result<usize, InvalidMessage> {
    match result {
        Ok(Status::Complete(head_end)) => Ok(head_end),
        Ok(Status::Partial) => {
            Err(InvalidMessage::new(InvalidMessageKind::IncompleteHead))
        }
        Err(err) => Err(head_error(err)),
    }
}

fn head_error(err: siparse::Error) -> InvalidMessage {
    let kind = if err.kind() == ErrorKind::TooManyHeaders {
        InvalidMessageKind::TooManyHeaders
    } else {
        InvalidMessageKind::Head(err.kind())
    };
    InvalidMessage::new(kind)
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
    // siparse accepts any three digits. `StatusCode` only takes the classes
    // RFC 3261 defines.
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

// `Method` uses siparse's own check, so it never rejects a parsed method.
// If that ever changed, this reports the method as invalid instead of
// panicking on untrusted input.
fn drifted(kind: ErrorKind) -> InvalidMessage {
    InvalidMessage::new(InvalidMessageKind::Head(kind))
}

/// Returns the body that follows the head.
///
/// Without `Content-Length`, the body is the rest of the input. With it, the
/// body is that many bytes, and anything after them is dropped, as RFC 3261
/// section 18.3 says for datagrams. A `Content-Length` larger than the rest is
/// an error, since the input is the whole message.
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
/// accepted only if every copy has the same value, because a message with two
/// different lengths has no single body.
pub(crate) fn content_length(
    headers: &HeaderMap,
) -> Result<Option<usize>, InvalidMessage> {
    let mut len = None;

    for value in headers.get_all(CONTENT_LENGTH) {
        let this = parse_content_length(value)
            .ok_or(InvalidMessage::new(InvalidMessageKind::ContentLength))?;
        if len.is_some_and(|len| len != this) {
            return Err(InvalidMessage::new(
                InvalidMessageKind::ContentLength,
            ));
        }
        len = Some(this);
    }

    Ok(len)
}

fn parse_content_length(value: &HeaderValue) -> Option<usize> {
    // siparse keeps trailing whitespace, including a trailing fold.
    let digits = value.as_str().trim_end_matches([' ', '\t', '\r', '\n']);

    // `usize::from_str` also takes a leading `+`, which the grammar does not.
    // It still rejects a value too large for `usize`.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}
