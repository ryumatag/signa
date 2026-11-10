/*!
Conversion from messages to the bytes of one complete SIP message.

Every part of a message was checked when it was built or parsed, so writing it
out cannot fail.
*/

use bytes::{BufMut, BytesMut};

use crate::message::{
    header::{CONTENT_LENGTH, HeaderMap},
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
    let body = response.body().as_ref();
    let reason = match response.reason() {
        Some(reason) => reason.as_str(),
        None => response.status().canonical_reason().unwrap_or(""),
    };
    // Ordinary encoding keeps the same infallible sizing path as requests.
    // Admission uses the checked preflight below to reject before allocation.
    let line_len = response.version().as_str().len() + reason.len() + 7;
    let len =
        line_len + head_fields_len(response.headers(), body) + body.len();
    response_with_len(response, body, len, dst);
}

/// Encodes after wire-byte admission, reusing its checked length. The caller
/// keeps the response and body unchanged between sizing and encoding.
#[inline(always)]
pub(super) fn response_with_len<T>(
    response: &Response<T>,
    body: &[u8],
    len: usize,
    dst: &mut BytesMut,
) {
    let version = response.version();
    let version = version.as_str();
    // Extension status codes may have no canonical reason. The status-line
    // grammar allows an empty reason in that case.
    let reason = match response.reason() {
        Some(reason) => reason.as_str(),
        None => response.status().canonical_reason().unwrap_or(""),
    };
    let start = dst.len();
    dst.reserve(len);

    dst.put_slice(version.as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(response.status().as_str().as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(reason.as_bytes());
    dst.put_slice(b"\r\n");

    fields_and_body(response.headers(), body, dst);
    debug_assert_eq!(dst.len() - start, len, "reserved length is off");
}

/// Checked wire length for admission before allocating an encoded response.
#[cfg(any(feature = "tokio", test))]
pub(crate) fn response_len<T>(
    response: &Response<T>,
    body_len: usize,
) -> Option<usize> {
    let reason = response.reason().map_or_else(
        || response.status().canonical_reason().unwrap_or(""),
        |reason| reason.as_str(),
    );
    // `VERSION SP CODE SP REASON CRLF`, where the code is three digits.
    let line = response
        .version()
        .as_str()
        .len()
        .checked_add(reason.len())?
        .checked_add(7)?;
    let fields = response
        .headers()
        .iter()
        .filter(|(name, _)| **name != CONTENT_LENGTH)
        .try_fold(0usize, |len, (name, value)| {
            len.checked_add(name.as_str().len())?
                .checked_add(value.len())?
                .checked_add(4)
        })?;
    line.checked_add(fields)?
        .checked_add("Content-Length: \r\n\r\n".len())?
        .checked_add(Digits::new(body_len).len())?
        .checked_add(body_len)
}

/// Checked wire length for admission before a request is encoded.
#[cfg(any(feature = "tokio", test))]
pub(crate) fn request_len<T>(
    request: &Request<T>,
    body_len: usize,
) -> Option<usize> {
    // `METHOD SP URI SP VERSION CRLF`
    let line = request
        .method()
        .as_str()
        .len()
        .checked_add(request.uri().as_str().len())?
        .checked_add(request.version().as_str().len())?
        .checked_add(4)?;
    let fields = request
        .headers()
        .iter()
        .filter(|(name, _)| **name != CONTENT_LENGTH)
        .try_fold(0usize, |len, (name, value)| {
            len.checked_add(name.as_str().len())?
                .checked_add(value.len())?
                .checked_add(4)
        })?;
    line.checked_add(fields)?
        .checked_add("Content-Length: \r\n\r\n".len())?
        .checked_add(Digits::new(body_len).len())?
        .checked_add(body_len)
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
    use super::*;

    #[test]
    fn checked_response_length_matches_normalized_wire_output() {
        fn property(body: Vec<u8>, custom_reason: bool) -> bool {
            let mut response = Response::builder()
                .status(299)
                .header("X-Trace", "kept")
                .header("Content-Length", "999")
                .header("Content-Length", "0")
                .body(body)
                .unwrap();
            if custom_reason {
                *response.reason_mut() =
                    Some(crate::message::ReasonPhrase::from_static("Custom"));
            }
            response_len(&response, response.body().len())
                == Some(response.to_bytes().len())
        }

        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 8 } else { 100 })
            .quickcheck(property as fn(Vec<u8>, bool) -> bool);
    }

    #[test]
    fn checked_request_length_matches_normalized_wire_output() {
        fn property(body: Vec<u8>, routes: u8) -> bool {
            let mut builder = Request::builder()
                .method("ACK")
                .uri("sip:bob@example.com")
                .header("CSeq", "1 ACK")
                .header("Content-Length", "999");
            for _ in 0..routes % 4 {
                builder = builder.header("Route", "<sip:p.example.com;lr>");
            }
            let request = builder.body(body).unwrap();
            request_len(&request, request.body().len())
                == Some(request.to_bytes().len())
        }

        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 8 } else { 100 })
            .quickcheck(property as fn(Vec<u8>, u8) -> bool);
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
