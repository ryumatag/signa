use std::hint::black_box as bb;

use bytes::Bytes;
use criterion::Criterion;
use signa::{Message, Request, Response};

use crate::benchmark;

/// A request with only the fields a request needs.
pub(crate) const REQUEST_MINIMAL: &[u8] =
    b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
    Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
    Max-Forwards: 70\r\n\
    To: <sip:carol@chicago.example.com>\r\n\
    From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
    Call-ID: a84b4c76e66710\r\n\
    CSeq: 63104 OPTIONS\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// The INVITE from RFC 3261 section 4, with its SDP body.
pub(crate) const REQUEST_TYPICAL: &[u8] =
    b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
    Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
    Max-Forwards: 70\r\n\
    To: Bob <sip:bob@biloxi.example.com>\r\n\
    From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
    Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
    CSeq: 314159 INVITE\r\n\
    Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
    Content-Type: application/sdp\r\n\
    Content-Length: 127\r\n\
    \r\n\
    v=0\r\n\
    o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n\
    s=-\r\n\
    c=IN IP4 192.0.2.101\r\n\
    t=0 0\r\n\
    m=audio 49172 RTP/AVP 0\r\n";

/// `REQUEST_TYPICAL` with compact names, custom fields, a fold, and UTF-8,
/// which take the slower paths of `HeaderName` and `HeaderValue`.
pub(crate) const REQUEST_VARIED: &[u8] =
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
    v: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
    Max-Forwards: 70\r\n\
    t: \"Bj\u{f6}rn\" <sip:bob@biloxi.example.com>\r\n\
    f: \"\u{7530}\u{4e2d}\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
    i: a84b4c76e66710@pc33.atlanta.example.com\r\n\
    CSeq: 314159 INVITE\r\n\
    m: <sip:alice@pc33.atlanta.example.com>\r\n\
    s: \u{4f1a}\u{8b70}\u{306e}\u{4ef6}\r\n \u{1f4de}\r\n\
    X-Account-Id: 8d4f1c2e-77b3-4a9e-9d0b-6f5a3c1e2b40\r\n\
    X-Trace: abc123\r\n\
    l: 0\r\n\
    \r\n"
        .as_bytes();

/// A typical final response to `REQUEST_TYPICAL`.
pub(crate) const RESPONSE_TYPICAL: &[u8] = b"SIP/2.0 200 OK\r\n\
    Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds;received=192.0.2.101\r\n\
    To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n\
    From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
    Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
    CSeq: 314159 INVITE\r\n\
    Contact: <sip:bob@192.0.2.4>\r\n\
    Content-Length: 0\r\n\
    \r\n";

pub(super) fn parse(c: &mut Criterion) {
    // `from_shared` on a static buffer, so no benchmark pays for copying
    // the input. `HeaderMap` and custom header names still allocate.
    let requests = [
        ("minimal", REQUEST_MINIMAL),
        ("typical", REQUEST_TYPICAL),
        ("varied", REQUEST_VARIED),
    ];
    for (variant, input) in requests {
        let headers = Request::from_bytes(input).unwrap().headers().len();
        benchmark(
            c,
            format!("parse/request/{variant}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let request =
                        Request::from_shared(Bytes::from_static(bb(input)))
                            .unwrap();
                    assert_eq!(bb(request).headers().len(), headers);
                });
            },
        );
    }

    let input = RESPONSE_TYPICAL;
    benchmark(c, "parse/response/typical", input.len() as u64, |b| {
        b.iter(|| {
            let response =
                Response::from_shared(Bytes::from_static(bb(input))).unwrap();
            assert_eq!(bb(response).headers().len(), 7);
        });
    });

    // The same request through `Message`, to show what deciding the kind
    // from the start-line costs next to `parse/request/typical`.
    let input = REQUEST_TYPICAL;
    benchmark(c, "parse/message/typical", input.len() as u64, |b| {
        b.iter(|| {
            let message =
                Message::from_shared(Bytes::from_static(bb(input))).unwrap();
            assert!(matches!(bb(message), Message::Request(_)));
        });
    });
}
