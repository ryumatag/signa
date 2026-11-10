use std::hint::black_box as bb;

use bytes::Bytes;
use criterion::Criterion;
use signa_core::HeaderValue;

use crate::benchmark;

pub(super) fn from_shared(c: &mut Criterion) {
    // `from_shared` on a static buffer neither copies nor allocates, so these
    // measure the check alone.
    let cases: [(_, &[u8]); _] = [
        ("short", b"0"),
        (
            "typical",
            b"SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds",
        ),
        (
            "long",
            b"SIP/2.0/UDP host-1.example.com:5060;\
              branch=z9hG4bKabcdefghijklmnop;rport;received=192.0.2.1",
        ),
        ("folded", b"I know you're there,\r\n pick up the phone"),
        (
            "escaped",
            b"\"Alice \\\x01 Liddell\" <sip:alice@atlanta.example.com>",
        ),
        (
            "utf8/short",
            "\"\u{7530}\u{4e2d}\" <sip:tanaka@example.com>;tag=1928301774"
                .as_bytes(),
        ),
        (
            "utf8/cjk",
            "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c6}\u{30b9}\u{30c8}\
             \u{6587}\u{5b57}\u{5217}\u{3092}\u{9577}\u{304f}\u{3057}\
             \u{305f}\u{4ef6}\u{540d}\u{3067}\u{3059}\u{3002}"
                .as_bytes(),
        ),
    ];

    for (variant, input) in cases {
        let expected_len = input.len();
        benchmark(
            c,
            format!("from_shared/header_value/{variant}"),
            expected_len as u64,
            |b| {
                b.iter(|| {
                    let value = HeaderValue::from_shared(Bytes::from_static(
                        bb(input),
                    ))
                    .unwrap();
                    assert_eq!(bb(value).len(), expected_len);
                });
            },
        );
    }
}
