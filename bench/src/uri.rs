use std::hint::black_box as bb;

use criterion::Criterion;
use signa::Uri;

use crate::benchmark;

pub(super) fn from_bytes(c: &mut Criterion) {
    // `from_bytes` copies the input into a new allocation, which is part of
    // every result here. Compare these only with each other.
    let cases: [(_, &[u8]); _] = [
        ("typical", b"sip:bob@biloxi.example.com"),
        ("ipv6", b"sip:bob@[2001:db8::1]"),
        (
            "long",
            b"sip:bob@biloxi.example.com:5060;transport=tcp;lr;\
              maddr=192.0.2.1?Subject=lunch&Priority=urgent",
        ),
    ];

    for (variant, input) in cases {
        benchmark(
            c,
            format!("from_bytes/uri/{variant}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let uri = Uri::from_bytes(bb(input)).unwrap();
                    assert_eq!(bb(uri).as_str().len(), input.len());
                });
            },
        );
    }
}
