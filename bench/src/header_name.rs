use std::hint::black_box as bb;

use criterion::Criterion;
use signa::HeaderName;

use crate::benchmark;

pub(super) fn from_bytes(c: &mut Criterion) {
    // Standard names, in canonical and other casings and in compact form,
    // allocate nothing. Custom names are lowercased into a new allocation.
    let cases: [(_, &[u8]); _] = [
        ("standard/short", b"Via"),
        ("standard/long", b"Proxy-Authorization"),
        ("standard/lowercase", b"content-length"),
        ("compact", b"i"),
        ("custom/short", b"X-Trace"),
        ("custom/long", b"X-Some-Vendor-Specific-Account-Identifier"),
    ];

    for (variant, input) in cases {
        benchmark(
            c,
            format!("from_bytes/header_name/{variant}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let name = HeaderName::from_bytes(bb(input)).unwrap();
                    assert!(!bb(name).as_str().is_empty());
                });
            },
        );
    }
}
