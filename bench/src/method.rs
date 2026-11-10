use std::hint::black_box as bb;

use criterion::Criterion;
use signa_core::Method;

use crate::benchmark;

pub(super) fn from_bytes(c: &mut Criterion) {
    // Known methods and short extensions are stored inline. Longer
    // extensions allocate.
    let cases: [(_, &[u8]); _] = [
        ("known", b"INVITE"),
        ("extension/short", b"PING"),
        ("extension/long", b"X-VENDOR-SPECIFIC-METHOD-NAME"),
    ];

    for (variant, input) in cases {
        benchmark(
            c,
            format!("from_bytes/method/{variant}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let method = Method::from_bytes(bb(input)).unwrap();
                    assert_eq!(bb(method).as_str().len(), input.len());
                });
            },
        );
    }
}
