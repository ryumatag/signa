use std::hint::black_box as bb;

use criterion::Criterion;
use signa_core::ReasonPhrase;

use crate::benchmark;

pub(super) fn from_bytes(c: &mut Criterion) {
    // `from_bytes` copies the input into a new allocation, which is part of
    // every result here. Compare these only with each other.
    let cases: [(_, &[u8]); _] = [
        ("short", b"OK"),
        ("typical", b"Call/Transaction Does Not Exist"),
        ("escaped", b"Say %22hi%22 to %E7%94%B0%E4%B8%AD"),
        ("utf8", "\u{8a71}\u{3057}\u{4e2d}\u{3067}\u{3059}".as_bytes()),
    ];

    for (variant, input) in cases {
        benchmark(
            c,
            format!("from_bytes/reason/{variant}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let reason = ReasonPhrase::from_bytes(bb(input)).unwrap();
                    assert_eq!(bb(reason).as_str().len(), input.len());
                });
            },
        );
    }
}
