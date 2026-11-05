use std::hint::black_box as bb;

use criterion::{BatchSize, Criterion};
use signa::{
    header::{HeaderValue, VIA},
    Request,
};

use crate::{benchmark, message::REQUEST_TYPICAL};

// A sender adding its `Via` above the existing ones, which shifts every row
// from the first `Via` on. Each iteration starts from a copy of the parsed
// map, as a proxy would modify the message it received. The copy is setup,
// and the map is returned so that dropping it is not measured either.
// Compare with `encode/request/typical` to see what the shift costs next to
// writing the message out.
pub(super) fn prepend(c: &mut Criterion) {
    let request = Request::from_bytes(REQUEST_TYPICAL).unwrap();
    let headers = request.headers();
    let via = HeaderValue::from_static(
        "SIP/2.0/UDP proxy.atlanta.example.com;branch=z9hG4bKnashds8",
    );
    benchmark(c, "prepend/header_map/typical", via.len() as u64, |b| {
        b.iter_batched(
            || headers.clone(),
            |mut headers| {
                assert!(headers.prepend(VIA, bb(via.clone())));
                assert_eq!(bb(&headers).len(), 10);
                headers
            },
            BatchSize::SmallInput,
        );
    });
}
