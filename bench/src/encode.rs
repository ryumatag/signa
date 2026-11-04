use std::hint::black_box as bb;

use bytes::BytesMut;
use criterion::Criterion;
use signa::{Request, Response};

use crate::{
    benchmark,
    message::{REQUEST_TYPICAL, REQUEST_VARIED, RESPONSE_TYPICAL},
};

pub(super) fn encode(c: &mut Criterion) {
    // The messages come from parsing, as when a proxy forwards what it
    // received. `encode` writes into one buffer that is cleared each time,
    // as a transport would reuse its send buffer.
    for (variant, input) in
        [("typical", REQUEST_TYPICAL), ("varied", REQUEST_VARIED)]
    {
        let request = Request::from_bytes(input).unwrap();
        let len = request.to_bytes().len();
        let mut dst = BytesMut::with_capacity(len);
        benchmark(c, format!("encode/request/{variant}"), len as u64, |b| {
            b.iter(|| {
                dst.clear();
                bb(&request).encode(&mut dst);
                assert_eq!(bb(&dst).len(), len);
            });
        });
    }

    let response = Response::from_bytes(RESPONSE_TYPICAL).unwrap();
    let len = response.to_bytes().len();
    let mut dst = BytesMut::with_capacity(len);
    benchmark(c, "encode/response/typical", len as u64, |b| {
        b.iter(|| {
            dst.clear();
            bb(&response).encode(&mut dst);
            assert_eq!(bb(&dst).len(), len);
        });
    });
}
