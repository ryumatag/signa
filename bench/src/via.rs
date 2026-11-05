use std::hint::black_box as bb;

use criterion::Criterion;
use signa::{
    bench::{CSeq, Via},
    header::HeaderValue,
    Method,
};

use crate::benchmark;

// The crate-private parsers for the headers the protocol layer reads. The
// receive path runs each once per message, so they are compared with
// `parse/message/typical` to see what they add to it.
pub(super) fn parse(c: &mut Criterion) {
    // The `Via` from `REQUEST_TYPICAL`.
    let value = HeaderValue::from_static(
        "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds",
    );
    benchmark(c, "parse/via/typical", value.len() as u64, |b| {
        b.iter(|| {
            let via = Via::top(bb(&value)).unwrap();
            assert_eq!(bb(via).branch, Some("z9hG4bK776asdhds"));
        });
    });

    // A `Via` a proxy has filled in, with every parameter signa reads, an
    // extension parameter, and a second parm after it.
    let value = HeaderValue::from_static(
        "SIP/2.0/UDP 192.0.2.4:5060;ttl=16;maddr=224.2.0.1;received=192.0.2.207\
         ;rport=49154;branch=z9hG4bK776asdhds;x-trace=\"a;b\",\
         SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhdt",
    );
    benchmark(c, "parse/via/full", value.len() as u64, |b| {
        b.iter(|| {
            let via = Via::top(bb(&value)).unwrap();
            assert_eq!(bb(via).rport, Some(Some(49154)));
        });
    });

    let value = HeaderValue::from_static("314159 INVITE");
    benchmark(c, "parse/cseq", value.len() as u64, |b| {
        b.iter(|| {
            let cseq = CSeq::parse(bb(&value)).unwrap();
            assert_eq!(bb(cseq).method, Method::INVITE);
        });
    });
}
