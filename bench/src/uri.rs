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

pub(super) fn structured(c: &mut Criterion) {
    use signa::message::uri::SipUri;

    for (variant, input) in [
        ("typical", "sip:bob@biloxi.example.com"),
        ("ipv6", "sips:bob@[2001:db8::1]:5061"),
        ("userinfo", "sip:alice;phone?work:secret%3a@example.com"),
        (
            "long",
            "sip:bob@biloxi.example.com:5060;transport=tcp;lr;maddr=192.0.2.1?Subject=lunch&Priority=urgent",
        ),
    ] {
        benchmark(
            c,
            format!("parse/sip_uri/{variant}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let uri = SipUri::parse(bb(input)).unwrap();
                    assert_eq!(bb(uri).as_str(), input);
                });
            },
        );
    }

    let input = "sip:example.com;transport=tcp;lr;%6daddr=192.0.2.1?Subject=lunch&Priority=urgent";
    let uri = SipUri::parse(input).unwrap();

    benchmark(c, "iterate/sip_uri/parameters", input.len() as u64, |b| {
        b.iter(|| {
            let count = bb(uri)
                .parameters()
                .inspect(|p| {
                    bb(p.name().as_str());
                })
                .count();
            assert_eq!(count, 3);
        });
    });
    benchmark(c, "iterate/sip_uri/headers", input.len() as u64, |b| {
        b.iter(|| {
            let count = bb(uri)
                .headers()
                .inspect(|h| {
                    bb(h.value().as_str());
                })
                .count();
            assert_eq!(count, 2);
        });
    });
    benchmark(c, "lookup/sip_uri/parameter", input.len() as u64, |b| {
        b.iter(|| {
            let parameter = bb(&uri).parameter(bb("maddr")).unwrap().unwrap();
            assert_eq!(parameter.value().unwrap().as_str(), "192.0.2.1");
        });
    });
}
