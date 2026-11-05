use std::hint::black_box as bb;

use bytes::BytesMut;
use criterion::{BatchSize, Criterion};
use signa::bench::{Decoder, Frame, Limits, Role};

use crate::{
    benchmark,
    message::{REQUEST_MINIMAL, REQUEST_TYPICAL, RESPONSE_TYPICAL},
};

// The stream decoder on a buffer that a read has just filled. Each iteration
// starts from a fresh `BytesMut` copy of the input, as a read into a new
// buffer would, so the copy is part of the cost. Compare `typical` with
// `parse/message/typical`, which parses the same request from a static buffer,
// to see what framing adds.
pub(super) fn stream(c: &mut Criterion) {
    const NAME: &str = "frame/stream";

    // One message per read.
    let input = REQUEST_TYPICAL;
    benchmark(c, format!("{NAME}/typical"), input.len() as u64, |b| {
        let mut decoder = Decoder::new(Role::Server, Limits::default());
        b.iter_batched(
            || BytesMut::from(input),
            |mut buf| {
                let frame = decoder.decode(&mut buf).unwrap().unwrap();
                assert!(matches!(bb(frame), Frame::Message(_)));
                assert!(buf.is_empty());
            },
            BatchSize::SmallInput,
        );
    });

    // Several messages in one read.
    let mut input = Vec::new();
    for message in [REQUEST_TYPICAL, RESPONSE_TYPICAL, REQUEST_MINIMAL] {
        input.extend_from_slice(message);
    }
    benchmark(c, format!("{NAME}/pipelined"), input.len() as u64, |b| {
        let mut decoder = Decoder::new(Role::Server, Limits::default());
        b.iter_batched(
            || BytesMut::from(&input[..]),
            |mut buf| {
                let mut frames = 0;
                while let Some(frame) = decoder.decode(&mut buf).unwrap() {
                    assert!(matches!(bb(frame), Frame::Message(_)));
                    frames += 1;
                }
                assert_eq!(frames, 3);
            },
            BatchSize::SmallInput,
        );
    });

    // One message in reads of 64 bytes, as a slow link delivers it. The
    // decoder is called after every read.
    let input = REQUEST_TYPICAL;
    benchmark(c, format!("{NAME}/fragmented"), input.len() as u64, |b| {
        let mut decoder = Decoder::new(Role::Server, Limits::default());
        b.iter_batched(
            BytesMut::new,
            |mut buf| {
                let mut frames = 0;
                for read in input.chunks(64) {
                    buf.extend_from_slice(bb(read));
                    while let Some(frame) = decoder.decode(&mut buf).unwrap() {
                        assert!(matches!(bb(frame), Frame::Message(_)));
                        frames += 1;
                    }
                }
                assert_eq!(frames, 1);
            },
            BatchSize::SmallInput,
        );
    });
}
