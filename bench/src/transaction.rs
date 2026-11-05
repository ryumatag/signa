use std::{hint::black_box as bb, time::Instant};

use bytes::Bytes;
use criterion::{BatchSize, Criterion};
use signa::{
    bench::{
        ClientEvent, ClientKey, ClientTransaction, ServerKey,
        ServerTransaction, Timers,
    },
    Request, Response,
};

use crate::{
    benchmark,
    message::{REQUEST_TYPICAL, RESPONSE_TYPICAL},
};

// The per-message work of the transaction layer on the receive path. Each
// received request is keyed to find or start a server transaction, and each
// received response is keyed to find its client transaction. Starting a server
// transaction copies the header fields its own 100 would carry.
pub(super) fn non_invite(c: &mut Criterion) {
    let request = Request::from_bytes(REQUEST_TYPICAL).unwrap();
    let response = Response::from_bytes(RESPONSE_TYPICAL).unwrap();
    let len = REQUEST_TYPICAL.len() as u64;

    benchmark(c, "transaction/non_invite/server_key", len, |b| {
        b.iter(|| {
            let key = ServerKey::from_request(bb(&request)).unwrap();
            assert_eq!(bb(&key), &key);
        });
    });

    benchmark(c, "transaction/non_invite/client_key", len, |b| {
        b.iter(|| {
            let key = ClientKey::from_response(bb(&response)).unwrap();
            assert_eq!(bb(&key), &key);
        });
    });

    let now = Instant::now();
    benchmark(c, "transaction/non_invite/server_start", len, |b| {
        b.iter(|| {
            let tx = ServerTransaction::new(
                bb(&request),
                false,
                Timers::default(),
                now,
            );
            assert!(!bb(&tx).is_terminated());
        });
    });

    // A client transaction from the request to its final response, as over UDP
    // when the response arrives before the first retransmission. The response
    // is cloned in setup, so only the transaction is measured.
    let encoded = Bytes::from_static(REQUEST_TYPICAL);
    benchmark(c, "transaction/non_invite/client_round_trip", len, |b| {
        b.iter_batched(
            || response.clone(),
            |response| {
                let mut tx = ClientTransaction::new(
                    encoded.clone(),
                    false,
                    Timers::default(),
                    now,
                );
                let event = tx.on_response(bb(response), now);
                assert!(matches!(event, ClientEvent::Final(_)));
                assert!(!bb(&tx).is_terminated());
            },
            BatchSize::SmallInput,
        );
    });
}
