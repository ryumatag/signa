use std::{hint::black_box as bb, time::Instant};

use bytes::Bytes;
use criterion::{BatchSize, Criterion};
use signa_core::{
    Request, Response,
    bench::{
        ClientEvent, ClientKey, ClientTransaction, ServerKey,
        ServerTransaction, Timers,
        invite::{
            ClientEvent as InviteEvent, ClientTransaction as InviteClient,
            ServerEvent as InviteServerEvent,
            ServerTransaction as InviteServer,
        },
    },
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
    let timers = Timers::default();
    benchmark(c, "transaction/non_invite/server_start", len, |b| {
        b.iter(|| {
            let tx = ServerTransaction::new(bb(&request), false, &timers, now);
            assert!(!bb(&tx).is_terminated());
        });
    });

    let final_bytes = Bytes::from_static(RESPONSE_TYPICAL);
    benchmark(c, "transaction/non_invite/server_response/final", len, |b| {
        b.iter_batched(
            || ServerTransaction::new(&request, false, &timers, now),
            |mut tx| {
                assert!(tx.on_response(
                    response.status(),
                    bb(final_bytes.clone()),
                    &timers,
                    now
                ));
                assert!(tx.on_retransmission().is_some());
            },
            BatchSize::SmallInput,
        );
    });

    let mut waiting = ServerTransaction::new(&request, false, &timers, now);
    let trying = signa_core::StatusCode::from_u16(100).unwrap();
    benchmark(c, "transaction/non_invite/server_response/early_100", 1, |b| {
        b.iter(|| {
            assert!(!waiting.on_response(
                trying,
                Bytes::new(),
                &timers,
                bb(now)
            ));
            assert!(waiting.deadline().is_some());
            assert!(waiting.on_retransmission().is_none());
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
                    &timers,
                    now,
                );
                let event = tx.on_response(bb(response), &timers, now);
                assert!(matches!(event, ClientEvent::Final(_)));
                assert!(!bb(&tx).is_terminated());
            },
            BatchSize::SmallInput,
        );
    });
}

pub(super) fn invite(c: &mut Criterion) {
    // REQUEST_TYPICAL is an INVITE with its Via already present.
    let request = Request::from_bytes(REQUEST_TYPICAL).unwrap();
    let now = Instant::now();
    let timers = Timers::default();
    let len = REQUEST_TYPICAL.len() as u64;
    let accepted =
        Response::reply_to(&request).status(200).body(Bytes::new()).unwrap();
    let rejected =
        Response::reply_to(&request).status(486).body(Bytes::new()).unwrap();

    benchmark(c, "transaction/invite/client_start", len, |b| {
        b.iter(|| {
            let tx =
                InviteClient::new(bb(&request), false, &timers, now).unwrap();
            assert_eq!(bb(tx.deadline()), Some(now + timers.t1()));
        });
    });

    benchmark(c, "transaction/invite/client_non_2xx", len, |b| {
        b.iter_batched(
            || {
                (
                    InviteClient::new(&request, false, &timers, now).unwrap(),
                    rejected.clone(),
                )
            },
            |(mut tx, response)| {
                assert!(matches!(
                    tx.on_response(bb(response), &timers, now),
                    InviteEvent::Final { ack: Some(_), .. }
                ));
                assert!(!bb(tx).is_terminated());
            },
            BatchSize::SmallInput,
        );
    });

    benchmark(c, "transaction/invite/client_accepted", len, |b| {
        b.iter_batched(
            || {
                let mut tx =
                    InviteClient::new(&request, false, &timers, now).unwrap();
                tx.on_response(accepted.clone(), &timers, now);
                (tx, accepted.clone())
            },
            |(mut tx, response)| {
                assert!(matches!(
                    tx.on_response(bb(response), &timers, now),
                    InviteEvent::Final { ack: None, .. }
                ));
            },
            BatchSize::SmallInput,
        );
    });

    benchmark(c, "transaction/invite/server_start", len, |b| {
        b.iter(|| {
            let (tx, trying) = InviteServer::new(bb(&request), false);
            assert!(bb(trying).starts_with(b"SIP/2.0 100"));
            assert!(!bb(tx).is_terminated());
        });
    });

    let encoded = rejected.to_bytes();
    benchmark(c, "transaction/invite/server_non_2xx", len, |b| {
        b.iter_batched(
            || (InviteServer::new(&request, false).0, encoded.clone()),
            |(mut tx, response)| {
                assert!(matches!(
                    tx.on_response(
                        rejected.status(),
                        bb(response),
                        &timers,
                        now
                    ),
                    Ok(InviteServerEvent::Send(_))
                ));
                assert_eq!(tx.on_ack(&timers, now), InviteServerEvent::None);
                assert_eq!(tx.deadline(), Some(now + timers.t4()));
            },
            BatchSize::SmallInput,
        );
    });

    let encoded = accepted.to_bytes();
    benchmark(c, "transaction/invite/server_accepted", len, |b| {
        b.iter_batched(
            || {
                let mut tx = InviteServer::new(&request, false).0;
                tx.on_response(
                    accepted.status(),
                    encoded.clone(),
                    &timers,
                    now,
                )
                .unwrap();
                (tx, encoded.clone())
            },
            |(mut tx, response)| {
                assert!(matches!(
                    tx.on_response(
                        accepted.status(),
                        bb(response),
                        &timers,
                        now
                    ),
                    Ok(InviteServerEvent::Send(_))
                ));
                assert_eq!(tx.on_retransmission(), InviteServerEvent::None);
                assert_eq!(tx.on_ack(&timers, now), InviteServerEvent::Ack);
            },
            BatchSize::SmallInput,
        );
    });
}
