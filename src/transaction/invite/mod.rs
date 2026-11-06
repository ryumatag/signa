/*!
INVITE transactions, [RFC 3261 section 17] as amended by [RFC 6026].

The driver matches input before calling these machines, sends returned bytes
on the transaction's original next hop or reply route, and delivers TU events.
It processes due timers before input at the same instant. In particular, a
response arriving at B or M cannot revive a transaction that has expired. The
caller supplies monotonically increasing instants and unchanged timers.

These machines do not create CANCEL transactions or generate 2xx ACKs. The
endpoint's cancellation intent and the TU own those operations.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 6026]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8
*/

pub use self::{
    client::{ClientEvent, ClientTransaction, InvalidInvite},
    server::{ResponseError, ServerEvent, ServerTransaction},
};

mod client;
mod server;

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;

    use super::{ClientEvent as C, ServerEvent as S, *};
    use crate::{
        header::{
            HeaderValue, CALL_ID, CONTENT_TYPE, CSEQ, FROM, MAX_FORWARDS,
            ROUTE, TO, VIA,
        },
        method::Method,
        request::Request,
        response::Response,
        status::StatusCode,
        transaction::Timers,
    };

    pub(super) const INVITE: &[u8] = b"\
INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP atlanta.example.com:5060;branch=z9hG4bKfirst;x=\"a,b\", SIP/2.0/UDP older.example.com;branch=z9hG4bKsecond\r\n\
Via: SIP/2.0/UDP oldest.example.com;branch=z9hG4bKthird\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=alice\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
Call-ID: call@atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Max-Forwards: 65\r\n\
Route: <sip:first.example.com;lr>, <sip:second.example.com;lr>\r\n\
Route: <sip:third.example.com;lr>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\r\nbody";

    const T1: Duration = Duration::from_millis(500);
    const TIMERS: Timers = Timers::new();

    fn request() -> Request<Bytes> {
        Request::from_bytes(INVITE).unwrap()
    }

    fn response(code: u16, tag: &str) -> Response<Bytes> {
        Response::reply_to(&request())
            .status(code)
            .body(Bytes::new())
            .map(|mut response| {
                response.headers_mut().insert(
                    TO,
                    HeaderValue::from_bytes(
                        format!("Bob <sip:bob@biloxi.example.com>;tag={tag}")
                            .as_bytes(),
                    )
                    .unwrap(),
                );
                response
            })
            .unwrap()
    }

    fn client(reliable: bool, now: Instant) -> ClientTransaction {
        ClientTransaction::new(&request(), reliable, &TIMERS, now).unwrap()
    }

    fn server(reliable: bool) -> ServerTransaction {
        let (tx, trying) = ServerTransaction::new(&request(), reliable);
        let trying = Response::from_shared(trying.clone()).unwrap();

        assert_eq!(trying.status(), StatusCode::TRYING);
        assert!(trying.body().is_empty());
        assert_eq!(tx.on_retransmission(), S::Send(trying.to_bytes()));

        tx
    }

    fn send(tx: &mut ServerTransaction, code: u16, now: Instant) -> S {
        let response = response(code, "bob");
        tx.on_response(response.status(), response.to_bytes(), &TIMERS, now)
            .unwrap()
    }

    // RFC 3261 17.1.1.2. A doubles past T2, and B wins at 64 T1.
    #[test]
    fn client_retransmits_invite_without_a_t2_cap() {
        let start = Instant::now();
        let mut tx = client(false, start);

        assert_eq!(tx.deadline(), Some(start + T1));
        assert!(matches!(tx.on_timeout(&TIMERS, start), C::None));

        for multiple in [1, 3, 7, 15, 31, 63] {
            let at = start + multiple * T1;
            assert_eq!(tx.deadline(), Some(at));

            match tx.on_timeout(&TIMERS, at) {
                C::Send(bytes) => assert_eq!(bytes, request().to_bytes()),
                event => {
                    panic!("expected INVITE retransmission, got {event:?}")
                }
            }
        }

        assert_eq!(tx.deadline(), Some(start + 64 * T1));
        assert!(matches!(tx.on_timeout(&TIMERS, start + 64 * T1), C::Timeout));
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
        assert!(matches!(tx.on_timeout(&TIMERS, start + 65 * T1), C::None));
    }

    #[test]
    fn client_b_wins_over_a_and_reliable_calling_still_times_out() {
        for reliable in [false, true] {
            let start = Instant::now();
            let mut tx = client(reliable, start);

            if reliable {
                assert_eq!(tx.deadline(), Some(start + 64 * T1));
                assert!(matches!(tx.on_timeout(&TIMERS, start + T1), C::None));
            }

            assert!(matches!(
                tx.on_timeout(&TIMERS, start + 64 * T1),
                C::Timeout
            ));
            assert!(matches!(
                tx.on_response(response(200, "bob"), &TIMERS, start + 64 * T1),
                C::None
            ));
        }
    }

    #[test]
    fn proceeding_stops_a_and_has_no_timer_b() {
        for reliable in [false, true] {
            let start = Instant::now();
            let mut tx = client(reliable, start);

            for code in 100..200 {
                assert!(matches!(
                    tx.on_response(response(code, "bob"), &TIMERS, start),
                    C::Provisional(r) if r.status().as_u16() == code
                ));
            }
            assert_eq!(tx.deadline(), None);
            assert!(matches!(
                tx.on_timeout(&TIMERS, start + 1000 * T1),
                C::None
            ));
            assert!(!tx.is_terminated());
        }
    }

    // RFC 3261 17.1.1.3. Only the top Via value is used, not its whole row.
    #[test]
    fn non_success_ack_uses_request_routing_and_response_to() {
        let start = Instant::now();
        for reliable in [false, true] {
            let mut tx = client(reliable, start);

            let final_response = response(486, "busy-branch");
            let ack =
                match tx.on_response(final_response.clone(), &TIMERS, start) {
                    C::Final { response, ack: Some(ack) } => {
                        assert_eq!(
                            response.headers().get(TO),
                            final_response.headers().get(TO)
                        );
                        ack
                    }
                    event => panic!("expected final and ACK, got {event:?}"),
                };
            let ack = Request::from_shared(ack).unwrap();
            let invite = request();

            assert_eq!(ack.method(), Method::ACK);
            assert_eq!(ack.uri().as_str(), invite.uri().as_str());
            assert_eq!(
                ack.headers().get(CALL_ID),
                invite.headers().get(CALL_ID)
            );
            assert_eq!(ack.headers().get(FROM), invite.headers().get(FROM));
            assert_eq!(
                ack.headers().get(TO),
                final_response.headers().get(TO)
            );
            assert_eq!(ack.headers().get(CSEQ).unwrap(), "314159 ACK");
            assert_eq!(ack.headers().get(MAX_FORWARDS).unwrap(), "70");
            assert_eq!(
                ack.headers().get(VIA).unwrap(),
                "SIP/2.0/UDP atlanta.example.com:5060;branch=z9hG4bKfirst;x=\"a,b\""
            );
            assert_eq!(ack.headers().get_all(VIA).count(), 1);
            assert_eq!(
                ack.headers().get_all(ROUTE).collect::<Vec<_>>(),
                invite.headers().get_all(ROUTE).collect::<Vec<_>>()
            );
            assert!(!ack.headers().contains_key(CONTENT_TYPE));
            assert!(ack.body().is_empty());
            assert_eq!(tx.is_terminated(), reliable);
        }
    }

    #[test]
    fn client_d_resends_the_cached_ack_and_never_redelivers_final() {
        let start = Instant::now();
        let mut tx = client(false, start);

        let ack = match tx.on_response(response(486, "first"), &TIMERS, start)
        {
            C::Final { ack: Some(ack), .. } => ack,
            event => panic!("{event:?}"),
        };
        let deadline = start + Duration::from_secs(32);

        for code in [300, 486, 503, 699] {
            assert!(matches!(
                tx.on_response(
                    response(code, "different"), &TIMERS, start + T1
                ),
                C::Send(bytes) if bytes == ack,
            ));
            assert_eq!(tx.deadline(), Some(deadline));
        }
        for code in [100, 180, 200, 299] {
            assert!(matches!(
                tx.on_response(response(code, "bob"), &TIMERS, start + T1),
                C::None
            ));
        }
        assert!(matches!(
            tx.on_timeout(&TIMERS, deadline - Duration::from_nanos(1)),
            C::None
        ));
        assert!(matches!(tx.on_timeout(&TIMERS, deadline), C::Terminated));
        assert!(matches!(
            tx.on_response(response(486, "first"), &TIMERS, deadline),
            C::None
        ));
    }

    // RFC 6026 8.4. M survives forks, retransmissions, and reliable transport.
    #[test]
    fn accepted_delivers_every_success_without_restarting_m() {
        for reliable in [false, true] {
            for proceeding in [false, true] {
                let start = Instant::now();
                let mut tx = client(reliable, start);

                if proceeding {
                    tx.on_response(response(180, "early"), &TIMERS, start);
                }

                for (offset, tag) in
                    [(0, "first"), (1, "second"), (2, "first")]
                {
                    assert!(
                        matches!(tx.on_response(response(200, tag), &TIMERS, start + offset * T1), C::Final { response: r, ack: None } if r.headers().get(TO) == response(200, tag).headers().get(TO))
                    );
                    assert_eq!(tx.deadline(), Some(start + 64 * T1));
                }
                for code in [100, 180, 300, 486, 699] {
                    assert!(matches!(
                        tx.on_response(
                            response(code, "late"),
                            &TIMERS,
                            start + 3 * T1
                        ),
                        C::None
                    ));
                }
                assert!(matches!(tx.on_transport_error(), C::None));
                assert!(matches!(
                    tx.on_timeout(&TIMERS, start + 63 * T1),
                    C::None
                ));
                assert!(matches!(
                    tx.on_timeout(&TIMERS, start + 64 * T1),
                    C::Terminated
                ));
                assert!(matches!(
                    tx.on_response(
                        response(200, "late"),
                        &TIMERS,
                        start + 64 * T1
                    ),
                    C::None
                ));
            }
        }
    }

    #[test]
    fn every_final_class_transitions_from_calling_and_proceeding() {
        let start = Instant::now();
        for reliable in [false, true] {
            for proceeding in [false, true] {
                for code in 200..700 {
                    let mut tx = client(reliable, start);

                    if proceeding {
                        tx.on_response(response(180, "early"), &TIMERS, start);
                    }

                    assert!(matches!(
                        tx.on_response(
                            response(code, "bob"), &TIMERS, start
                        ),
                        C::Final { ack, .. } if ack.is_some() == (code >= 300)
                    ));
                    assert_eq!(tx.is_terminated(), reliable && code >= 300);
                }
            }
        }
    }

    #[test]
    fn transport_errors_end_calling_proceeding_and_completed() {
        let start = Instant::now();
        for code in [None, Some(180), Some(486)] {
            let mut tx = client(false, start);

            if let Some(code) = code {
                tx.on_response(response(code, "bob"), &TIMERS, start);
            }

            assert!(matches!(tx.on_transport_error(), C::TransportError));
            assert!(tx.is_terminated());
            assert!(matches!(tx.on_transport_error(), C::None));
            assert_eq!(tx.deadline(), None);
        }
    }

    #[test]
    fn malformed_ack_inputs_leave_no_partial_transition() {
        let start = Instant::now();
        let mut tx = client(false, start);

        let mut bad = response(486, "bob");
        bad.headers_mut().remove(TO);

        assert!(matches!(
            tx.on_response(bad, &TIMERS, start),
            C::InvalidResponse
        ));
        assert_eq!(tx.deadline(), Some(start + T1));
        assert!(matches!(
            tx.on_response(response(486, "bob"), &TIMERS, start),
            C::Final { ack: Some(_), .. }
        ));
        for name in [FROM, TO, CALL_ID, CSEQ, VIA] {
            let mut bad = request();
            bad.headers_mut().remove(&name);

            assert_eq!(
                ClientTransaction::new(&bad, false, &TIMERS, start)
                    .unwrap_err(),
                InvalidInvite::Missing(name)
            );
        }
        for cseq in ["broken", "1 OPTIONS", "2147483648 INVITE"] {
            let mut bad = request();
            bad.headers_mut().insert(CSEQ, HeaderValue::from_static(cseq));

            assert_eq!(
                ClientTransaction::new(&bad, false, &TIMERS, start)
                    .unwrap_err(),
                InvalidInvite::CSeq
            );
        }

        let mut bad = request();
        *bad.method_mut() = Method::OPTIONS;

        assert_eq!(
            ClientTransaction::new(&bad, false, &TIMERS, start).unwrap_err(),
            InvalidInvite::Method
        );

        *bad.method_mut() = Method::INVITE;
        bad.headers_mut().insert(VIA, HeaderValue::from_static("bad"));

        assert_eq!(
            ClientTransaction::new(&bad, false, &TIMERS, start).unwrap_err(),
            InvalidInvite::Via
        );
    }

    #[test]
    fn server_proceeding_retransmits_the_latest_provisional() {
        let start = Instant::now();
        for reliable in [false, true] {
            let mut tx = server(reliable);

            assert!(tx.headers().is_some());
            assert_eq!(tx.deadline(), None);
            assert_eq!(tx.on_ack(&TIMERS, start), S::None);

            for code in [100, 180, 183, 199] {
                let sent = send(&mut tx, code, start);

                assert_eq!(tx.on_retransmission(), sent);
                assert_eq!(tx.deadline(), None);
            }

            assert_eq!(tx.on_timeout(&TIMERS, start + 1000 * T1), S::None);
        }
    }

    // RFC 3261 17.2.1. H wins over G, and G caps at T2.
    #[test]
    fn server_g_caps_at_t2_and_h_times_out() {
        let start = Instant::now();
        let mut tx = server(false);
        let sent = send(&mut tx, 486, start);

        assert!(tx.headers().is_none());
        assert_eq!(tx.on_retransmission(), sent);

        for multiple in [1, 3, 7, 15, 23, 31, 39, 47, 55, 63] {
            let at = start + multiple * T1;

            assert_eq!(tx.deadline(), Some(at));
            assert_eq!(
                tx.on_timeout(&TIMERS, at - Duration::from_nanos(1)),
                S::None
            );
            assert_eq!(tx.on_timeout(&TIMERS, at), sent);
        }

        assert_eq!(tx.deadline(), Some(start + 64 * T1));
        assert_eq!(tx.on_timeout(&TIMERS, start + 64 * T1), S::Timeout);
        assert!(tx.is_terminated());
        assert_eq!(tx.on_retransmission(), S::None);

        let mut late = server(false);
        send(&mut late, 486, start);

        assert_eq!(late.on_timeout(&TIMERS, start + 64 * T1), S::Timeout);
    }

    #[test]
    fn reliable_server_waits_for_ack_or_h_without_g() {
        let start = Instant::now();
        let mut tx = server(true);
        let sent = send(&mut tx, 486, start);

        assert_eq!(tx.deadline(), Some(start + 64 * T1));
        assert_eq!(tx.on_timeout(&TIMERS, start + T1), S::None);
        assert_eq!(tx.on_retransmission(), sent);
        assert_eq!(tx.on_timeout(&TIMERS, start + 64 * T1), S::Timeout);

        let mut tx = server(true);
        send(&mut tx, 486, start);

        assert_eq!(tx.on_ack(&TIMERS, start + T1), S::Terminated);
        assert!(tx.is_terminated());
    }

    #[test]
    fn non_success_ack_starts_i_and_repeated_ack_does_not_extend_it() {
        let start = Instant::now();
        let mut tx = server(false);
        send(&mut tx, 486, start);

        assert_eq!(tx.on_ack(&TIMERS, start + T1), S::None);

        let end = start + T1 + TIMERS.t4();

        assert_eq!(tx.deadline(), Some(end));
        assert_eq!(tx.on_retransmission(), S::None);
        assert_eq!(tx.on_ack(&TIMERS, start + 2 * T1), S::None);
        assert_eq!(tx.deadline(), Some(end));
        assert_eq!(
            tx.on_timeout(&TIMERS, end - Duration::from_nanos(1)),
            S::None
        );
        assert_eq!(tx.on_timeout(&TIMERS, end), S::Terminated);
        assert_eq!(tx.on_ack(&TIMERS, end), S::None);
    }

    // RFC 6026 8.7/8.8. L remains live across ACK and response transport
    // errors.
    #[test]
    fn accepted_server_absorbs_invites_and_passes_ack_without_restarting_l() {
        let start = Instant::now();
        for reliable in [false, true] {
            let mut tx = server(reliable);

            for offset in 0..3 {
                assert!(matches!(
                    send(
                        &mut tx,
                        200 + offset,
                        start + u32::from(offset) * T1
                    ),
                    S::Send(_)
                ));
                assert_eq!(tx.on_retransmission(), S::None);
                assert_eq!(
                    tx.on_ack(&TIMERS, start + u32::from(offset) * T1),
                    S::Ack
                );
                assert_eq!(tx.on_transport_error(), S::TransportError);
                assert_eq!(tx.deadline(), Some(start + 64 * T1));
            }

            assert_eq!(tx.on_timeout(&TIMERS, start + 63 * T1), S::None);
            assert_eq!(tx.on_timeout(&TIMERS, start + 64 * T1), S::Terminated);
            assert_eq!(tx.on_transport_error(), S::None);
            assert!(tx.is_terminated());
        }
    }

    #[test]
    fn server_transport_failure_preserves_each_live_state() {
        let start = Instant::now();
        for state in 0..4 {
            let mut tx = server(false);

            match state {
                1 => {
                    send(&mut tx, 486, start);
                }
                2 => {
                    send(&mut tx, 486, start);
                    tx.on_ack(&TIMERS, start);
                }
                3 => {
                    send(&mut tx, 200, start);
                }
                _ => {}
            }
            let deadline = tx.deadline();
            let retransmission = tx.on_retransmission();

            assert_eq!(tx.on_transport_error(), S::TransportError);
            assert_eq!(tx.deadline(), deadline);
            assert_eq!(tx.on_retransmission(), retransmission);
            assert!(!tx.is_terminated());
        }
    }

    #[test]
    fn server_rejects_responses_outside_the_current_state() {
        let start = Instant::now();
        for initial in [200, 486] {
            let mut tx = server(false);

            send(&mut tx, initial, start);
            let deadline = tx.deadline();

            for code in [100, 180, 300, 486, 699] {
                assert!(tx
                    .on_response(
                        StatusCode::from_u16(code).unwrap(),
                        Bytes::new(),
                        &TIMERS,
                        start
                    )
                    .is_err());
                assert_eq!(tx.deadline(), deadline);
            }

            if initial == 486 {
                assert!(tx
                    .on_response(StatusCode::OK, Bytes::new(), &TIMERS, start)
                    .is_err());
                tx.on_ack(&TIMERS, start);
                assert!(tx
                    .on_response(StatusCode::OK, Bytes::new(), &TIMERS, start)
                    .is_err());
            }

            tx.on_timeout(&TIMERS, start + 64 * T1);

            assert!(tx
                .on_response(
                    StatusCode::OK,
                    Bytes::new(),
                    &TIMERS,
                    start + 64 * T1
                )
                .is_err());
        }
    }

    #[test]
    fn configurable_d_is_independent_of_t1() {
        let start = Instant::now();
        let timers = Timers::builder()
            .t1(Duration::from_millis(10))
            .d(Duration::from_secs(60))
            .build()
            .unwrap();
        let mut tx =
            ClientTransaction::new(&request(), false, &timers, start).unwrap();
        tx.on_response(response(486, "bob"), &timers, start);

        assert_eq!(tx.deadline(), Some(start + Duration::from_secs(60)));
    }
}
