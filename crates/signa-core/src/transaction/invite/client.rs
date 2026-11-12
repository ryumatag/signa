use std::{fmt, time::Instant};

use bytes::Bytes;

use crate::{
    message::{
        Method,
        header::{
            CALL_ID, CSEQ, FROM, HeaderName, HeaderValue, MAX_FORWARDS, ROUTE,
            TO, VIA, cseq::CSeq, via::Via,
        },
        request::{self, Request},
        response::Response,
    },
    transaction::Timers,
};

/// The INVITE client machine, including RFC 6026's Accepted state.
#[derive(Debug)]
pub struct ClientTransaction {
    state: State,
}

#[derive(Debug)]
enum State {
    Calling {
        request: Bytes,
        ack: request::Parts,
        a: Option<Instant>,
        b: Instant,
        doublings: u8,
    },
    // Request retransmissions stop at the first provisional. Only the fields
    // that the ACK and CANCEL copy survive until a final response.
    Proceeding {
        ack: request::Parts,
        reliable: bool,
    },
    Completed {
        ack: Bytes,
        d: Instant,
    },
    Accepted {
        m: Instant,
    },
    Terminated,
}

/// Actions for the caller. A non-2xx final delivers both a response and ACK.
#[derive(Debug)]
pub enum ClientEvent {
    /// No action is required.
    None,
    /// Retransmit on the original next hop.
    Send(Bytes),
    /// Deliver a provisional response to the TU.
    Provisional(Response<Bytes>),
    /// Deliver a final response and submit the transaction ACK, if present.
    Final {
        /// The received final response.
        response: Response<Bytes>,
        /// Non-2xx ACK bytes. The TU owns ACK for 2xx.
        ack: Option<Bytes>,
    },
    /// A non-2xx final without To cannot be acknowledged. State is unchanged.
    InvalidResponse,
    /// Timer B elapsed without a response.
    Timeout,
    /// A request or ACK write failed and ended the transaction.
    TransportError,
    /// Timer D or M elapsed.
    Terminated,
}

/// An INVITE cannot supply the fields needed for the transaction ACK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidInvite {
    /// The request method is not INVITE.
    Method,
    /// A required header is absent or empty.
    Missing(HeaderName),
    /// CSeq has an invalid number or method.
    CSeq,
    /// The top Via cannot be parsed.
    Via,
}

impl fmt::Display for InvalidInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidInvite::Method => f.write_str("expected an INVITE"),
            InvalidInvite::Missing(name) => {
                write!(f, "missing {name} for the INVITE ACK")
            }
            InvalidInvite::CSeq => f.write_str("invalid INVITE CSeq"),
            InvalidInvite::Via => f.write_str("invalid INVITE Via"),
        }
    }
}

impl std::error::Error for InvalidInvite {}

impl ClientTransaction {
    /// Starts after the caller submits the first INVITE to transport.
    ///
    /// The request already has its top Via. The caller validates complete
    /// header semantics. This constructor checks the fields it reads and keeps
    /// a bodyless template for the ACK and the CANCEL, without retaining the
    /// input buffer.
    pub fn new(
        request: &Request<Bytes>,
        reliable: bool,
        timers: &Timers,
        now: Instant,
    ) -> Result<ClientTransaction, InvalidInvite> {
        ClientTransaction::from_encoded(
            request,
            request.to_bytes(),
            reliable,
            timers,
            now,
        )
    }

    /// [`ClientTransaction::new`] for a caller that has encoded `request`
    /// already, as `encoded`, to send it.
    pub fn from_encoded(
        request: &Request<Bytes>,
        encoded: Bytes,
        reliable: bool,
        timers: &Timers,
        now: Instant,
    ) -> Result<ClientTransaction, InvalidInvite> {
        let ack = template(request)?;

        Ok(ClientTransaction {
            state: State::Calling {
                request: encoded,
                ack,
                a: (!reliable).then_some(now + timers.t1()),
                b: now + timers.transaction_timeout(),
                doublings: 0,
            },
        })
    }

    /// Whether the driver can remove this transaction.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Terminated)
    }

    /// Whether no response has arrived yet.
    pub fn is_calling(&self) -> bool {
        matches!(self.state, State::Calling { .. })
    }

    /// Whether a provisional response has arrived, but no final one.
    pub fn is_proceeding(&self) -> bool {
        matches!(self.state, State::Proceeding { .. })
    }

    /// The next timer deadline, if this state has a timer.
    pub fn deadline(&self) -> Option<Instant> {
        match self.state {
            State::Calling { a, b, .. } => Some(a.map_or(b, |a| a.min(b))),
            State::Completed { d, .. } => Some(d),
            State::Accepted { m } => Some(m),
            State::Proceeding { .. } | State::Terminated => None,
        }
    }

    /// Processes a due timer. Calling before the deadline does nothing.
    pub fn on_timeout(
        &mut self,
        timers: &Timers,
        now: Instant,
    ) -> ClientEvent {
        match &mut self.state {
            State::Calling { b, .. } if *b <= now => {
                self.state = State::Terminated;
                ClientEvent::Timeout
            }
            State::Calling { request, a: Some(a), b, doublings, .. }
                if *a <= now =>
            {
                // B fires before a seventh doubling. A has no T2 cap.
                *doublings += 1;
                let gap = timers.t1() * (1 << *doublings);
                *a = now + gap.min(b.saturating_duration_since(now));
                ClientEvent::Send(request.clone())
            }
            State::Completed { d, .. } if *d <= now => {
                self.state = State::Terminated;
                ClientEvent::Terminated
            }
            State::Accepted { m } if *m <= now => {
                self.state = State::Terminated;
                ClientEvent::Terminated
            }
            _ => ClientEvent::None,
        }
    }

    /// Processes a matched response. Run due timers first at equal times.
    pub fn on_response(
        &mut self,
        response: Response<Bytes>,
        timers: &Timers,
        now: Instant,
    ) -> ClientEvent {
        let code = response.status().as_u16();

        match &self.state {
            State::Completed { ack, .. } => {
                if code >= 300 {
                    ClientEvent::Send(ack.clone())
                } else {
                    ClientEvent::None
                }
            }
            State::Accepted { .. } => {
                if (200..300).contains(&code) {
                    ClientEvent::Final { response, ack: None }
                } else {
                    ClientEvent::None
                }
            }
            State::Terminated => ClientEvent::None,

            State::Calling { .. } | State::Proceeding { .. } => {
                if code >= 300
                    && response
                        .headers()
                        .get(TO)
                        .is_none_or(|v| v.as_str().trim().is_empty())
                {
                    return ClientEvent::InvalidResponse;
                }

                let (mut ack, reliable) = match std::mem::replace(
                    &mut self.state,
                    State::Terminated,
                ) {
                    State::Calling { ack, a, .. } => (ack, a.is_none()),
                    State::Proceeding { ack, reliable } => (ack, reliable),
                    _ => unreachable!("active state checked above"),
                };

                match code {
                    ..=199 => {
                        self.state = State::Proceeding { ack, reliable };
                        ClientEvent::Provisional(response)
                    }
                    200..=299 => {
                        self.state = State::Accepted {
                            m: now + timers.transaction_timeout(),
                        };

                        ClientEvent::Final { response, ack: None }
                    }
                    _ => {
                        ack.headers.insert(
                            TO,
                            response
                                .headers()
                                .get(TO)
                                .expect("checked above")
                                .clone(),
                        );

                        let ack =
                            Request::from_parts(ack, Bytes::new()).to_bytes();

                        if !reliable {
                            self.state = State::Completed {
                                ack: ack.clone(),
                                d: now + timers.d(),
                            };
                        }

                        ClientEvent::Final { response, ack: Some(ack) }
                    }
                }
            }
        }
    }

    /// Reports a failed INVITE or transaction ACK send.
    ///
    /// Accepted sends nothing. An error from an earlier write cannot remove
    /// the state that RFC 6026 retains for forked 2xx responses.
    pub fn on_transport_error(&mut self) -> ClientEvent {
        match self.state {
            State::Calling { .. }
            | State::Proceeding { .. }
            | State::Completed { .. } => {
                self.state = State::Terminated;
                ClientEvent::TransportError
            }
            State::Accepted { .. } | State::Terminated => ClientEvent::None,
        }
    }

    /// Builds the CANCEL for this INVITE, once a provisional response has
    /// arrived and before a final one.
    ///
    /// [RFC 3261 section 9.1] copies the Request-URI, Call-ID, To, From and
    /// the CSeq number, the Route values and the single top Via. The CSeq
    /// method is CANCEL, and neither Require nor Proxy-Require is present.
    /// The caller starts a separate non-INVITE transaction with it.
    ///
    /// [RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
    pub fn cancel_request(&self) -> Option<Request<Bytes>> {
        let State::Proceeding { ack, .. } = &self.state else { return None };
        let number = ack
            .headers
            .get(CSEQ)
            .and_then(CSeq::parse)
            .expect("the template has a valid CSeq")
            .number;

        let mut parts = request::Parts::new(Method::CANCEL, ack.uri.copy());
        parts.headers = ack.headers.clone();
        parts
            .headers
            .insert(CSEQ, HeaderValue::from_built(format!("{number} CANCEL")));

        Some(Request::from_parts(parts, Bytes::new()))
    }

    /// Ends Calling or Proceeding without a final response.
    ///
    /// The driver calls this when its cancellation deadline passes, 64 T1
    /// after it sent a CANCEL ([RFC 3261 section 9.1]). This is not Timer B,
    /// which only times out Calling. Returns `false` once a final response
    /// has arrived, which the caller then processes normally.
    ///
    /// [RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
    pub fn abandon(&mut self) -> bool {
        if matches!(
            self.state,
            State::Calling { .. } | State::Proceeding { .. }
        ) {
            self.state = State::Terminated;
            true
        } else {
            false
        }
    }
}

/// RFC 3261 sections 17.1.1.3 and 9.1. Copy selected values so a large INVITE
/// body or read chunk is not retained throughout Proceeding by a header slice.
///
/// The template is the ACK with the INVITE's own To. A non-2xx final replaces
/// To with the response's, and a CANCEL keeps it.
fn template(
    request: &Request<Bytes>,
) -> Result<request::Parts, InvalidInvite> {
    if request.method() != Method::INVITE {
        return Err(InvalidInvite::Method);
    }

    let headers = request.headers();
    let required = |name: HeaderName| {
        headers
            .get(&name)
            .filter(|v| !v.as_str().trim().is_empty())
            .ok_or(InvalidInvite::Missing(name))
    };

    let cseq = CSeq::parse(required(CSEQ)?).ok_or(InvalidInvite::CSeq)?;
    if cseq.method != Method::INVITE || cseq.number >= 1 << 31 {
        return Err(InvalidInvite::CSeq);
    }

    let via_value = required(VIA)?;
    let via = Via::top(via_value).ok_or(InvalidInvite::Via)?;

    // The URI has already been validated. This copy changes ownership only.
    let mut ack = request::Parts::new(Method::ACK, request.uri().copy());
    ack.headers.append(
        VIA,
        HeaderValue::from_built(via_value.as_str()[..via.end].to_owned()),
    );

    for name in [FROM, TO, CALL_ID] {
        let value = HeaderValue::from_built(
            required(name.clone())?.as_str().to_owned(),
        );
        ack.headers.append(name, value);
    }

    ack.headers
        .append(CSEQ, HeaderValue::from_built(format!("{} ACK", cseq.number)));
    ack.headers.append(MAX_FORWARDS, HeaderValue::from_static("70"));
    for route in headers.get_all(ROUTE) {
        ack.headers
            .append(ROUTE, HeaderValue::from_built(route.as_str().to_owned()));
    }

    Ok(ack)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::tests::{T1, TIMERS, request, response};
    use super::ClientEvent as C;
    use super::*;
    use crate::message::header::CONTENT_TYPE;

    #[test]
    fn proceeding_does_not_retain_the_request_buffer() {
        let input = Bytes::copy_from_slice(super::super::tests::INVITE);
        let range = input.as_ptr_range();
        let request = Request::from_shared(input.clone()).unwrap();
        let now = Instant::now();
        let timers = Timers::new();
        let mut tx =
            ClientTransaction::new(&request, false, &timers, now).unwrap();

        let response = Response::reply_to(&request)
            .status(180)
            .body(Bytes::new())
            .unwrap();

        assert!(matches!(
            tx.on_response(response, &timers, now),
            ClientEvent::Provisional(_)
        ));

        let State::Proceeding { ack, .. } = &tx.state else {
            panic!("provisional response must enter Proceeding");
        };

        assert!(!range.contains(&ack.uri.as_str().as_ptr()));
        for (_, value) in &ack.headers {
            assert!(!range.contains(&value.as_bytes().as_ptr()));
        }
        drop(request);
        assert!(input.is_unique());
    }
    fn client(reliable: bool, now: Instant) -> ClientTransaction {
        ClientTransaction::new(&request(), reliable, &TIMERS, now).unwrap()
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

    // RFC 3261 section 9.1. Only Proceeding can be cancelled, and the
    // CANCEL keeps the INVITE's own To even after the template served an ACK.
    #[test]
    fn cancel_copies_the_invite_identity_routing_and_top_via() {
        let start = Instant::now();
        let mut tx = client(false, start);
        assert!(tx.is_calling());
        assert!(tx.cancel_request().is_none());

        tx.on_response(response(180, "early"), &TIMERS, start);
        assert!(tx.is_proceeding());
        let cancel = tx.cancel_request().unwrap();
        let invite = request();

        assert_eq!(cancel.method(), Method::CANCEL);
        assert_eq!(cancel.uri().as_str(), invite.uri().as_str());
        for name in [FROM, TO, CALL_ID] {
            assert_eq!(
                cancel.headers().get(&name),
                invite.headers().get(&name)
            );
        }
        assert_eq!(cancel.headers().get(CSEQ).unwrap(), "314159 CANCEL");
        assert_eq!(
            cancel.headers().get_all(VIA).collect::<Vec<_>>(),
            ["SIP/2.0/UDP atlanta.example.com:5060;\
              branch=z9hG4bKfirst;x=\"a,b\""]
        );
        assert_eq!(
            cancel.headers().get_all(ROUTE).collect::<Vec<_>>(),
            invite.headers().get_all(ROUTE).collect::<Vec<_>>()
        );
        for name in ["Require", "Proxy-Require", "Content-Type"] {
            assert!(!cancel.headers().contains_key(name), "{name}");
        }
        assert!(cancel.body().is_empty());

        assert!(matches!(
            tx.on_response(response(487, "late"), &TIMERS, start),
            C::Final { ack: Some(_), .. }
        ));
        assert!(tx.cancel_request().is_none());
    }

    // The driver's cancellation deadline, not Timer B. A final that won the
    // race leaves nothing to abandon.
    #[test]
    fn abandon_ends_only_states_without_a_final() {
        let start = Instant::now();
        let mut tx = client(false, start);
        assert!(tx.abandon());
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);

        let mut tx = client(true, start);
        tx.on_response(response(183, "early"), &TIMERS, start);
        assert!(tx.abandon());
        assert!(matches!(
            tx.on_response(response(200, "late"), &TIMERS, start),
            C::None
        ));

        for code in [200, 486] {
            let mut tx = client(false, start);
            tx.on_response(response(code, "bob"), &TIMERS, start);
            let deadline = tx.deadline();

            assert!(!tx.abandon());
            assert_eq!(tx.deadline(), deadline);
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
