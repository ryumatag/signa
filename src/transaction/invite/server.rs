use std::{
    fmt,
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::{
    message::{
        header::HeaderMap,
        request::Request,
        response::{bare_response, reply_headers},
        StatusCode,
    },
    transaction::Timers,
};

/// The INVITE server machine, including RFC 6026's Accepted state.
#[derive(Debug)]
pub struct ServerTransaction {
    state: State,
}

#[derive(Debug)]
enum State {
    Proceeding {
        response: Bytes,
        headers: HeaderMap,
        reliable: bool,
    },
    Completed {
        response: Bytes,
        g: Option<Instant>,
        h: Instant,
        interval: Duration,
    },
    Confirmed {
        i: Instant,
    },
    Accepted {
        l: Instant,
    },
    Terminated,
}

/// Actions to perform outside the machine.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerEvent {
    /// No action is required.
    None,
    /// Send on the transaction's original reply route.
    Send(Bytes),
    /// Pass this ACK to the TU. It does not terminate Accepted.
    Ack,
    /// Timer H elapsed without the transaction ACK.
    Timeout,
    /// Notify the TU without discarding transaction state.
    TransportError,
    /// Timer I or L elapsed, or a reliable transaction received its ACK.
    Terminated,
}

/// The TU supplied a response that the current state cannot send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseError;

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("response is not permitted in the INVITE server state")
    }
}

impl std::error::Error for ResponseError {}

impl ServerTransaction {
    /// Creates Proceeding and returns the initial 100 to send immediately.
    ///
    /// The driver performs request validation and admission before this call.
    /// Sending 100 immediately satisfies RFC 3261 section 17.2.1 without
    /// predicting whether the TU can respond within 200 ms.
    pub fn new(
        request: &Request<Bytes>,
        reliable: bool,
    ) -> (ServerTransaction, Bytes) {
        let headers = reply_headers(request.headers());
        let response = bare_response(&headers, StatusCode::TRYING);
        let tx = ServerTransaction {
            state: State::Proceeding {
                response: response.clone(),
                headers,
                reliable,
            },
        };
        (tx, response)
    }

    /// Reply headers for a fallback response while the TU can still answer.
    pub fn headers(&self) -> Option<&HeaderMap> {
        match &self.state {
            State::Proceeding { headers, .. } => Some(headers),
            _ => None,
        }
    }

    /// Whether the driver can remove this transaction.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Terminated)
    }

    /// The next timer deadline, if this state has a timer.
    pub fn deadline(&self) -> Option<Instant> {
        match self.state {
            State::Completed { g, h, .. } => Some(g.map_or(h, |g| g.min(h))),
            State::Confirmed { i } => Some(i),
            State::Accepted { l } => Some(l),
            State::Proceeding { .. } | State::Terminated => None,
        }
    }

    /// The caller has validated and encoded the TU response.
    pub fn on_response(
        &mut self,
        status: StatusCode,
        response: Bytes,
        timers: &Timers,
        now: Instant,
    ) -> Result<ServerEvent, ResponseError> {
        match &mut self.state {
            State::Proceeding { response: last, reliable, .. } => {
                if status.is_provisional() {
                    *last = response.clone();
                } else if status.is_success() {
                    self.state = State::Accepted {
                        l: now + timers.transaction_timeout(),
                    };
                } else {
                    self.state = State::Completed {
                        response: response.clone(),
                        g: (!*reliable).then_some(now + timers.t1()),
                        h: now + timers.transaction_timeout(),
                        interval: timers.t1(),
                    };
                }
                Ok(ServerEvent::Send(response))
            }
            State::Accepted { .. } if status.is_success() => {
                Ok(ServerEvent::Send(response))
            }
            _ => Err(ResponseError),
        }
    }

    /// Processes a matched INVITE retransmission.
    pub fn on_retransmission(&self) -> ServerEvent {
        match &self.state {
            State::Proceeding { response, .. }
            | State::Completed { response, .. } => {
                ServerEvent::Send(response.clone())
            }
            _ => ServerEvent::None,
        }
    }

    /// Absorbs a non-2xx ACK or hands an Accepted-state ACK to the TU.
    pub fn on_ack(&mut self, timers: &Timers, now: Instant) -> ServerEvent {
        match self.state {
            State::Completed { g, .. } => {
                if g.is_some() {
                    self.state = State::Confirmed { i: now + timers.t4() };
                    ServerEvent::None
                } else {
                    self.state = State::Terminated;
                    ServerEvent::Terminated
                }
            }
            State::Accepted { .. } => ServerEvent::Ack,
            _ => ServerEvent::None,
        }
    }

    /// Processes a due timer, with H taking precedence over G.
    pub fn on_timeout(
        &mut self,
        timers: &Timers,
        now: Instant,
    ) -> ServerEvent {
        match &mut self.state {
            State::Completed { h, .. } if *h <= now => {
                self.state = State::Terminated;
                ServerEvent::Timeout
            }
            State::Completed { response, g: Some(g), h, interval }
                if *g <= now =>
            {
                *interval = interval.saturating_mul(2).min(timers.t2());
                *g = now + (*interval).min(h.saturating_duration_since(now));
                ServerEvent::Send(response.clone())
            }
            State::Confirmed { i } if *i <= now => {
                self.state = State::Terminated;
                ServerEvent::Terminated
            }
            State::Accepted { l } if *l <= now => {
                self.state = State::Terminated;
                ServerEvent::Terminated
            }
            _ => ServerEvent::None,
        }
    }

    /// RFC 6026 section 8.8 retains state after a response transport error.
    pub fn on_transport_error(&self) -> ServerEvent {
        if self.is_terminated() {
            ServerEvent::None
        } else {
            ServerEvent::TransportError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{request, response, T1, TIMERS};
    use super::ServerEvent as S;
    use super::*;
    use crate::message::Response;
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
}
