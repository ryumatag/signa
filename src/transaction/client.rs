/*!
The non-INVITE client transaction of RFC 3261 section 17.1.2.
*/

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::{response::Response, transaction::Timers};

/// A non-INVITE client transaction.
///
/// The caller sends the encoded request once when it creates the transaction,
/// then calls [`ClientTransaction::on_timeout`] when the [`deadline`] passes
/// and [`ClientTransaction::on_response`] for each response that matches (see
/// [`ClientKey`]). Each call returns what to do next. The caller drops the
/// transaction once [`is_terminated`] returns `true`.
///
/// Over an unreliable transport the request is retransmitted on Timer E, which
/// starts at T1 and doubles up to T2. Timer F ends the transaction without a
/// response after 64 T1. After the final response the transaction stays in
/// `Completed` for Timer K, which is T4, to absorb retransmissions of that
/// response. A reliable transport has no retransmissions and ends the
/// transaction with the final response.
///
/// [`ClientKey`]: super::ClientKey
/// [`deadline`]: ClientTransaction::deadline
/// [`is_terminated`]: ClientTransaction::is_terminated
#[derive(Debug)]
pub struct ClientTransaction {
    state: State,
}

/// What the caller does after an event.
#[derive(Debug)]
pub enum ClientEvent {
    /// Nothing.
    None,
    /// Send the request again.
    Retransmit(Bytes),
    /// Hand up a provisional response. The transaction goes on.
    ///
    /// The endpoint does not hand provisional responses up in 0.2.0, since a
    /// non-INVITE request gets none worth seeing (RFC 4320). INVITE
    /// transactions will.
    #[cfg_attr(not(any(test, feature = "__bench")), allow(dead_code))]
    Provisional(Response<Bytes>),
    /// Hand up the final response. The transaction is over for the caller,
    /// though it may linger to absorb retransmissions.
    Final(Response<Bytes>),
    /// Timer F fired without a final response. The transaction is over.
    /// RFC 3261 section 8.1.3.1 treats this as a 408.
    Timeout,
}

/// What the transaction keeps is what its next step needs. The encoded
/// request lives in the states that retransmit it, so that it is freed with
/// the final response rather than with the transaction, and the timers are
/// the caller's, passed in with each event that uses them.
#[derive(Debug)]
enum State {
    /// No response yet. `e` is the next retransmission, `None` over a reliable
    /// transport, and `doublings` how many times the gap before the one after
    /// it has doubled from T1. `f` is the transaction timeout.
    Trying {
        request: Bytes,
        e: Option<Instant>,
        doublings: u8,
        f: Instant,
    },
    /// A provisional response arrived. Retransmissions continue at T2.
    Proceeding {
        request: Bytes,
        e: Option<Instant>,
        f: Instant,
    },
    /// The final response arrived. Retransmissions of it are absorbed until
    /// Timer K.
    Completed {
        k: Instant,
    },
    Terminated,
}

impl ClientTransaction {
    /// Starts a transaction for `request`, which the caller sends now.
    ///
    /// `reliable` says whether the transport retransmits on its own, as TCP
    /// does, or needs the transaction to, as UDP does.
    pub fn new(
        request: Bytes,
        reliable: bool,
        timers: &Timers,
        now: Instant,
    ) -> ClientTransaction {
        let e = if reliable { None } else { Some(now + timers.t1) };
        let f = now + timers.transaction_timeout();

        ClientTransaction {
            state: State::Trying { request, e, doublings: 0, f },
        }
    }

    /// Returns when the caller should call [`on_timeout`] next, or `None` once
    /// the transaction is terminated.
    ///
    /// [`on_timeout`]: ClientTransaction::on_timeout
    pub fn deadline(&self) -> Option<Instant> {
        match self.state {
            State::Trying { e, f, .. } | State::Proceeding { e, f, .. } => {
                Some(e.map_or(f, |e| e.min(f)))
            }
            State::Completed { k } => Some(k),
            State::Terminated => None,
        }
    }

    /// Returns `true` once the transaction is over and can be dropped.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Terminated)
    }

    /// Fires every timer whose deadline has passed at `now`.
    ///
    /// Calling this early is harmless and returns [`ClientEvent::None`]. When
    /// Timer E and Timer F are both due, F wins, since a request sent now
    /// could not be answered in time anyway.
    pub fn on_timeout(
        &mut self,
        timers: &Timers,
        now: Instant,
    ) -> ClientEvent {
        match &mut self.state {
            State::Trying { request, e, doublings, f } => {
                if *f <= now {
                    self.state = State::Terminated;
                    return ClientEvent::Timeout;
                }
                // RFC 3261 section 17.1.2.2 doubles the interval after each
                // retransmission, up to T2.
                match e {
                    Some(due) if *due <= now => {
                        *doublings = doublings.saturating_add(1);
                        *due = now + interval(timers, *doublings);
                        ClientEvent::Retransmit(request.clone())
                    }
                    _ => ClientEvent::None,
                }
            }
            State::Proceeding { request, e, f } => {
                if *f <= now {
                    self.state = State::Terminated;
                    return ClientEvent::Timeout;
                }
                // In Proceeding, every retransmission waits T2.
                match e {
                    Some(due) if *due <= now => {
                        *due = now + timers.t2;
                        ClientEvent::Retransmit(request.clone())
                    }
                    _ => ClientEvent::None,
                }
            }
            State::Completed { k } => {
                if *k <= now {
                    self.state = State::Terminated;
                }
                ClientEvent::None
            }
            State::Terminated => ClientEvent::None,
        }
    }

    /// Takes a response that matches this transaction.
    ///
    /// A provisional response is handed up and the transaction goes on. The
    /// first final response is handed up and ends the transaction for the
    /// caller. Later responses are absorbed.
    pub fn on_response(
        &mut self,
        response: Response<Bytes>,
        timers: &Timers,
        now: Instant,
    ) -> ClientEvent {
        let (e, f) = match self.state {
            State::Trying { e, f, .. } | State::Proceeding { e, f, .. } => {
                (e, f)
            }
            State::Completed { .. } | State::Terminated => {
                return ClientEvent::None
            }
        };

        if response.status().is_final() {
            // Timer K is T4 over an unreliable transport, where a
            // retransmitted response may still arrive, and zero over a
            // reliable one. The request goes with the old state.
            self.state = match e {
                Some(_) => State::Completed { k: now + timers.t4 },
                None => State::Terminated,
            };

            return ClientEvent::Final(response);
        }

        // The retransmission that is due next keeps its deadline. Only the
        // interval after it changes, to T2.
        let request =
            match std::mem::replace(&mut self.state, State::Terminated) {
                State::Trying { request, .. }
                | State::Proceeding { request, .. } => request,
                State::Completed { .. } | State::Terminated => {
                    unreachable!("checked above")
                }
            };
        self.state = State::Proceeding { request, e, f };

        ClientEvent::Provisional(response)
    }

    /// Ends the transaction because the transport could not send the request.
    ///
    /// RFC 3261 section 8.1.3.1 treats this as a 503. The caller reports
    /// it, since the error happened in the caller's hands.
    pub fn on_transport_error(&mut self) {
        self.state = State::Terminated;
    }
}

/// The gap before the next retransmission after `doublings` of them, T1
/// doubled that many times and no more than T2.
///
/// The count stands in for the interval itself, which is 16 bytes, and
/// saturates where the interval would overflow, which is past T2 anyway.
fn interval(timers: &Timers, doublings: u8) -> Duration {
    let factor = 1u32.checked_shl(u32::from(doublings)).unwrap_or(u32::MAX);

    timers.t1.checked_mul(factor).map_or(timers.t2, |gap| gap.min(timers.t2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusCode;

    const T1: Duration = Duration::from_millis(500);
    const T2: Duration = Duration::from_secs(4);
    const T4: Duration = Duration::from_secs(5);
    const TIMERS: Timers = Timers { t1: T1, t2: T2, t4: T4 };

    fn request() -> Bytes {
        Bytes::from_static(b"OPTIONS sip:a@b SIP/2.0\r\n\r\n")
    }

    fn response(status: u16) -> Response<Bytes> {
        Response::builder().status(status).body(Bytes::new()).unwrap()
    }

    fn status(event: &ClientEvent) -> Option<StatusCode> {
        match event {
            ClientEvent::Provisional(r) | ClientEvent::Final(r) => {
                Some(r.status())
            }
            _ => None,
        }
    }

    #[test]
    fn retransmits_on_timer_e_until_timer_f() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), false, &TIMERS, start);

        // T1, then doubling, then every T2.
        let mut now = start;
        let mut sent = Vec::new();
        for ms in [500, 1000, 2000, 4000, 4000, 4000, 4000, 4000, 4000, 4000] {
            let deadline = tx.deadline().unwrap();
            assert_eq!(deadline, now + Duration::from_millis(ms));
            now = deadline;
            let event = tx.on_timeout(&TIMERS, now);
            assert!(
                matches!(event, ClientEvent::Retransmit(ref b) if *b == request()),
                "{event:?}"
            );
            sent.push(now - start);
        }
        assert_eq!(sent.last(), Some(&Duration::from_millis(31_500)));

        // Timer F at 64 T1 comes before the next E and ends it all.
        let f = start + 64 * T1;
        assert_eq!(tx.deadline(), Some(f));
        assert!(matches!(tx.on_timeout(&TIMERS, f), ClientEvent::Timeout));
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
        assert!(matches!(tx.on_timeout(&TIMERS, f + T1), ClientEvent::None));
        assert!(matches!(
            tx.on_response(response(200), &TIMERS, f),
            ClientEvent::None
        ));
    }

    #[test]
    fn calling_on_timeout_early_does_nothing() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), false, &TIMERS, start);
        assert!(matches!(tx.on_timeout(&TIMERS, start), ClientEvent::None));
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + T1 - Duration::from_millis(1)),
            ClientEvent::None
        ));
        assert_eq!(tx.deadline(), Some(start + T1));
    }

    #[test]
    fn timer_f_wins_when_both_are_due() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), false, &TIMERS, start);
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + 64 * T1),
            ClientEvent::Timeout
        ));
        assert!(tx.is_terminated());
    }

    #[test]
    fn a_provisional_response_moves_retransmissions_to_t2() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), false, &TIMERS, start);

        let event = tx.on_response(
            response(100),
            &TIMERS,
            start + Duration::from_millis(100),
        );
        assert_eq!(status(&event), Some(StatusCode::from_u16(100).unwrap()));

        // The retransmission that was due stays due, the next waits T2.
        assert_eq!(tx.deadline(), Some(start + T1));
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + T1),
            ClientEvent::Retransmit(_)
        ));
        assert_eq!(tx.deadline(), Some(start + T1 + T2));
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + T1 + T2),
            ClientEvent::Retransmit(_)
        ));
        assert_eq!(tx.deadline(), Some(start + T1 + 2 * T2));

        // More provisionals change nothing. Timer F still ends it.
        let event = tx.on_response(response(100), &TIMERS, start + 2 * T2);
        assert!(matches!(event, ClientEvent::Provisional(_)));
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + 64 * T1),
            ClientEvent::Timeout
        ));
    }

    #[test]
    fn the_final_response_ends_it_after_timer_k() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), false, &TIMERS, start);

        let at = start + Duration::from_millis(300);
        let event = tx.on_response(response(404), &TIMERS, at);
        assert_eq!(status(&event), Some(StatusCode::from_u16(404).unwrap()));
        assert!(matches!(event, ClientEvent::Final(_)));
        assert!(!tx.is_terminated());

        // Completed absorbs retransmitted responses and sends nothing.
        assert_eq!(tx.deadline(), Some(at + T4));
        assert!(matches!(
            tx.on_response(response(404), &TIMERS, at + T1),
            ClientEvent::None
        ));
        assert!(matches!(
            tx.on_response(response(200), &TIMERS, at + T1),
            ClientEvent::None
        ));
        assert!(matches!(tx.on_timeout(&TIMERS, at + T1), ClientEvent::None));
        assert!(!tx.is_terminated());

        assert!(matches!(tx.on_timeout(&TIMERS, at + T4), ClientEvent::None));
        assert!(tx.is_terminated());
    }

    #[test]
    fn a_reliable_transport_never_retransmits_and_ends_with_the_response() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), true, &TIMERS, start);
        assert_eq!(tx.deadline(), Some(start + 64 * T1));
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + T2),
            ClientEvent::None
        ));

        let event = tx.on_response(response(180), &TIMERS, start + T2);
        assert!(matches!(event, ClientEvent::Provisional(_)));
        assert_eq!(tx.deadline(), Some(start + 64 * T1));

        let event = tx.on_response(response(200), &TIMERS, start + 2 * T2);
        assert!(matches!(event, ClientEvent::Final(_)));
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
    }

    #[test]
    fn a_reliable_transport_still_times_out() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), true, &TIMERS, start);
        assert!(matches!(
            tx.on_timeout(&TIMERS, start + 64 * T1),
            ClientEvent::Timeout
        ));
        assert!(tx.is_terminated());
    }

    #[test]
    fn a_transport_error_ends_it() {
        let start = Instant::now();
        let mut tx = ClientTransaction::new(request(), false, &TIMERS, start);
        tx.on_transport_error();
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
        assert!(matches!(
            tx.on_response(response(200), &TIMERS, start),
            ClientEvent::None
        ));
    }
}
