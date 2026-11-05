/*!
The non-INVITE server transaction of RFC 3261 section 17.2.2.
*/

use std::time::Instant;

use bytes::Bytes;

use super::Timers;
use crate::{
    header::HeaderMap,
    response::{self, reply_headers},
    Request, Response, StatusCode,
};

/// A non-INVITE server transaction.
///
/// The caller creates one when a request arrives that matches no transaction
/// (see [`ServerKey`]) and hands the request up. Retransmissions of the
/// request go to [`ServerTransaction::on_retransmission`], which says what to
/// send back instead of handing them up again. The transaction user's response
/// goes through [`ServerTransaction::on_response`], and
/// [`ServerTransaction::on_timeout`] runs when the [`deadline`] passes. The
/// caller drops the transaction once [`is_terminated`] returns `true`.
///
/// After the final response the transaction stays in `Completed` for Timer J,
/// which is 64 T1 over an unreliable transport and zero over a reliable one,
/// to answer retransmissions with that response.
///
/// RFC 4320 section 4 shapes what goes out. A provisional response other than
/// 100 is dropped. A 100 is sent by the transaction itself if nothing else was
/// sent by the time the client's Timer E reaches T2, and never before that. A
/// 408 is dropped and ends the transaction, since the client gives up at the
/// same time anyway. The transaction user therefore has no reason to send
/// anything but the final response.
///
/// [`ServerKey`]: super::ServerKey
/// [`deadline`]: ServerTransaction::deadline
/// [`is_terminated`]: ServerTransaction::is_terminated
#[derive(Debug)]
pub struct ServerTransaction {
    timers: Timers,
    reliable: bool,
    /// The header fields a response has to carry, copied from the request for
    /// the 100 that the transaction may send itself.
    headers: HeaderMap,
    state: State,
}

#[derive(Debug)]
enum State {
    /// Nothing sent. At `trying`, a 100 goes out on its own.
    Trying {
        trying: Instant,
    },
    /// A provisional response went out. Retransmissions get it again.
    Proceeding {
        response: Bytes,
    },
    /// The final response went out. Retransmissions get it again until
    /// Timer J.
    Completed {
        response: Bytes,
        j: Instant,
    },
    Terminated,
}

const TRYING: StatusCode = match StatusCode::from_u16(100) {
    Ok(status) => status,
    Err(_) => panic!("100 is a status code"),
};

const REQUEST_TIMEOUT: StatusCode = match StatusCode::from_u16(408) {
    Ok(status) => status,
    Err(_) => panic!("408 is a status code"),
};

impl ServerTransaction {
    /// Starts a transaction for `request`, which the caller hands up.
    ///
    /// `reliable` says whether the transport retransmits on its own, as TCP
    /// does, or needs the transaction to, as UDP does.
    pub fn new(
        request: &Request<Bytes>,
        reliable: bool,
        timers: Timers,
        now: Instant,
    ) -> ServerTransaction {
        ServerTransaction {
            timers,
            reliable,
            headers: reply_headers(request.headers()),
            state: State::Trying { trying: now + timers.trying_after() },
        }
    }

    /// The header fields a response to the request has to carry, as the
    /// request had them. The caller builds a response of its own from them,
    /// such as a 500 when the transaction user gave it nothing usable.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns when the caller should call [`on_timeout`] next, or `None` when
    /// no timer runs.
    ///
    /// [`on_timeout`]: ServerTransaction::on_timeout
    pub fn deadline(&self) -> Option<Instant> {
        match self.state {
            State::Trying { trying } => Some(trying),
            State::Proceeding { .. } | State::Terminated => None,
            State::Completed { j, .. } => Some(j),
        }
    }

    /// Returns `true` once the transaction is over and can be dropped.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Terminated)
    }

    /// Fires the timer whose deadline has passed at `now`.
    ///
    /// Returns a 100 to send when the transaction user has not responded in
    /// time (RFC 4320 section 4.1). Calling this early is harmless.
    pub fn on_timeout(&mut self, now: Instant) -> Option<Bytes> {
        match &self.state {
            State::Trying { trying } if *trying <= now => {
                let response = bare_response(&self.headers, TRYING);
                self.state = State::Proceeding { response: response.clone() };

                Some(response)
            }
            State::Completed { j, .. } if *j <= now => {
                self.state = State::Terminated;

                None
            }
            _ => None,
        }
    }

    /// Takes a retransmission of the request and returns what to send back.
    ///
    /// Nothing before a response went out, the last provisional response in
    /// `Proceeding`, and the final response in `Completed`.
    pub fn on_retransmission(&self) -> Option<Bytes> {
        match &self.state {
            State::Proceeding { response }
            | State::Completed { response, .. } => Some(response.clone()),
            State::Trying { .. } | State::Terminated => None,
        }
    }

    /// Takes a response from the transaction user, encoded by the caller, and
    /// returns `true` if the caller sends it.
    ///
    /// A provisional response other than 100 and a 408 are not sent (RFC 4320
    /// section 4). The 408 still ends the transaction. Anything after the
    /// final response is not sent either.
    pub fn on_response(
        &mut self,
        status: StatusCode,
        response: Bytes,
        now: Instant,
    ) -> bool {
        match self.state {
            State::Trying { .. } | State::Proceeding { .. } => {}
            State::Completed { .. } | State::Terminated => return false,
        }

        if !status.is_final() {
            if status != TRYING {
                return false;
            }
            self.state = State::Proceeding { response };

            return true;
        }

        if status == REQUEST_TIMEOUT {
            self.state = State::Terminated;

            return false;
        }

        // Timer J is 64 T1 over an unreliable transport, where the request may
        // still be retransmitted, and zero over a reliable one.
        self.state = if self.reliable {
            State::Terminated
        } else {
            State::Completed {
                response,
                j: now + self.timers.transaction_timeout(),
            }
        };

        true
    }

    /// Ends the transaction because the transport could not send a response.
    pub fn on_transport_error(&mut self) {
        self.state = State::Terminated;
    }
}

/// Encodes a response with `status`, `headers`, and no body. This is what the
/// transaction layer sends on its own, such as the 100 and the 500.
pub(crate) fn bare_response(headers: &HeaderMap, status: StatusCode) -> Bytes {
    let mut parts = response::Parts::new(status);
    parts.headers = headers.clone();

    Response::from_parts(parts, Bytes::new()).to_bytes()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const T1: Duration = Duration::from_millis(500);

    const REQUEST: &[u8] = b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bKnashds8\r\n\
        Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
        Max-Forwards: 70\r\n\
        To: <sip:carol@chicago.example.com>\r\n\
        From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 63104 OPTIONS\r\n\
        Content-Length: 0\r\n\
        \r\n";

    fn request() -> Request<Bytes> {
        Request::from_bytes(REQUEST).unwrap()
    }

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    fn response(code: u16) -> Bytes {
        Bytes::from(format!("SIP/2.0 {code} X\r\n\r\n"))
    }

    fn transaction(reliable: bool, now: Instant) -> ServerTransaction {
        ServerTransaction::new(&request(), reliable, Timers::default(), now)
    }

    #[test]
    fn sends_a_100_itself_when_nothing_was_sent_in_time() {
        let start = Instant::now();
        let mut tx = transaction(false, start);

        // Retransmissions before any response are absorbed.
        assert_eq!(tx.on_retransmission(), None);
        assert_eq!(tx.deadline(), Some(start + 7 * T1));
        assert_eq!(tx.on_timeout(start + 6 * T1), None);

        let trying = tx.on_timeout(start + 7 * T1).unwrap();
        let trying = Response::from_shared(trying).unwrap();
        assert_eq!(trying.status(), status(100));
        let rows: Vec<_> = trying
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("Via", "SIP/2.0/UDP proxy.example.com;branch=z9hG4bKnashds8"),
                ("Via", "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877"),
                ("To", "<sip:carol@chicago.example.com>"),
                ("From", "Alice <sip:alice@atlanta.example.com>;tag=1928301774"),
                ("Call-ID", "a84b4c76e66710"),
                ("CSeq", "63104 OPTIONS"),
                ("Content-Length", "0"),
            ]
        );

        // Proceeding has no timer and answers retransmissions with the 100.
        assert_eq!(tx.deadline(), None);
        assert_eq!(tx.on_timeout(start + 64 * T1), None);
        let again = tx.on_retransmission().unwrap();
        assert_eq!(
            Response::from_shared(again).unwrap().status(),
            status(100)
        );
        assert!(!tx.is_terminated());
    }

    #[test]
    fn a_response_in_time_cancels_the_100() {
        let start = Instant::now();
        let mut tx = transaction(false, start);
        assert!(tx.on_response(status(200), response(200), start + T1));
        assert_eq!(tx.deadline(), Some(start + T1 + 64 * T1));
        assert_eq!(tx.on_timeout(start + 7 * T1), None);
        assert_eq!(tx.on_retransmission(), Some(response(200)));
    }

    #[test]
    fn a_100_from_the_user_is_sent_and_other_provisionals_are_not() {
        let start = Instant::now();
        let mut tx = transaction(false, start);
        assert!(!tx.on_response(status(180), response(180), start));
        assert_eq!(tx.on_retransmission(), None);
        assert!(tx.on_response(status(100), response(100), start));
        assert_eq!(tx.on_retransmission(), Some(response(100)));
        assert_eq!(tx.deadline(), None);
        assert!(!tx.on_response(status(183), response(183), start));
        assert_eq!(tx.on_retransmission(), Some(response(100)));
    }

    #[test]
    fn the_final_response_is_resent_until_timer_j() {
        let start = Instant::now();
        let mut tx = transaction(false, start);
        assert!(tx.on_response(status(100), response(100), start + T1));
        let at = start + 2 * T1;
        assert!(tx.on_response(status(486), response(486), at));
        assert!(!tx.is_terminated());
        assert_eq!(tx.deadline(), Some(at + 64 * T1));
        assert_eq!(tx.on_retransmission(), Some(response(486)));

        // Nothing more goes out after the final response.
        assert!(!tx.on_response(status(200), response(200), at + T1));
        assert!(!tx.on_response(status(100), response(100), at + T1));
        assert_eq!(tx.on_retransmission(), Some(response(486)));

        assert_eq!(tx.on_timeout(at + 63 * T1), None);
        assert!(!tx.is_terminated());
        assert_eq!(tx.on_timeout(at + 64 * T1), None);
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
        assert_eq!(tx.on_retransmission(), None);
    }

    #[test]
    fn a_reliable_transport_ends_with_the_final_response() {
        let start = Instant::now();
        let mut tx = transaction(true, start);
        // The 100 rule holds on every transport.
        assert_eq!(tx.deadline(), Some(start + 7 * T1));
        assert!(tx.on_response(status(200), response(200), start + T1));
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
        assert_eq!(tx.on_retransmission(), None);
    }

    #[test]
    fn a_408_is_dropped_and_ends_it() {
        let start = Instant::now();
        let mut tx = transaction(false, start);
        assert!(!tx.on_response(status(408), response(408), start + T1));
        assert!(tx.is_terminated());
        assert_eq!(tx.deadline(), None);
    }

    #[test]
    fn a_transport_error_ends_it() {
        let start = Instant::now();
        let mut tx = transaction(false, start);
        tx.on_transport_error();
        assert!(tx.is_terminated());
        assert!(!tx.on_response(status(200), response(200), start));
        assert_eq!(tx.on_timeout(start + 7 * T1), None);
    }
}
