use std::{
    fmt,
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::{
    header::HeaderMap,
    response::reply_headers,
    transaction::{bare_response, Timers},
    Request, StatusCode,
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
