use std::{fmt, time::Instant};

use bytes::Bytes;

use crate::{
    header::{
        cseq::CSeq, via::Via, HeaderName, HeaderValue, CALL_ID, CSEQ, FROM,
        MAX_FORWARDS, ROUTE, TO, VIA,
    },
    method::Method,
    request::{self, Request},
    response::Response,
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
    // Request retransmissions stop at the first provisional. Only the selected
    // ACK fields survive until a final response.
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
            Self::Method => f.write_str("expected an INVITE"),
            Self::Missing(name) => {
                write!(f, "missing {name} for the INVITE ACK")
            }
            Self::CSeq => f.write_str("invalid INVITE CSeq"),
            Self::Via => f.write_str("invalid INVITE Via"),
        }
    }
}

impl std::error::Error for InvalidInvite {}

impl ClientTransaction {
    /// Starts after the caller submits the first INVITE to transport.
    ///
    /// The request already has its top Via. The caller validates complete
    /// header semantics. This constructor checks the fields it reads and keeps
    /// a bodyless ACK template, without retaining the input buffer.
    pub fn new(
        request: &Request<Bytes>,
        reliable: bool,
        timers: &Timers,
        now: Instant,
    ) -> Result<ClientTransaction, InvalidInvite> {
        let ack = ack_template(request)?;

        Ok(ClientTransaction {
            state: State::Calling {
                request: request.to_bytes(),
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
                        .map_or(true, |v| v.as_str().trim().is_empty())
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
}

/// RFC 3261 section 17.1.1.3. Copy selected values so a large INVITE body or
/// read chunk is not retained throughout Proceeding by a header slice.
fn ack_template(
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

    required(TO)?;

    // The URI has already been validated. This copy changes ownership only.
    let mut ack = request::Parts::new(Method::ACK, request.uri().copy());
    ack.headers.append(
        VIA,
        HeaderValue::from_built(via_value.as_str()[..via.end].to_owned()),
    );

    for name in [FROM, CALL_ID] {
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
    use super::*;

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
}
