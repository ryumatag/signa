/*!
The classes of failure an operation can end in.

A failure is first of all a statement about the wire. The caller has to know
whether anything may have reached the peer before it retries, reports or gives
up, so each class fixes its [`WireEffect`].

A failure is not a SIP response. The model does not turn a Rust error into a
500, 503 or 487 on the way out. Whether a response goes out, and which, is
decided by the protocol state, never by mapping an error. In particular an ACK
never gets a response, and an internal failure is not a 487 unless a CANCEL
arrived.
*/

use std::{error, fmt};

use signa_core::StatusCode;

/// Why an operation failed.
///
/// Each class says what may have reached the peer, through
/// [`Error::wire_effect`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub enum Error {
    /// The request made no sense, such as a malformed plan.
    InvalidInput,
    /// The state does not allow the operation, such as a BYE on an ended
    /// usage.
    InvalidTransition,
    /// The command queue is full. The command was handed back.
    Busy,
    /// A table or budget the operation needs is full.
    CapacityExceeded,
    /// The core refused the message and kept its state, as its
    /// `SubmitError` does for every variant but `Closed`.
    CoreSubmissionRejected,
    /// The next hop could not be resolved, or needs a transport this UA does
    /// not have, such as TLS for a SIPS URI.
    Unroutable,
    /// A write failed, possibly after some of it went out.
    TransportFailure,
    /// The peer answered with a non-2xx final.
    RemoteFailure(StatusCode),
    /// The transaction timed out without a response, as Timer B ends an
    /// INVITE that got none. RFC 3261 section 8.1.3.1 treats this as a 408,
    /// but no 408 came from the peer, and the request may not have reached
    /// it.
    Timeout,
    /// The external description provider or validator failed.
    NegotiationFailure,
    /// Responses or events were lost, such as by a core response overflow,
    /// so the result may be incomplete.
    ObservationIncomplete,
    /// The input is for something that ended or whose slot was reused,
    /// such as a decision for an exchange that is gone.
    StaleDecision,
    /// Another final response won the race, such as the 487 for a CANCEL
    /// ahead of an accept.
    AlreadyFinalized,
    /// The UA no longer admits new work.
    Closed,
    /// The UA failed in itself, such as its source of randomness. Nothing was
    /// sent.
    Internal,
    /// The driver stopped while the operation ran. This includes the core's
    /// `Closed`, after which nobody knows whether the core took the message.
    DriverStopped,
    /// The session ended while the operation ran, such as a re-INVITE whose
    /// session a BYE ended before its final response. The request may have
    /// reached the peer.
    SessionEnded,
}

/// What a failure says about the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub enum WireEffect {
    /// Nothing was sent.
    None,
    /// Something may have been sent.
    Unknown,
    /// The peer received a request, since it answered.
    Delivered,
}

impl Error {
    /// Returns what the failure says about the wire.
    #[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
    pub fn wire_effect(self) -> WireEffect {
        match self {
            Error::InvalidInput
            | Error::InvalidTransition
            | Error::Busy
            | Error::CapacityExceeded
            | Error::CoreSubmissionRejected
            | Error::Unroutable
            | Error::StaleDecision
            | Error::AlreadyFinalized
            | Error::Internal
            | Error::Closed => WireEffect::None,
            Error::TransportFailure
            | Error::Timeout
            | Error::NegotiationFailure
            | Error::ObservationIncomplete
            | Error::DriverStopped
            | Error::SessionEnded => WireEffect::Unknown,
            Error::RemoteFailure(_) => WireEffect::Delivered,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput => f.write_str("invalid input"),
            Error::InvalidTransition => {
                f.write_str("the state does not allow the operation")
            }
            Error::Busy => f.write_str("the UA's command queue is full"),
            Error::CapacityExceeded => f.write_str("a UA limit is reached"),
            Error::CoreSubmissionRejected => {
                f.write_str("the endpoint refused the message")
            }
            Error::Unroutable => f.write_str("no usable next hop"),
            Error::TransportFailure => f.write_str("a write failed"),
            Error::RemoteFailure(status) => {
                write!(f, "the peer answered {}", status.as_u16())
            }
            Error::Timeout => f.write_str("no response came in time"),
            Error::Internal => f.write_str("the UA failed in itself"),
            Error::NegotiationFailure => {
                f.write_str("the session description provider failed")
            }
            Error::ObservationIncomplete => {
                f.write_str("responses or events were lost")
            }
            Error::StaleDecision => {
                f.write_str("the operation's target is gone")
            }
            Error::AlreadyFinalized => {
                f.write_str("another final response came first")
            }
            Error::Closed => f.write_str("the UA admits no new work"),
            Error::DriverStopped => f.write_str("the UA's driver stopped"),
            Error::SessionEnded => {
                f.write_str("the session ended while the operation ran")
            }
        }
    }
}

impl error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_response_proves_delivery() {
        let busy_here = StatusCode::from_u16(486).unwrap();
        let errors = [
            Error::InvalidInput,
            Error::InvalidTransition,
            Error::Busy,
            Error::CapacityExceeded,
            Error::CoreSubmissionRejected,
            Error::Unroutable,
            Error::TransportFailure,
            Error::RemoteFailure(busy_here),
            Error::Timeout,
            Error::NegotiationFailure,
            Error::ObservationIncomplete,
            Error::StaleDecision,
            Error::AlreadyFinalized,
            Error::Closed,
            Error::Internal,
            Error::DriverStopped,
        ];

        let delivered: Vec<Error> = errors
            .into_iter()
            .filter(|error| error.wire_effect() == WireEffect::Delivered)
            .collect();
        assert_eq!(delivered, [Error::RemoteFailure(busy_here)]);

        for error in
            [Error::TransportFailure, Error::Timeout, Error::DriverStopped]
        {
            assert_eq!(error.wire_effect(), WireEffect::Unknown, "{error:?}");
        }
    }
}
