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

use signa_core::StatusCode;

/// Why an operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
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
    /// A write failed, possibly after some of it went out.
    TransportFailure,
    /// The peer answered with a non-2xx final.
    RemoteFailure(StatusCode),
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
    /// The driver stopped while the operation ran. This includes the core's
    /// `Closed`, after which nobody knows whether the core took the message.
    DriverStopped,
}

/// What a failure says about the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireEffect {
    /// Nothing was sent.
    None,
    /// Something may have been sent.
    Unknown,
    /// The peer received a request, since it answered.
    Delivered,
}

impl Error {
    pub(crate) fn wire_effect(self) -> WireEffect {
        match self {
            Error::InvalidInput
            | Error::InvalidTransition
            | Error::Busy
            | Error::CapacityExceeded
            | Error::CoreSubmissionRejected
            | Error::StaleDecision
            | Error::AlreadyFinalized
            | Error::Closed => WireEffect::None,
            Error::TransportFailure
            | Error::NegotiationFailure
            | Error::ObservationIncomplete
            | Error::DriverStopped => WireEffect::Unknown,
            Error::RemoteFailure(_) => WireEffect::Delivered,
        }
    }
}

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
            Error::TransportFailure,
            Error::RemoteFailure(busy_here),
            Error::NegotiationFailure,
            Error::ObservationIncomplete,
            Error::StaleDecision,
            Error::AlreadyFinalized,
            Error::Closed,
            Error::DriverStopped,
        ];

        let delivered: Vec<Error> = errors
            .into_iter()
            .filter(|error| error.wire_effect() == WireEffect::Delivered)
            .collect();
        assert_eq!(delivered, [Error::RemoteFailure(busy_here)]);

        for error in [Error::TransportFailure, Error::DriverStopped] {
            assert_eq!(error.wire_effect(), WireEffect::Unknown, "{error:?}");
        }
    }
}
