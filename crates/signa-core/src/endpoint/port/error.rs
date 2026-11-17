/*!
The errors of a port's operations, and of a datagram's disposition.

They are not [`endpoint::Error`], whose kinds are an endpoint's: client
admission, SIP validation and transaction timers. A port's raw paths, raw sends
and dispositions fail for reasons of their own, which [`Error`] names.

[`endpoint::Error`]: crate::endpoint::Error
*/

use std::{error, fmt, io};

use super::ReceivedDatagram;
use crate::endpoint::path::Unchecked;

/// The error of a [`DatagramPort`] operation, a datagram's disposition or a
/// raw write.
///
/// # Example
///
/// What to do with a datagram the application could not forward.
///
/// ```
/// use signa_core::endpoint::port::{DispositionError, RawPath};
///
/// fn after_refusal(refused: DispositionError, other: &RawPath) {
///     let error = refused.error();
///     if error.is_busy() {
///         // The port's write limits are full. The peer retransmits, so
///         // dropping the datagram here is like losing it on the wire.
///         refused.into_datagram().discard();
///     } else if error.is_foreign() {
///         // A path of another port. This one can try a path of its own.
///         let _ = refused.into_datagram().try_forward(other);
///     } else {
///         // Expired, too large or closing. Nothing can send it now.
///         refused.into_datagram().discard();
///     }
/// }
/// ```
///
/// [`DatagramPort`]: super::DatagramPort
pub struct Error {
    kind: Kind,
}

enum Kind {
    Closed(Closed),
    Expired,
    Busy(Busy),
    Foreign,
    TooLarge { len: usize, max: usize },
    PathRefused(io::Error),
    Transport(io::Error),
    OutcomeUnknown(io::Error),
}

/// What has closed, for the message.
#[derive(Clone, Copy, Debug)]
pub(super) enum Closed {
    /// The port is closing, or its task has ended.
    Port,
    /// The port takes no new paths.
    Quiesced,
    /// The endpoint a datagram was to go to has stopped.
    Endpoint,
}

/// What was full, for the message.
#[derive(Clone, Copy, Debug)]
pub(super) enum Busy {
    /// The share of the port's write limits that raw sends may take.
    Writes,
    /// The endpoint's delivery queue.
    Deliveries,
    /// The port's context limits.
    Contexts,
    /// Another observer of the port is alive.
    Observer,
}

impl Error {
    pub(super) fn closed(what: Closed) -> Error {
        Error { kind: Kind::Closed(what) }
    }

    pub(super) fn expired() -> Error {
        Error { kind: Kind::Expired }
    }

    pub(super) fn busy(what: Busy) -> Error {
        Error { kind: Kind::Busy(what) }
    }

    pub(super) fn foreign() -> Error {
        Error { kind: Kind::Foreign }
    }

    pub(super) fn too_large(len: usize, max: usize) -> Error {
        Error { kind: Kind::TooLarge { len, max } }
    }

    pub(super) fn path_refused(err: io::Error) -> Error {
        Error { kind: Kind::PathRefused(err) }
    }

    pub(super) fn transport(err: io::Error) -> Error {
        Error { kind: Kind::Transport(err) }
    }

    pub(super) fn outcome_unknown(err: io::Error) -> Error {
        Error { kind: Kind::OutcomeUnknown(err) }
    }

    /// Returns `true` if the port is closing or closed, if it is quiesced and
    /// takes no new paths, or if the endpoint a datagram was to go to has
    /// stopped. [`fmt::Display`] says which.
    pub fn is_closed(&self) -> bool {
        matches!(self.kind, Kind::Closed(_))
    }

    /// Returns `true` if a [`ReceivedDatagram`]'s decision deadline has
    /// passed, so that it can no longer be delivered or forwarded.
    pub fn is_expired(&self) -> bool {
        matches!(self.kind, Kind::Expired)
    }

    /// Returns `true` if a limit the operation needs is full: the share of
    /// [`Builder::write_limits`] raw sends may take, the endpoint's
    /// [`Builder::delivery_queue`], [`Builder::context_limits`], or the one
    /// observer a port has. [`fmt::Display`] names the limit.
    ///
    /// [`Builder::write_limits`]: super::Builder::write_limits
    /// [`Builder::delivery_queue`]: super::Builder::delivery_queue
    /// [`Builder::context_limits`]: super::Builder::context_limits
    pub fn is_busy(&self) -> bool {
        matches!(self.kind, Kind::Busy(_))
    }

    /// Returns `true` if an [`EndpointIngress`] or a [`RawPath`] belongs to
    /// another port. A datagram can go only to an endpoint or along a path
    /// of the port that received it.
    ///
    /// [`EndpointIngress`]: super::EndpointIngress
    /// [`RawPath`]: super::RawPath
    pub fn is_foreign(&self) -> bool {
        matches!(self.kind, Kind::Foreign)
    }

    /// Returns `true` if a payload is over the backend's
    /// [`max_payload`](crate::transport::datagram::Capabilities::max_payload).
    /// A raw send has no other size limit.
    pub fn is_too_large(&self) -> bool {
        matches!(self.kind, Kind::TooLarge { .. })
    }

    /// Returns `true` if the backend refused a path, as
    /// [`DatagramIo::check_path`] does for a source address it may not send
    /// from or a context it cannot read, or if an address of the path is
    /// unspecified, multicast or broadcast or has port 0.
    /// [`Error::source`] has the I/O error.
    ///
    /// [`DatagramIo::check_path`]: crate::transport::datagram::DatagramIo::check_path
    /// [`Error::source`]: error::Error::source
    pub fn is_path_refused(&self) -> bool {
        matches!(self.kind, Kind::PathRefused(_))
    }

    /// Returns `true` if a raw write did not go out, as the backend failed it
    /// or the port closed before offering it. [`Error::source`] has the I/O
    /// error.
    ///
    /// [`Error::source`]: error::Error::source
    pub fn is_transport(&self) -> bool {
        matches!(self.kind, Kind::Transport(_))
    }

    /// Returns `true` if a raw write may or may not have gone out: the
    /// backend cannot tell, or the port closed while the backend held it
    /// unreported. [`Error::source`] says why.
    ///
    /// [`Error::source`]: error::Error::source
    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self.kind, Kind::OutcomeUnknown(_))
    }
}

impl From<Unchecked> for Error {
    fn from(unchecked: Unchecked) -> Error {
        match unchecked {
            Unchecked::Refused(error) => Error::path_refused(error),
            Unchecked::Full => Error::busy(Busy::Contexts),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_tuple("signa::endpoint::port::Error");
        match &self.kind {
            Kind::Closed(what) => {
                debug.field(&format_args!("Closed({what:?})"))
            }
            Kind::Expired => debug.field(&"Expired"),
            Kind::Busy(what) => debug.field(&format_args!("Busy({what:?})")),
            Kind::Foreign => debug.field(&"Foreign"),
            Kind::TooLarge { len, max } => {
                debug.field(&format_args!("TooLarge({len}, {max})"))
            }
            Kind::PathRefused(err) => {
                debug.field(&format_args!("PathRefused({err:?})"))
            }
            Kind::Transport(err) => {
                debug.field(&format_args!("Transport({err:?})"))
            }
            Kind::OutcomeUnknown(err) => {
                debug.field(&format_args!("OutcomeUnknown({err:?})"))
            }
        };
        debug.finish()
    }
}

impl fmt::Display for Error {
    // An I/O error is the source, which a report prints after this.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Closed(Closed::Port) => f.write_str("the port is closed"),
            Kind::Closed(Closed::Quiesced) => {
                f.write_str("the port is quiesced and takes no new paths")
            }
            Kind::Closed(Closed::Endpoint) => {
                f.write_str("the endpoint has stopped")
            }
            Kind::Expired => {
                f.write_str("the datagram's decision deadline has passed")
            }
            Kind::Busy(Busy::Writes) => {
                f.write_str("the port's write limits for raw sends are full")
            }
            Kind::Busy(Busy::Deliveries) => {
                f.write_str("the endpoint's delivery queue is full")
            }
            Kind::Busy(Busy::Contexts) => {
                f.write_str("the port's context limits are full")
            }
            Kind::Busy(Busy::Observer) => {
                f.write_str("another observer of the port is alive")
            }
            Kind::Foreign => f.write_str(
                "the endpoint ingress or path belongs to another port",
            ),
            Kind::TooLarge { len, max } => write!(
                f,
                "the datagram is {len} bytes, over the {max} its backend sends"
            ),
            Kind::PathRefused(_) => {
                f.write_str("the backend refused the path")
            }
            Kind::Transport(_) => f.write_str("the datagram was not written"),
            Kind::OutcomeUnknown(_) => {
                f.write_str("the write's outcome is unknown")
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            Kind::PathRefused(err)
            | Kind::Transport(err)
            | Kind::OutcomeUnknown(err) => Some(err),
            Kind::Closed(_)
            | Kind::Expired
            | Kind::Busy(_)
            | Kind::Foreign
            | Kind::TooLarge { .. } => None,
        }
    }
}

/// A datagram that was not delivered or forwarded, with the reason.
///
/// The datagram still holds its disposition, unless it
/// [expired](Error::is_expired), and can be tried again or discarded.
// Boxed, since a refusal is rare and the datagram is large for an `Err`.
pub struct DispositionError(Box<(ReceivedDatagram, Error)>);

impl DispositionError {
    pub(super) fn new(
        datagram: ReceivedDatagram,
        error: Error,
    ) -> DispositionError {
        DispositionError(Box::new((datagram, error)))
    }

    /// Why the datagram was refused.
    pub fn error(&self) -> &Error {
        &self.0.1
    }

    /// Takes the datagram back.
    pub fn into_datagram(self) -> ReceivedDatagram {
        self.0.0
    }

    /// Takes the datagram and the reason apart.
    pub fn into_parts(self) -> (ReceivedDatagram, Error) {
        *self.0
    }
}

impl fmt::Debug for DispositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DispositionError")
            .field("datagram", &self.0.0)
            .field("error", &self.0.1)
            .finish()
    }
}

impl fmt::Display for DispositionError {
    // The reason is the source, which a report prints after this.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the datagram was neither delivered nor forwarded")
    }
}

impl error::Error for DispositionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.0.1)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn an_error_with_a_source_does_not_repeat_it() {
        let io = || io::Error::other("the cable is out");
        for error in [
            Error::path_refused(io()),
            Error::transport(io()),
            Error::outcome_unknown(io()),
        ] {
            assert!(error.source().is_some(), "{error}");
            assert!(!error.to_string().contains("cable"), "{error}");
        }
    }

    #[test]
    fn each_kind_answers_only_its_own_predicate() {
        let io = || io::Error::other("refused");
        let errors = [
            Error::closed(Closed::Port),
            Error::closed(Closed::Quiesced),
            Error::closed(Closed::Endpoint),
            Error::expired(),
            Error::busy(Busy::Writes),
            Error::busy(Busy::Deliveries),
            Error::busy(Busy::Contexts),
            Error::busy(Busy::Observer),
            Error::foreign(),
            Error::too_large(1473, 1472),
            Error::path_refused(io()),
            Error::transport(io()),
            Error::outcome_unknown(io()),
        ];

        for error in &errors {
            let answers = [
                error.is_closed(),
                error.is_expired(),
                error.is_busy(),
                error.is_foreign(),
                error.is_too_large(),
                error.is_path_refused(),
                error.is_transport(),
                error.is_outcome_unknown(),
            ];
            assert_eq!(
                answers.iter().filter(|&&yes| yes).count(),
                1,
                "{error}"
            );
        }
        let messages = errors.each_ref().map(ToString::to_string);
        for (i, message) in messages.iter().enumerate() {
            assert!(!messages[..i].contains(message), "{message}");
        }
    }
}
