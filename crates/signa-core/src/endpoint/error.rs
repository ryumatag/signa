/*!
The errors of binding an endpoint and of a message sent through
[`Endpoint::start`], [`Endpoint::send_request`] or
[`Endpoint::forward_response`].

[`Endpoint::start`]: super::Endpoint::start
[`Endpoint::send_request`]: super::Endpoint::send_request
[`Endpoint::forward_response`]: super::Endpoint::forward_response
*/

use std::{error, fmt, io};

use super::driver::MAX_UDP_REQUEST;
use crate::message::HeaderName;

/// The error of an endpoint operation, or the terminal error of a client
/// response stream.
///
/// RFC 3261 section 8.1.3.1 tells a transaction user to treat a timeout as a
/// 408 and a transport error as a 503. signa reports both as errors instead
/// of making up a response, and [`Error::is_timeout`] and
/// [`Error::is_transport`] tell them apart. [`Error::is_cancel_timeout`] is
/// the deadline after a CANCEL. The other cases are refusals: a request too
/// large for UDP, a missing request header, an invalid `CSeq`, INVITE
/// identity header or forwarded `Via`, a method the operation cannot send, an
/// operation the endpoint's [`Reception`] does not offer, a destination signa
/// cannot route to, a full limit, or an endpoint that has stopped. Response
/// delivery overflow is reported after already queued responses, without
/// ending the underlying SIP machine.
///
/// The operations of a [`DatagramPort`] have an error of their own,
/// [`port::Error`].
///
/// # Example
///
/// What a terminal error on a client's [`Responses`] means. None of them is a
/// SIP response, and none comes from the peer.
///
/// ```
/// use signa_core::endpoint::Error;
///
/// fn describe(error: &Error) -> &'static str {
///     if error.is_timeout() {
///         "no response before Timer B or F, which RFC 3261 treats as a 408"
///     } else if error.is_cancel_timeout() {
///         "no final response within 64 T1 of the CANCEL"
///     } else if error.is_transport() {
///         "the transport failed, which RFC 3261 treats as a 503"
///     } else if error.is_outcome_unknown() {
///         "the request may or may not have gone out"
///     } else if error.is_delivery_overflow() {
///         "responses came faster than they were read, and the rest is lost"
///     } else if error.is_closed() {
///         "the endpoint stopped"
///     } else {
///         "refused before anything was sent"
///     }
/// }
/// ```
///
/// [`Endpoint::start`]: super::Endpoint::start
/// [`Reception`]: super::Reception
/// [`Responses`]: super::Responses
/// [`DatagramPort`]: super::port::DatagramPort
/// [`port::Error`]: super::port::Error
pub struct Error {
    kind: Kind,
}

enum Kind {
    Timeout,
    CancelTimeout,
    DeliveryOverflow,
    Transport(io::Error),
    OutcomeUnknown(io::Error),
    TooLarge(usize),
    Missing(HeaderName),
    InvalidCSeq,
    InvalidHeader(HeaderName),
    UnsupportedMethod,
    UnsupportedRouting,
    UnsupportedReception,
    StalePath,
    PathRefused(io::Error),
    Busy(Busy),
    Closed,
}

/// What was full when an operation was refused as busy, for the message.
#[derive(Clone, Copy, Debug)]
pub(super) enum Busy {
    /// Client request admission: requests, response streams or client
    /// transactions.
    Client,
    /// The bytes of one-shot sends, [`Builder::max_reply_bytes`].
    ///
    /// [`Builder::max_reply_bytes`]: super::Builder::max_reply_bytes
    Replies,
    /// Routes, connections or connection attempts.
    Connections,
    /// The transport's write limits or queue.
    Writes,
    /// The bytes and count of contexts the endpoint keeps.
    Contexts,
    /// Another observer of the endpoint is alive.
    Observer,
    /// As many work guards as the endpoint can count.
    Guards,
}

impl Busy {
    fn message(self) -> &'static str {
        match self {
            Busy::Client => "client admission capacity is exhausted",
            Busy::Replies => "the bytes for one-shot sends are exhausted",
            Busy::Connections => {
                "the route, connection or connection attempt limits are full"
            }
            Busy::Writes => "the transport's write capacity is exhausted",
            Busy::Contexts => "the context limits are full",
            Busy::Observer => "another observer of the endpoint is alive",
            Busy::Guards => "the endpoint holds as many work guards as it can",
        }
    }
}

impl Error {
    pub(super) fn timeout() -> Error {
        Error { kind: Kind::Timeout }
    }

    pub(super) fn cancel_timeout() -> Error {
        Error { kind: Kind::CancelTimeout }
    }

    pub(super) fn delivery_overflow() -> Error {
        Error { kind: Kind::DeliveryOverflow }
    }

    pub(super) fn transport(err: io::Error) -> Error {
        Error { kind: Kind::Transport(err) }
    }

    pub(super) fn outcome_unknown(err: io::Error) -> Error {
        Error { kind: Kind::OutcomeUnknown(err) }
    }

    pub(super) fn too_large(len: usize) -> Error {
        Error { kind: Kind::TooLarge(len) }
    }

    pub(super) fn missing(name: HeaderName) -> Error {
        Error { kind: Kind::Missing(name) }
    }

    pub(super) fn invalid_cseq() -> Error {
        Error { kind: Kind::InvalidCSeq }
    }

    pub(super) fn invalid_header(name: HeaderName) -> Error {
        Error { kind: Kind::InvalidHeader(name) }
    }

    pub(super) fn unsupported_method() -> Error {
        Error { kind: Kind::UnsupportedMethod }
    }

    pub(super) fn unsupported_routing() -> Error {
        Error { kind: Kind::UnsupportedRouting }
    }

    pub(super) fn unsupported_reception() -> Error {
        Error { kind: Kind::UnsupportedReception }
    }

    pub(super) fn stale_path() -> Error {
        Error { kind: Kind::StalePath }
    }

    pub(super) fn path_refused(err: io::Error) -> Error {
        Error { kind: Kind::PathRefused(err) }
    }

    pub(super) fn busy(what: Busy) -> Error {
        Error { kind: Kind::Busy(what) }
    }

    pub(super) fn closed() -> Error {
        Error { kind: Kind::Closed }
    }

    /// Returns `true` if no response arrived in time: no final response
    /// before Timer F for a non-INVITE, or no response at all before Timer B
    /// for an INVITE. Both are 64 T1 after the request was sent. An INVITE
    /// that received a provisional response has no such timer.
    pub fn is_timeout(&self) -> bool {
        matches!(self.kind, Kind::Timeout)
    }

    /// Returns `true` if an INVITE got no final response within 64 T1 of its
    /// CANCEL, so signa stopped waiting and ended the transaction
    /// ([RFC 3261 section 9.1]). A later final response is discarded.
    ///
    /// [RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
    pub fn is_cancel_timeout(&self) -> bool {
        matches!(self.kind, Kind::CancelTimeout)
    }

    /// Returns `true` if response count or byte capacity was exhausted.
    /// Queued responses precede this terminal error. SIP work continues.
    pub fn is_delivery_overflow(&self) -> bool {
        matches!(self.kind, Kind::DeliveryOverflow)
    }

    /// Returns `true` if the transport could not send the request or lost
    /// the connection it went over. [`Error::source`] has the I/O error.
    ///
    /// [`Error::source`]: error::Error::source
    pub fn is_transport(&self) -> bool {
        matches!(self.kind, Kind::Transport(_))
    }

    /// Returns `true` if a write was handed to the transport and its outcome
    /// is not known, so that it may or may not have gone out.
    /// [`Error::source`] says why.
    ///
    /// A UDP backend reports this when it can no longer account for a write,
    /// and a [`DatagramPort`] an endpoint is registered on when it closes
    /// with a write of the endpoint's that its backend took and never
    /// reported. It is not [`Error::is_transport`], which means the write did
    /// not go out.
    ///
    /// [`Error::source`]: error::Error::source
    /// [`DatagramPort`]: super::port::DatagramPort
    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self.kind, Kind::OutcomeUnknown(_))
    }

    /// Returns `true` if the request is too large to go over UDP.
    ///
    /// RFC 3261 section 18.1.1 sends a request over a congestion-controlled
    /// transport when it is within 200 bytes of the path MTU, or over 1300
    /// bytes when the MTU is unknown, as it is here. The caller starts such a
    /// request with a TCP target instead.
    pub fn is_too_large(&self) -> bool {
        matches!(self.kind, Kind::TooLarge(_))
    }

    /// Returns `true` if a request has no CSeq, or an INVITE has no From, To
    /// or Call-ID. [`fmt::Display`] names the header. The request was not
    /// sent.
    ///
    /// A header that is present but duplicated or malformed is
    /// [`Error::is_invalid_cseq`] or [`Error::is_invalid_header`] instead.
    pub fn is_missing_header(&self) -> bool {
        matches!(self.kind, Kind::Missing(_))
    }

    /// Returns `true` if CSeq is duplicated, malformed, or names a method
    /// other than the request's method, or if an INVITE's number is
    /// 2<sup>31</sup> or more. The request was not sent.
    pub fn is_invalid_cseq(&self) -> bool {
        matches!(self.kind, Kind::InvalidCSeq)
    }

    /// Returns `true` if an INVITE has more than one From, To or Call-ID, or
    /// one that does not parse, which its ACK and CANCEL would copy, or if a
    /// forwarded response has no top Via, or one whose `received` is not an
    /// IP address or whose port is zero. [`fmt::Display`] names the header.
    ///
    /// An INVITE missing one of the three is [`Error::is_missing_header`].
    pub fn is_invalid_header(&self) -> bool {
        matches!(self.kind, Kind::InvalidHeader(_))
    }

    /// Returns `true` for a method the operation cannot send with its
    /// required semantics: ACK or CANCEL through `start`.
    pub fn is_unsupported_method(&self) -> bool {
        matches!(self.kind, Kind::UnsupportedMethod)
    }

    /// Returns `true` if the message needs a transport or a destination the
    /// endpoint cannot provide. Nothing was sent.
    ///
    /// That covers a `sips:` Request-URI, which needs TLS, a multicast target,
    /// a UDP target on an endpoint without a UDP socket, and a TCP target on a
    /// stateless endpoint. For a forwarded response it covers a top Via that
    /// names a transport other than UDP, has `maddr`, or names a host that is
    /// not an IP address and has no `received`, which would need DNS.
    pub fn is_unsupported_routing(&self) -> bool {
        matches!(self.kind, Kind::UnsupportedRouting)
    }

    /// Returns `true` if the operation is not available with the endpoint's
    /// [`Reception`](super::Reception): [`Endpoint::start`] on a stateless
    /// endpoint, or [`Endpoint::forward_response`] on a stateful one. Nothing
    /// was sent.
    ///
    /// [`Endpoint::start`]: super::Endpoint::start
    /// [`Endpoint::forward_response`]: super::Endpoint::forward_response
    pub fn is_unsupported_reception(&self) -> bool {
        matches!(self.kind, Kind::UnsupportedReception)
    }

    /// Returns `true` if a [`SendPath`] or a [`PreparedRequest`] belongs to
    /// another endpoint, or a prepared TCP request's connection has closed
    /// since. Nothing was sent. Prepare it again on this endpoint, as it is
    /// never sent another way in its place.
    ///
    /// [`SendPath`]: super::SendPath
    /// [`PreparedRequest`]: super::PreparedRequest
    pub fn is_stale_path(&self) -> bool {
        matches!(self.kind, Kind::StalePath)
    }

    /// Returns `true` if the UDP backend refused a path, as
    /// [`DatagramIo::check_path`] does for a source address it may not send
    /// from or a context it cannot read. [`Error::source`] has its I/O error.
    ///
    /// [`DatagramIo::check_path`]: crate::transport::datagram::DatagramIo::check_path
    /// [`Error::source`]: error::Error::source
    pub fn is_path_refused(&self) -> bool {
        matches!(self.kind, Kind::PathRefused(_))
    }

    /// Returns `true` if a limit the operation needs is full. Nothing was
    /// sent, and [`fmt::Display`] names the limit.
    ///
    /// That covers client admission (requests, response streams and client
    /// transactions), the bytes of one-shot sends, routes, connections and
    /// connection attempts, the transport's write limits, the contexts paths
    /// keep, and an observer that is still alive. Request admission refuses
    /// before the command is queued, the others in the driver.
    pub fn is_busy(&self) -> bool {
        matches!(self.kind, Kind::Busy(_))
    }

    /// Returns `true` if the endpoint has stopped or closed client admission
    /// for shutdown.
    ///
    /// On a [`DatagramPort`] it also means the port is closing.
    ///
    /// [`DatagramPort`]: super::port::DatagramPort
    pub fn is_closed(&self) -> bool {
        matches!(self.kind, Kind::Closed)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_tuple("signa::endpoint::Error");
        match &self.kind {
            Kind::Timeout => debug.field(&"Timeout"),
            Kind::CancelTimeout => debug.field(&"CancelTimeout"),
            Kind::DeliveryOverflow => debug.field(&"DeliveryOverflow"),
            Kind::Transport(err) => debug.field(err),
            Kind::OutcomeUnknown(err) => {
                debug.field(&format_args!("OutcomeUnknown({err:?})"))
            }
            Kind::TooLarge(len) => {
                debug.field(&format_args!("TooLarge({len})"))
            }
            Kind::Missing(name) => {
                debug.field(&format_args!("Missing({name:?})"))
            }
            Kind::InvalidCSeq => debug.field(&"InvalidCSeq"),
            Kind::InvalidHeader(name) => {
                debug.field(&format_args!("InvalidHeader({name:?})"))
            }
            Kind::UnsupportedMethod => debug.field(&"UnsupportedMethod"),
            Kind::UnsupportedRouting => debug.field(&"UnsupportedRouting"),
            Kind::UnsupportedReception => debug.field(&"UnsupportedReception"),
            Kind::StalePath => debug.field(&"StalePath"),
            Kind::PathRefused(err) => {
                debug.field(&format_args!("PathRefused({err:?})"))
            }
            Kind::Busy(what) => debug.field(&format_args!("Busy({what:?})")),
            Kind::Closed => debug.field(&"Closed"),
        };
        debug.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Timeout => f.write_str("no response before the timeout"),
            Kind::CancelTimeout => {
                f.write_str("no final response within 64 T1 of the CANCEL")
            }
            Kind::DeliveryOverflow => {
                f.write_str("client response delivery capacity is exhausted")
            }
            // The I/O error is the source, which a report prints after this.
            Kind::Transport(_) => f.write_str("the transport failed"),
            Kind::OutcomeUnknown(_) => {
                f.write_str("the write's outcome is unknown")
            }
            Kind::TooLarge(len) => write!(
                f,
                "the request is {len} bytes, over the {MAX_UDP_REQUEST} \
                 that go over UDP"
            ),
            Kind::Missing(name) => write!(f, "the request has no {name}"),
            Kind::InvalidCSeq => f.write_str(
                "the request needs one valid CSeq matching its method",
            ),
            Kind::InvalidHeader(name) => {
                write!(f, "the message needs one valid {name}")
            }
            Kind::UnsupportedMethod => f.write_str(
                "this operation cannot send a request with this method",
            ),
            Kind::UnsupportedRouting => f.write_str(
                "the endpoint has no transport or route for this destination",
            ),
            Kind::UnsupportedReception => f.write_str(
                "the endpoint's reception mode does not offer this operation",
            ),
            Kind::StalePath => f.write_str(
                "the path or prepared request belongs to another endpoint or \
                 connection",
            ),
            Kind::PathRefused(_) => {
                f.write_str("the UDP backend refused the path")
            }
            Kind::Busy(what) => f.write_str(what.message()),
            Kind::Closed => f.write_str("the endpoint is closed"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            Kind::Transport(err)
            | Kind::OutcomeUnknown(err)
            | Kind::PathRefused(err) => Some(err),
            _ => None,
        }
    }
}

/// Why [`Builder::bind`] could not start an endpoint.
///
/// [`BindError::is_invalid_config`] separates a configuration that no socket
/// could satisfy from a socket that failed to bind, and
/// [`BindError::is_unsupported_config`] a combination signa does not support
/// yet. It converts into an [`io::Error`] for callers that report I/O errors,
/// with `InvalidInput` for an invalid configuration and `Unsupported` for an
/// unsupported one.
///
/// [`Builder::bind`]: super::Builder::bind
pub struct BindError {
    kind: BindKind,
}

enum BindKind {
    Io(io::Error),
    InvalidConfig(&'static str),
    InvalidPortConfig(&'static str),
    UnsupportedConfig(&'static str),
    PortClosed,
    PortFull,
}

impl BindError {
    pub(super) fn io(err: io::Error) -> BindError {
        BindError { kind: BindKind::Io(err) }
    }

    pub(super) fn invalid_config(reason: &'static str) -> BindError {
        BindError { kind: BindKind::InvalidConfig(reason) }
    }

    pub(super) fn invalid_port_config(reason: &'static str) -> BindError {
        BindError { kind: BindKind::InvalidPortConfig(reason) }
    }

    pub(super) fn unsupported_config(reason: &'static str) -> BindError {
        BindError { kind: BindKind::UnsupportedConfig(reason) }
    }

    pub(super) fn port_closed() -> BindError {
        BindError { kind: BindKind::PortClosed }
    }

    pub(super) fn port_full() -> BindError {
        BindError { kind: BindKind::PortFull }
    }

    /// Returns `true` if the configuration is invalid, such as a zero
    /// capacity where the endpoint or the [`DatagramPort`] needs a positive
    /// one. No socket was bound.
    ///
    /// [`DatagramPort`]: super::port::DatagramPort
    pub fn is_invalid_config(&self) -> bool {
        matches!(
            self.kind,
            BindKind::InvalidConfig(_) | BindKind::InvalidPortConfig(_)
        )
    }

    /// Returns `true` if the configuration asks for something signa does not
    /// support yet, such as [`Reception::Stateless`] with a TCP listener. No
    /// socket was bound.
    ///
    /// [`Reception::Stateless`]: super::Reception::Stateless
    pub fn is_unsupported_config(&self) -> bool {
        matches!(self.kind, BindKind::UnsupportedConfig(_))
    }

    /// Returns `true` if binding or setting up a socket failed.
    /// [`BindError::source`] has the I/O error.
    ///
    /// [`BindError::source`]: error::Error::source
    pub fn is_io(&self) -> bool {
        matches!(self.kind, BindKind::Io(_))
    }

    /// Returns `true` if the [`DatagramPort`] the endpoint would share takes
    /// no new endpoints, as it is quiesced or closing.
    ///
    /// [`DatagramPort`]: super::port::DatagramPort
    pub fn is_closed(&self) -> bool {
        matches!(self.kind, BindKind::PortClosed)
    }

    /// Returns `true` if the [`DatagramPort`] the endpoint would share has as
    /// many endpoints as [`port::Builder::max_registrations`] lets it.
    ///
    /// [`DatagramPort`]: super::port::DatagramPort
    /// [`port::Builder::max_registrations`]: super::port::Builder::max_registrations
    pub fn is_busy(&self) -> bool {
        matches!(self.kind, BindKind::PortFull)
    }
}

impl fmt::Debug for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_tuple("signa::endpoint::BindError");
        match &self.kind {
            BindKind::Io(err) => debug.field(err),
            BindKind::InvalidConfig(reason) => {
                debug.field(&format_args!("InvalidConfig({reason:?})"))
            }
            BindKind::InvalidPortConfig(reason) => {
                debug.field(&format_args!("InvalidPortConfig({reason:?})"))
            }
            BindKind::UnsupportedConfig(reason) => {
                debug.field(&format_args!("UnsupportedConfig({reason:?})"))
            }
            BindKind::PortClosed => debug.field(&"PortClosed"),
            BindKind::PortFull => debug.field(&"PortFull"),
        };
        debug.finish()
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            // The I/O error is the source, which a report prints after this.
            BindKind::Io(_) => f.write_str("binding a socket failed"),
            BindKind::InvalidConfig(reason) => {
                write!(f, "invalid endpoint configuration: {reason}")
            }
            BindKind::InvalidPortConfig(reason) => {
                write!(f, "invalid port configuration: {reason}")
            }
            BindKind::UnsupportedConfig(reason) => {
                write!(f, "unsupported endpoint configuration: {reason}")
            }
            BindKind::PortClosed => {
                f.write_str("the datagram port takes no new endpoints")
            }
            BindKind::PortFull => {
                f.write_str("the datagram port has all the endpoints it takes")
            }
        }
    }
}

impl error::Error for BindError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            BindKind::Io(err) => Some(err),
            BindKind::InvalidConfig(_)
            | BindKind::InvalidPortConfig(_)
            | BindKind::UnsupportedConfig(_)
            | BindKind::PortClosed
            | BindKind::PortFull => None,
        }
    }
}

impl From<BindError> for io::Error {
    fn from(err: BindError) -> io::Error {
        match err.kind {
            BindKind::Io(err) => err,
            BindKind::InvalidConfig(_) | BindKind::InvalidPortConfig(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
            BindKind::UnsupportedConfig(_) => {
                io::Error::new(io::ErrorKind::Unsupported, err)
            }
            BindKind::PortClosed => {
                io::Error::new(io::ErrorKind::NotConnected, err)
            }
            // Not `WouldBlock`, since only an endpoint that stops makes room.
            BindKind::PortFull => io::Error::other(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{CancelError, ReplyError};

    // A report prints the source after the error, so an error that also
    // printed it would say it twice.
    #[test]
    fn an_error_with_a_source_does_not_repeat_it() {
        let io = || io::Error::other("the cable is out");
        let errors: [Box<dyn error::Error>; 7] = [
            Box::new(Error::transport(io())),
            Box::new(Error::outcome_unknown(io())),
            Box::new(Error::path_refused(io())),
            Box::new(BindError::io(io())),
            Box::new(ReplyError::Transport(io())),
            Box::new(ReplyError::OutcomeUnknown(io())),
            Box::new(CancelError::Transport(io())),
        ];

        for error in errors {
            assert!(error.source().is_some(), "{error}");
            assert!(!error.to_string().contains("cable"), "{error}");
        }
    }

    #[test]
    fn a_busy_error_names_what_was_full() {
        let all = [
            Busy::Client,
            Busy::Replies,
            Busy::Connections,
            Busy::Writes,
            Busy::Contexts,
            Busy::Observer,
            Busy::Guards,
        ];

        let messages = all.map(|what| {
            let error = Error::busy(what);
            assert!(error.is_busy());
            error.to_string()
        });
        for (i, message) in messages.iter().enumerate() {
            assert!(!messages[..i].contains(message), "{message}");
        }
        assert_eq!(
            Error::busy(Busy::Observer).to_string(),
            "another observer of the endpoint is alive"
        );
    }
}
