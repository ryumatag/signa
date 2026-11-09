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
/// large for UDP, a missing or invalid `CSeq`, INVITE identity header or
/// forwarded `Via`, a method the operation cannot send, an operation the
/// endpoint's [`Reception`] does not offer, a destination signa cannot route
/// to, exhausted request or connection admission, or an endpoint that has
/// stopped. Response delivery overflow is reported after already queued
/// responses, without ending the underlying SIP machine.
///
/// A request without a CSeq, or an INVITE without a From, To or Call-ID, is
/// refused with an error that none of the predicates below matches. Its
/// [`fmt::Display`] names the header.
///
/// # Example
///
/// What a terminal error on a client's [`Responses`] means. None of them is a
/// SIP response, and none comes from the peer.
///
/// ```
/// use signa::endpoint::Error;
///
/// fn describe(error: &Error) -> &'static str {
///     if error.is_timeout() {
///         "no response before Timer B or F, which RFC 3261 treats as a 408"
///     } else if error.is_cancel_timeout() {
///         "no final response within 64 T1 of the CANCEL"
///     } else if error.is_transport() {
///         "the transport failed, which RFC 3261 treats as a 503"
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
pub struct Error {
    kind: Kind,
}

enum Kind {
    Timeout,
    CancelTimeout,
    DeliveryOverflow,
    Transport(io::Error),
    TooLarge(usize),
    Missing(HeaderName),
    InvalidCSeq,
    InvalidHeader(HeaderName),
    UnsupportedMethod,
    UnsupportedRouting,
    UnsupportedReception,
    Busy,
    Closed,
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

    pub(super) fn busy() -> Error {
        Error { kind: Kind::Busy }
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

    /// Returns `true` if the request is too large to go over UDP.
    ///
    /// RFC 3261 section 18.1.1 sends a request over a congestion-controlled
    /// transport when it is within 200 bytes of the path MTU, or over 1300
    /// bytes when the MTU is unknown, as it is here. The caller starts such a
    /// request with a TCP target instead.
    pub fn is_too_large(&self) -> bool {
        matches!(self.kind, Kind::TooLarge(_))
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
    /// An INVITE missing one of the three gets an error that this does not
    /// match. See [`Error`].
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

    /// Returns `true` if request or connection admission is exhausted.
    ///
    /// Request count and logical-byte limits refuse before command enqueue.
    /// Route, connection and connect-attempt limits refuse in the driver. In
    /// either case the request was not sent.
    pub fn is_busy(&self) -> bool {
        matches!(self.kind, Kind::Busy)
    }

    /// Returns `true` if the endpoint has stopped or closed client admission
    /// for shutdown.
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
            Kind::Busy => debug.field(&"Busy"),
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
            Kind::Transport(err) => write!(f, "transport error: {err}"),
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
            Kind::Busy => {
                f.write_str("client admission capacity is exhausted")
            }
            Kind::Closed => f.write_str("the endpoint is closed"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            Kind::Transport(err) => Some(err),
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
    UnsupportedConfig(&'static str),
}

impl BindError {
    pub(super) fn io(err: io::Error) -> BindError {
        BindError { kind: BindKind::Io(err) }
    }

    pub(super) fn invalid_config(reason: &'static str) -> BindError {
        BindError { kind: BindKind::InvalidConfig(reason) }
    }

    pub(super) fn unsupported_config(reason: &'static str) -> BindError {
        BindError { kind: BindKind::UnsupportedConfig(reason) }
    }

    /// Returns `true` if the configuration is invalid, such as a zero
    /// capacity where the endpoint needs a positive one. No socket was bound.
    pub fn is_invalid_config(&self) -> bool {
        matches!(self.kind, BindKind::InvalidConfig(_))
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
}

impl fmt::Debug for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_tuple("signa::endpoint::BindError");
        match &self.kind {
            BindKind::Io(err) => debug.field(err),
            BindKind::InvalidConfig(reason) => {
                debug.field(&format_args!("InvalidConfig({reason:?})"))
            }
            BindKind::UnsupportedConfig(reason) => {
                debug.field(&format_args!("UnsupportedConfig({reason:?})"))
            }
        };
        debug.finish()
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            BindKind::Io(err) => write!(f, "binding a socket failed: {err}"),
            BindKind::InvalidConfig(reason) => {
                write!(f, "invalid endpoint configuration: {reason}")
            }
            BindKind::UnsupportedConfig(reason) => {
                write!(f, "unsupported endpoint configuration: {reason}")
            }
        }
    }
}

impl error::Error for BindError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            BindKind::Io(err) => Some(err),
            BindKind::InvalidConfig(_) | BindKind::UnsupportedConfig(_) => {
                None
            }
        }
    }
}

impl From<BindError> for io::Error {
    fn from(err: BindError) -> io::Error {
        match err.kind {
            BindKind::Io(err) => err,
            BindKind::InvalidConfig(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
            BindKind::UnsupportedConfig(_) => {
                io::Error::new(io::ErrorKind::Unsupported, err)
            }
        }
    }
}
