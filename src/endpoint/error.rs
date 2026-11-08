/*!
The errors of binding an endpoint and of a request sent through
[`Endpoint::start`].

[`Endpoint::start`]: super::Endpoint::start
*/

use std::{error, fmt, io};

use super::driver::MAX_UDP_REQUEST;
use crate::message::HeaderName;

/// A start rejection or a terminal client response-stream failure.
///
/// RFC 3261 section 8.1.3.1 tells a transaction user to treat a timeout as a
/// 408 and a transport error as a 503. signa reports both as errors instead
/// of making up a response, and [`Error::is_timeout`] and
/// [`Error::is_transport`] tell them apart. The other cases are refusals: a
/// request too large for UDP, a missing or invalid `CSeq`, a method this
/// client cannot send, exhausted request or connection admission, or an
/// endpoint that has stopped. Response delivery overflow is reported after
/// already queued responses, without ending the underlying SIP machine.
///
/// [`Endpoint::start`]: super::Endpoint::start
pub struct Error {
    kind: Kind,
}

enum Kind {
    Timeout,
    DeliveryOverflow,
    Transport(io::Error),
    TooLarge(usize),
    Missing(HeaderName),
    InvalidCSeq,
    UnsupportedMethod,
    UnsupportedRouting,
    Busy,
    Closed,
}

impl Error {
    pub(super) fn timeout() -> Error {
        Error { kind: Kind::Timeout }
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

    pub(super) fn unsupported_method() -> Error {
        Error { kind: Kind::UnsupportedMethod }
    }

    pub(super) fn unsupported_routing() -> Error {
        Error { kind: Kind::UnsupportedRouting }
    }

    pub(super) fn busy() -> Error {
        Error { kind: Kind::Busy }
    }

    pub(super) fn closed() -> Error {
        Error { kind: Kind::Closed }
    }

    /// Returns `true` if no final response arrived before Timer F, which is
    /// 64 T1 after the request was sent.
    pub fn is_timeout(&self) -> bool {
        matches!(self.kind, Kind::Timeout)
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
    /// other than the request's method. The request was not sent.
    pub fn is_invalid_cseq(&self) -> bool {
        matches!(self.kind, Kind::InvalidCSeq)
    }

    /// Returns `true` for INVITE, ACK or CANCEL, which this non-INVITE
    /// client cannot send with the required transaction semantics.
    pub fn is_unsupported_method(&self) -> bool {
        matches!(self.kind, Kind::UnsupportedMethod)
    }

    /// Returns `true` if the request needs TLS, targets multicast, or targets
    /// UDP on an endpoint without a UDP socket. The request was not sent.
    pub fn is_unsupported_routing(&self) -> bool {
        matches!(self.kind, Kind::UnsupportedRouting)
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
            Kind::DeliveryOverflow => debug.field(&"DeliveryOverflow"),
            Kind::Transport(err) => debug.field(err),
            Kind::TooLarge(len) => {
                debug.field(&format_args!("TooLarge({len})"))
            }
            Kind::Missing(name) => {
                debug.field(&format_args!("Missing({name:?})"))
            }
            Kind::InvalidCSeq => debug.field(&"InvalidCSeq"),
            Kind::UnsupportedMethod => debug.field(&"UnsupportedMethod"),
            Kind::UnsupportedRouting => debug.field(&"UnsupportedRouting"),
            Kind::Busy => debug.field(&"Busy"),
            Kind::Closed => debug.field(&"Closed"),
        };
        debug.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Timeout => f.write_str("no final response before Timer F"),
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
            Kind::UnsupportedMethod => f.write_str(
                "the client does not support INVITE, ACK or CANCEL",
            ),
            Kind::UnsupportedRouting => {
                f.write_str("the endpoint has no transport for this target")
            }
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
/// could satisfy from a socket that failed to bind. It converts into an
/// [`io::Error`] for callers that report I/O errors, with `InvalidInput` for
/// an invalid configuration.
///
/// [`Builder::bind`]: super::Builder::bind
pub struct BindError {
    kind: BindKind,
}

enum BindKind {
    Io(io::Error),
    InvalidConfig(&'static str),
}

impl BindError {
    pub(super) fn io(err: io::Error) -> BindError {
        BindError { kind: BindKind::Io(err) }
    }

    pub(super) fn invalid_config(reason: &'static str) -> BindError {
        BindError { kind: BindKind::InvalidConfig(reason) }
    }

    /// Returns `true` if the configuration is invalid, such as a zero
    /// capacity where the endpoint needs a positive one. No socket was bound.
    pub fn is_invalid_config(&self) -> bool {
        matches!(self.kind, BindKind::InvalidConfig(_))
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
        }
    }
}

impl error::Error for BindError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.kind {
            BindKind::Io(err) => Some(err),
            BindKind::InvalidConfig(_) => None,
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
        }
    }
}
