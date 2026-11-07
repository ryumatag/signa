/*!
The errors of binding an endpoint and of a request sent through a [`Client`].

[`Client`]: super::Client
*/

use std::{error, fmt, io};

use super::driver::MAX_UDP_REQUEST;
use crate::message::HeaderName;

/// Why a request sent through a [`Client`] got no final response.
///
/// RFC 3261 section 8.1.3.1 tells a transaction user to treat a timeout as a
/// 408 and a transport error as a 503. signa reports both as errors instead
/// of making up a response, and [`Error::is_timeout`] and
/// [`Error::is_transport`] tell them apart. The other cases are refusals: a
/// request too large for UDP, one without the `CSeq` the response is matched
/// by, exhausted request or connection admission, or an endpoint that has
/// stopped.
///
/// [`Client`]: super::Client
pub struct Error {
    kind: Kind,
}

enum Kind {
    Timeout,
    Transport(io::Error),
    TooLarge(usize),
    Missing(HeaderName),
    Busy,
    Closed,
}

impl Error {
    pub(super) fn timeout() -> Error {
        Error { kind: Kind::Timeout }
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
    /// bytes when the MTU is unknown, as it is here. The caller sends such a
    /// request through a TCP client instead.
    pub fn is_too_large(&self) -> bool {
        matches!(self.kind, Kind::TooLarge(_))
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
            Kind::Transport(err) => debug.field(err),
            Kind::TooLarge(len) => {
                debug.field(&format_args!("TooLarge({len})"))
            }
            Kind::Missing(name) => {
                debug.field(&format_args!("Missing({name:?})"))
            }
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
            Kind::Transport(err) => write!(f, "transport error: {err}"),
            Kind::TooLarge(len) => write!(
                f,
                "the request is {len} bytes, over the {MAX_UDP_REQUEST} \
                 that go over UDP"
            ),
            Kind::Missing(name) => write!(f, "the request has no {name}"),
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
