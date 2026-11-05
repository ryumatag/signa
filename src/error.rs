/*!
Error types.

Each conversion into a SIP message part has its own error, such as
[`InvalidMethod`] for [`Method`]. They all convert into [`Error`], which
builders and other code that takes several kinds of input report.

[`Method`]: crate::Method
*/

use std::{convert::Infallible, error, fmt};

/// A general error for building SIP messages.
///
/// The more specific errors in this module, such as [`InvalidMethod`], all
/// convert into this one, so builders and other code that takes several kinds
/// of input can report any of them through `?`.
///
/// [`Error::get_ref`] returns the underlying error, and [`Error::is`] checks
/// its type.
///
/// ```
/// use signa::{error::InvalidMethod, Request};
///
/// let err = Request::builder()
///     .method("IN VITE")
///     .uri("sip:bob@biloxi.example.com")
///     .body(())
///     .unwrap_err();
///
/// assert!(err.is::<InvalidMethod>());
/// ```
pub struct Error {
    inner: ErrorKind,
}

enum ErrorKind {
    Method(InvalidMethod),
    Uri(InvalidUri),
    StatusCode(InvalidStatusCode),
    ReasonPhrase(InvalidReasonPhrase),
    HeaderName(InvalidHeaderName),
    HeaderValue(InvalidHeaderValue),
    Missing(Missing),
}

/// A required part was never given to a builder.
///
/// This is not public. Callers can tell it apart from the other kinds because
/// [`Error::is`] matches none of the public error types.
struct Missing(&'static str);

impl Error {
    /// Returns `true` if the underlying error has type `T`.
    pub fn is<T: error::Error + 'static>(&self) -> bool {
        self.get_ref().is::<T>()
    }

    /// Returns the underlying error.
    pub fn get_ref(&self) -> &(dyn error::Error + 'static) {
        match &self.inner {
            ErrorKind::Method(err) => err,
            ErrorKind::Uri(err) => err,
            ErrorKind::StatusCode(err) => err,
            ErrorKind::ReasonPhrase(err) => err,
            ErrorKind::HeaderName(err) => err,
            ErrorKind::HeaderValue(err) => err,
            ErrorKind::Missing(err) => err,
        }
    }

    /// Returns the error for a builder that never got `what`, such as
    /// `"method"`.
    pub(crate) fn missing(what: &'static str) -> Error {
        Error { inner: ErrorKind::Missing(Missing(what)) }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show the underlying error without the private `ErrorKind` noise.
        f.debug_tuple("signa::Error").field(&self.get_ref()).finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.get_ref(), f)
    }
}

impl error::Error for Error {
    // The underlying error is what `Display` shows, so it is not reported
    // again as the source. Its own source, if any, is.
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.get_ref().source()
    }
}

// Builders accept values that are already of the target type, whose `TryFrom`
// error is `Infallible`.
impl From<Infallible> for Error {
    fn from(err: Infallible) -> Error {
        match err {}
    }
}

impl fmt::Debug for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Missing").field(&self.0).finish()
    }
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "builder has no {}", self.0)
    }
}

impl error::Error for Missing {}

// Defines an error that only says the input was invalid, along with its
// conversion into `Error`.
macro_rules! invalid_errors {
    ($(
        $(#[$attr:meta])*
        $name:ident => $kind:ident, $message:literal;
    )+) => {
        $(
            $(#[$attr])*
            pub struct $name {
                _priv: (),
            }

            impl $name {
                pub(crate) const fn new() -> $name {
                    $name { _priv: () }
                }
            }

            impl fmt::Debug for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_struct(stringify!($name)).finish()
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str($message)
                }
            }

            impl error::Error for $name {}

            impl From<$name> for Error {
                fn from(err: $name) -> Error {
                    Error { inner: ErrorKind::$kind(err) }
                }
            }
        )+
    };
}

invalid_errors! {
    /// An error returned when parsing an invalid SIP method.
    InvalidMethod => Method, "invalid SIP method";

    /// An error returned when parsing an invalid SIP request URI.
    InvalidUri => Uri, "invalid SIP request URI";

    /// An error returned when parsing an invalid SIP status code.
    InvalidStatusCode => StatusCode, "invalid SIP status code";

    /// An error returned when parsing an invalid SIP reason phrase.
    InvalidReasonPhrase => ReasonPhrase, "invalid SIP reason phrase";

    /// An error returned when parsing an invalid SIP header field name.
    InvalidHeaderName => HeaderName, "invalid SIP header name";
}

/// An error returned when parsing an invalid SIP header field value.
///
/// Its `Display` output says what was wrong with the value and at which byte,
/// counting from 0, as in `CR not followed by LF at byte 6`.
///
/// The error deliberately does not keep the rejected value, not even the byte
/// at fault. Header values can carry credentials, such as `Authorization`, and
/// an error is easy to log by accident. Not keeping the value also avoids
/// allocating on the error path.
pub struct InvalidHeaderValue {
    kind: siparse::ErrorKind,
    offset: usize,
}

impl InvalidHeaderValue {
    pub(crate) const fn new(
        kind: siparse::ErrorKind,
        offset: usize,
    ) -> InvalidHeaderValue {
        InvalidHeaderValue { kind, offset }
    }
}

impl fmt::Debug for InvalidHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvalidHeaderValue")
            .field("kind", &self.kind)
            .field("offset", &self.offset)
            .finish()
    }
}

impl fmt::Display for InvalidHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // siparse describes the kind, such as "invalid SIP header value" or
        // "CR not followed by LF".
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl error::Error for InvalidHeaderValue {}

impl From<InvalidHeaderValue> for Error {
    fn from(err: InvalidHeaderValue) -> Error {
        Error { inner: ErrorKind::HeaderValue(err) }
    }
}

/// An error returned when parsing an invalid SIP message from bytes.
///
/// Its `Display` output says which part of the message was wrong. Like
/// [`InvalidHeaderValue`], it does not keep any of the rejected bytes.
///
/// It does not convert into [`Error`], which is for building messages.
pub struct InvalidMessage {
    kind: InvalidMessageKind,
}

/// What made a message invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidMessageKind {
    /// siparse rejected the head. `TooManyHeaders` never appears here.
    Head(siparse::ErrorKind),
    TooManyHeaders,
    IncompleteHead,
    StatusCode,
    ContentLength,
    TruncatedBody,
}

impl InvalidMessage {
    pub(crate) const fn new(kind: InvalidMessageKind) -> InvalidMessage {
        InvalidMessage { kind }
    }

    #[cfg(test)]
    pub(crate) const fn kind(&self) -> InvalidMessageKind {
        self.kind
    }
}

impl fmt::Debug for InvalidMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvalidMessage").field("kind", &self.kind).finish()
    }
}

impl fmt::Display for InvalidMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            InvalidMessageKind::Head(kind) => fmt::Display::fmt(&kind, f),
            InvalidMessageKind::TooManyHeaders => write!(
                f,
                "more than {} header fields in SIP message",
                crate::parse::MAX_HEADERS
            ),
            InvalidMessageKind::IncompleteHead => {
                f.write_str("incomplete SIP message head")
            }
            InvalidMessageKind::StatusCode => {
                f.write_str("SIP status code out of range")
            }
            InvalidMessageKind::ContentLength => {
                f.write_str("invalid Content-Length in SIP message")
            }
            InvalidMessageKind::TruncatedBody => {
                f.write_str("SIP message body shorter than Content-Length")
            }
        }
    }
}

impl error::Error for InvalidMessage {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::Method;

    #[test]
    fn wraps_specific_errors() {
        let err: Error = Method::from_bytes(b"").unwrap_err().into();
        assert!(err.is::<InvalidMethod>());
        assert!(!err.is::<InvalidUri>());
        assert_eq!(err.to_string(), "invalid SIP method");
        assert_eq!(format!("{err:?}"), "signa::Error(InvalidMethod)");
    }

    #[test]
    fn missing_parts() {
        let err = Error::missing("method");
        assert_eq!(err.to_string(), "builder has no method");
        assert!(!err.is::<InvalidMethod>());
        assert_eq!(format!("{err:?}"), "signa::Error(Missing(\"method\"))");
    }
}
