/*!
Error types.

Each conversion into a SIP message part has its own error, such as
[`InvalidMethod`] for [`Method`]. They all convert into [`Error`], which
builders and other code that takes several kinds of input report.

[`Method`]: crate::Method
*/

use std::{convert::Infallible, error, fmt, str};

/// A general error for building SIP messages.
///
/// The more specific errors in this module, such as [`InvalidMethod`], all
/// convert into this one, so builders and other code that takes several
/// kinds of input can report any of them through `?`.
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
/// This is not public. Callers can tell it apart from the other kinds
/// because [`Error::is`] matches none of the public error types.
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

// Builders accept values that are already of the target type, whose
// `TryFrom` error is `Infallible`.
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
/// Unlike the other errors in this module, its `Display` output says what
/// was wrong with the value.
///
/// The error deliberately does not keep the rejected value. Header values can
/// carry credentials, such as `Authorization`, and an error is easy to log by
/// accident. Not keeping the value also avoids allocating on the error path.
pub struct InvalidHeaderValue {
    kind: InvalidHeaderValueKind,
}

/// What made a header value invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidHeaderValueKind {
    Byte(u8),
    BareCr,
    BareLf,
    MissingWspAfterCrLf,
    Utf8(str::Utf8Error),
}

impl InvalidHeaderValue {
    pub(crate) const fn new(
        kind: InvalidHeaderValueKind,
    ) -> InvalidHeaderValue {
        InvalidHeaderValue { kind }
    }
}

impl fmt::Debug for InvalidHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvalidHeaderValue").field("kind", &self.kind).finish()
    }
}

impl fmt::Display for InvalidHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            InvalidHeaderValueKind::Byte(byte) => {
                write!(f, "invalid byte 0x{byte:02X} in SIP header value")
            }
            InvalidHeaderValueKind::BareCr => {
                f.write_str("bare CR in SIP header value")
            }
            InvalidHeaderValueKind::BareLf => {
                f.write_str("bare LF in SIP header value")
            }
            InvalidHeaderValueKind::MissingWspAfterCrLf => f.write_str(
                "missing SP or HTAB after CRLF in SIP header value",
            ),
            InvalidHeaderValueKind::Utf8(_) => {
                f.write_str("invalid UTF-8 in SIP header value")
            }
        }
    }
}

impl error::Error for InvalidHeaderValue {}

impl From<InvalidHeaderValue> for Error {
    fn from(err: InvalidHeaderValue) -> Error {
        Error { inner: ErrorKind::HeaderValue(err) }
    }
}

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
