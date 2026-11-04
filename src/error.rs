/*!
The general error type.
*/

use std::{convert::Infallible, error, fmt};

use crate::{
    header::{InvalidHeaderName, InvalidHeaderValue},
    method::InvalidMethod,
    reason::InvalidReasonPhrase,
    status::InvalidStatusCode,
    uri::InvalidUri,
};

/// A general error for building SIP messages.
///
/// The more specific errors in this crate, such as [`InvalidMethod`], all
/// convert into this one, so builders and other code that takes several
/// kinds of input can report any of them through `?`.
///
/// [`Error::get_ref`] returns the underlying error, and [`Error::is`] checks
/// its type.
///
/// ```
/// use signa::{InvalidMethod, Request};
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
pub(crate) struct Missing(&'static str);

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

macro_rules! from_errors {
    ($($kind:ident($ty:ty),)+) => {
        $(
            impl From<$ty> for Error {
                fn from(err: $ty) -> Error {
                    Error { inner: ErrorKind::$kind(err) }
                }
            }
        )+
    };
}

from_errors! {
    Method(InvalidMethod),
    Uri(InvalidUri),
    StatusCode(InvalidStatusCode),
    ReasonPhrase(InvalidReasonPhrase),
    HeaderName(InvalidHeaderName),
    HeaderValue(InvalidHeaderValue),
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
