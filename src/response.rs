/*!
SIP response types.

This module defines [`Response`] and its [`Parts`].
*/

use std::fmt;

use crate::{
    error::Error,
    extensions::Extensions,
    header::{HeaderMap, HeaderName, HeaderValue},
    reason::ReasonPhrase,
    status::StatusCode,
    version::Version,
};

/// A SIP response: a status-line, header fields, and a body.
///
/// The body type `T` is generic. A response read from the wire has a
/// `Bytes` body, and higher layers can turn it into a typed body with
/// [`Response::map`].
///
/// The reason phrase is optional. A response read from the wire keeps the
/// phrase it arrived with. A response built without one leaves the choice to
/// serialization, which uses [`StatusCode::canonical_reason`].
///
/// [`Response::builder`] builds a response step by step:
///
/// ```
/// use signa::{Response, StatusCode};
///
/// let response = Response::builder()
///     .status(StatusCode::SERVICE_UNAVAILABLE)
///     .reason("Maintenance")
///     .header("Retry-After", "300")
///     .body(())?;
///
/// assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
/// assert_eq!(response.reason().unwrap(), "Maintenance");
/// # Ok::<(), signa::Error>(())
/// ```
///
/// The builder is the only way to create a response from scratch. A
/// response can also be taken apart with [`Response::into_parts`] and put
/// back together with [`Response::from_parts`].
#[derive(Clone)]
pub struct Response<T> {
    head: Parts,
    body: T,
}

/// The parts of a [`Response`] other than its body.
///
/// [`Response::into_parts`] splits a response into its parts and body, and
/// [`Response::from_parts`] joins them again. The fields are public so they
/// can be changed in between.
#[derive(Clone)]
#[non_exhaustive]
pub struct Parts {
    /// The status code.
    pub status: StatusCode,
    /// The reason phrase, or `None` to leave it to serialization.
    pub reason: Option<ReasonPhrase>,
    /// The SIP version.
    pub version: Version,
    /// The header fields.
    pub headers: HeaderMap,
    /// Extra data that is not part of the message.
    pub extensions: Extensions,
}

/// A builder for a [`Response`].
///
/// This is created by [`Response::builder`]. Each method takes anything that
/// converts into the target type. The first conversion that fails is kept,
/// later calls are ignored, and [`Builder::body`] returns that error.
///
/// SIP has no default status, so [`Builder::body`] also fails if the status
/// was never set.
#[derive(Debug)]
pub struct Builder {
    inner: Result<Head, Error>,
}

// What a `Builder` has collected so far. The status starts out unset
// because, unlike HTTP's 200, no status makes sense as a default.
#[derive(Debug, Default)]
struct Head {
    status: Option<StatusCode>,
    reason: Option<ReasonPhrase>,
    headers: HeaderMap,
    extensions: Extensions,
}

impl Response<()> {
    /// Creates a [`Builder`] for a response.
    pub fn builder() -> Builder {
        Builder::new()
    }
}

impl<T> Response<T> {
    /// Creates a response from its parts and body.
    pub fn from_parts(parts: Parts, body: T) -> Response<T> {
        Response { head: parts, body }
    }

    /// Returns the status code.
    pub fn status(&self) -> StatusCode {
        self.head.status
    }

    /// Returns a mutable reference to the status code.
    pub fn status_mut(&mut self) -> &mut StatusCode {
        &mut self.head.status
    }

    /// Returns the reason phrase, if one is set.
    pub fn reason(&self) -> Option<&ReasonPhrase> {
        self.head.reason.as_ref()
    }

    /// Returns a mutable reference to the reason phrase.
    pub fn reason_mut(&mut self) -> &mut Option<ReasonPhrase> {
        &mut self.head.reason
    }

    /// Returns the SIP version.
    pub fn version(&self) -> Version {
        self.head.version
    }

    /// Returns the header fields.
    pub fn headers(&self) -> &HeaderMap {
        &self.head.headers
    }

    /// Returns a mutable reference to the header fields.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.head.headers
    }

    /// Returns the extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.head.extensions
    }

    /// Returns a mutable reference to the extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.head.extensions
    }

    /// Returns the body.
    pub fn body(&self) -> &T {
        &self.body
    }

    /// Returns a mutable reference to the body.
    pub fn body_mut(&mut self) -> &mut T {
        &mut self.body
    }

    /// Consumes the response and returns its body.
    pub fn into_body(self) -> T {
        self.body
    }

    /// Consumes the response and returns its parts and body.
    pub fn into_parts(self) -> (Parts, T) {
        (self.head, self.body)
    }

    /// Converts the body with `f`, keeping the other parts.
    pub fn map<U, F>(self, f: F) -> Response<U>
    where
        F: FnOnce(T) -> U,
    {
        Response { head: self.head, body: f(self.body) }
    }
}

impl<T: fmt::Debug> fmt::Debug for Response<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status())
            .field("reason", &self.reason())
            .field("version", &self.version())
            .field("headers", self.headers())
            .field("extensions", self.extensions())
            .field("body", self.body())
            .finish()
    }
}

impl Parts {
    fn new(status: StatusCode) -> Parts {
        Parts {
            status,
            reason: None,
            version: Version::SIP_2_0,
            headers: HeaderMap::new(),
            extensions: Extensions::new(),
        }
    }
}

impl fmt::Debug for Parts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parts")
            .field("status", &self.status)
            .field("reason", &self.reason)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Builder {
    /// Creates a builder with no status, reason phrase, or headers.
    pub fn new() -> Builder {
        Builder { inner: Ok(Head::default()) }
    }

    /// Sets the status code.
    pub fn status<S>(self, status: S) -> Builder
    where
        StatusCode: TryFrom<S>,
        <StatusCode as TryFrom<S>>::Error: Into<Error>,
    {
        self.and_then(|mut head| {
            head.status =
                Some(StatusCode::try_from(status).map_err(Into::into)?);
            Ok(head)
        })
    }

    /// Returns the status code set so far, if any.
    ///
    /// Returns `None` after an error.
    pub fn status_ref(&self) -> Option<&StatusCode> {
        self.inner.as_ref().ok()?.status.as_ref()
    }

    /// Sets the reason phrase.
    ///
    /// Without one, serialization uses the status code's canonical reason.
    pub fn reason<R>(self, reason: R) -> Builder
    where
        ReasonPhrase: TryFrom<R>,
        <ReasonPhrase as TryFrom<R>>::Error: Into<Error>,
    {
        self.and_then(|mut head| {
            head.reason =
                Some(ReasonPhrase::try_from(reason).map_err(Into::into)?);
            Ok(head)
        })
    }

    /// Returns the reason phrase set so far, if any.
    ///
    /// Returns `None` after an error.
    pub fn reason_ref(&self) -> Option<&ReasonPhrase> {
        self.inner.as_ref().ok()?.reason.as_ref()
    }

    /// Appends a header field, as [`HeaderMap::append`] does.
    ///
    /// Rows with the same name are kept, so calling this twice with `Via`
    /// gives two `Via` rows in that order.
    pub fn header<K, V>(self, name: K, value: V) -> Builder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<Error>,
    {
        self.and_then(|mut head| {
            let name = HeaderName::try_from(name).map_err(Into::into)?;
            let value = HeaderValue::try_from(value).map_err(Into::into)?;
            head.headers.append(name, value);
            Ok(head)
        })
    }

    /// Returns the header fields set so far.
    ///
    /// Returns `None` after an error.
    pub fn headers_ref(&self) -> Option<&HeaderMap> {
        Some(&self.inner.as_ref().ok()?.headers)
    }

    /// Returns a mutable reference to the header fields set so far.
    ///
    /// Returns `None` after an error.
    pub fn headers_mut(&mut self) -> Option<&mut HeaderMap> {
        Some(&mut self.inner.as_mut().ok()?.headers)
    }

    /// Adds an extension, replacing any earlier one of the same type.
    pub fn extension<E>(self, extension: E) -> Builder
    where
        E: Clone + Send + Sync + 'static,
    {
        self.and_then(|mut head| {
            head.extensions.insert(extension);
            Ok(head)
        })
    }

    /// Returns the extensions set so far.
    ///
    /// Returns `None` after an error.
    pub fn extensions_ref(&self) -> Option<&Extensions> {
        Some(&self.inner.as_ref().ok()?.extensions)
    }

    /// Returns a mutable reference to the extensions set so far.
    ///
    /// Returns `None` after an error.
    pub fn extensions_mut(&mut self) -> Option<&mut Extensions> {
        Some(&mut self.inner.as_mut().ok()?.extensions)
    }

    /// Finishes the response with `body`.
    ///
    /// # Errors
    ///
    /// Returns the first error from an earlier call, or an error if the
    /// status was never set.
    pub fn body<T>(self, body: T) -> Result<Response<T>, Error> {
        let head = self.inner?;
        let status = head.status.ok_or_else(|| Error::missing("status"))?;

        let mut parts = Parts::new(status);
        parts.reason = head.reason;
        parts.headers = head.headers;
        parts.extensions = head.extensions;
        Ok(Response::from_parts(parts, body))
    }

    fn and_then<F>(self, f: F) -> Builder
    where
        F: FnOnce(Head) -> Result<Head, Error>,
    {
        Builder { inner: self.inner.and_then(f) }
    }
}

impl Default for Builder {
    fn default() -> Builder {
        Builder::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::header::{HeaderValue, TO};

    use super::*;

    fn response<T>(status: StatusCode, body: T) -> Response<T> {
        Response::builder().status(status).body(body).unwrap()
    }

    #[test]
    fn builder_defaults() {
        let response = response(StatusCode::RINGING, ());
        assert_eq!(response.status(), StatusCode::RINGING);
        assert!(response.reason().is_none());
        assert_eq!(response.version(), Version::SIP_2_0);
        assert!(response.headers().is_empty());
        assert!(response.extensions().is_empty());
    }

    #[test]
    fn accessors_change_the_response() {
        let mut response = response(StatusCode::TRYING, "");
        *response.status_mut() = StatusCode::BUSY_HERE;
        *response.reason_mut() = Some(ReasonPhrase::from_static("Busy"));
        response
            .headers_mut()
            .append(TO, HeaderValue::from_static("<sip:bob@b>;tag=1"));
        response.extensions_mut().insert(7u8);
        *response.body_mut() = "busy";

        assert_eq!(response.status(), StatusCode::BUSY_HERE);
        assert_eq!(response.reason().unwrap(), "Busy");
        assert_eq!(response.headers().get(TO).unwrap(), "<sip:bob@b>;tag=1");
        assert_eq!(response.extensions().get::<u8>(), Some(&7));
        assert_eq!(response.into_body(), "busy");
    }

    #[test]
    fn parts_round_trip_and_map() {
        let response = response(StatusCode::OK, "v=0");

        let (mut parts, body) = response.into_parts();
        parts.reason = Some(ReasonPhrase::from_static("Fine"));
        let response = Response::from_parts(parts, body).map(str::len);

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.reason().unwrap(), "Fine");
        assert_eq!(*response.body(), 3);
    }

    #[test]
    fn builder_builds_a_response() {
        let response = Response::builder()
            .status(486)
            .reason("Busy Here")
            .header(TO, "<sip:bob@b>;tag=1")
            .header("Retry-After", "60")
            .extension(7u8)
            .body("busy")
            .unwrap();

        assert_eq!(response.status(), StatusCode::BUSY_HERE);
        assert_eq!(response.reason().unwrap(), "Busy Here");
        assert_eq!(response.headers().get(TO).unwrap(), "<sip:bob@b>;tag=1");
        assert_eq!(response.headers().len(), 2);
        assert_eq!(response.extensions().get::<u8>(), Some(&7));
        assert_eq!(*response.body(), "busy");
    }

    #[test]
    fn builder_refs_follow_the_calls() {
        let mut builder = Response::builder().status(StatusCode::OK);
        assert_eq!(builder.status_ref(), Some(&StatusCode::OK));
        assert!(builder.reason_ref().is_none());

        builder
            .headers_mut()
            .unwrap()
            .append(TO, HeaderValue::from_static("<sip:b>"));
        builder.extensions_mut().unwrap().insert(1u8);
        assert_eq!(builder.headers_ref().unwrap().len(), 1);
        assert_eq!(builder.extensions_ref().unwrap().len(), 1);
    }

    #[test]
    fn builder_keeps_the_first_error() {
        let err = Response::builder()
            .status(99)
            .reason("<bad>")
            .status(StatusCode::OK)
            .body(())
            .unwrap_err();
        assert!(err.is::<crate::error::InvalidStatusCode>());

        let err = Response::builder()
            .status(200)
            .reason("<bad>")
            .body(())
            .unwrap_err();
        assert!(err.is::<crate::error::InvalidReasonPhrase>());
    }

    #[test]
    fn builder_requires_a_status() {
        let err = Response::builder().reason("OK").body(()).unwrap_err();
        assert_eq!(err.to_string(), "builder has no status");
    }

    #[test]
    fn debug_shows_the_head_and_body() {
        let response = response(StatusCode::OK, ());
        let debug = format!("{response:?}");
        assert!(debug.starts_with("Response { status: 200, reason: None"));
        assert!(debug.ends_with("body: () }"));
    }
}
