/*!
SIP request types.

This module defines [`Request`] and its [`Parts`].
*/

use std::fmt;

use bytes::{Bytes, BytesMut};

use crate::message::{
    Method, Uri, Version,
    error::{BuildError, InvalidMessage},
    extensions::Extensions,
    header::{HeaderMap, HeaderName, HeaderValue},
};

/// A SIP request: a request-line, header fields, and a body.
///
/// The body type `T` is generic. A request read from the wire has a `Bytes`
/// body, and higher layers can turn it into a typed body with
/// [`Request::map`].
///
/// # Example
///
/// [`Request::builder`] builds a request step by step:
///
/// ```
/// use signa::{Method, Request, message::header::CALL_ID};
///
/// let request = Request::builder()
///     .method("OPTIONS")
///     .uri("sip:carol@chicago.example.com")
///     .header("Call-ID", "a84b4c76e66710")
///     .header("Max-Forwards", "70")
///     .body(())?;
///
/// assert_eq!(request.method(), Method::OPTIONS);
/// assert_eq!(request.uri().as_str(), "sip:carol@chicago.example.com");
/// assert_eq!(request.headers().get(CALL_ID).unwrap(), "a84b4c76e66710");
/// # Ok::<(), signa::message::BuildError>(())
/// ```
///
/// The builder is the only way to create a request from scratch. A request
/// can also be taken apart with [`Request::into_parts`] and put back together
/// with [`Request::from_parts`].
#[derive(Clone)]
pub struct Request<T> {
    head: Parts,
    body: T,
}

/// The parts of a [`Request`] other than its body.
///
/// [`Request::into_parts`] splits a request into its parts and body, and
/// [`Request::from_parts`] joins them again. The fields are public so they
/// can be changed in between.
#[derive(Clone)]
#[non_exhaustive]
pub struct Parts {
    /// The request method.
    pub method: Method,
    /// The Request-URI.
    pub uri: Uri,
    /// The SIP version.
    pub version: Version,
    /// The header fields.
    pub headers: HeaderMap,
    /// Extra data that is not part of the message.
    pub extensions: Extensions,
}

/// A builder for a [`Request`].
///
/// This is created by [`Request::builder`]. Each method takes anything that
/// converts into the target type. The first conversion that fails is kept,
/// later calls are ignored, and [`Builder::body`] returns that error.
///
/// SIP has no default method or Request-URI, so [`Builder::body`] also fails
/// if either was never set.
#[derive(Debug)]
pub struct Builder {
    inner: Result<Head, BuildError>,
}

// What a `Builder` has collected so far. The method and URI start out unset
// because, unlike in HTTP, there is nothing sensible to default them to.
#[derive(Debug, Default)]
struct Head {
    method: Option<Method>,
    uri: Option<Uri>,
    headers: HeaderMap,
    extensions: Extensions,
}

impl Request<()> {
    /// Creates a [`Builder`] for a request.
    pub fn builder() -> Builder {
        Builder::new()
    }
}

impl Request<Bytes> {
    /// Parses a request from the bytes of one complete message, copying them.
    ///
    /// This is [`Request::from_shared`] on a copy of `src`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Request::from_shared`].
    pub fn from_bytes(src: &[u8]) -> Result<Request<Bytes>, InvalidMessage> {
        Request::from_shared(Bytes::copy_from_slice(src))
    }

    /// Parses a request from the bytes of one complete message without copying
    /// them.
    ///
    /// The Request-URI, the header values, and the body share `src`. Only
    /// header names are copied, when they are not standard names, because
    /// [`HeaderName`] normalizes them.
    ///
    /// `src` must hold the whole message, such as one UDP datagram. This does
    /// not frame messages on a stream. The body is the rest of `src` after the
    /// head, cut to `Content-Length` if the message has one. Bytes after that
    /// are dropped, as RFC 3261 section 18.3 says for datagrams.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa::{Method, Request, message::header::CALL_ID};
    ///
    /// let request = Request::from_shared(Bytes::from_static(
    ///     b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\n\
    ///       Call-ID: a84b4c76e66710\r\n\
    ///       Content-Length: 5\r\n\
    ///       \r\n\
    ///       hello",
    /// ))?;
    ///
    /// assert_eq!(request.method(), Method::MESSAGE);
    /// assert_eq!(request.headers().get(CALL_ID).unwrap(), "a84b4c76e66710");
    /// assert_eq!(request.body(), "hello");
    /// # Ok::<(), signa::message::error::InvalidMessage>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] if:
    ///
    /// * the head is invalid or ends before its empty line;
    /// * the head has more than 100 header fields;
    /// * `Content-Length` is not a number, or appears more than once with
    ///   different values;
    /// * the body is shorter than `Content-Length`.
    pub fn from_shared(src: Bytes) -> Result<Request<Bytes>, InvalidMessage> {
        super::parse::request(src)
    }
}

impl<T: AsRef<[u8]>> Request<T> {
    /// Writes the request to the end of `dst` as one complete message.
    ///
    /// Header fields are written in the order of [`Request::headers`], with
    /// their values as stored, folds included. Standard names take their long
    /// form, such as `Call-ID`, and other names stay lowercase.
    ///
    /// The `Content-Length` field always comes from the body, after the other
    /// fields. Any `Content-Length` in the headers is skipped, so the two
    /// cannot disagree.
    ///
    /// A request built without a body has a `()` body, which this cannot
    /// write. Give it an empty `Bytes` instead.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::{Bytes, BytesMut};
    /// use signa::Request;
    ///
    /// let request = Request::builder()
    ///     .method("OPTIONS")
    ///     .uri("sip:carol@chicago.example.com")
    ///     .header("Call-ID", "a84b4c76e66710")
    ///     .body(Bytes::new())?;
    ///
    /// let mut dst = BytesMut::new();
    /// request.encode(&mut dst);
    ///
    /// assert_eq!(
    ///     dst,
    ///     &b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
    ///        Call-ID: a84b4c76e66710\r\n\
    ///        Content-Length: 0\r\n\
    ///        \r\n"[..]
    /// );
    /// # Ok::<(), signa::message::BuildError>(())
    /// ```
    pub fn encode(&self, dst: &mut BytesMut) {
        super::encode::request(self, dst);
    }

    /// Wire length for transport admission before encoding.
    #[cfg(feature = "tokio")]
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        super::encode::request_len(self, self.body().as_ref().len())
    }

    /// Returns the request as the bytes of one complete message.
    ///
    /// This is [`Request::encode`] into a new buffer.
    pub fn to_bytes(&self) -> Bytes {
        let mut dst = BytesMut::new();
        self.encode(&mut dst);
        dst.freeze()
    }
}

impl<T> Request<T> {
    /// Creates a request from its parts and body.
    pub fn from_parts(parts: Parts, body: T) -> Request<T> {
        Request { head: parts, body }
    }

    /// Returns the request method.
    pub fn method(&self) -> &Method {
        &self.head.method
    }

    /// Returns a mutable reference to the request method.
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.head.method
    }

    /// Returns the Request-URI.
    pub fn uri(&self) -> &Uri {
        &self.head.uri
    }

    /// Returns a mutable reference to the Request-URI.
    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.head.uri
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

    /// Consumes the request and returns its body.
    pub fn into_body(self) -> T {
        self.body
    }

    /// Consumes the request and returns its parts and body.
    pub fn into_parts(self) -> (Parts, T) {
        (self.head, self.body)
    }

    /// Converts the body with `f`, keeping the other parts.
    ///
    /// # Example
    ///
    /// ```
    /// use signa::Request;
    ///
    /// let request = Request::builder()
    ///     .method("MESSAGE")
    ///     .uri("sip:bob@biloxi.example.com")
    ///     .body("Watson, come here.")?;
    ///
    /// let request = request.map(|body| body.len());
    /// assert_eq!(*request.body(), 18);
    /// # Ok::<(), signa::message::BuildError>(())
    /// ```
    pub fn map<U, F>(self, f: F) -> Request<U>
    where
        F: FnOnce(T) -> U,
    {
        Request { head: self.head, body: f(self.body) }
    }
}

impl<T: fmt::Debug> fmt::Debug for Request<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", self.method())
            .field("uri", self.uri())
            .field("version", &self.version())
            .field("headers", self.headers())
            .field("extensions", self.extensions())
            .field("body", self.body())
            .finish()
    }
}

impl Parts {
    pub(crate) fn new(method: Method, uri: Uri) -> Parts {
        Parts {
            method,
            uri,
            version: Version::SIP_2_0,
            headers: HeaderMap::new(),
            extensions: Extensions::new(),
        }
    }
}

impl fmt::Debug for Parts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parts")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Builder {
    /// Creates a builder with no method, Request-URI, or headers.
    pub fn new() -> Builder {
        Builder { inner: Ok(Head::default()) }
    }

    /// Sets the request method.
    pub fn method<M>(self, method: M) -> Builder
    where
        Method: TryFrom<M>,
        <Method as TryFrom<M>>::Error: Into<BuildError>,
    {
        self.and_then(|mut head| {
            head.method = Some(Method::try_from(method).map_err(Into::into)?);
            Ok(head)
        })
    }

    /// Returns the method set so far, if any.
    ///
    /// Returns `None` after an error.
    pub fn method_ref(&self) -> Option<&Method> {
        self.inner.as_ref().ok()?.method.as_ref()
    }

    /// Sets the Request-URI.
    pub fn uri<U>(self, uri: U) -> Builder
    where
        Uri: TryFrom<U>,
        <Uri as TryFrom<U>>::Error: Into<BuildError>,
    {
        self.and_then(|mut head| {
            head.uri = Some(Uri::try_from(uri).map_err(Into::into)?);
            Ok(head)
        })
    }

    /// Returns the Request-URI set so far, if any.
    ///
    /// Returns `None` after an error.
    pub fn uri_ref(&self) -> Option<&Uri> {
        self.inner.as_ref().ok()?.uri.as_ref()
    }

    /// Appends a header field, as [`HeaderMap::append`] does.
    ///
    /// Rows with the same name are kept, so calling this twice with `Via`
    /// gives two `Via` rows in that order.
    pub fn header<K, V>(self, name: K, value: V) -> Builder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<BuildError>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<BuildError>,
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

    /// Finishes the request with `body`.
    ///
    /// # Errors
    ///
    /// Returns the first error from an earlier call, or an error if the method
    /// or Request-URI was never set.
    pub fn body<T>(self, body: T) -> Result<Request<T>, BuildError> {
        let head = self.inner?;
        let method =
            head.method.ok_or_else(|| BuildError::missing("method"))?;
        let uri =
            head.uri.ok_or_else(|| BuildError::missing("Request-URI"))?;

        let mut parts = Parts::new(method, uri);
        parts.headers = head.headers;
        parts.extensions = head.extensions;
        Ok(Request::from_parts(parts, body))
    }

    fn and_then<F>(self, f: F) -> Builder
    where
        F: FnOnce(Head) -> Result<Head, BuildError>,
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
    use crate::message::header::{CSEQ, HeaderValue, VIA};

    use super::*;

    fn invite() -> Request<&'static str> {
        Request::builder()
            .method(Method::INVITE)
            .uri("sip:bob@biloxi.example.com")
            .body("v=0")
            .unwrap()
    }

    #[test]
    fn builder_defaults() {
        let request = invite();
        assert_eq!(request.method(), Method::INVITE);
        assert_eq!(request.uri().as_str(), "sip:bob@biloxi.example.com");
        assert_eq!(request.version(), Version::SIP_2_0);
        assert!(request.headers().is_empty());
        assert!(request.extensions().is_empty());
        assert_eq!(*request.body(), "v=0");
    }

    #[test]
    fn accessors_change_the_request() {
        let mut request = invite();
        *request.method_mut() = Method::ACK;
        *request.uri_mut() = Uri::from_static("sip:bob@192.0.2.4");
        request.headers_mut().append(CSEQ, HeaderValue::from_static("1 ACK"));
        request.extensions_mut().insert(7u8);
        *request.body_mut() = "";

        assert_eq!(request.method(), Method::ACK);
        assert_eq!(request.uri().as_str(), "sip:bob@192.0.2.4");
        assert_eq!(request.headers().get(CSEQ).unwrap(), "1 ACK");
        assert_eq!(request.extensions().get::<u8>(), Some(&7));
        assert_eq!(request.into_body(), "");
    }

    #[test]
    fn parts_round_trip() {
        let mut request = invite();
        request
            .headers_mut()
            .append(VIA, HeaderValue::from_static("SIP/2.0/UDP a"));

        let (mut parts, body) = request.into_parts();
        parts.method = Method::CANCEL;
        let request = Request::from_parts(parts, body);

        assert_eq!(request.method(), Method::CANCEL);
        assert_eq!(request.headers().get(VIA).unwrap(), "SIP/2.0/UDP a");
        assert_eq!(*request.body(), "v=0");
    }

    #[test]
    fn map_keeps_the_head() {
        let mut request = invite();
        request.extensions_mut().insert("received");

        let request = request.map(str::len);
        assert_eq!(request.method(), Method::INVITE);
        assert_eq!(request.extensions().get::<&str>(), Some(&"received"));
        assert_eq!(*request.body(), 3);
    }

    #[test]
    fn builder_builds_a_request() {
        let request = Request::builder()
            .method(Method::INVITE)
            .uri("sip:bob@biloxi.example.com")
            .header(VIA, "SIP/2.0/UDP a")
            .header("v", HeaderValue::from_static("SIP/2.0/UDP b"))
            .header("CSeq", "1 INVITE")
            .extension(7u8)
            .body("v=0")
            .unwrap();

        assert_eq!(request.method(), Method::INVITE);
        assert_eq!(request.uri().as_str(), "sip:bob@biloxi.example.com");
        assert_eq!(
            request.headers().get_all(VIA).collect::<Vec<_>>(),
            ["SIP/2.0/UDP a", "SIP/2.0/UDP b"]
        );
        assert_eq!(request.headers().get(CSEQ).unwrap(), "1 INVITE");
        assert_eq!(request.extensions().get::<u8>(), Some(&7));
        assert_eq!(*request.body(), "v=0");
    }

    #[test]
    fn builder_refs_follow_the_calls() {
        let mut builder = Request::builder().method("BYE");
        assert_eq!(builder.method_ref(), Some(&Method::BYE));
        assert!(builder.uri_ref().is_none());

        builder
            .headers_mut()
            .unwrap()
            .append(CSEQ, HeaderValue::from_static("2 BYE"));
        builder.extensions_mut().unwrap().insert(1u8);
        assert_eq!(builder.headers_ref().unwrap().len(), 1);
        assert_eq!(builder.extensions_ref().unwrap().len(), 1);
    }

    #[test]
    fn builder_keeps_the_first_error() {
        let mut builder = Request::builder()
            .method("INVITE")
            .uri("sip:bob@biloxi.example.com bad")
            .header("Bad Name", "x")
            .method("IN VITE");

        assert!(builder.method_ref().is_none());
        assert!(builder.headers_mut().is_none());
        let err = builder.body(()).unwrap_err();
        assert!(err.is::<crate::message::error::InvalidUri>());
    }

    #[test]
    fn builder_rejects_invalid_headers() {
        let err = Request::builder()
            .method("INVITE")
            .uri("sip:bob@biloxi.example.com")
            .header("Subject", "bare\nlf")
            .body(())
            .unwrap_err();
        assert!(err.is::<crate::message::error::InvalidHeaderValue>());
    }

    #[test]
    fn builder_requires_method_and_uri() {
        let err = Request::builder().uri("sip:bob@b").body(()).unwrap_err();
        assert_eq!(err.to_string(), "builder has no method");

        let err = Request::builder().method("ACK").body(()).unwrap_err();
        assert_eq!(err.to_string(), "builder has no Request-URI");
    }

    #[test]
    fn debug_shows_the_head_and_body() {
        let debug = format!("{:?}", invite());
        assert!(debug.starts_with(
            "Request { method: INVITE, uri: \"sip:bob@biloxi.example.com\""
        ));
        assert!(debug.ends_with("body: \"v=0\" }"));
    }
}
