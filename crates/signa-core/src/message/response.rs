/*!
SIP response types.

This module defines [`Response`] and its [`Parts`].
*/

use std::fmt;

use bytes::{Bytes, BytesMut};

use crate::message::{
    ReasonPhrase, StatusCode, Version,
    error::{BuildError, InvalidMessage},
    extensions::Extensions,
    header::{
        CALL_ID, CSEQ, FROM, HeaderMap, HeaderName, HeaderValue, TO, Tag, VIA,
        address::tagged,
    },
    request::Request,
};

/// A SIP response: a status-line, header fields, and a body.
///
/// The body type `T` is generic. A response read from the wire has a `Bytes`
/// body, and higher layers can turn it into a typed body with
/// [`Response::map`].
///
/// The reason phrase is optional. A response read from the wire keeps the
/// phrase it arrived with. A response built without one leaves the choice to
/// serialization, which uses [`StatusCode::canonical_reason`].
///
/// # Example
///
/// [`Response::builder`] builds a response step by step, and
/// [`Response::reply_to`] starts one from the request it answers:
///
/// ```
/// use signa_core::{Response, StatusCode};
///
/// let response = Response::builder()
///     .status(StatusCode::SERVICE_UNAVAILABLE)
///     .reason("Maintenance")
///     .header("Retry-After", "300")
///     .body(())?;
///
/// assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
/// assert_eq!(response.reason().unwrap(), "Maintenance");
/// # Ok::<(), signa_core::message::BuildError>(())
/// ```
///
/// The builder is the only way to create a response from scratch. A response
/// can also be taken apart with [`Response::into_parts`] and put back together
/// with [`Response::from_parts`].
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
    inner: Result<Head, BuildError>,
}

// What a `Builder` has collected so far. The status starts out unset because,
// unlike HTTP's 200, no status makes sense as a default.
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

    /// Creates a [`Builder`] for a response to `request`, with the header
    /// fields every response has to carry copied from it.
    ///
    /// RFC 3261 section 8.2.6.2 requires `Via`, `From`, `To`, `Call-ID`, and
    /// `CSeq` to be copied from the request. The endpoint routes the response
    /// by the `Via` and refuses a response that changes these fields
    /// (`SubmitError::InvalidResponse` or `ReplyError::InvalidResponse`), so
    /// this is the way to start a response to a received request.
    /// The request's `To` usually has no tag. Every response other than 100
    /// needs one (RFC 3261 section 8.2.6.2), and [`Builder::to_tag`] adds it.
    /// Choosing the tag belongs to the caller, since it identifies the dialog.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{Request, Response, StatusCode, message::header::{CSEQ, TO, VIA}};
    ///
    /// let request = Request::from_bytes(
    ///     b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
    ///       Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
    ///       Max-Forwards: 70\r\n\
    ///       To: <sip:carol@chicago.example.com>\r\n\
    ///       From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
    ///       Call-ID: a84b4c76e66710\r\n\
    ///       CSeq: 63104 OPTIONS\r\n\
    ///       Content-Length: 0\r\n\
    ///       \r\n",
    /// )?;
    ///
    /// let response = Response::reply_to(&request)
    ///     .status(StatusCode::OK)
    ///     .header("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE")
    ///     .body(Bytes::new())?;
    ///
    /// assert_eq!(response.headers().get(VIA), request.headers().get(VIA));
    /// assert_eq!(response.headers().get(TO), request.headers().get(TO));
    /// assert_eq!(response.headers().get(CSEQ).unwrap(), "63104 OPTIONS");
    /// assert!(!response.headers().contains_key("Max-Forwards"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn reply_to<T>(request: &Request<T>) -> Builder {
        let head = Head {
            headers: reply_headers(request.headers()),
            ..Head::default()
        };

        Builder { inner: Ok(head) }
    }
}

/// Copies the header fields that every response carries from the headers of a
/// request (RFC 3261 section 8.2.6.2), in the order the request has them.
pub(crate) fn reply_headers(request: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(request.len().min(8));
    for (name, value) in request.iter() {
        if [&VIA, &FROM, &TO, &CALL_ID, &CSEQ].contains(&name) {
            headers.append(name.clone(), value.clone());
        }
    }

    headers
}

/// Encodes a response with `status`, `headers`, and no body. This is what the
/// transaction layer sends on its own, such as the 100 and the 500.
#[cfg(any(feature = "tokio", feature = "__bench", test))]
pub(crate) fn bare_response(headers: &HeaderMap, status: StatusCode) -> Bytes {
    let mut parts = Parts::new(status);
    parts.headers = headers.clone();

    Response::from_parts(parts, Bytes::new()).to_bytes()
}

impl Response<Bytes> {
    /// Parses a response from the bytes of one complete message, copying
    /// them.
    ///
    /// This is [`Response::from_shared`] on a copy of `src`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Response::from_shared`].
    pub fn from_bytes(src: &[u8]) -> Result<Response<Bytes>, InvalidMessage> {
        Response::from_shared(Bytes::copy_from_slice(src))
    }

    /// Parses a response from the bytes of one complete message without
    /// copying them.
    ///
    /// This works like [`Request::from_shared`](crate::Request::from_shared).
    /// The reason phrase is kept as received, even when it is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{Response, StatusCode};
    ///
    /// let response = Response::from_shared(Bytes::from_static(
    ///     b"SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n",
    /// ))?;
    ///
    /// assert_eq!(response.status(), StatusCode::BUSY_HERE);
    /// assert_eq!(response.reason().unwrap().as_str(), "Busy Here");
    /// # Ok::<(), signa_core::message::error::InvalidMessage>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Request::from_shared`], and also if the status code is outside
    /// `100..=699`.
    ///
    /// [`Request::from_shared`]: crate::Request::from_shared
    pub fn from_shared(src: Bytes) -> Result<Response<Bytes>, InvalidMessage> {
        crate::message::parse::response(src)
    }
}

impl<T: AsRef<[u8]>> Response<T> {
    /// Writes the response to the end of `dst` as one complete message.
    ///
    /// This works like [`Request::encode`](crate::Request::encode). A
    /// response without a [`ReasonPhrase`] uses
    /// [`StatusCode::canonical_reason`], or an empty reason phrase if its
    /// code has none.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{Response, StatusCode};
    ///
    /// let response = Response::builder()
    ///     .status(StatusCode::RINGING)
    ///     .body(Bytes::new())?;
    ///
    /// assert_eq!(
    ///     response.to_bytes(),
    ///     &b"SIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n"[..]
    /// );
    /// # Ok::<(), signa_core::message::BuildError>(())
    /// ```
    pub fn encode(&self, dst: &mut BytesMut) {
        crate::message::encode::response(self, dst);
    }

    /// Wire length for transport admission before encoding a second copy.
    #[cfg(feature = "tokio")]
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        crate::message::encode::response_len(self, self.body().as_ref().len())
    }

    /// Encodes an unchanged response after admission reserved its wire length.
    #[cfg(feature = "tokio")]
    pub(crate) fn to_bytes_reserved(&self, len: usize) -> Bytes {
        let mut dst = BytesMut::with_capacity(len);
        crate::message::encode::response_with_len(
            self,
            self.body().as_ref(),
            len,
            &mut dst,
        );
        dst.freeze()
    }

    /// Returns the response as the bytes of one complete message.
    ///
    /// This is [`Response::encode`] into a new buffer.
    pub fn to_bytes(&self) -> Bytes {
        let mut dst = BytesMut::new();
        self.encode(&mut dst);
        dst.freeze()
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
    pub(crate) fn new(status: StatusCode) -> Parts {
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
        <StatusCode as TryFrom<S>>::Error: Into<BuildError>,
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
        <ReasonPhrase as TryFrom<R>>::Error: Into<BuildError>,
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

    /// Adds `tag` to the single `To` header field unless it already has one.
    ///
    /// This follows [RFC 3261 section 8.2.6.2]. A response to a request
    /// whose `To` has no tag must add one, and a response to a request whose
    /// `To` has a tag must copy it unchanged. So the same call suits both the
    /// initial request and a request within a dialog, after
    /// [`Response::reply_to`] copied the `To`. Use [`Tag::random`] for a new
    /// tag, or the one already chosen for this request so that its responses
    /// agree.
    ///
    /// # Errors
    ///
    /// [`Builder::body`] reports [`InvalidTag`] for a tag that is not a SIP
    /// token. It also returns a [`BuildError`] if there is not exactly one
    /// `To` header field, or if that field is not one `name-addr` or
    /// `addr-spec` followed by `generic-param`s (RFC 3261 section 25.1). A
    /// value that cannot be read might already hold a tag, so I report it
    /// rather than append a second one or send the response without one.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{message::header::{Tag, TO}, Request, Response};
    ///
    /// let request = Request::from_bytes(
    ///     b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
    ///       Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
    ///       To: <sip:carol@chicago.example.com>\r\n\
    ///       From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
    ///       Call-ID: a84b4c76e66710\r\n\
    ///       CSeq: 63104 OPTIONS\r\n\
    ///       Content-Length: 0\r\n\
    ///       \r\n",
    /// )?;
    /// let local_tag: Tag = "a6c85cf".parse()?;
    ///
    /// let response = Response::reply_to(&request)
    ///     .status(200)
    ///     .to_tag(local_tag)
    ///     .body(Bytes::new())?;
    ///
    /// assert_eq!(
    ///     response.headers().get(TO).unwrap(),
    ///     "<sip:carol@chicago.example.com>;tag=a6c85cf"
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// [RFC 3261 section 8.2.6.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.2.6.2
    /// [`InvalidTag`]: crate::message::error::InvalidTag
    pub fn to_tag<T>(self, tag: T) -> Builder
    where
        Tag: TryFrom<T>,
        <Tag as TryFrom<T>>::Error: Into<BuildError>,
    {
        self.and_then(|mut head| {
            let tag = Tag::try_from(tag).map_err(Into::into)?;
            let mut values = head.headers.get_all(TO);
            let (Some(to), None) = (values.next(), values.next()) else {
                return Err(BuildError::missing("single To header"));
            };
            match tagged(to.as_str()) {
                Some(true) => return Ok(head),
                Some(false) => {}
                None => return Err(BuildError::missing("readable To header")),
            }

            // A token after `;tag=` keeps a valid header value valid. Without
            // angle brackets, a parameter after the URI is a header parameter
            // too (RFC 3261 section 20), so no rewriting is needed.
            let tagged = format!("{};tag={tag}", to.as_str());
            head.headers.insert(TO, HeaderValue::from_built(tagged));
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
    /// Returns the first error from an earlier call, or an error if the status
    /// was never set.
    pub fn body<T>(self, body: T) -> Result<Response<T>, BuildError> {
        let head = self.inner?;
        let status =
            head.status.ok_or_else(|| BuildError::missing("status"))?;

        let mut parts = Parts::new(status);
        parts.reason = head.reason;
        parts.headers = head.headers;
        parts.extensions = head.extensions;
        Ok(Response::from_parts(parts, body))
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
    use crate::message::header::{HeaderValue, TO};

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
    fn to_tag_appends_one_header_parameter() {
        for (to, tagged) in [
            ("<sip:bob@b>", "<sip:bob@b>;tag=uas"),
            (
                "Bob <sip:bob@b;transport=tcp>",
                "Bob <sip:bob@b;transport=tcp>;tag=uas",
            ),
            ("sip:bob@b", "sip:bob@b;tag=uas"),
        ] {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(TO, to)
                .to_tag("uas")
                .body(())
                .unwrap();

            assert_eq!(response.headers().get(TO).unwrap(), tagged);
        }
    }

    // Appending `;tag=` works for every value siparse reads, since a header
    // parameter may follow any address, after whitespace or a fold too.
    #[test]
    fn a_tag_appended_to_a_readable_value_reads_back() {
        use crate::message::header::address;

        for to in [
            "<sip:bob@b>",
            "\"Bob; B.\" <sip:bob@b>",
            "<sip:bob@[2001:db8::1]>",
            "tel:+12015550123;phone-context=example.com",
            "<sip:bob@b>;x=[2001:db8::1]",
            "<sip:bob@b>\r\n ",
        ] {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(TO, to)
                .to_tag("uas")
                .body(())
                .unwrap();

            let tagged = response.headers().get(TO).unwrap().as_str();
            let tag = siparse::value::address(tagged)
                .unwrap()
                .params
                .iter()
                .find(|param| param.name == "tag")
                .and_then(|param| param.value);
            assert_eq!(tag, Some("uas"), "{to:?}");
            assert_eq!(address::uri(tagged), address::uri(to), "{to:?}");
        }
    }

    #[test]
    fn to_tag_keeps_the_tag_of_a_request_within_a_dialog() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(TO, "<sip:bob@b>;tag=dialog")
            .to_tag("uas")
            .body(())
            .unwrap();

        assert_eq!(
            response.headers().get(TO).unwrap(),
            "<sip:bob@b>;tag=dialog"
        );
    }

    #[test]
    fn to_tag_rejects_invalid_or_ambiguous_input() {
        let invalid = Response::builder()
            .status(StatusCode::OK)
            .header(TO, "<sip:bob@b>")
            .to_tag("not a token")
            .body(())
            .unwrap_err();
        assert!(invalid.is::<crate::message::error::InvalidTag>());

        for headers in [&[][..], &["<sip:bob@b>", "<sip:carol@c>"][..]] {
            let mut builder = Response::builder().status(StatusCode::OK);
            for to in headers {
                builder = builder.header(TO, *to);
            }

            assert!(builder.to_tag("uas").body(()).is_err(), "{headers:?}");
        }

        for to in ["Bob<sip:bob@b>", "<sip:bob@b>;x=a/b", "\"Bob <sip:bob@b>"]
        {
            let error = Response::builder()
                .status(StatusCode::OK)
                .header(TO, to)
                .to_tag("uas")
                .body(())
                .unwrap_err();
            assert_eq!(error.to_string(), "builder has no readable To header");
        }
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
        assert!(err.is::<crate::message::error::InvalidStatusCode>());

        let err = Response::builder()
            .status(200)
            .reason("<bad>")
            .body(())
            .unwrap_err();
        assert!(err.is::<crate::message::error::InvalidReasonPhrase>());
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
