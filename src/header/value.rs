use std::{
    any::Any,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    iter::FusedIterator,
    str::{self, FromStr},
};

use bytes::Bytes;

/// A generic SIP header field value as defined by RFC 3261.
///
/// This type models the generic `header-value` production from RFC 3261,
/// Section 25.1:
///
/// ```text
/// header-value = *(TEXT-UTF8char / UTF8-CONT / LWS)
/// ```
///
/// This type intentionally validates only the *generic* header field value
/// grammar. It does not attempt to enforce the grammar or semantics of
/// specific header fields such as `Subject`, `From`, `To`, `Warning`,
/// `Contact`, and so on. Those checks belong in higher-level typed header
/// parsers.
///
/// The value is stored exactly as given, including folds (`CRLF` followed by
/// `SP` or `HTAB`) and leading or trailing whitespace. This matches what
/// [`siparse`] returns for a parsed head, so a received value can be kept as
/// it arrived without copying or rewriting it. [`HeaderValue::lines`] splits
/// the value at its folds for consumers that need the unfolded text.
///
/// I keep folds instead of unfolding at construction because unfolding has to
/// allocate. That would rule out a `const` [`HeaderValue::from_static`] and
/// zero-copy construction from a received buffer.
///
/// [`siparse`]: https://docs.rs/siparse
#[derive(Clone)]
pub struct HeaderValue {
    raw: Bytes,
    is_sensitive: bool,
}

/// Represents an invalid header field value.
///
/// This is an error returned when constructing a [`HeaderValue`] from bytes
/// or text. Its `Display` output says what was wrong with the value.
///
/// The error deliberately does not keep the rejected value. Header values can
/// carry credentials, such as `Authorization`, and an error is easy to log by
/// accident. Not keeping the value also avoids allocating on the error path.
pub struct InvalidHeaderValue {
    kind: InvalidHeaderValueKind,
}

impl HeaderValue {
    /// Creates a new `HeaderValue` from a static string.
    ///
    /// The input must satisfy the same rules as [`HeaderValue::from_bytes`].
    /// A `&'static str` is already valid UTF-8, so only the byte-level rules
    /// are checked. This makes the function usable in `const` contexts.
    ///
    /// ```
    /// use signa::HeaderValue;
    ///
    /// const APPLICATION_SDP: HeaderValue =
    ///     HeaderValue::from_static("application/sdp");
    ///
    /// assert_eq!(APPLICATION_SDP, "application/sdp");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `src` contains bytes that are illegal in a generic SIP
    /// header field value. In a `const` context this is a compile error.
    pub const fn from_static(src: &'static str) -> HeaderValue {
        let bytes = src.as_bytes();
        if check_bytes(bytes).is_err() {
            panic!("invalid SIP header field value");
        }

        HeaderValue { raw: Bytes::from_static(bytes), is_sensitive: false }
    }

    /// Attempts to create a new `HeaderValue` from raw bytes.
    ///
    /// Validation follows RFC 3261's generic `header-value` production:
    ///
    /// ```text
    /// header-value = *(TEXT-UTF8char / UTF8-CONT / LWS)
    /// ```
    ///
    /// More concretely, this constructor accepts:
    ///
    /// * visible ASCII octets in `0x21..=0x7E` except where otherwise rejected
    ///   below;
    /// * `SP` and `HTAB` as linear whitespace;
    /// * folded linear whitespace of the form `CRLF 1*(SP / HTAB)`;
    /// * non-ASCII octets that participate in a well-formed UTF-8 sequence.
    ///
    /// This constructor rejects:
    ///
    /// * bare `CR` or bare `LF`;
    /// * `CRLF` not followed by at least one `SP` or `HTAB`;
    /// * `NUL` and other control octets except `HTAB`, `CR`, and `LF` where
    ///   `CRLF 1*(SP / HTAB)` forms a valid fold;
    /// * `DEL` (`0x7F`);
    /// * `0xFE` and `0xFF`;
    /// * any byte sequence that is not valid UTF-8.
    ///
    /// The bytes are stored as given, folds included.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeaderValue`] when `src` is not a valid generic SIP
    /// header field value.
    pub fn from_bytes(src: &[u8]) -> Result<HeaderValue, InvalidHeaderValue> {
        validate(src)?;

        Ok(HeaderValue {
            raw: Bytes::copy_from_slice(src),
            is_sensitive: false,
        })
    }

    /// Attempts to create a new `HeaderValue` from an arbitrary byte buffer
    /// while performing zero-copy when possible.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeaderValue`] when `src` is not a valid generic SIP
    /// header field value.
    pub fn from_maybe_shared<T>(
        src: T,
    ) -> Result<HeaderValue, InvalidHeaderValue>
    where
        T: AsRef<[u8]> + 'static,
    {
        let mut slot = Some(src);

        if let Some(bytes) =
            (&mut slot as &mut dyn Any).downcast_mut::<Option<Bytes>>()
        {
            return HeaderValue::from_shared(
                bytes
                    .take()
                    // OK because `slot` was initialized with `Some(src)`, and
                    // this branch has exclusive access to the same
                    // `Option<Bytes>`. No earlier code can have taken the
                    // value out of it.
                    .unwrap(),
            );
        }

        HeaderValue::from_bytes(
            // OK because `slot` was initialized with `Some(src)`, and the
            // `Bytes` downcast branch above is the only code path that can
            // replace it with `None`. Reaching this branch therefore
            // guarantees the value is still present.
            slot.unwrap().as_ref(),
        )
    }

    fn from_shared(src: Bytes) -> Result<HeaderValue, InvalidHeaderValue> {
        validate(src.as_ref())?;
        Ok(HeaderValue { raw: src, is_sensitive: false })
    }

    /// Returns the value as bytes, folds included.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /// Returns the value as a string slice, folds included.
    ///
    /// Construction validates UTF-8, so this always succeeds.
    pub fn as_str(&self) -> &str {
        // SAFETY: `from_static` takes a `str`, and every other constructor
        // checks the bytes with `validate`, which rejects invalid UTF-8.
        unsafe { str::from_utf8_unchecked(self.as_ref()) }
    }

    /// Returns the lines of the value, split at each fold.
    ///
    /// Each item is the text between two folds, without the `CRLF` and the
    /// whitespace that starts the next line. [RFC 3261 section 7.3.1] treats
    /// a fold as a single `SP`, so joining the items with one `SP` gives the
    /// unfolded value. A value without folds yields itself as its only line.
    ///
    /// ```
    /// use signa::HeaderValue;
    ///
    /// let subject = HeaderValue::from_static(
    ///     "I know you're there,\r\n   pick up the phone",
    /// );
    ///
    /// let lines: Vec<&str> = subject.lines().collect();
    /// assert_eq!(lines, ["I know you're there,", "pick up the phone"]);
    /// ```
    ///
    /// [RFC 3261 section 7.3.1]: https://www.rfc-editor.org/rfc/rfc3261#section-7.3.1
    pub fn lines(&self) -> ValueLines<'_> {
        // `siparse` already splits a value at its folds, and its `Header` can
        // be built by hand, so this reuses that instead of a second copy.
        let header = siparse::Header { name: "", value: self.as_str() };
        ValueLines(header.value_lines())
    }

    /// Returns the length of this header field value in bytes.
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Returns `true` when this header field value is empty.
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    /// Returns `true` when this header field value is marked sensitive.
    pub fn is_sensitive(&self) -> bool {
        self.is_sensitive
    }

    /// Marks this header field value as sensitive or non-sensitive.
    pub fn set_sensitive(&mut self, yes: bool) {
        self.is_sensitive = yes;
    }
}

/// An iterator over the lines of a folded [`HeaderValue`].
///
/// This is created by [`HeaderValue::lines`].
#[derive(Clone, Debug)]
pub struct ValueLines<'a>(siparse::ValueLines<'a>);

impl<'a> Iterator for ValueLines<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        self.0.next()
    }
}

impl FusedIterator for ValueLines<'_> {}

impl AsRef<[u8]> for HeaderValue {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sensitive {
            return f.write_str("\"<sensitive>\"");
        }
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl Eq for HeaderValue {}

impl PartialEq for HeaderValue {
    fn eq(&self, other: &HeaderValue) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<[u8]> for HeaderValue {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl PartialEq<str> for HeaderValue {
    fn eq(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<'a, T> PartialEq<&'a T> for HeaderValue
where
    T: ?Sized,
    HeaderValue: PartialEq<T>,
{
    fn eq(&self, other: &&'a T) -> bool {
        *self == **other
    }
}

impl Ord for HeaderValue {
    fn cmp(&self, other: &HeaderValue) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for HeaderValue {
    fn partial_cmp(&self, other: &HeaderValue) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<[u8]> for HeaderValue {
    fn partial_cmp(&self, other: &[u8]) -> Option<Ordering> {
        self.as_bytes().partial_cmp(other)
    }
}

impl PartialOrd<str> for HeaderValue {
    fn partial_cmp(&self, other: &str) -> Option<Ordering> {
        self.as_bytes().partial_cmp(other.as_bytes())
    }
}

impl<'a, T> PartialOrd<&'a T> for HeaderValue
where
    T: ?Sized,
    HeaderValue: PartialOrd<T>,
{
    fn partial_cmp(&self, other: &&'a T) -> Option<Ordering> {
        self.partial_cmp(&**other)
    }
}

impl Hash for HeaderValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl FromStr for HeaderValue {
    type Err = InvalidHeaderValue;

    /// Attempts to create a new `HeaderValue` from a string slice.
    ///
    /// This validates the resulting octets against RFC 3261's generic
    /// `header-value` production.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeaderValue`] when `src` is not a valid generic SIP
    /// header field value.
    fn from_str(src: &str) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_bytes(src.as_bytes())
    }
}

impl TryFrom<&str> for HeaderValue {
    type Error = InvalidHeaderValue;

    fn try_from(value: &str) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvalidHeaderValueKind {
    Byte(u8),
    BareCr,
    BareLf,
    MissingWspAfterCrLf,
    Utf8(str::Utf8Error),
}

impl InvalidHeaderValue {
    const fn new(kind: InvalidHeaderValueKind) -> InvalidHeaderValue {
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

impl std::error::Error for InvalidHeaderValue {}

/// Validates the generic SIP `header-value` grammar, including UTF-8.
fn validate(src: &[u8]) -> Result<(), InvalidHeaderValue> {
    if let Err(kind) = check_bytes(src) {
        return Err(InvalidHeaderValue::new(kind));
    }

    if let Err(err) = str::from_utf8(src) {
        return Err(InvalidHeaderValue::new(InvalidHeaderValueKind::Utf8(
            err,
        )));
    }

    Ok(())
}

/// Checks the byte-level rules of the generic SIP `header-value` grammar.
///
/// This leaves UTF-8 validation to the caller so that it can run in `const`
/// contexts, where the input is a `str` that is already valid UTF-8.
const fn check_bytes(src: &[u8]) -> Result<(), InvalidHeaderValueKind> {
    let mut i = 0;

    while i < src.len() {
        match src[i] {
            b'\r' => {
                if i + 1 >= src.len() || src[i + 1] != b'\n' {
                    return Err(InvalidHeaderValueKind::BareCr);
                }
                if i + 2 >= src.len() || !is_wsp(src[i + 2]) {
                    return Err(InvalidHeaderValueKind::MissingWspAfterCrLf);
                }

                i += 3;
            }

            b'\n' => return Err(InvalidHeaderValueKind::BareLf),

            byte @ (b'\0'..=b'\x08'
            | b'\x0B'
            | b'\x0C'
            | b'\x0E'..=b'\x1F'
            | b'\x7F'
            | b'\xFE'
            | b'\xFF') => return Err(InvalidHeaderValueKind::Byte(byte)),

            _ => i += 1,
        }
    }

    Ok(())
}

const fn is_wsp(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn from_bytes_accepts_space_tab_and_utf8_text() {
        let value =
            HeaderValue::from_bytes("hello world\tこんにちは".as_bytes())
                .unwrap();

        assert_eq!(value.as_str(), "hello world\tこんにちは");
    }

    #[test]
    fn from_bytes_keeps_folds() {
        let value = HeaderValue::from_bytes(b"folded\r\n\t value").unwrap();

        assert_eq!(value.as_bytes(), b"folded\r\n\t value");
        assert_eq!(value.as_str(), "folded\r\n\t value");
    }

    #[test]
    fn from_static_keeps_folds() {
        const VALUE: HeaderValue = HeaderValue::from_static("folded\r\n more");

        assert_eq!(VALUE.as_str(), "folded\r\n more");
    }

    #[test]
    #[should_panic(expected = "invalid SIP header field value")]
    fn from_static_rejects_invalid_values() {
        let _ = HeaderValue::from_static("bare\nlf");
    }

    #[test]
    fn lines_split_at_folds() {
        let value =
            HeaderValue::from_bytes(b"value \r\n more\r\n\t parts").unwrap();

        // Whitespace before a fold stays at the end of its line.
        let lines: Vec<&str> = value.lines().collect();
        assert_eq!(lines, ["value ", "more", "parts"]);
    }

    #[test]
    fn lines_of_unfolded_values() {
        let value = HeaderValue::from_static("no folds");
        assert_eq!(value.lines().collect::<Vec<_>>(), ["no folds"]);

        let empty = HeaderValue::from_static("");
        assert_eq!(empty.lines().collect::<Vec<_>>(), [""]);
    }

    #[test]
    fn from_bytes_accepts_leading_and_trailing_whitespace() {
        let value = HeaderValue::from_bytes(b" \t value \t ").unwrap();

        assert_eq!(value.as_bytes(), b" \t value \t ");
        assert_eq!(value.as_str(), " \t value \t ");
    }

    #[test]
    fn from_bytes_accepts_trailing_fold() {
        let value = HeaderValue::from_bytes(b"value\r\n ").unwrap();

        assert_eq!(value.as_bytes(), b"value\r\n ");
        assert_eq!(value.lines().collect::<Vec<_>>(), ["value", ""]);
    }

    #[test]
    fn from_bytes_rejects_invalid_fold() {
        let err = HeaderValue::from_bytes(b"folded\r\nvalue").unwrap_err();
        assert_eq!(
            err.to_string(),
            "missing SP or HTAB after CRLF in SIP header value"
        );

        let err = HeaderValue::from_bytes(b"folded\r\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "missing SP or HTAB after CRLF in SIP header value"
        );

        let err = HeaderValue::from_bytes(b"folded\rvalue").unwrap_err();
        assert_eq!(err.to_string(), "bare CR in SIP header value");
    }

    #[test]
    fn from_bytes_rejects_cr_lf_and_other_controls() {
        let err = HeaderValue::from_bytes(b"hello\r").unwrap_err();
        assert_eq!(err.to_string(), "bare CR in SIP header value");

        let err = HeaderValue::from_bytes(b"hello\n").unwrap_err();
        assert_eq!(err.to_string(), "bare LF in SIP header value");

        let err = HeaderValue::from_bytes(b"\0").unwrap_err();
        assert_eq!(err.to_string(), "invalid byte 0x00 in SIP header value");

        let err = HeaderValue::from_bytes(&[0x1f]).unwrap_err();
        assert_eq!(err.to_string(), "invalid byte 0x1F in SIP header value");

        let err = HeaderValue::from_bytes(&[0x7f]).unwrap_err();
        assert_eq!(err.to_string(), "invalid byte 0x7F in SIP header value");
    }

    #[test]
    fn from_maybe_shared_reuses_bytes_when_possible() {
        let bytes = Bytes::from_static(b"text/plain");
        let expected = bytes.as_ptr();

        let value = HeaderValue::from_maybe_shared(bytes).unwrap();

        assert_eq!(value.as_bytes().as_ptr(), expected);
    }

    #[test]
    fn from_bytes_rejects_invalid_utf8() {
        let err = HeaderValue::from_bytes(b"\x80").unwrap_err();
        assert_eq!(err.to_string(), "invalid UTF-8 in SIP header value");

        let err = HeaderValue::from_bytes(b"\xc3\x28").unwrap_err();
        assert_eq!(err.to_string(), "invalid UTF-8 in SIP header value");
    }

    #[test]
    fn sensitive_flag_can_be_toggled() {
        let mut value = HeaderValue::from_static("secret");

        value.set_sensitive(true);
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "\"<sensitive>\"");

        value.set_sensitive(false);
        assert!(!value.is_sensitive());
        assert_eq!(format!("{value:?}"), "\"secret\"");
    }

    #[test]
    fn len_and_empty_follow_bytes() {
        let empty = HeaderValue::from_static("");
        let non_empty = HeaderValue::from_static("abc");

        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(!non_empty.is_empty());
        assert_eq!(non_empty.len(), 3);
    }

    #[test]
    fn parsing_apis_are_consistent() {
        let a = HeaderValue::from_bytes(b"text/plain").unwrap();
        let b = HeaderValue::from_str("text/plain").unwrap();
        let c = <HeaderValue as FromStr>::from_str("text/plain").unwrap();

        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn invalid_header_value_error_text() {
        let err = HeaderValue::from_bytes(b"\r").unwrap_err();

        assert_eq!(err.to_string(), "bare CR in SIP header value");
        assert_eq!(format!("{err:?}"), "InvalidHeaderValue { kind: BareCr }");
    }

    #[test]
    fn invalid_header_value_does_not_reveal_the_value() {
        let err = HeaderValue::from_bytes(b"Digest response=\"s3cr3t\"\0")
            .unwrap_err();

        assert!(!format!("{err:?}").contains("s3cr3t"));
        assert!(!err.to_string().contains("s3cr3t"));
    }

    #[test]
    fn debug_escapes_folds() {
        let value = HeaderValue::from_static("a\r\n b");
        assert_eq!(format!("{value:?}"), "\"a\\r\\n b\"");
    }
}
