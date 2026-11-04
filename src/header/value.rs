use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    iter::FusedIterator,
    str::{self, FromStr},
};

use bytes::Bytes;

use crate::error::{InvalidHeaderValue, InvalidHeaderValueKind};

/// A SIP header field value.
///
/// One type holds the value of every header field, so it cannot check a
/// value against the grammar of its field. It accepts the same bytes as
/// [`siparse`], which cover every field's grammar in RFC 3261 section 25.1.
/// The generic `header-value` production allows no ASCII controls besides
/// `HTAB` in folds and whitespace:
///
/// ```text
/// header-value = *(TEXT-UTF8char / UTF8-CONT / LWS)
/// ```
///
/// But the `quoted-string` and `comment` productions in fields such as
/// `From`, `Contact`, and `Authorization` also allow a `quoted-pair`, which
/// can escape any ASCII control except `CR` and `LF`:
///
/// ```text
/// quoted-pair = "\" (%x00-09 / %x0B-0C / %x0E-7F)
/// ```
///
/// So this type also accepts such a control right after an odd run of
/// backslashes, in any field. Checking that it sits in a quoted string or
/// comment that the field allows is left to typed header parsers, along with
/// the rest of each field's grammar. Matching `siparse` means that any value
/// received in a parsed head can be built here too.
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
    /// This accepts:
    ///
    /// * printable ASCII (`0x20..=0x7E`) and `HTAB`;
    /// * folds of the form `CRLF 1*(SP / HTAB)`;
    /// * other ASCII controls and `DEL`, except `CR` and `LF`, right after an
    ///   odd run of backslashes, as in a `quoted-pair`;
    /// * modern UTF-8.
    ///
    /// It rejects:
    ///
    /// * bare `CR` or bare `LF`, even after a backslash;
    /// * `CRLF` not followed by `SP` or `HTAB`;
    /// * any other ASCII control or `DEL`;
    /// * bytes that are not valid UTF-8.
    ///
    /// The bytes are stored as given, folds included.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeaderValue`] if `src` contains a byte or sequence
    /// that this rejects.
    pub fn from_bytes(src: &[u8]) -> Result<HeaderValue, InvalidHeaderValue> {
        validate(src)?;

        Ok(HeaderValue {
            raw: Bytes::copy_from_slice(src),
            is_sensitive: false,
        })
    }

    /// Attempts to create a new `HeaderValue` from shared bytes without
    /// copying them.
    ///
    /// This accepts the same bytes as [`HeaderValue::from_bytes`]. The value
    /// keeps a reference to `src`, so a value taken from a larger buffer
    /// keeps the whole buffer alive. A `Vec<u8>` or `String` converts into
    /// `Bytes` without copying.
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa::HeaderValue;
    ///
    /// let value = HeaderValue::from_shared(Bytes::from(String::from(
    ///     "<sip:alice@atlanta.example.com>;tag=1928301774",
    /// )))?;
    ///
    /// assert_eq!(value, "<sip:alice@atlanta.example.com>;tag=1928301774");
    /// # Ok::<(), signa::error::InvalidHeaderValue>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeaderValue`] if `src` contains a byte or sequence
    /// that [`HeaderValue::from_bytes`] rejects.
    pub fn from_shared(src: Bytes) -> Result<HeaderValue, InvalidHeaderValue> {
        validate(&src)?;
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

impl TryFrom<&[u8]> for HeaderValue {
    type Error = InvalidHeaderValue;

    fn try_from(value: &[u8]) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_bytes(value)
    }
}

impl TryFrom<&str> for HeaderValue {
    type Error = InvalidHeaderValue;

    fn try_from(value: &str) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(value)
    }
}

/// Validates a header field value, including UTF-8.
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

// TODO: Switch to `siparse`'s public header value check once it exists, so
// the rules live in one place. It is planned together with the other shared
// checks before signa 0.1.0.
//
/// Checks the byte-level rules of a header field value.
///
/// This leaves UTF-8 validation to the caller so that it can run in `const`
/// contexts, where the input is a `str` that is already valid UTF-8.
const fn check_bytes(src: &[u8]) -> Result<(), InvalidHeaderValueKind> {
    let mut i = 0;
    // Whether the bytes just before `i` end in an odd run of backslashes.
    // A pair consumes its backslash, so `\\` escapes nothing.
    let mut escaped = false;

    while i < src.len() {
        let byte = src[i];
        let was_escaped = escaped;
        escaped = byte == b'\\' && !was_escaped;

        match byte {
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

            b'\0'..=b'\x08'
            | b'\x0B'
            | b'\x0C'
            | b'\x0E'..=b'\x1F'
            | b'\x7F'
                if was_escaped =>
            {
                i += 1;
            }

            b'\0'..=b'\x08'
            | b'\x0B'
            | b'\x0C'
            | b'\x0E'..=b'\x1F'
            | b'\x7F'
            | b'\xFE'
            | b'\xFF' => return Err(InvalidHeaderValueKind::Byte(byte)),

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
    fn from_bytes_accepts_controls_after_an_odd_backslash_run() {
        let value = HeaderValue::from_bytes(
            b"\"Bob\\\x01\" <sip:bob@biloxi.example.com>",
        )
        .unwrap();
        assert_eq!(
            value.as_bytes(),
            b"\"Bob\\\x01\" <sip:bob@biloxi.example.com>"
        );

        HeaderValue::from_bytes(b"a\\\\\\\x7f").unwrap();

        let err = HeaderValue::from_bytes(b"a\\\\\x01").unwrap_err();
        assert_eq!(err.to_string(), "invalid byte 0x01 in SIP header value");

        // A pair consumes the control too, so it cannot escape what follows.
        let err = HeaderValue::from_bytes(b"a\\\x01\x01").unwrap_err();
        assert_eq!(err.to_string(), "invalid byte 0x01 in SIP header value");
    }

    #[test]
    fn backslash_does_not_escape_cr_or_lf() {
        let err = HeaderValue::from_bytes(b"a\\\rb").unwrap_err();
        assert_eq!(err.to_string(), "bare CR in SIP header value");

        let err = HeaderValue::from_bytes(b"a\\\nb").unwrap_err();
        assert_eq!(err.to_string(), "bare LF in SIP header value");

        HeaderValue::from_bytes(b"a\\\r\n b").unwrap();
    }

    #[test]
    fn from_static_accepts_escaped_controls() {
        const VALUE: HeaderValue = HeaderValue::from_static("\"a\\\x00\"");

        assert_eq!(VALUE.as_bytes(), b"\"a\\\x00\"");
    }

    /// Returns whether `siparse` accepts `value` as a header field value.
    fn siparse_accepts(value: &[u8]) -> bool {
        let mut head =
            b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\nX: ".to_vec();
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n\r\n");

        let mut headers = siparse::HeaderBuf::<1>::new();
        let mut request = siparse::RequestHead::new(&mut headers);
        matches!(request.parse(&head), Ok(siparse::Status::Complete(_)))
    }

    // Any value that `siparse` accepts in a header row must be accepted here,
    // and the reverse, so received heads can be rebuilt. Each value starts
    // and ends with a visible character because `siparse` strips leading
    // whitespace as part of the separator.
    #[test]
    fn agrees_with_siparse_for_every_byte_and_backslash_run() {
        for byte in 0..=255u8 {
            for backslashes in 0..=4 {
                let mut value = vec![b'a'];
                value.resize(1 + backslashes, b'\\');
                value.extend([byte, b'z']);
                assert_eq!(
                    HeaderValue::from_bytes(&value).is_ok(),
                    siparse_accepts(&value),
                    "{value:?}"
                );
            }
        }
    }

    #[test]
    fn agrees_with_siparse_on_folds_and_utf8() {
        for value in [
            &b"a\r\n b"[..],
            b"a\r\n\tb",
            b"a\\\r\n b",
            b"a\\\x00\r\n \\\x00b",
            b"a\r\nb",
            b"a\rb",
            "a\\é".as_bytes(),
            "話し中".as_bytes(),
            b"a\\\xc3",
            b"a\\\xff",
            b"\xed\xa0\x80",
        ] {
            assert_eq!(
                HeaderValue::from_bytes(value).is_ok(),
                siparse_accepts(value),
                "{value:?}"
            );
        }
    }

    #[test]
    fn from_shared_does_not_copy() {
        let bytes = Bytes::from_static(b"text/plain");
        let expected = bytes.as_ptr();

        let value = HeaderValue::from_shared(bytes).unwrap();

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
