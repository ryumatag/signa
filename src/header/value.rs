use std::{
    any::Any,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    str::{self, FromStr},
};

use bytes::{Bytes, BytesMut};

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
/// In particular, this type:
///
/// * validates the generic byte-level `header-value` grammar;
/// * accepts valid folded linear whitespace (`LWS`);
/// * rejects invalid UTF-8 byte sequences;
/// * unfolds any folded `LWS` to a single `SP` during construction;
/// * always stores an unfolded, interpretation-ready generic header value;
/// * preserves leading and trailing whitespace exactly as provided.
///
/// Folded `LWS` is message syntax, not part of the stored semantic value.
/// Accordingly, constructors accept `CRLF 1*(SP / HTAB)` but normalize it to a
/// single `SP` before storing the value. The stored bytes are therefore always
/// valid UTF-8 and always unfolded according to RFC 3261's generic
/// `header-value` interpretation rules.
///
/// This layer does not trim or otherwise normalize leading or trailing
/// whitespace, and it does not perform any field-specific parsing.
#[derive(Clone)]
pub struct HeaderValue {
    raw: Bytes,
    is_sensitive: bool,
}

/// Represents an invalid header field value.
///
/// This is an error returned when constructing a [`HeaderValue`] from bytes
/// or text.
///
/// The original rejected octets are retained for diagnostics.
pub struct InvalidHeaderValue {
    raw: Bytes,
    kind: InvalidHeaderValueKind,
    _priv: (),
}

impl HeaderValue {
    /// Creates a new `HeaderValue` from a static string.
    ///
    /// The input must satisfy RFC 3261's generic `header-value` grammar.
    /// Because the input is a Rust `&'static str`, it is already valid UTF-8;
    /// this function only checks the SIP byte-level constraints.
    ///
    /// Valid folded `LWS` is accepted, but any `CRLF 1*(SP / HTAB)` sequence is
    /// normalized to a single `SP` before storage. Leading and trailing
    /// whitespace are otherwise preserved as provided.
    ///
    /// # Panics
    ///
    /// Panics if `src` contains bytes that are illegal in a generic SIP
    /// header field value.
    pub fn from_static(src: &'static str) -> HeaderValue {
        let bytes = src.as_bytes();
        let Ok(first_fold) = validate(bytes) else {
            panic!("invalid SIP header field value");
        };

        HeaderValue {
            raw: unfold(Bytes::from_static(bytes), first_fold),
            is_sensitive: false,
        }
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
    /// Valid folded `LWS` is accepted, but any `CRLF 1*(SP / HTAB)` sequence
    /// is normalized to a single `SP` before storage. Leading and trailing
    /// whitespace are otherwise preserved as provided.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeaderValue`] when `src` is not a valid generic SIP
    /// header field value.
    pub fn from_bytes(src: &[u8]) -> Result<HeaderValue, InvalidHeaderValue> {
        let first_fold = validate(src)?;

        Ok(HeaderValue {
            raw: unfold(Bytes::copy_from_slice(src), first_fold),
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
        let first_fold = validate(src.as_ref())?;
        Ok(HeaderValue { raw: unfold(src, first_fold), is_sensitive: false })
    }

    /// Returns the normalized bytes stored by this header field value.
    ///
    /// The returned bytes are always valid UTF-8 and always unfolded.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /// Returns the normalized textual representation of this header field
    /// value.
    ///
    /// Because construction validates UTF-8 and unfolds folded `LWS`, this
    /// always succeeds and returns the stored unfolded representation.
    pub fn as_str(&self) -> &str {
        // SAFETY: Every constructor validates UTF-8, and unfolding only
        // replaces ASCII bytes with `SP`.
        unsafe { str::from_utf8_unchecked(self.as_ref()) }
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
        fmt::Debug::fmt(bstr::BStr::new(self.as_ref()), f)
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
    fn new(raw: &[u8], kind: InvalidHeaderValueKind) -> InvalidHeaderValue {
        InvalidHeaderValue {
            raw: Bytes::copy_from_slice(raw),
            kind,
            _priv: (),
        }
    }

    /// Returns the rejected raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for InvalidHeaderValue {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl fmt::Debug for InvalidHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(bstr::BStr::new(self.as_ref()), f)
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

/// Validates the generic SIP `header-value` grammar.
///
/// On success, returns the byte index of the first folded `LWS` sequence, if
/// any.
fn validate(src: &[u8]) -> Result<Option<usize>, InvalidHeaderValue> {
    let mut first_fold = None;
    let mut i = 0;

    while i < src.len() {
        match src[i] {
            b'\r' => {
                if first_fold.is_none() {
                    first_fold = Some(i);
                }

                if i + 2 >= src.len()
                    || src[i + 1] != b'\n'
                    || !is_wsp(src[i + 2])
                {
                    return Err(InvalidHeaderValue::new(
                        src,
                        if i + 1 >= src.len() || src[i + 1] != b'\n' {
                            InvalidHeaderValueKind::BareCr
                        } else {
                            InvalidHeaderValueKind::MissingWspAfterCrLf
                        },
                    ));
                }

                i += 3;

                while i < src.len() && is_wsp(src[i]) {
                    i += 1;
                }
            }

            b'\n' => {
                return Err(InvalidHeaderValue::new(
                    src,
                    InvalidHeaderValueKind::BareLf,
                ));
            }

            b'\0'..=b'\x08'
            | b'\x0B'
            | b'\x0C'
            | b'\x0E'..=b'\x1F'
            | b'\x7F'
            | b'\xFE'
            | b'\xFF' => {
                return Err(InvalidHeaderValue::new(
                    src,
                    InvalidHeaderValueKind::Byte(src[i]),
                ));
            }

            _ => {
                i += 1;
            }
        }
    }

    if let Err(err) = str::from_utf8(src) {
        return Err(InvalidHeaderValue::new(
            src,
            InvalidHeaderValueKind::Utf8(err),
        ));
    }

    Ok(first_fold)
}

fn unfold(mut src: Bytes, first_fold: Option<usize>) -> Bytes {
    use bytes::{Buf, BufMut};

    let Some(i) = first_fold else { return src };
    let mut unfolded = BytesMut::with_capacity(src.len());

    unfolded.extend_from_slice(&src[..i]);
    src.advance(i);

    while src.has_remaining() {
        let b = src.get_u8();

        if b == b'\r' {
            if cfg!(debug_assertions) {
                let chunk = src.chunk();

                assert!(chunk.len() >= 2);
                assert_eq!(chunk[0], b'\n');
                assert!(is_wsp(chunk[1]));
            }

            unfolded.put_u8(b' ');

            src.advance(2);

            while let Some(&byte) = src.chunk().first() {
                if !is_wsp(byte) {
                    break;
                }

                src.advance(1);
            }
        } else {
            unfolded.put_u8(b);
        }
    }

    unfolded.freeze()
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
    fn from_bytes_unfolds_folded_lws_to_single_space() {
        let value = HeaderValue::from_bytes(b"folded\r\n\t value").unwrap();

        assert_eq!(value.as_bytes(), b"folded value");
        assert_eq!(value.as_str(), "folded value");
    }

    #[test]
    fn from_static_unfolds_folded_lws_to_single_space() {
        let value = HeaderValue::from_static("folded\r\n more");

        assert_eq!(value.as_bytes(), b"folded more");
        assert_eq!(value.as_str(), "folded more");
    }

    #[test]
    fn from_bytes_unfolds_multiple_folded_segments() {
        let value =
            HeaderValue::from_bytes(b"value\r\n more\r\n\tparts").unwrap();

        assert_eq!(value.as_bytes(), b"value more parts");
        assert_eq!(value.as_str(), "value more parts");
    }

    #[test]
    fn from_bytes_accepts_leading_and_trailing_whitespace() {
        let value = HeaderValue::from_bytes(b" \t value \t ").unwrap();

        assert_eq!(value.as_bytes(), b" \t value \t ");
        assert_eq!(value.as_str(), " \t value \t ");
    }

    #[test]
    fn from_bytes_accepts_fold_that_normalizes_to_trailing_space() {
        let value = HeaderValue::from_bytes(b"value\r\n ").unwrap();

        assert_eq!(value.as_bytes(), b"value ");
        assert_eq!(value.as_str(), "value ");
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
        assert_eq!(format!("{err:?}"), "\"\\r\"");
    }
}
