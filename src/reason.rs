/*!
SIP reason phrase types.

This module defines [`ReasonPhrase`], the text after the status code in a
status-line.
*/

use std::{fmt, str};

use bytes::Bytes;

use crate::{error::InvalidReasonPhrase, util::ByteStr};

/// The reason phrase of a SIP status-line.
///
/// The reason phrase is a short text for humans, such as `Busy Here`.
/// [RFC 3261 section 25.1] defines it as:
///
/// ```text
/// Reason-Phrase = *(reserved / unreserved / escaped
///                 / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
/// ```
///
/// This type accepts what [`siparse`] accepts in a status-line:
///
/// * ASCII letters and digits, `SP`, and `HTAB`
/// * the RFC 3261 `reserved` and `mark` characters
/// * `%` followed by two hex digits, kept as is and not decoded
/// * any non-ASCII text that is valid UTF-8
///
/// Other ASCII characters, such as `"`, `<`, and `#`, must be `%`-escaped.
/// An empty reason phrase is valid. Matching `siparse` means that any reason
/// phrase received in a response can also be built with this type, and the
/// reverse.
///
/// Equality compares the text exactly. The reason phrase carries no protocol
/// meaning, so there is no looser notion of equivalence to follow.
///
/// ```
/// use signa::ReasonPhrase;
///
/// let reason: ReasonPhrase = "Busy Here".parse()?;
/// assert_eq!(reason, "Busy Here");
///
/// assert!("Say \"hi\"".parse::<ReasonPhrase>().is_err());
/// assert!("Say %22hi%22".parse::<ReasonPhrase>().is_ok());
/// # Ok::<(), signa::error::InvalidReasonPhrase>(())
/// ```
///
/// [`siparse`]: https://docs.rs/siparse
/// [RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261#section-25.1
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReasonPhrase(ByteStr);

impl ReasonPhrase {
    /// Creates a `ReasonPhrase` from a static string without copying it.
    ///
    /// A `&'static str` is already valid UTF-8, so only the ASCII rules are
    /// checked. This makes the function usable in `const` contexts.
    ///
    /// ```
    /// use signa::ReasonPhrase;
    ///
    /// const MAINTENANCE: ReasonPhrase = ReasonPhrase::from_static("Maintenance");
    /// assert_eq!(MAINTENANCE.as_str(), "Maintenance");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `src` is not a valid reason phrase. In a `const` context this
    /// is a compile error.
    pub const fn from_static(src: &'static str) -> ReasonPhrase {
        if !check_bytes(src.as_bytes()) {
            panic!("invalid SIP reason phrase");
        }

        ReasonPhrase(ByteStr::from_static(src))
    }

    /// Creates a `ReasonPhrase` from bytes, copying them.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidReasonPhrase`] if `src` contains an ASCII character
    /// outside the accepted set, a malformed `%`-escape, or invalid UTF-8.
    pub fn from_bytes(
        src: &[u8],
    ) -> Result<ReasonPhrase, InvalidReasonPhrase> {
        if !check_bytes(src) || str::from_utf8(src).is_err() {
            return Err(InvalidReasonPhrase::new());
        }

        // SAFETY: `str::from_utf8` just accepted `src`.
        Ok(ReasonPhrase(unsafe {
            ByteStr::from_utf8_unchecked(Bytes::copy_from_slice(src))
        }))
    }

    /// Returns the reason phrase as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ReasonPhrase {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for ReasonPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for ReasonPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for ReasonPhrase {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ReasonPhrase {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<ReasonPhrase> for str {
    fn eq(&self, other: &ReasonPhrase) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<ReasonPhrase> for &str {
    fn eq(&self, other: &ReasonPhrase) -> bool {
        *self == other.as_str()
    }
}

impl TryFrom<&[u8]> for ReasonPhrase {
    type Error = InvalidReasonPhrase;

    fn try_from(src: &[u8]) -> Result<ReasonPhrase, InvalidReasonPhrase> {
        ReasonPhrase::from_bytes(src)
    }
}

impl TryFrom<&str> for ReasonPhrase {
    type Error = InvalidReasonPhrase;

    fn try_from(src: &str) -> Result<ReasonPhrase, InvalidReasonPhrase> {
        ReasonPhrase::from_bytes(src.as_bytes())
    }
}

impl str::FromStr for ReasonPhrase {
    type Err = InvalidReasonPhrase;

    fn from_str(src: &str) -> Result<ReasonPhrase, InvalidReasonPhrase> {
        ReasonPhrase::from_bytes(src.as_bytes())
    }
}

// TODO: Switch to `siparse`'s public reason phrase check once it exists, so
// the grammar lives in one place. It is planned together with the other shared
// checks before signa 0.1.0.
//
/// Checks the ASCII rules of the reason phrase grammar.
///
/// Non-ASCII bytes pass here. The caller checks them as UTF-8, which a
/// `&'static str` already is, so this can run in `const` contexts.
const fn check_bytes(src: &[u8]) -> bool {
    let mut i = 0;

    while i < src.len() {
        let byte = src[i];

        if byte == b'%' {
            if i + 2 >= src.len()
                || !is_hex_digit(src[i + 1])
                || !is_hex_digit(src[i + 2])
            {
                return false;
            }
            i += 3;
        } else if byte >= 0x80 || REASON_PHRASE_CHARS[byte as usize] {
            i += 1;
        } else {
            return false;
        }
    }

    true
}

const fn is_hex_digit(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

// The same ASCII set as `siparse`'s reason phrase check. RFC 3261 `reserved`
// and `unreserved` characters, `SP`, and `HTAB`. `%` is handled separately
// because it starts an escape.
const REASON_PHRASE_CHARS: [bool; 128] = {
    let mut table = [false; 128];
    let mut i = 0;

    while i < 128 {
        table[i] = matches!(
            i as u8,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b';'
                | b'/'
                | b'?'
                | b':'
                | b'@'
                | b'&'
                | b'='
                | b'+'
                | b'$'
                | b','
                | b'-'
                | b'_'
                | b'.'
                | b'!'
                | b'~'
                | b'*'
                | b'\''
                | b'('
                | b')'
                | b' '
                | b'\t'
        );
        i += 1;
    }

    table
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns whether `siparse` accepts `reason` in a status-line.
    fn siparse_accepts(reason: &[u8]) -> bool {
        let mut head = b"SIP/2.0 486 ".to_vec();
        head.extend_from_slice(reason);
        head.extend_from_slice(b"\r\n\r\n");

        let mut headers = siparse::HeaderBuf::<1>::new();
        let mut response = siparse::ResponseHead::new(&mut headers);
        matches!(response.parse(&head), Ok(siparse::Status::Complete(_)))
    }

    #[test]
    fn accepts_typical_reason_phrases() {
        for src in [
            "",
            "OK",
            "Busy Here",
            "Call/Transaction Does Not Exist",
            "Server Time-out",
            "Maintenance\tuntil 05:00",
            "Say %22hi%22",
            "話し中",
        ] {
            let reason = ReasonPhrase::from_bytes(src.as_bytes()).unwrap();
            assert_eq!(reason.as_str(), src);
        }
    }

    #[test]
    fn rejects_invalid_reason_phrases() {
        for src in [
            &b"Say \"hi\""[..],
            b"<busy>",
            b"Busy #1",
            b"Busy\r\nHere",
            b"Busy\x7f",
            b"100%",
            b"100%4",
            b"100%4g",
            b"\xe8\xa9",
            b"\xff",
        ] {
            assert!(ReasonPhrase::from_bytes(src).is_err(), "{src:?}");
        }
    }

    // Any reason phrase that `siparse` accepts in a status-line must be
    // accepted here, and the reverse, so received responses can be rebuilt.
    #[test]
    fn agrees_with_siparse_for_every_byte() {
        for byte in 0..=255u8 {
            let reason = [b'a', byte, b'z'];
            assert_eq!(
                ReasonPhrase::from_bytes(&reason).is_ok(),
                siparse_accepts(&reason),
                "{byte:#04x}"
            );
        }
    }

    #[test]
    fn agrees_with_siparse_on_escapes_and_utf8() {
        for reason in [
            &b"%41"[..],
            b"%4a%4A",
            b"%",
            b"%4",
            b"%g1",
            b"a%",
            "é".as_bytes(),
            "話し中".as_bytes(),
            "🎉".as_bytes(),
            b"\xc3",
            b"\xc0\xaf",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
        ] {
            assert_eq!(
                ReasonPhrase::from_bytes(reason).is_ok(),
                siparse_accepts(reason),
                "{reason:?}"
            );
        }
    }

    #[test]
    fn from_static_is_const() {
        const REASON: ReasonPhrase =
            ReasonPhrase::from_static("Temporarily Unavailable");
        assert_eq!(REASON, "Temporarily Unavailable");
    }

    #[test]
    #[should_panic(expected = "invalid SIP reason phrase")]
    fn from_static_rejects_invalid_reason_phrases() {
        let _ = ReasonPhrase::from_static("Say \"hi\"");
    }

    #[test]
    fn parsing_apis_are_consistent() {
        let src = "Not Found";
        let a = ReasonPhrase::from_bytes(src.as_bytes()).unwrap();
        let b = ReasonPhrase::try_from(src).unwrap();
        let c = ReasonPhrase::try_from(src.as_bytes()).unwrap();
        let d: ReasonPhrase = src.parse().unwrap();

        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
        assert_eq!(a.to_string(), src);
        assert_eq!(format!("{a:?}"), format!("{src:?}"));
        assert_eq!(src, a);
    }

    #[test]
    fn invalid_reason_phrase_error_text() {
        let err = ReasonPhrase::from_bytes(b"<busy>").unwrap_err();
        assert_eq!(err.to_string(), "invalid SIP reason phrase");
        assert_eq!(format!("{err:?}"), "InvalidReasonPhrase");
    }
}
