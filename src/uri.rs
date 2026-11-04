/*!
SIP request URI types.

This module defines [`Uri`], the target of a SIP request.
*/

use std::{fmt, str::FromStr};

use bytes::Bytes;

use crate::{error::InvalidUri, util::ByteStr};

// TODO: Add structured access before transport work in 0.2.0, which needs
// the host, port, `transport`, `maddr`, and `sips` scheme to pick a target
// (RFC 3263). It is deferred because it needs its own design.
//
// * SIP and SIPS URIs (RFC 3261 section 19.1), tel URIs (RFC 3966), and
//   other absolute URIs each have their own grammar.
// * Views should be offsets into the stored text, as in `http::Uri`, so the
//   original text stays intact for forwarding while `%`-escapes can be
//   decoded for comparison.
// * RFC 3261 section 19.1.4 equivalence decides what `PartialEq` means.
//
// Keeping the text in `Bytes` lets this be added as new methods, such as a
// SIP URI view.
//
/// A SIP `Request-URI`.
///
/// [RFC 3261 section 25.1] defines `Request-URI` as
/// `SIP-URI / SIPS-URI / absoluteURI`, so a request may target `sip:`,
/// `sips:`, `tel:`, or any other URI scheme. This type stores the URI as
/// text and does not parse its structure. It only checks that every byte
/// belongs to the URI character classes that [`siparse`] accepts in a
/// request-line:
///
/// * ASCII letters and digits
/// * the RFC 2396 `reserved` and `mark` characters, `%`, `[`, and `]`
///
/// Whitespace, controls, `DEL`, raw non-ASCII bytes, and other visible ASCII
/// characters are rejected. Matching `siparse` means that any URI received
/// in a request can also be built with this type, and the reverse.
///
/// Accepting a URI does not establish that it is well formed for its scheme.
/// Structured access to SIP URIs (user, host, parameters) is later work.
///
/// `Uri` does not implement `PartialEq` or `Hash`. [RFC 3261 section 19.1.4]
/// compares SIP URIs component by component, with case-insensitive parts
/// and rules for parameters, so comparing the text would give the wrong
/// answer for equivalent URIs. Compare [`Uri::as_str`] when exact text is
/// what you want. I would rather add RFC equivalence later than change what
/// `==` means.
///
/// ```
/// use signa::Uri;
///
/// let uri: Uri = "sip:bob@biloxi.example.com;transport=tcp".parse()?;
/// assert_eq!(uri.as_str(), "sip:bob@biloxi.example.com;transport=tcp");
///
/// assert!("sip:bob@biloxi.example.com bad".parse::<Uri>().is_err());
/// # Ok::<(), signa::error::InvalidUri>(())
/// ```
///
/// [`siparse`]: https://docs.rs/siparse
/// [RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261#section-25.1
/// [RFC 3261 section 19.1.4]: https://www.rfc-editor.org/rfc/rfc3261#section-19.1.4
#[derive(Clone)]
pub struct Uri(ByteStr);

impl Uri {
    /// Creates a `Uri` from a static string without copying it.
    ///
    /// This is usable in `const` contexts.
    ///
    /// ```
    /// use signa::Uri;
    ///
    /// const REGISTRAR: Uri = Uri::from_static("sip:registrar.biloxi.example.com");
    /// assert_eq!(REGISTRAR.as_str(), "sip:registrar.biloxi.example.com");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `src` is not a valid request URI. In a `const` context this
    /// is a compile error.
    pub const fn from_static(src: &'static str) -> Uri {
        if !is_valid(src.as_bytes()) {
            panic!("invalid SIP request URI");
        }

        Uri(ByteStr::from_static(src))
    }

    /// Creates a `Uri` from bytes, copying them.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidUri`] if `src` is empty or contains a byte outside
    /// the accepted URI character classes.
    pub fn from_bytes(src: &[u8]) -> Result<Uri, InvalidUri> {
        if !is_valid(src) {
            return Err(InvalidUri::new());
        }

        // SAFETY: `is_valid` only accepts ASCII bytes.
        Ok(Uri(unsafe {
            ByteStr::from_utf8_unchecked(Bytes::copy_from_slice(src))
        }))
    }

    /// Returns the URI as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Uri {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&[u8]> for Uri {
    type Error = InvalidUri;

    fn try_from(src: &[u8]) -> Result<Uri, InvalidUri> {
        Uri::from_bytes(src)
    }
}

impl TryFrom<&str> for Uri {
    type Error = InvalidUri;

    fn try_from(src: &str) -> Result<Uri, InvalidUri> {
        Uri::from_bytes(src.as_bytes())
    }
}

impl FromStr for Uri {
    type Err = InvalidUri;

    fn from_str(src: &str) -> Result<Uri, InvalidUri> {
        Uri::from_bytes(src.as_bytes())
    }
}

// TODO: Switch to `siparse`'s public request URI check once it exists, so
// the character classes live in one place. It is planned together with the
// other shared checks before signa 0.1.0.
//
/// Returns `true` if `src` is a non-empty run of URI characters.
const fn is_valid(src: &[u8]) -> bool {
    if src.is_empty() {
        return false;
    }

    let mut i = 0;
    while i < src.len() {
        if !URI_CHARS[src[i] as usize] {
            return false;
        }
        i += 1;
    }

    true
}

// The same character classes as `siparse`'s request-line URI check. RFC 2396
// `reserved` and `unreserved` cover every URI form that RFC 3261 allows,
// with `%` for escapes and `[` `]` for IPv6 references.
const URI_CHARS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;

    while i < 256 {
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
                | b'%'
                | b'['
                | b']'
        );
        i += 1;
    }

    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_sip_sips_and_other_schemes() {
        for src in [
            "sip:bob@biloxi.example.com",
            "sips:bob@biloxi.example.com:5061;transport=tls",
            "sip:alice@[2001:db8::10]:5070",
            "sip:%61lice@atlanta.example.com?subject=project%20x&priority=urgent",
            "tel:+1-201-555-0123",
            "urn:service:sos",
        ] {
            assert_eq!(Uri::from_bytes(src.as_bytes()).unwrap().as_str(), src);
        }
    }

    #[test]
    fn rejects_bytes_outside_the_uri_classes() {
        for src in [
            &b""[..],
            b"sip:bob@biloxi.example.com bad",
            b"sip:bob\t@biloxi.example.com",
            b"sip:bob@biloxi.example.com\r\n",
            b"sip:<bob>@biloxi.example.com",
            b"sip:\"bob\"@biloxi.example.com",
            b"sip:bob@biloxi.example.com#frag",
            b"sip:b\x7fob@biloxi.example.com",
            "sip:b\u{f6}b@biloxi.example.com".as_bytes(),
        ] {
            assert!(Uri::from_bytes(src).is_err(), "{src:?}");
        }
    }

    #[test]
    fn every_byte_matches_the_documented_classes() {
        for byte in 0..=255u8 {
            let expected = byte.is_ascii_alphanumeric()
                || b";/?:@&=+$,-_.!~*'()%[]".contains(&byte);
            assert_eq!(URI_CHARS[byte as usize], expected, "{byte:#04x}");
        }
    }

    // Any URI that `siparse` accepts in a request-line must be accepted
    // here, and the reverse, so received requests can be rebuilt.
    #[test]
    fn agrees_with_siparse_for_every_byte() {
        for byte in 0..=255u8 {
            let mut uri = b"sip:a".to_vec();
            uri.push(byte);
            uri.extend_from_slice(b"@b");

            let mut line = b"OPTIONS ".to_vec();
            line.extend_from_slice(&uri);
            line.extend_from_slice(b" SIP/2.0\r\n\r\n");

            let mut headers = siparse::HeaderBuf::<1>::new();
            let mut head = siparse::RequestHead::new(&mut headers);
            let parsed =
                matches!(head.parse(&line), Ok(siparse::Status::Complete(_)));

            assert_eq!(Uri::from_bytes(&uri).is_ok(), parsed, "{byte:#04x}");
        }
    }

    #[test]
    fn from_static_is_const() {
        const URI: Uri = Uri::from_static("sip:carol@chicago.example.com");
        assert_eq!(URI.as_str(), "sip:carol@chicago.example.com");
    }

    #[test]
    #[should_panic(expected = "invalid SIP request URI")]
    fn from_static_rejects_invalid_uris() {
        let _ = Uri::from_static("sip:carol@chicago.example.com bad");
    }

    #[test]
    fn parsing_apis_are_consistent() {
        let src = "sip:carol@chicago.example.com";
        let a = Uri::from_bytes(src.as_bytes()).unwrap();
        let b = Uri::try_from(src).unwrap();
        let c = Uri::try_from(src.as_bytes()).unwrap();
        let d: Uri = src.parse().unwrap();

        for uri in [a, b, c, d] {
            assert_eq!(uri.as_str(), src);
            assert_eq!(uri.to_string(), src);
            assert_eq!(format!("{uri:?}"), format!("{src:?}"));
        }
    }

    #[test]
    fn invalid_uri_error_text() {
        let err = Uri::from_bytes(b"bad uri").unwrap_err();
        assert_eq!(err.to_string(), "invalid SIP request URI");
        assert_eq!(format!("{err:?}"), "InvalidUri");
    }
}
