/*!
Request-URI text and borrowed SIP/SIPS structure.

[`Uri`] retains the original message token. [`SipUri`] validates its structure
on demand, or borrows a standalone string. Neither rewrites the text.
Component getters retain escapes. Use [`Component::decoded_bytes`] or
[`Component::decode`] to decode a component explicitly. The result is bytes,
because percent escapes need not encode UTF-8. A `+` stays a plus.

The view checks component syntax, escapes and IP literals according to
[RFC 3261 sections 19.1 and 25.1] and [RFC 5954]. Parameters use the generic
`pname [ "=" pvalue ]` grammar. Their specialized values and usage rules,
such as TTL, transport reliability and maddr routing, belong to the consumer.
Duplicate parameters remain visible in iteration. [`SipUri::parameter`]
rejects ambiguous lookup rather than selecting one occurrence.

An omitted port stays omitted. A present port retains all its digits, and
[`SipUri::port_u16`] checks whether it fits a network port. No transport or
port defaults, DNS lookup, normalization or URI-header application is implied.
Parsing SIPS does not add TLS support. Non-SIP schemes, including tel, remain
opaque. URI comparison and mutation are outside this API.

```
use signa::message::uri::{Scheme, SipUri};

let target = SipUri::parse(
    "sips:alice%40work@[2001:db8::1]:5061;transport=tcp;lr?Subject=lunch%20plans"
)?;
assert_eq!(target.scheme(), Scheme::Sips);
assert_eq!(target.user().unwrap().decode().as_ref(), b"alice@work");
assert_eq!(target.host(), "2001:db8::1");
assert_eq!(target.port_u16()?, Some(5061));
assert_eq!(target.parameter("transport")?.unwrap().value().unwrap().as_str(), "tcp");
assert!(target.parameter("lr")?.unwrap().value().is_none());
assert_eq!(target.headers().next().unwrap().value().decode().as_ref(), b"lunch plans");
# Ok::<(), Box<dyn std::error::Error>>(())
```

[RFC 3261 sections 19.1 and 25.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1
[RFC 5954]: https://www.rfc-editor.org/rfc/rfc5954.html
*/

use std::{fmt, str::FromStr};

use bytes::Bytes;
use siparse::check;

use crate::message::{byte_str::ByteStr, error::InvalidUri};

pub use self::{
    component::{Component, DecodedBytes},
    sip::{
        Header, Headers, InvalidSipUri, InvalidSipUriKind, Parameter,
        Parameters, Scheme, SipUri,
    },
};

mod component;
mod sip;

/// A SIP `Request-URI`.
///
/// [RFC 3261 section 25.1] defines `Request-URI` as `SIP-URI / SIPS-URI /
/// absoluteURI`, so a request may target `sip:`, `sips:`, `tel:`, or any other
/// URI scheme. This type stores the URI as text and does not parse its
/// structure.
///
/// # Accepted bytes
///
/// It only checks that every byte belongs to the URI character classes that
/// [siparse] accepts in a request-line:
///
/// * ASCII letters and digits
/// * the RFC 2396 `reserved` and `mark` characters, `%`, `[`, and `]`
///
/// Whitespace, controls, `DEL`, raw non-ASCII bytes, and other visible ASCII
/// characters are rejected. Matching siparse means that any URI received in a
/// request can also be built with this type, and the reverse.
///
/// Accepting a URI does not establish that it is well formed for its scheme.
/// [`Uri::sip`] validates SIP/SIPS structure on demand. Other schemes remain
/// opaque.
///
/// # Equality
///
/// `Uri` does not implement `PartialEq` or `Hash`. [RFC 3261 section 19.1.4]
/// comparison is not transitive, so it cannot implement Rust's `PartialEq`
/// contract. Compare [`Uri::as_str`] when exact text is what you want.
/// This module provides no RFC URI comparison operation.
///
/// # Example
///
/// ```
/// use signa::Uri;
///
/// let uri: Uri = "sip:bob@biloxi.example.com;transport=tcp".parse()?;
/// assert_eq!(uri.as_str(), "sip:bob@biloxi.example.com;transport=tcp");
///
/// assert!("sip:bob@biloxi.example.com bad".parse::<Uri>().is_err());
/// # Ok::<(), signa::message::error::InvalidUri>(())
/// ```
///
/// [siparse]: https://docs.rs/siparse
/// [RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261#section-25.1
/// [RFC 3261 section 19.1.4]: https://www.rfc-editor.org/rfc/rfc3261#section-19.1.4
#[derive(Clone)]
pub struct Uri(ByteStr);

impl Uri {
    /// Creates a `Uri` from a static string without copying it.
    ///
    /// This is usable in `const` contexts.
    ///
    /// # Example
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
    /// Panics if `src` is empty or contains a byte outside the accepted URI
    /// character classes. In a `const` context this is a compile error.
    pub const fn from_static(src: &'static str) -> Uri {
        if check::request_uri_const(src.as_bytes()).is_err() {
            panic!("invalid SIP request URI");
        }

        Uri(ByteStr::from_static(src))
    }

    /// Creates a `Uri` from bytes, copying them.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidUri`] if `src` is empty or contains a byte outside the
    /// accepted URI character classes.
    pub fn from_bytes(src: &[u8]) -> Result<Uri, InvalidUri> {
        let uri = check::request_uri(src).map_err(|_| InvalidUri::new())?;
        Ok(Uri(ByteStr::from(uri)))
    }

    /// Returns the URI as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates and borrows the SIP/SIPS structure, without copying it.
    ///
    /// Returns `Ok(None)` when the text does not start with a SIP/SIPS scheme.
    /// This does not validate another scheme. Message parsing itself never
    /// invokes this operation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSipUri`] for malformed SIP/SIPS structure or escapes.
    pub fn sip(&self) -> Result<Option<SipUri<'_>>, InvalidSipUri> {
        match SipUri::parse(self.as_str()) {
            Ok(uri) => Ok(Some(uri)),
            Err(error) if error.kind() == InvalidSipUriKind::Scheme => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Copies validated text so a retained URI does not pin a read buffer.
    #[cfg(any(feature = "tokio", feature = "__bench", test))]
    pub(crate) fn copy(&self) -> Uri {
        Uri(ByteStr::from(self.as_str()))
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

impl Uri {
    /// Creates a `Uri` from a Request-URI that siparse parsed out of `src`,
    /// without copying or checking it again.
    ///
    /// # Panics
    ///
    /// Panics if `uri` does not lie within `src`.
    pub(crate) fn from_parsed(src: &Bytes, uri: &str) -> Uri {
        debug_assert!(check::request_uri(uri.as_bytes()).is_ok());

        // SAFETY: The slice holds the same bytes as `uri`, which is a `str`.
        Uri(unsafe {
            ByteStr::from_utf8_unchecked(src.slice_ref(uri.as_bytes()))
        })
    }
}

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
            assert_eq!(
                Uri::from_bytes(&[byte]).is_ok(),
                expected,
                "{byte:#04x}"
            );
        }
    }

    // Any URI that siparse accepts in a request-line must be accepted here,
    // and the reverse, so received requests can be rebuilt.
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

    #[test]
    fn sip_access_distinguishes_opaque_schemes_from_bad_sip_structure() {
        for text in ["tel:+12025550123", "urn:service:sos", "opaque"] {
            assert!(Uri::from_bytes(text.as_bytes())
                .unwrap()
                .sip()
                .unwrap()
                .is_none());
        }
        let bad = Uri::from_static("sip:example.com;transport=");
        assert_eq!(
            bad.sip().unwrap_err().kind(),
            InvalidSipUriKind::Parameter
        );
        assert_eq!(bad.as_str(), "sip:example.com;transport=");
    }

    #[test]
    fn a_view_borrows_the_received_uri_and_all_raw_components() {
        let input = Bytes::from_static(b"sip:alice:secret@[2001:db8::1]:5060;transport=tcp;lr?Subject=hello");
        let uri =
            Uri::from_parsed(&input, std::str::from_utf8(&input).unwrap());
        let view = uri.sip().unwrap().unwrap();
        let range = input.as_ptr_range();

        assert_eq!(view.as_str().as_ptr(), input.as_ptr());
        for text in [
            view.user().unwrap().as_str(),
            view.password().unwrap().as_str(),
            view.host(),
            view.port().unwrap(),
        ] {
            assert!(range.contains(&text.as_ptr()));
        }
        for parameter in view.parameters() {
            assert!(range.contains(&parameter.name().as_str().as_ptr()));
            if let Some(value) = parameter.value() {
                assert!(range.contains(&value.as_str().as_ptr()));
            }
        }
        for header in view.headers() {
            assert!(range.contains(&header.name().as_str().as_ptr()));
            assert!(range.contains(&header.value().as_str().as_ptr()));
        }
        assert!(matches!(
            view.user().unwrap().decode(),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn escaped_components_round_trip_arbitrary_octets() {
        fn property(octets: Vec<u8>) -> bool {
            use std::fmt::Write;
            let mut escaped = String::new();
            for byte in &octets {
                write!(escaped, "%{byte:02X}").unwrap();
            }
            let text = format!("sip:alice:{escaped}@example.com?x={escaped}");
            let uri = SipUri::parse(&text).unwrap();

            uri.as_str() == text
                && uri.password().unwrap().decode().as_ref() == octets
                && uri.headers().next().unwrap().value().decode().as_ref()
                    == octets
        }

        // A smaller generated sample under Miri still exercises the same
        // borrowing and decoding paths without an expensive randomized run.
        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 32 } else { 1000 })
            .gen(quickcheck::Gen::new(if cfg!(miri) { 16 } else { 256 }))
            .quickcheck(property as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn arbitrary_text_never_yields_invalid_component_boundaries() {
        fn property(octets: Vec<u8>) -> bool {
            let text = format!("sip:{}", String::from_utf8_lossy(&octets));
            let Ok(uri) = SipUri::parse(&text) else {
                return true;
            };

            assert_eq!(uri.as_str(), text);
            let _ = (
                uri.user(),
                uri.password(),
                uri.host(),
                uri.port(),
                uri.port_u16(),
            );
            for parameter in uri.parameters() {
                let _ = parameter.name().decoded_bytes().count();
                let _ = parameter.value().map(|v| v.decoded_bytes().count());
            }
            for header in uri.headers() {
                let _ = header.name().decoded_bytes().count();
                let _ = header.value().decoded_bytes().count();
            }
            true
        }

        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 32 } else { 1000 })
            .quickcheck(property as fn(Vec<u8>) -> bool);
    }
}
