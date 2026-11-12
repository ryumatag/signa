use std::{error, fmt, iter::FusedIterator, num::ParseIntError};

use siparse::{ErrorKind, uri};

use super::component::Component;

/// A SIP URI scheme. Recognizing SIPS does not enable a secure transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    /// The `sip` scheme.
    Sip,
    /// The `sips` scheme.
    Sips,
}

impl Scheme {
    /// Returns the lowercase scheme name without its colon.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Sip => "sip",
            Scheme::Sips => "sips",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error validating SIP/SIPS structure or looking up a repeated parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSipUri {
    kind: InvalidSipUriKind,
}

/// The component that prevented structured access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InvalidSipUriKind {
    /// The string does not start with `sip:` or `sips:`.
    Scheme,
    /// Empty or malformed user information.
    User,
    /// A malformed password.
    Password,
    /// An empty or malformed host, including invalid IP literals.
    Host,
    /// An explicit port is empty or contains a non-digit.
    Port,
    /// An empty or malformed URI parameter name or value.
    Parameter,
    /// An empty or malformed URI header name/value pair.
    Header,
    /// A percent escape does not contain exactly two hexadecimal digits.
    Escape,
    /// A name-based lookup matched multiple URI parameters.
    DuplicateParameter,
}

impl InvalidSipUri {
    /// Returns the component or lookup error.
    pub fn kind(self) -> InvalidSipUriKind {
        self.kind
    }
}

impl fmt::Display for InvalidSipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            InvalidSipUriKind::Scheme => "expected a SIP or SIPS URI",
            InvalidSipUriKind::User => "invalid SIP URI user",
            InvalidSipUriKind::Password => "invalid SIP URI password",
            InvalidSipUriKind::Host => "invalid SIP URI host",
            InvalidSipUriKind::Port => "invalid SIP URI port",
            InvalidSipUriKind::Parameter => "invalid SIP URI parameter",
            InvalidSipUriKind::Header => "invalid SIP URI header",
            InvalidSipUriKind::Escape => "invalid SIP URI percent escape",
            InvalidSipUriKind::DuplicateParameter => {
                "duplicate SIP URI parameter"
            }
        })
    }
}

impl error::Error for InvalidSipUri {}

/// A borrowed SIP/SIPS URI with validated component boundaries.
///
/// siparse validates the text. Parsing allocates nothing and retains the
/// original text. Getters do not
/// decode escapes or choose routing defaults. The view checks generic parameter
/// syntax, not specialized parameter values or their usage rules. Iteration
/// preserves duplicates. [`SipUri::parameter`] rejects ambiguous lookups.
///
/// This type has no `PartialEq`, `Eq` or `Hash` implementation. RFC 3261 URI
/// comparison is not transitive and cannot implement Rust's equality contract.
/// Use [`SipUri::as_str`] for an exact text comparison.
///
/// ```compile_fail
/// use signa_core::message::uri::SipUri;
/// let target = SipUri::parse("sip:alice@example.com").unwrap();
/// // RFC URI comparison cannot satisfy PartialEq's transitivity requirement.
/// assert!(target == target);
/// ```
///
/// A view cannot outlive the text it borrows:
///
/// ```compile_fail
/// use signa_core::message::uri::SipUri;
/// let target = {
///     let text = String::from("sip:alice@example.com");
///     SipUri::parse(&text).unwrap()
/// };
/// println!("{}", target.host());
/// ```
#[derive(Clone, Copy)]
pub struct SipUri<'a> {
    src: &'a str,
    parts: uri::SipUri<'a>,
}

impl<'a> SipUri<'a> {
    /// Validates a standalone SIP/SIPS URI, borrowing its original text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSipUri`] for another scheme, malformed component syntax,
    /// invalid escapes or invalid IP literals. It does not validate whether
    /// parameter combinations are suitable for routing or a particular header.
    pub fn parse(src: &'a str) -> Result<SipUri<'a>, InvalidSipUri> {
        let parts = uri::sip_uri(src).map_err(|error| {
            invalid(match error.kind() {
                ErrorKind::UriScheme => InvalidSipUriKind::Scheme,
                ErrorKind::UriUser => InvalidSipUriKind::User,
                ErrorKind::UriPassword => InvalidSipUriKind::Password,
                ErrorKind::UriHost => InvalidSipUriKind::Host,
                ErrorKind::UriPort => InvalidSipUriKind::Port,
                ErrorKind::UriParam => InvalidSipUriKind::Parameter,
                ErrorKind::UriHeader => InvalidSipUriKind::Header,
                ErrorKind::UriEscape => InvalidSipUriKind::Escape,
                // `sip_uri` returns only the kinds above. A kind a later
                // siparse adds is still an error, and not `Scheme`, which
                // `Uri::sip` reads as another scheme rather than a failure.
                _ => InvalidSipUriKind::Host,
            })
        })?;
        Ok(SipUri { src, parts })
    }

    /// Returns the original URI, including its scheme spelling and escapes.
    pub fn as_str(&self) -> &'a str {
        self.src
    }

    /// Returns the parsed scheme without implying a transport choice.
    pub fn scheme(&self) -> Scheme {
        match self.parts.scheme {
            uri::Scheme::Sip => Scheme::Sip,
            uri::Scheme::Sips => Scheme::Sips,
        }
    }

    /// Returns the escaped user, or `None` if user information was absent.
    pub fn user(&self) -> Option<Component<'a>> {
        self.parts.user.map(Component)
    }

    /// Returns the escaped password, distinguishing absent from empty.
    pub fn password(&self) -> Option<Component<'a>> {
        self.parts.password.map(Component)
    }

    /// Returns the original host text, without IPv6 brackets.
    ///
    /// Host names retain case and an optional trailing dot. IP literals are
    /// validated using RFC 5954's grammar. No name resolution is performed.
    pub fn host(&self) -> &'a str {
        let host = self.parts.host;
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
    }

    /// Returns the original explicit port digits, or `None` when omitted.
    ///
    /// RFC 3261 defines this component as one or more digits, without a
    /// syntactic upper bound. Leading zeroes and oversized values are retained.
    pub fn port(&self) -> Option<&'a str> {
        self.parts.port
    }

    /// Converts an explicit port to `u16`, without supplying a default.
    ///
    /// # Errors
    ///
    /// Returns [`ParseIntError`] when the explicit digits overflow `u16`.
    pub fn port_u16(&self) -> Result<Option<u16>, ParseIntError> {
        self.port().map(str::parse).transpose()
    }

    /// Iterates URI parameters in their original order, including duplicates.
    pub fn parameters(&self) -> Parameters<'a> {
        Parameters(self.parts.params.iter())
    }

    /// Looks up an unescaped parameter name, ignoring ASCII case.
    ///
    /// Names are percent-decoded for lookup. Returned spelling stays raw.
    /// The result distinguishes an absent parameter from a valueless flag.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSipUriKind::DuplicateParameter`] when multiple names
    /// match, including names with different case or escape spelling. No
    /// occurrence is silently chosen. This scans only the requested name, so
    /// lookup stays linear and needs no parameter index.
    pub fn parameter(
        &self,
        name: &str,
    ) -> Result<Option<Parameter<'a>>, InvalidSipUri> {
        let mut found = None;
        for parameter in self.parameters() {
            if parameter.name().name_is(name) {
                if found.is_some() {
                    return Err(invalid(
                        InvalidSipUriKind::DuplicateParameter,
                    ));
                }
                found = Some(parameter);
            }
        }
        Ok(found)
    }

    /// Iterates URI header name/value pairs in their original order.
    ///
    /// These are URI components, not validated SIP header fields. Decoded
    /// octets can include controls. Request construction must validate and
    /// apply its own policy rather than insert these bytes into a message.
    pub fn headers(&self) -> Headers<'a> {
        Headers(self.parts.headers.iter())
    }
}

impl fmt::Debug for SipUri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SipUri").field(&self.src).finish()
    }
}

impl AsRef<str> for SipUri<'_> {
    fn as_ref(&self) -> &str {
        self.src
    }
}

impl fmt::Display for SipUri<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.src)
    }
}

/// One URI parameter, preserving its raw name and optional value.
#[derive(Clone, Copy, Debug)]
pub struct Parameter<'a> {
    name: Component<'a>,
    value: Option<Component<'a>>,
}

impl<'a> Parameter<'a> {
    /// Returns the escaped parameter name.
    pub fn name(self) -> Component<'a> {
        self.name
    }

    /// Returns the escaped value, or `None` for a flag such as `lr`.
    pub fn value(self) -> Option<Component<'a>> {
        self.value
    }
}

/// URI parameters in wire order. Each item borrows the original text.
#[derive(Clone)]
pub struct Parameters<'a>(uri::UriParamsIter<'a>);

impl<'a> Iterator for Parameters<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Parameter<'a>> {
        let uri::UriParam { name, value } = self.0.next()?;
        Some(Parameter { name: Component(name), value: value.map(Component) })
    }
}

impl FusedIterator for Parameters<'_> {}

// The parameters left, rather than siparse's iterator, whose name is not
// part of this API.
impl fmt::Debug for Parameters<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// One URI header pair. Its value may be empty but is always present.
#[derive(Clone, Copy, Debug)]
pub struct Header<'a> {
    name: Component<'a>,
    value: Component<'a>,
}

impl<'a> Header<'a> {
    /// Returns the escaped header name.
    pub fn name(self) -> Component<'a> {
        self.name
    }

    /// Returns the escaped header value, which may be empty.
    pub fn value(self) -> Component<'a> {
        self.value
    }
}

/// URI header pairs in wire order. Duplicates are retained.
#[derive(Clone)]
pub struct Headers<'a>(uri::UriHeadersIter<'a>);

impl<'a> Iterator for Headers<'a> {
    type Item = Header<'a>;

    fn next(&mut self) -> Option<Header<'a>> {
        let uri::UriHeader { name, value } = self.0.next()?;
        Some(Header { name: Component(name), value: Component(value) })
    }
}

impl FusedIterator for Headers<'_> {}

impl fmt::Debug for Headers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

fn invalid(kind: InvalidSipUriKind) -> InvalidSipUri {
    InvalidSipUri { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_delimiters_are_not_parameter_or_header_delimiters() {
        let src = "SiPs:alice;phone?work/desk:secret%3a@[2001:db8::1]:005061;Transport=quic;lr?Subject=hello%20world&Subject=";
        let uri = SipUri::parse(src).unwrap();

        assert_eq!(uri.as_str(), src);
        assert_eq!(uri.scheme(), Scheme::Sips);
        assert_eq!(uri.user().unwrap().as_str(), "alice;phone?work/desk");
        assert_eq!(uri.password().unwrap().decode().as_ref(), b"secret:");
        assert_eq!(uri.host(), "2001:db8::1");
        assert_eq!(uri.port(), Some("005061"));
        assert_eq!(uri.port_u16().unwrap(), Some(5061));
        assert_eq!(
            uri.parameter("TRANSPORT")
                .unwrap()
                .unwrap()
                .value()
                .unwrap()
                .as_str(),
            "quic"
        );
        assert!(uri.parameter("lr").unwrap().unwrap().value().is_none());
        assert!(uri.parameter("maddr").unwrap().is_none());

        let pairs: Vec<_> = uri
            .headers()
            .map(|h| (h.name().as_str(), h.value().as_str()))
            .collect();
        assert_eq!(pairs, [("Subject", "hello%20world"), ("Subject", "")]);
    }

    #[test]
    fn missing_and_empty_components_have_distinct_results() {
        let bare = SipUri::parse("sip:Example.COM.").unwrap();
        let empty =
            SipUri::parse("sip:alice:@Example.COM.:0;lr?Subject=").unwrap();

        assert_eq!(bare.host(), "Example.COM.");
        assert!(bare.user().is_none());
        assert!(bare.password().is_none());
        assert_eq!(bare.port_u16().unwrap(), None);
        assert!(bare.parameters().next().is_none());
        assert!(bare.headers().next().is_none());
        assert_eq!(empty.password().unwrap().as_str(), "");
        assert_eq!(empty.port_u16().unwrap(), Some(0));
        assert!(empty.parameters().next().unwrap().value().is_none());
        assert_eq!(empty.headers().next().unwrap().value().as_str(), "");
    }

    #[test]
    fn port_syntax_and_network_port_conversion_are_separate() {
        for port in ["65536", "999999999999999999999999999999999999"] {
            let text = format!("sip:example.com:{port}");
            let uri = SipUri::parse(&text).unwrap();

            assert_eq!(uri.port(), Some(port));
            assert!(uri.port_u16().is_err());
        }
        for port in ["0", "65535", "00000000000000000000000000000000000005060"]
        {
            let text = format!("sip:example.com:{port}");
            assert!(SipUri::parse(&text).unwrap().port_u16().is_ok());
        }
    }

    #[test]
    fn hosts_follow_the_corrected_ip_and_sip_hostname_grammar() {
        for host in [
            "192.0.2.1",
            "[::]",
            "[::1]",
            "[::ffff:192.0.2.1]",
            "[2001:DB8:0:0:0:0:0:1]",
            "example",
            "3com.Example.",
            "a-b.example",
        ] {
            let src = format!("sip:{host}");
            assert!(SipUri::parse(&src).is_ok(), "{src}");
        }
        for host in [
            "",
            "256.1.1.1",
            "192.000.2.1",
            "192.0.2.1.",
            "1",
            "example.1",
            "a..example",
            "-a.example",
            "a-.example",
            "example..",
            "a_b.example",
            "ex%61mple.com",
            "[::ffff:192.000.2.1]",
            "[2001:db8:::1]",
            "[::1",
            "::1",
            "[v1.a]",
            "[fe80::1%25eth0]",
            "[example.com]",
        ] {
            let src = format!("sip:{host}");
            assert!(SipUri::parse(&src).is_err(), "{src}");
        }
    }

    #[test]
    fn malformed_components_and_escapes_are_rejected() {
        use InvalidSipUriKind as K;
        for (src, kind) in [
            ("http://example.com", K::Scheme),
            ("SIP", K::Scheme),
            ("sip:@example.com", K::User),
            ("sip::password@example.com", K::User),
            ("sip:alice:pass:word@example.com", K::Password),
            ("sip:alice:pass;word@example.com", K::Password),
            ("sip:alice@@example.com", K::Host),
            ("sip:example.com:", K::Port),
            ("sip:example.com:-1", K::Port),
            ("sip:[::1]garbage", K::Port),
            ("sip:example.com;", K::Parameter),
            ("sip:example.com;;lr", K::Parameter),
            ("sip:example.com;x=", K::Parameter),
            ("sip:example.com;=x", K::Parameter),
            ("sip:example.com;x=a=b", K::Parameter),
            ("sip:example.com?", K::Header),
            ("sip:example.com?x", K::Header),
            ("sip:example.com?=x", K::Header),
            ("sip:example.com?x=y&", K::Header),
            ("sip:example.com?x=y=z", K::Header),
            ("sip:a%2@example.com", K::Escape),
            ("sip:a%gg@example.com", K::Escape),
            ("sip:example.com;x=%", K::Escape),
            ("sip:example.com?x=%a", K::Escape),
            ("sip:alice:%zz@example.com", K::Escape),
            ("sip:example.com;%=x", K::Escape),
            ("sip:example.com?%=x", K::Escape),
        ] {
            assert_eq!(SipUri::parse(src).unwrap_err().kind(), kind, "{src}");
        }
        for src in [
            "sip:a\u{e9}@example.com",
            "sip:example.com;x=\u{e9}",
            "sip:example.com?x=\r\n",
            "sip:example.com#fragment",
            "sip:example.com/path",
            "sip:example.com?x=raw value",
        ] {
            assert!(SipUri::parse(src).is_err(), "{src:?}");
        }
    }

    #[test]
    fn escaped_delimiters_stay_in_their_original_components() {
        let uri = SipUri::parse("sip:alice%40work:p%3Ass@example.com;p%3Bname=a%3Bb%3Fc?x=a%26b%3Dc").unwrap();

        assert_eq!(uri.user().unwrap().decode().as_ref(), b"alice@work");
        assert_eq!(uri.password().unwrap().decode().as_ref(), b"p:ss");
        let parameter = uri.parameter("p;name").unwrap().unwrap();
        assert_eq!(parameter.value().unwrap().decode().as_ref(), b"a;b?c");
        assert_eq!(
            uri.headers().next().unwrap().value().decode().as_ref(),
            b"a&b=c"
        );
    }

    #[test]
    fn duplicate_names_are_preserved_and_never_silently_selected() {
        let uri =
            SipUri::parse("sip:example.com;lr;LR=x;%6cr=y;other=z").unwrap();

        assert_eq!(uri.parameters().count(), 4);
        assert_eq!(
            uri.parameter("lr").unwrap_err().kind(),
            InvalidSipUriKind::DuplicateParameter
        );
        assert_eq!(
            uri.parameter("other").unwrap().unwrap().value().unwrap().as_str(),
            "z"
        );
        assert!(uri.parameter("missing").unwrap().is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn every_byte_obeys_its_component_class() {
        for byte in 0..=255u8 {
            // The RFC 3261 alphabets, spelled out here rather than taken
            // from siparse, so that the test does not share the parser's.
            let unreserved = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!~*'()";
            for (prefix, suffix, extra) in [
                ("sip:", "@example.com", &b"&=+$,;?/"[..]),
                ("sip:alice:", "@example.com", &b"&=+$,"[..]),
                ("sip:example.com;x=", "", &b"[]/:&+$"[..]),
                ("sip:example.com?x=", "", &b"[]/?:+$"[..]),
            ] {
                let mut src = prefix.as_bytes().to_vec();
                src.push(byte);
                src.extend_from_slice(suffix.as_bytes());
                // A delimiter byte outside the class does not split the URI
                // into another valid shape. It leaves an empty or malformed
                // component, so the whole parse rejects it like any other
                // byte outside the class.
                let parsed = std::str::from_utf8(&src)
                    .is_ok_and(|src| SipUri::parse(src).is_ok());
                assert_eq!(
                    parsed,
                    unreserved.contains(&byte) || extra.contains(&byte),
                    "{prefix}{byte:#x}{suffix}"
                );
            }
        }
    }

    #[test]
    fn iterators_are_cloneable_and_fused() {
        let uri = SipUri::parse("sip:example.com;a;b=c?x=&y=z").unwrap();
        let mut params = uri.parameters();
        assert_eq!(params.next().unwrap().name().as_str(), "a");
        assert_eq!(params.clone().count(), 1);
        assert_eq!(params.next().unwrap().value().unwrap().as_str(), "c");
        assert!(params.next().is_none());
        assert!(params.next().is_none());

        let mut headers = uri.headers();
        assert_eq!(headers.next().unwrap().name().as_str(), "x");
        assert_eq!(headers.clone().count(), 1);
        assert_eq!(headers.next().unwrap().value().as_str(), "z");
        assert!(headers.next().is_none());
        assert!(headers.next().is_none());
    }

    // Debug shows the items left, not siparse's iterator type.
    #[test]
    fn iterators_debug_as_the_items_left() {
        let uri = SipUri::parse("sip:example.com;lr?x=y").unwrap();
        assert_eq!(
            format!("{:?}", uri.parameters()),
            r#"[Parameter { name: "lr", value: None }]"#
        );

        let mut headers = uri.headers();
        assert_eq!(
            format!("{headers:?}"),
            r#"[Header { name: "x", value: "y" }]"#
        );
        headers.next();
        assert_eq!(format!("{headers:?}"), "[]");
    }
}
