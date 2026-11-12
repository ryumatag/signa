use std::{
    error, fmt,
    iter::FusedIterator,
    net::{Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
};

use super::component::{Component, hex};

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
/// Parsing allocates nothing and retains the original text. Getters do not
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
    scheme: Scheme,
    // These offsets are boundaries of ASCII delimiters in validated text.
    // password_at is the @ position when there is no password.
    password_at: usize,
    host_start: usize,
    host_end: usize,
    port_end: usize,
    params_end: usize,
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
        let scheme =
            scheme(src).ok_or_else(|| invalid(InvalidSipUriKind::Scheme))?;
        let start = scheme.as_str().len() + 1;

        // Raw @ is not allowed in any later component. User information may
        // contain ; and ?, so identify it before looking for those delimiters.
        let (host_start, password_at) = if let Some(at) =
            src[start..].find('@')
        {
            let at = start + at;
            let info = &src[start..at];
            let password_at = info.find(':').map_or(at, |colon| start + colon);
            component(
                &src[start..password_at],
                user_char,
                false,
                InvalidSipUriKind::User,
            )?;
            if password_at < at {
                component(
                    &src[password_at + 1..at],
                    password_char,
                    true,
                    InvalidSipUriKind::Password,
                )?;
            }
            (at + 1, password_at)
        } else {
            (start, start - 1)
        };

        let port_end = src[host_start..]
            .find([';', '?'])
            .map_or(src.len(), |n| host_start + n);
        let authority = &src[host_start..port_end];
        let host_len = if authority.starts_with('[') {
            let close = authority
                .find(']')
                .ok_or_else(|| invalid(InvalidSipUriKind::Host))?;
            host(&authority[..=close])?;
            close + 1
        } else {
            let end = authority.find(':').unwrap_or(authority.len());
            host(&authority[..end])?;
            end
        };
        let host_end = host_start + host_len;
        if host_end < port_end {
            let rest = &src[host_end..port_end];
            if !rest.starts_with(':')
                || rest.len() == 1
                || !rest.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            {
                return Err(invalid(InvalidSipUriKind::Port));
            }
        }

        let params_end =
            src[port_end..].find('?').map_or(src.len(), |n| port_end + n);
        let params = &src[port_end..params_end];
        if !params.is_empty() {
            for pair in params[1..].split(';') {
                let (name, value) = pair
                    .split_once('=')
                    .map_or((pair, None), |(n, v)| (n, Some(v)));
                component(
                    name,
                    param_char,
                    false,
                    InvalidSipUriKind::Parameter,
                )?;
                if let Some(value) = value {
                    component(
                        value,
                        param_char,
                        false,
                        InvalidSipUriKind::Parameter,
                    )?;
                }
            }
        }

        if params_end < src.len() {
            for pair in src[params_end + 1..].split('&') {
                let (name, value) = pair
                    .split_once('=')
                    .ok_or_else(|| invalid(InvalidSipUriKind::Header))?;
                component(
                    name,
                    header_char,
                    false,
                    InvalidSipUriKind::Header,
                )?;
                component(
                    value,
                    header_char,
                    true,
                    InvalidSipUriKind::Header,
                )?;
            }
        }

        Ok(SipUri {
            src,
            scheme,
            password_at,
            host_start,
            host_end,
            port_end,
            params_end,
        })
    }

    /// Returns the original URI, including its scheme spelling and escapes.
    pub fn as_str(&self) -> &'a str {
        self.src
    }

    /// Returns the parsed scheme without implying a transport choice.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Returns the escaped user, or `None` if user information was absent.
    pub fn user(&self) -> Option<Component<'a>> {
        let start = self.scheme.as_str().len() + 1;
        (self.host_start > start)
            .then(|| Component(&self.src[start..self.password_at]))
    }

    /// Returns the escaped password, distinguishing absent from empty.
    pub fn password(&self) -> Option<Component<'a>> {
        (self.password_at + 1 < self.host_start).then(|| {
            Component(&self.src[self.password_at + 1..self.host_start - 1])
        })
    }

    /// Returns the original host text, without IPv6 brackets.
    ///
    /// Host names retain case and an optional trailing dot. IP literals are
    /// validated using RFC 5954's grammar. No name resolution is performed.
    pub fn host(&self) -> &'a str {
        let raw = &self.src[self.host_start..self.host_end];
        if raw.starts_with('[') { &raw[1..raw.len() - 1] } else { raw }
    }

    /// Returns the original explicit port digits, or `None` when omitted.
    ///
    /// RFC 3261 defines this component as one or more digits, without a
    /// syntactic upper bound. Leading zeroes and oversized values are retained.
    pub fn port(&self) -> Option<&'a str> {
        (self.port_end > self.host_end)
            .then(|| &self.src[self.host_end + 1..self.port_end])
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
        Parameters(
            self.src[self.port_end..self.params_end]
                .strip_prefix(';')
                .unwrap_or(""),
        )
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
    /// occurrence is silently chosen. This scans only the requested name so
    /// parsing and lookup stay linear without allocating a parameter index.
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
        Headers(if self.params_end < self.src.len() {
            &self.src[self.params_end + 1..]
        } else {
            ""
        })
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
#[derive(Clone, Debug)]
pub struct Parameters<'a>(&'a str);

impl<'a> Iterator for Parameters<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Parameter<'a>> {
        let pair = take(&mut self.0, ';')?;
        let (name, value) = pair
            .split_once('=')
            .map_or((pair, None), |(n, v)| (n, Some(Component(v))));
        Some(Parameter { name: Component(name), value })
    }
}

impl FusedIterator for Parameters<'_> {}

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
#[derive(Clone, Debug)]
pub struct Headers<'a>(&'a str);

impl<'a> Iterator for Headers<'a> {
    type Item = Header<'a>;

    fn next(&mut self) -> Option<Header<'a>> {
        let pair = take(&mut self.0, '&')?;
        let (name, value) =
            pair.split_once('=').expect("validated URI header pair");
        Some(Header { name: Component(name), value: Component(value) })
    }
}

impl FusedIterator for Headers<'_> {}

fn take<'a>(rest: &mut &'a str, delimiter: char) -> Option<&'a str> {
    if rest.is_empty() {
        return None;
    }
    let (item, tail) = rest.split_once(delimiter).unwrap_or((rest, ""));
    *rest = tail;
    Some(item)
}

fn scheme(src: &str) -> Option<Scheme> {
    if src.get(..4).is_some_and(|s| s.eq_ignore_ascii_case("sip:")) {
        Some(Scheme::Sip)
    } else if src.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("sips:")) {
        Some(Scheme::Sips)
    } else {
        None
    }
}

fn invalid(kind: InvalidSipUriKind) -> InvalidSipUri {
    InvalidSipUri { kind }
}

fn component(
    src: &str,
    allowed: impl Fn(u8) -> bool,
    empty: bool,
    kind: InvalidSipUriKind,
) -> Result<(), InvalidSipUri> {
    if src.is_empty() && !empty {
        return Err(invalid(kind));
    }
    let bytes = src.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes.get(index + 1).and_then(|&b| hex(b)).is_none()
                || bytes.get(index + 2).and_then(|&b| hex(b)).is_none()
            {
                return Err(invalid(InvalidSipUriKind::Escape));
            }
            index += 3;
        } else if allowed(bytes[index]) {
            index += 1;
        } else {
            return Err(invalid(kind));
        }
    }
    Ok(())
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b)
}

fn user_char(b: u8) -> bool {
    unreserved(b) || b"&=+$,;?/".contains(&b)
}

fn password_char(b: u8) -> bool {
    unreserved(b) || b"&=+$,".contains(&b)
}

fn param_char(b: u8) -> bool {
    unreserved(b) || b"[]/:&+$".contains(&b)
}

fn header_char(b: u8) -> bool {
    unreserved(b) || b"[]/?:+$".contains(&b)
}

fn host(src: &str) -> Result<(), InvalidSipUri> {
    if let Some(inner) =
        src.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| invalid(InvalidSipUriKind::Host));
    }
    if src.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }

    // RFC 3261 hostname labels end in alphanum, and the top label begins
    // with ALPHA. RFC 5954 replaces the older permissive IPv4 production.
    let name = src.strip_suffix('.').unwrap_or(src);
    let top = name.rsplit('.').next().unwrap_or("");
    if !top.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
        return Err(invalid(InvalidSipUriKind::Host));
    }
    for label in name.split('.') {
        if !label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            || !label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid(InvalidSipUriKind::Host));
        }
    }
    Ok(())
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
            // An explicit RFC alphabet is independent of the predicates used
            // by the parser, including their ASCII/UTF-8 boundary checks.
            let unreserved = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!~*'()";
            for (prefix, suffix, allowed, extra) in [
                (
                    "sip:",
                    "@example.com",
                    user_char as fn(u8) -> bool,
                    &b"&=+$,;?/"[..],
                ),
                ("sip:alice:", "@example.com", password_char, &b"&=+$,"[..]),
                ("sip:example.com;x=", "", param_char, &b"[]/:&+$"[..]),
                ("sip:example.com?x=", "", header_char, &b"[]/?:+$"[..]),
            ] {
                let mut src = prefix.as_bytes().to_vec();
                src.push(byte);
                src.extend_from_slice(suffix.as_bytes());
                // Some delimiter bytes can form another valid URI structure.
                // This checks the component scanner directly, not that split.
                let part = String::from_utf8_lossy(&[byte]).into_owned();
                assert_eq!(
                    component(&part, allowed, false, InvalidSipUriKind::User)
                        .is_ok(),
                    unreserved.contains(&byte) || extra.contains(&byte),
                    "{byte:#x}"
                );
                if allowed(byte) {
                    assert!(
                        SipUri::parse(std::str::from_utf8(&src).unwrap())
                            .is_ok()
                    );
                }
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
}
