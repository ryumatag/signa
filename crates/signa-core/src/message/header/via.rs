/*!
Crate-private parsing of the topmost `Via`.

The transport reads the top `Via` of a received request to add `received` and
`rport` (RFC 3261 section 18.2.1, RFC 3581), and of a response it sends to pick
the destination (section 18.2.2). Transactions match on its `branch` and
`sent-by` (sections 17.1.3 and 17.2.3). That is all signa needs from a `Via`,
so this reads the first `via-parm` of a value and nothing after it. Typed
header support for applications belongs to a separate crate.
*/

use siparse::scan;

use super::value::HeaderValue;

/// The first `via-parm` of a `Via` value.
///
/// Every field borrows from the value. Parameter values are returned as
/// written. Tokens and hosts compare case-insensitively (RFC 3261 section
/// 7.3.1), which is left to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Via<'a> {
    /// The `transport` of `sent-protocol`, such as `UDP`.
    pub transport: &'a str,
    /// The `host` of `sent-by`, without the brackets of an IPv6 reference.
    pub host: &'a str,
    /// The `port` of `sent-by`.
    pub port: Option<u16>,
    /// The `branch` parameter.
    pub branch: Option<&'a str>,
    /// The last `received` parameter. RFC 3261 only allows an IP address
    /// here, but this does not check that it is one. The caller that uses it
    /// as an address parses it.
    ///
    /// Unlike the other parameters, a repeated `received` keeps its last
    /// value. The endpoint appends its own after anything the sender wrote,
    /// so a `received` the sender made up cannot pick where a response is
    /// forwarded.
    pub received: Option<&'a str>,
    /// The `rport` parameter. `Some(None)` is `rport` without a value, by
    /// which a client asks for the port (RFC 3581 section 4).
    pub rport: Option<Option<u16>>,
    /// The offset in the value just past a valueless `rport`, where the server
    /// puts `=port`. `None` when there is no such parameter.
    pub rport_at: Option<usize>,
    /// The `maddr` parameter.
    pub maddr: Option<&'a str>,
    /// The `ttl` parameter.
    pub ttl: Option<u8>,
    /// The offset in the value just past the parm's last byte, before any
    /// whitespace and the comma that starts the next parm. A parameter added
    /// to this parm, such as `received`, goes here.
    pub end: usize,
}

impl<'a> Via<'a> {
    /// Parses the first `via-parm` of `value`.
    ///
    /// When `value` is the first `Via` row of a message, this is its topmost
    /// `Via`. Returns `None` if the parm does not match the grammar in
    /// RFC 3261 section 25.1, with the `rport` parameter from RFC 3581.
    ///
    /// A parameter that appears twice keeps its first value, except
    /// `received`, which keeps its last. The protocol name and version in
    /// `sent-protocol` are not checked beyond being tokens. signa cannot route
    /// by a `Via` it does not understand, but it has no reason to reject the
    /// message for it either.
    pub fn top(value: &'a HeaderValue) -> Option<Via<'a>> {
        let src = value.as_str();

        // sent-protocol = protocol-name SLASH protocol-version SLASH
        //                 transport
        let rest = scan::sws(src);
        let (_, rest) = scan::token(rest)?;
        let rest = scan::separator(rest, '/')?;
        let (_, rest) = scan::token(rest)?;
        let rest = scan::separator(rest, '/')?;
        let (transport, rest) = scan::token(rest)?;

        // LWS sent-by, where sent-by = host [ COLON port ].
        let rest = scan::lws(rest)?;
        let (host, mut rest) = scan::host(rest)?;
        let mut via = Via {
            transport,
            host: unbracket(host),
            port: None,
            branch: None,
            received: None,
            rport: None,
            rport_at: None,
            maddr: None,
            ttl: None,
            end: 0,
        };
        if let Some(after) = scan::separator(rest, ':') {
            let (port, after) = scan::digits(after)?;
            via.port = Some(port.parse().ok()?);
            rest = after;
        }

        // *( SEMI via-params ), ending at the value's end or at the COMMA
        // before the next parm. Trailing whitespace stays outside `end`.
        loop {
            let next = scan::sws(rest);
            if next.is_empty() || next.starts_with(',') {
                break;
            }
            let next = scan::sws(next.strip_prefix(';')?);
            let asked = via.rport.is_none();
            rest = via.param(next)?;
            if asked && via.rport == Some(None) {
                via.rport_at = Some(src.len() - rest.len());
            }
        }
        via.end = src.len() - rest.len();

        Some(via)
    }

    /// Parses one `via-params` at the start of `src`, keeps it if signa
    /// reads it, and returns what follows it.
    fn param(&mut self, src: &'a str) -> Option<&'a str> {
        let (name, rest) = scan::token(src)?;
        // The value after `EQUAL`, if the parameter has one.
        let value = scan::separator(rest, '=');

        // Parameter names are case-insensitive (RFC 3261 section 7.3.1).
        if name.eq_ignore_ascii_case("branch") {
            let (branch, rest) = scan::token(value?)?;
            self.branch.get_or_insert(branch);
            return Some(rest);
        }
        if name.eq_ignore_ascii_case("received") {
            // IPv4address / IPv6address, without brackets, as a character
            // class. siparse has no scan for a bare address yet.
            let value = value?;
            let n = value
                .bytes()
                .take_while(|&b| {
                    b.is_ascii_hexdigit() || b == b'.' || b == b':'
                })
                .count();
            if n == 0 {
                return None;
            }
            let (received, rest) = value.split_at(n);
            self.received = Some(received);
            return Some(rest);
        }
        if name.eq_ignore_ascii_case("rport") {
            let Some(value) = value else {
                self.rport.get_or_insert(None);
                return Some(rest);
            };
            let (port, rest) = scan::digits(value)?;
            self.rport.get_or_insert(Some(port.parse().ok()?));
            return Some(rest);
        }
        if name.eq_ignore_ascii_case("maddr") {
            let (host, rest) = scan::host(value?)?;
            self.maddr.get_or_insert(unbracket(host));
            return Some(rest);
        }
        if name.eq_ignore_ascii_case("ttl") {
            let (ttl, rest) = scan::digits(value?)?;
            self.ttl.get_or_insert(ttl.parse().ok()?);
            return Some(rest);
        }

        // via-extension = generic-param, whose value is a token, a host, or
        // a quoted-string. A quoted string may hold `;` and `,`, so it has
        // to be skipped as one. Anything else runs to the next separator.
        // That takes more than the grammar allows, which keeps an unusual
        // extension from making the whole `Via` unreadable.
        let Some(value) = value else {
            return Some(rest);
        };
        if value.starts_with('"') {
            let (_, rest) = scan::quoted_string(value)?;
            return Some(rest);
        }
        let n = value
            .find([';', ',', ' ', '\t', '\r', '\n'])
            .unwrap_or(value.len());
        if n == 0 {
            return None;
        }
        Some(&value[n..])
    }
}

/// Strips the brackets of an IPv6 reference, which `scan::host` keeps.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a literal. The value is a `static` so that the test can hold
    /// the borrowed fields without leaking anything, which Miri would flag.
    macro_rules! top {
        ($value:expr) => {{
            static HEADER_VALUE: HeaderValue =
                HeaderValue::from_static($value);
            Via::top(&HEADER_VALUE)
        }};
    }

    #[test]
    fn parses_a_typical_via() {
        const VALUE: &str =
            "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds";
        assert_eq!(
            top!(VALUE),
            Some(Via {
                transport: "UDP",
                host: "pc33.atlanta.example.com",
                port: None,
                branch: Some("z9hG4bK776asdhds"),
                received: None,
                rport: None,
                rport_at: None,
                maddr: None,
                ttl: None,
                end: VALUE.len(),
            })
        );
    }

    #[test]
    fn parses_every_parameter_signa_reads() {
        const VALUE: &str = "SIP/2.0/TCP 192.0.2.4:5061;ttl=16;maddr=224.2.0.1\
                     ;received=192.0.2.207;rport=49154;branch=z9hG4bKa;x=1";
        assert_eq!(
            top!(VALUE),
            Some(Via {
                transport: "TCP",
                host: "192.0.2.4",
                port: Some(5061),
                branch: Some("z9hG4bKa"),
                received: Some("192.0.2.207"),
                rport: Some(Some(49154)),
                rport_at: None,
                maddr: Some("224.2.0.1"),
                ttl: Some(16),
                end: VALUE.len(),
            })
        );
    }

    #[test]
    fn rport_without_a_value_asks_for_one() {
        const VALUE: &str = "SIP/2.0/UDP a.example.com;rport;branch=z9hG4bKa";
        let via = top!(VALUE).unwrap();
        assert_eq!(via.rport, Some(None));
        assert_eq!(&VALUE[via.rport_at.unwrap()..], ";branch=z9hG4bKa");
        assert_eq!(via.branch, Some("z9hG4bKa"));
        let via = top!("SIP/2.0/UDP a.example.com;rport").unwrap();
        assert_eq!(via.rport, Some(None));
        assert_eq!(via.end, 31);
    }

    #[test]
    fn ipv6_hosts_lose_their_brackets() {
        let via =
            top!("SIP/2.0/UDP [2001:db8::1]:5060;maddr=[ff02::1]").unwrap();
        assert_eq!(via.host, "2001:db8::1");
        assert_eq!(via.port, Some(5060));
        assert_eq!(via.maddr, Some("ff02::1"));
        let via =
            top!("SIP/2.0/UDP [2001:db8::1];received=2001:db8::2").unwrap();
        assert_eq!(via.port, None);
        assert_eq!(via.received, Some("2001:db8::2"));
    }

    #[test]
    fn stops_at_the_second_parm() {
        const VALUE: &str = "SIP/2.0/UDP a.example.com;branch=z9hG4bKa \r\n ,\
                     SIP/2.0/UDP b.example.com;branch=z9hG4bKb";
        let via = top!(VALUE).unwrap();
        assert_eq!(via.host, "a.example.com");
        assert_eq!(via.branch, Some("z9hG4bKa"));
        assert_eq!(
            &VALUE[..via.end],
            "SIP/2.0/UDP a.example.com;branch=z9hG4bKa"
        );
    }

    #[test]
    fn end_excludes_trailing_whitespace() {
        const VALUE: &str =
            "SIP/2.0/UDP a.example.com;branch=z9hG4bKa \t\r\n ";
        let via = top!(VALUE).unwrap();
        assert_eq!(
            &VALUE[..via.end],
            "SIP/2.0/UDP a.example.com;branch=z9hG4bKa"
        );
        const SHORT: &str = "SIP/2.0/UDP a.example.com ";
        assert_eq!(top!(SHORT).unwrap().end, SHORT.len() - 1);
    }

    #[test]
    fn allows_whitespace_and_folds_around_separators() {
        const VALUE: &str = " SIP / 2.0 /\r\n UDP\r\n\ta.example.com : 5060 ; branch = z9hG4bKa ;\
                     rport = 5 ";
        let via = top!(VALUE).unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.host, "a.example.com");
        assert_eq!(via.port, Some(5060));
        assert_eq!(via.branch, Some("z9hG4bKa"));
        assert_eq!(via.rport, Some(Some(5)));
        assert_eq!(&VALUE[via.end..], " ");
    }

    #[test]
    fn parameter_names_are_case_insensitive() {
        let via = top!("SIP/2.0/UDP a.example.com;BRANCH=z9hG4bKa;Received=192.0.2.1;RPort")
            .unwrap();
        assert_eq!(via.branch, Some("z9hG4bKa"));
        assert_eq!(via.received, Some("192.0.2.1"));
        assert_eq!(via.rport, Some(None));
    }

    #[test]
    fn a_repeated_parameter_keeps_its_first_value() {
        let via = top!("SIP/2.0/UDP a.example.com;branch=z9hG4bKa;branch=z9hG4bKb;rport=1;rport")
            .unwrap();
        assert_eq!(via.branch, Some("z9hG4bKa"));
        assert_eq!(via.rport, Some(Some(1)));
    }

    // The endpoint appends its own `received`, so the last one is the one the
    // receiving transport wrote.
    #[test]
    fn a_repeated_received_keeps_its_last_value() {
        let via = top!(
            "SIP/2.0/UDP a.example.com;received=192.0.2.9;branch=z9hG4bKa\
             ;received=192.0.2.1"
        )
        .unwrap();
        assert_eq!(via.received, Some("192.0.2.1"));
    }

    #[test]
    fn skips_extension_parameters() {
        const VALUE: &str = "SIP/2.0/UDP a.example.com;x;y=token;z=\"a;b,c\\\"d\";w=[::1];branch=z9hG4bKa";
        let via = top!(VALUE).unwrap();
        assert_eq!(via.branch, Some("z9hG4bKa"));
        assert_eq!(via.end, VALUE.len());
    }

    #[test]
    fn rejects_malformed_values() {
        for value in [
            "",
            "SIP/2.0/UDP",
            "SIP/2.0/UDP ",
            "SIP/2.0/UDPa.example.com",
            "SIP/2.0 a.example.com",
            "SIP//UDP a.example.com",
            "/2.0/UDP a.example.com",
            "SIP/2.0/UDP a.example.com:",
            "SIP/2.0/UDP a.example.com:port",
            "SIP/2.0/UDP a.example.com:65536",
            "SIP/2.0/UDP [2001:db8::1",
            "SIP/2.0/UDP [2001:db8::1]:5060x",
            "SIP/2.0/UDP []",
            "SIP/2.0/UDP a.example.com;",
            "SIP/2.0/UDP a.example.com;;branch=z9hG4bKa",
            "SIP/2.0/UDP a.example.com;=z9hG4bKa",
            "SIP/2.0/UDP a.example.com;branch",
            "SIP/2.0/UDP a.example.com;branch=",
            "SIP/2.0/UDP a.example.com;branch=a b",
            "SIP/2.0/UDP a.example.com;received",
            "SIP/2.0/UDP a.example.com;received=[2001:db8::1]",
            "SIP/2.0/UDP a.example.com;rport=x",
            "SIP/2.0/UDP a.example.com;rport=65536",
            "SIP/2.0/UDP a.example.com;maddr",
            "SIP/2.0/UDP a.example.com;ttl",
            "SIP/2.0/UDP a.example.com;ttl=256",
            "SIP/2.0/UDP a.example.com;x=\"unterminated",
            "SIP/2.0/UDP a.example.com;x=\"esc\\\"",
            "SIP/2.0/UDP a.example.com extra",
            "SIP/2.0/UDP a.example.com=1",
        ] {
            let value = HeaderValue::from_static(value);
            assert_eq!(Via::top(&value), None, "{}", value.as_str());
        }
    }
}
