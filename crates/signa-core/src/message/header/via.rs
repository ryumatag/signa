/*!
Crate-private parsing of the topmost `Via`.

The transport reads the top `Via` of a received request to add `received` and
`rport` (RFC 3261 section 18.2.1, RFC 3581), and of a response it sends to pick
the destination (section 18.2.2). Transactions match on its `branch` and
`sent-by` (sections 17.1.3 and 17.2.3). That is all signa needs from a `Via`,
so this reads the first `via-parm` of a value and nothing after it. Typed
header support for applications belongs to a separate crate.
*/

use siparse::{scan, value::Param};

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
    /// here, but this only checks that it is written with the characters of
    /// one. The caller that uses it as an address parses it.
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
    /// `received`, which keeps its last. Only the value kept is checked
    /// beyond `generic-param`, so a repeat that is not kept, such as a
    /// second `ttl` above 255 or without a value, does not reject the parm.
    /// The protocol name and version in `sent-protocol` are not checked
    /// beyond being tokens. signa cannot route by a `Via` it does not
    /// understand, but it has no reason to reject the message for it either.
    pub fn top(value: &'a HeaderValue) -> Option<Via<'a>> {
        let src = value.as_str();
        let mut parm = siparse::value::via_parm(src).ok()?;

        // siparse checks each parameter as a `generic-param`, or a
        // `received` as a bare IPv6 address, as it yields it. The loop only
        // picks out the ones signa reads, and their narrower values are
        // checked once it is done. Checking them in the loop made
        // `parse/via/full` slower.
        let mut branch = None;
        let mut received = None;
        let mut rport = None;
        let mut rport_at = None;
        let mut maddr = None;
        let mut ttl = None;
        for param in &mut parm {
            let Param { name, value } = param.ok()?;
            // Parameter names are case-insensitive (RFC 3261 section 7.3.1).
            if name.eq_ignore_ascii_case("branch") {
                keep_first(&mut branch, value)?;
            } else if name.eq_ignore_ascii_case("received") {
                received = Some(value?);
            } else if name.eq_ignore_ascii_case("rport") {
                if rport.is_none() && value.is_none() {
                    rport_at = Some(offset(src, name) + name.len());
                }
                rport.get_or_insert(value);
            } else if name.eq_ignore_ascii_case("maddr") {
                keep_first(&mut maddr, value)?;
            } else if name.eq_ignore_ascii_case("ttl") {
                keep_first(&mut ttl, value)?;
            }
        }
        let text = parm.text();

        Some(Via {
            transport: parm.transport,
            host: unbracket(parm.host),
            port: match parm.port {
                Some(port) => Some(port.parse().ok()?),
                None => None,
            },
            // siparse yields a quoted string, a bracketed host, a token, or
            // for `received` alone a bare IPv6 address. A `branch` that is
            // neither of the first two is a token.
            branch: match branch {
                Some(branch) if branch.starts_with(['"', '[']) => return None,
                branch => branch,
            },
            received: match received {
                Some(received) if !is_address(received) => return None,
                received => received,
            },
            rport: match rport {
                Some(Some(port)) => Some(Some(digits(port)?.parse().ok()?)),
                Some(None) => Some(None),
                None => None,
            },
            rport_at,
            maddr: match maddr {
                Some(maddr) if !is_host(maddr) => return None,
                maddr => maddr.map(unbracket),
            },
            ttl: match ttl {
                Some(ttl) => Some(digits(ttl)?.parse().ok()?),
                None => None,
            },
            end: offset(src, text) + text.len(),
        })
    }
}

/// Keeps `value` in `slot` unless an earlier one is there. Returns `None`
/// when the value is kept but missing, since every parameter this keeps
/// needs one.
fn keep_first<'a>(
    slot: &mut Option<&'a str>,
    value: Option<&'a str>,
) -> Option<()> {
    if slot.is_none() {
        *slot = Some(value?);
    }
    Some(())
}

/// Returns whether `value` is an IPv4address or IPv6address, without
/// brackets, as a character class.
fn is_address(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':')
}

/// Returns where `part` starts in `src`, which it borrows from.
fn offset(src: &str, part: &str) -> usize {
    part.as_ptr() as usize - src.as_ptr() as usize
}

/// Returns `src` if it is `1*DIGIT`. `str::parse` would also take a sign.
fn digits(src: &str) -> Option<&str> {
    scan::digits(src).filter(|(_, rest)| rest.is_empty()).map(|(d, _)| d)
}

/// Returns whether a `generic-param` value is a `host`.
fn is_host(value: &str) -> bool {
    scan::host(value).is_some_and(|(_, rest)| rest.is_empty())
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

    #[test]
    fn a_repeat_that_is_not_kept_is_checked_as_a_generic_param() {
        let via = top!(
            "SIP/2.0/UDP a.example.com;ttl=16;ttl=300;ttl;branch=z9hG4bKa\
             ;branch=\"b\";branch;maddr=224.2.0.1;maddr;received=\"x\"\
             ;received=192.0.2.1"
        )
        .unwrap();
        assert_eq!(via.ttl, Some(16));
        assert_eq!(via.branch, Some("z9hG4bKa"));
        assert_eq!(via.maddr, Some("224.2.0.1"));
        assert_eq!(via.received, Some("192.0.2.1"));

        // The repeat still has to be a `generic-param`, and the value kept
        // has to be what its parameter allows.
        assert_eq!(top!("SIP/2.0/UDP a.example.com;ttl=16;ttl=x/y"), None);
        assert_eq!(top!("SIP/2.0/UDP a.example.com;ttl=300;ttl=16"), None);
        assert_eq!(
            top!("SIP/2.0/UDP a.example.com;branch;branch=z9hG4bKa"),
            None
        );
        assert_eq!(
            top!(
                "SIP/2.0/UDP a.example.com;received=192.0.2.1;received=\"x\""
            ),
            None
        );
    }

    #[test]
    fn numbers_take_their_whole_range() {
        let via = top!("SIP/2.0/UDP a.example.com:65535;ttl=255;rport=65535")
            .unwrap();
        assert_eq!(via.port, Some(65535));
        assert_eq!(via.ttl, Some(255));
        assert_eq!(via.rport, Some(Some(65535)));

        let via =
            top!("SIP/2.0/UDP a.example.com:0;ttl=0016;rport=0").unwrap();
        assert_eq!(via.port, Some(0));
        assert_eq!(via.ttl, Some(16));
        assert_eq!(via.rport, Some(Some(0)));
    }

    #[test]
    fn rport_at_follows_the_first_rport_only() {
        const SPACED: &str =
            "SIP/2.0/UDP a.example.com;rport ;branch=z9hG4bKa";
        let via = top!(SPACED).unwrap();
        assert_eq!(&SPACED[via.rport_at.unwrap()..], " ;branch=z9hG4bKa");

        let via = top!("SIP/2.0/UDP a.example.com;rport=5;rport").unwrap();
        assert_eq!(via.rport, Some(Some(5)));
        assert_eq!(via.rport_at, None);
    }

    #[test]
    fn received_may_be_a_bare_ipv6_address() {
        for (value, received) in [
            ("SIP/2.0/UDP a.example.com;received=::1", "::1"),
            (
                "SIP/2.0/UDP a.example.com;received=::ffff:192.0.2.1",
                "::ffff:192.0.2.1",
            ),
        ] {
            let value = HeaderValue::from_static(value);
            let via = Via::top(&value).unwrap();
            assert_eq!(via.received, Some(received), "{}", value.as_str());
        }
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
            "SIP/2.0/UDP a.example.com;branch=\"z9hG4bKa\"",
            "SIP/2.0/UDP a.example.com;branch=[::1]",
            "SIP/2.0/UDP a.example.com;branch=::1",
            "SIP/2.0/UDP a.example.com;x=2001:db8::1",
            "SIP/2.0/UDP a.example.com;maddr=\"224.2.0.1\"",
            "SIP/2.0/UDP a.example.com;ttl=100000000000000000000000000000",
            "SIP/2.0/UDP a.example.com;maddr=a_b.example.com",
            "SIP/2.0/UDP a.example.com;ttl=+1",
            "SIP/2.0/UDP a.example.com;rport=+5060",
            "SIP/2.0/UDP a.example.com;x=a/b",
            "SIP/2.0/UDP a.example.com;x=a@b",
        ] {
            let value = HeaderValue::from_static(value);
            assert_eq!(Via::top(&value), None, "{}", value.as_str());
        }
    }
}
