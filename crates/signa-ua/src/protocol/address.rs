/*!
Addresses in From, To, Contact, Route and Record-Route values.

Each of these is a `name-addr` or an `addr-spec` followed by header parameters
(RFC 3261 section 25.1), and Contact, Route and Record-Route hold a
comma-separated list of them. A comma or semicolon can sit inside a quoted
display name, a quoted parameter value, or a URI in angle brackets, so the
value is scanned element by element. RFC 3261 section 20 requires the angle
brackets around a URI that holds a comma, question mark or semicolon, which is
what lets an `addr-spec` end at the first of them.
*/

use siparse::scan::{host, quoted_string, sws, token};

/// One address of a header value, borrowed from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Address<'a> {
    /// The URI, without angle brackets. It is not validated here.
    pub(crate) uri: &'a str,
    /// Whether the URI was in angle brackets, as a `name-addr` has it.
    pub(crate) bracketed: bool,
    /// The header parameters as written, from the first `;`.
    pub(crate) parameters: &'a str,
}

/// The value is not a list of addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Invalid;

impl<'a> Address<'a> {
    /// Looks up a header parameter by name, ignoring ASCII case.
    ///
    /// The outer `Option` is whether the parameter is there, and the inner
    /// one whether it has a value. A quoted value keeps its quotes. A name
    /// that appears twice is an error, since no occurrence is the right
    /// one to pick.
    pub(crate) fn parameter(
        &self,
        name: &str,
    ) -> Result<Option<Option<&'a str>>, Invalid> {
        let mut rest = self.parameters;
        let mut found = None;

        while !rest.is_empty() {
            let (parameter, value, tail) = parameter(rest).ok_or(Invalid)?;
            if parameter.eq_ignore_ascii_case(name) {
                if found.is_some() {
                    return Err(Invalid);
                }
                found = Some(value);
            }
            rest = tail;
        }

        Ok(found)
    }
}

/// Iterates the addresses of one header value, in order.
///
/// After an error the iterator ends, since nothing past the malformed part
/// can be trusted to start an address.
pub(crate) fn addresses(value: &str) -> Addresses<'_> {
    Addresses { rest: Some(value) }
}

#[derive(Debug)]
pub(crate) struct Addresses<'a> {
    rest: Option<&'a str>,
}

impl<'a> Iterator for Addresses<'a> {
    type Item = Result<Address<'a>, Invalid>;

    fn next(&mut self) -> Option<Result<Address<'a>, Invalid>> {
        let rest = self.rest.take()?;

        match address(rest) {
            Some((address, tail)) => {
                let tail = sws(tail);
                if let Some(next) = tail.strip_prefix(',') {
                    self.rest = Some(next);
                } else if !tail.is_empty() {
                    return Some(Err(Invalid));
                }
                Some(Ok(address))
            }
            None => Some(Err(Invalid)),
        }
    }
}

/// Reads one address and its parameters from the start of `src`.
fn address(src: &str) -> Option<(Address<'_>, &str)> {
    let src = sws(src);

    let (uri, bracketed, rest) = match name_addr(src) {
        Some((uri, rest)) => (uri, true, rest),
        // Only a `name-addr` starts with these. An unclosed one is not an
        // `addr-spec` either.
        None if src.starts_with(['"', '<']) => return None,
        None => {
            // An `addr-spec` ends at the first `;`, `,` or whitespace.
            let end = src
                .find([';', ',', ' ', '\t', '\r', '\n'])
                .unwrap_or(src.len());
            (&src[..end], false, &src[end..])
        }
    };
    if uri.is_empty() {
        return None;
    }

    // The parameters run while each `;` is followed by a parameter.
    let mut end = rest;
    loop {
        let after = sws(end);
        if !after.starts_with(';') {
            break;
        }
        let (_, _, tail) = parameter(after)?;
        end = tail;
    }

    let parameters = &rest[..rest.len() - end.len()];
    Some((Address { uri, bracketed, parameters: sws(parameters) }, end))
}

/// Reads `[ display-name ] LAQUOT addr-spec RAQUOT`, or returns `None` when
/// `src` does not start with one.
fn name_addr(src: &str) -> Option<(&str, &str)> {
    let mut rest = src;

    if rest.starts_with('"') {
        rest = sws(quoted_string(rest)?.1);
    } else {
        // An unquoted display name is tokens separated by whitespace. Without
        // a `<` after them this is not a `name-addr`.
        while let Some((_, tail)) = token(rest) {
            rest = sws(tail);
        }
    }

    let inner = rest.strip_prefix('<')?;
    let close = inner.find('>')?;
    Some((&inner[..close], &inner[close + 1..]))
}

/// Reads `SEMI generic-param` from the start of `src`, returning the name,
/// the value if any, and what follows.
fn parameter(src: &str) -> Option<(&str, Option<&str>, &str)> {
    let rest = sws(sws(src).strip_prefix(';')?);
    let (name, rest) = token(rest)?;

    let Some(value) = sws(rest).strip_prefix('=') else {
        return Some((name, None, rest));
    };

    // `gen-value = token / host / quoted-string`. A host can be an IPv6
    // reference, which no token matches.
    let value = sws(value);
    let (value, rest) = if value.starts_with('"') {
        let (_, tail) = quoted_string(value)?;
        (&value[..value.len() - tail.len()], tail)
    } else if value.starts_with('[') {
        host(value)?
    } else {
        token(value)?
    };
    Some((name, Some(value), rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(value: &str) -> Result<Vec<&str>, Invalid> {
        addresses(value).map(|address| Ok(address?.uri)).collect()
    }

    #[test]
    fn quoted_comma_does_not_split_address() {
        assert_eq!(
            uris(
                "\"Bob, the builder\" <sip:bob@biloxi.com>, <sip:b2@biloxi.com>"
            ),
            Ok(vec!["sip:bob@biloxi.com", "sip:b2@biloxi.com"]),
        );
        assert_eq!(
            uris("<sip:p1.example.com;lr>;x=\"a,b\", <sip:p2.example.com;lr>"),
            Ok(vec!["sip:p1.example.com;lr", "sip:p2.example.com;lr"]),
        );
    }

    #[test]
    fn uri_parameters_stay_with_the_uri() {
        let address = addresses("<sip:p1.example.com;lr;transport=tcp>;tag=x")
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(address.uri, "sip:p1.example.com;lr;transport=tcp");
        assert!(address.bracketed);
        assert_eq!(address.parameters, ";tag=x");
        assert_eq!(address.parameter("lr"), Ok(None));
        assert_eq!(address.parameter("TAG"), Ok(Some(Some("x"))));
    }

    #[test]
    fn an_addr_spec_ends_at_its_parameters() {
        let address = addresses("sip:bob@biloxi.com;tag=a6c85cf")
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(address.uri, "sip:bob@biloxi.com");
        assert!(!address.bracketed);
        assert_eq!(address.parameter("tag"), Ok(Some(Some("a6c85cf"))));
    }

    #[test]
    fn ipv6_references_survive() {
        assert_eq!(
            uris("<sip:[2001:db8::1]:5060;lr>;received=[2001:db8::2]"),
            Ok(vec!["sip:[2001:db8::1]:5060;lr"]),
        );
        assert_eq!(uris("sip:[2001:db8::1]"), Ok(vec!["sip:[2001:db8::1]"]));
    }

    #[test]
    fn display_names_come_in_both_forms() {
        for value in [
            "Bob <sip:bob@biloxi.com>",
            "Bob B <sip:bob@biloxi.com>",
            "\"Bob \\\"B\\\"\" <sip:bob@biloxi.com>",
            "<sip:bob@biloxi.com>",
        ] {
            assert_eq!(uris(value), Ok(vec!["sip:bob@biloxi.com"]), "{value}");
        }
    }

    #[test]
    fn folds_are_whitespace() {
        assert_eq!(
            uris("<sip:p1.example.com;lr>,\r\n <sip:p2.example.com;lr>"),
            Ok(vec!["sip:p1.example.com;lr", "sip:p2.example.com;lr"]),
        );
    }

    #[test]
    fn rejects_what_is_not_a_list_of_addresses() {
        for value in [
            "",
            "<>",
            "<sip:bob@biloxi.com",
            "\"Bob <sip:bob@biloxi.com>",
            "<sip:bob@biloxi.com> junk",
            "<sip:bob@biloxi.com>,",
            "<sip:bob@biloxi.com>;",
            "<sip:bob@biloxi.com>;x=\"open",
            ", <sip:bob@biloxi.com>",
        ] {
            assert_eq!(uris(value), Err(Invalid), "{value:?}");
        }
    }

    #[test]
    fn a_repeated_parameter_is_ambiguous() {
        let address =
            addresses("<sip:bob@biloxi.com>;x=1;X=2").next().unwrap().unwrap();

        assert_eq!(address.parameter("x"), Err(Invalid));
        assert_eq!(address.parameter("y"), Ok(None));
    }
}
