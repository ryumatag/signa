/*!
The protocol layer's minimal interpretation of address header parameters.
*/

use siparse::scan::{quoted_string, sws, token};

// Only identify the header's tag. The message parser owns head syntax, and
// siparse's lexer skips quoted text. URI parameters inside <> are not tags.
pub(crate) fn has_tag(mut rest: &str) -> bool {
    while let Some(ch) = rest.chars().next() {
        match ch {
            '"' => match quoted_string(rest) {
                Some((_, tail)) => rest = tail,
                None => return true,
            },
            '<' => match rest.split_once('>') {
                Some((_, tail)) => rest = tail,
                None => return true,
            },
            ';' => match token(sws(&rest[1..])) {
                Some((name, tail)) => {
                    if name.eq_ignore_ascii_case("tag") {
                        return true;
                    }

                    rest = tail;
                }
                None => return true,
            },
            _ => rest = &rest[ch.len_utf8()..],
        }
    }

    false
}

/// Returns the URI of a From or To value, or `None` if the value is not a
/// `name-addr` or `addr-spec` followed by parameters (RFC 3261 section 25.1).
///
/// This reads the structure the protocol layer copies into an ACK or CANCEL.
/// The caller validates the URI itself. Parameters are not interpreted.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn uri(value: &str) -> Option<&str> {
    let mut rest = sws(value);
    let (uri, params) = if let Some(quoted) =
        rest.starts_with('"').then(|| quoted_string(rest)).flatten()
    {
        rest = sws(quoted.1).strip_prefix('<')?;
        rest.split_once('>')?
    } else if let Some((mut display, addr)) = rest.split_once('<') {
        // An unquoted display name is tokens separated by whitespace.
        loop {
            display = sws(display);
            if display.is_empty() {
                break;
            }
            display = token(display)?.1;
        }
        addr.split_once('>')?
    } else {
        // Without angle brackets, a `;` starts the header parameters.
        let end = rest.find(';').unwrap_or(rest.len());
        (rest[..end].trim_end(), &rest[end..])
    };

    let params = sws(params);
    (!uri.is_empty() && (params.is_empty() || params.starts_with(';')))
        .then_some(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_values_yield_their_uri() {
        for (value, expected) in [
            ("<sip:bob@example.com>", "sip:bob@example.com"),
            ("Bob <sip:bob@example.com>;tag=1", "sip:bob@example.com"),
            ("\"Bob, B.\" <sip:bob@example.com;lr>", "sip:bob@example.com;lr"),
            ("sip:bob@example.com;tag=1", "sip:bob@example.com"),
            ("  sip:bob@example.com ", "sip:bob@example.com"),
            ("A B <tel:+1-201-555-0123>", "tel:+1-201-555-0123"),
        ] {
            assert_eq!(uri(value), Some(expected), "{value}");
        }

        for value in [
            "",
            "<>",
            "<sip:bob@example.com",
            "\"Bob <sip:bob@example.com>",
            "\"Bob\" sip:bob@example.com",
            "Bob; <sip:bob@example.com>",
            "<sip:bob@example.com> junk",
            ";tag=1",
        ] {
            assert_eq!(uri(value), None, "{value}");
        }
    }

    #[test]
    fn only_header_parameters_count_as_to_tags() {
        for value in [
            "<sip:bob@example.com>;tag=bob",
            "sip:bob@example.com; TAG = bob",
            "\"Bob\" <sip:bob@example.com>;x=\"a;b\";tag=bob",
        ] {
            assert!(has_tag(value), "{value}");
        }

        for value in [
            "<sip:bob@example.com;tag=uri>",
            "\";tag=display\" <sip:bob@example.com>",
            "<sip:bob@example.com>;x=\";tag=value\"",
        ] {
            assert!(!has_tag(value), "{value}");
        }
    }
}
