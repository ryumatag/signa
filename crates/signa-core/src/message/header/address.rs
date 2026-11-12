/*!
The protocol layer's minimal interpretation of address header parameters.
*/

use siparse::value;

/// Returns whether a From or To value has a `tag` header parameter, or
/// `None` if the value is not one `name-addr` or `addr-spec` followed by
/// `generic-param`s (RFC 3261 section 25.1).
///
/// A `tag` URI parameter inside the angle brackets is not a header
/// parameter. A valueless `tag` still counts.
pub(crate) fn tagged(value: &str) -> Option<bool> {
    let address = value::address(value).ok()?;
    let mut params = address.params.iter();
    Some(params.any(|param| param.name.eq_ignore_ascii_case("tag")))
}

/// Returns whether a From or To value has a `tag` header parameter, counting
/// a value that [`tagged`] cannot read as tagged.
///
/// The callers add a tag only to a value without one. Appending `;tag=` to a
/// value they cannot read could add a second tag.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn has_tag(value: &str) -> bool {
    tagged(value).unwrap_or(true)
}

/// Returns the URI of a From or To value, or `None` if the value is not a
/// `name-addr` or `addr-spec` followed by `generic-param`s (RFC 3261 section
/// 25.1).
///
/// This reads the structure the protocol layer copies into an ACK or CANCEL.
/// The caller validates the URI itself. Parameters are checked against
/// `generic-param` but not interpreted.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn uri(value: &str) -> Option<&str> {
    value::address(value).ok().map(|address| address.uri)
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
            ("<sip:bob@[2001:db8::1]>", "sip:bob@[2001:db8::1]"),
            ("sip:bob@[2001:db8::1];tag=1", "sip:bob@[2001:db8::1]"),
            ("<sip:bob@example.com>\r\n ;tag=1", "sip:bob@example.com"),
            // Without angle brackets, a `;` ends the URI, so the
            // `phone-context` is a header parameter (RFC 3261 section 20).
            ("tel:+12015550123;phone-context=example.com", "tel:+12015550123"),
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
            // RFC 3261 section 25.1 requires whitespace after an unquoted
            // display name and none inside the angle brackets. A `gen-value`
            // cannot hold `/`, an `addr-spec` needs a scheme, and one without
            // angle brackets cannot hold `?` (section 20).
            "Bob<sip:bob@example.com>",
            "< sip:bob@example.com>",
            "<sip:bob@example.com>;x=a/b",
            "<bob@example.com>",
            "sip:bob@example.com?subject=lunch",
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
            "sip:bob@[2001:db8::1];tag=bob",
            "<sip:bob@example.com>\t;tag=bob",
            "<sip:bob@example.com>\r\n ;tag=bob",
            // A valueless tag is still a tag, so nothing appends another.
            "<sip:bob@example.com>;tag",
        ] {
            assert!(has_tag(value), "{value}");
        }

        for value in [
            "<sip:bob@example.com;tag=uri>",
            "\";tag=display\" <sip:bob@example.com>",
            "<sip:bob@example.com>;x=\";tag=value\"",
            "<sip:bob@[2001:db8::1]>",
            "<sip:bob@example.com>;x=[2001:db8::1]",
            "<sip:bob@example.com>\r\n ",
        ] {
            assert!(!has_tag(value), "{value}");
        }
    }

    #[test]
    fn unreadable_values_count_as_tagged() {
        for value in [
            "",
            "\"Bob <sip:bob@example.com>",
            "<sip:bob@example.com",
            "Bob<sip:bob@example.com>",
            "<sip:bob@example.com>;x=a/b",
            "<sip:bob@example.com>;",
            "<sip:bob@example.com>;tag=",
            "sip:bob@example.com?subject=lunch",
        ] {
            assert_eq!(tagged(value), None, "{value}");
            assert!(has_tag(value), "{value}");
        }
    }
}
