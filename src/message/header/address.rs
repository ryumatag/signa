/*!
The protocol layer's minimal interpretation of address header parameters.
*/

// Only identify the header's tag. The message parser owns head syntax, and
// siparse's lexer skips quoted text. URI parameters inside <> are not tags.
pub(crate) fn has_tag(mut rest: &str) -> bool {
    while let Some(ch) = rest.chars().next() {
        match ch {
            '"' => match siparse::scan::quoted_string(rest) {
                Some((_, tail)) => rest = tail,
                None => return true,
            },
            '<' => match rest.split_once('>') {
                Some((_, tail)) => rest = tail,
                None => return true,
            },
            ';' => {
                match siparse::scan::token(siparse::scan::sws(&rest[1..])) {
                    Some((name, tail)) => {
                        if name.eq_ignore_ascii_case("tag") {
                            return true;
                        }

                        rest = tail;
                    }
                    None => return true,
                }
            }
            _ => rest = &rest[ch.len_utf8()..],
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
