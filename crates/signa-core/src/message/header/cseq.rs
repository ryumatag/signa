//! Crate-private parsing of `CSeq`.
//!
//! Transactions match a response to a request by the `CSeq` method, and
//! responses carry the request's `CSeq`. Typed header support for
//! applications belongs to a separate crate, so this stays inside signa and
//! reads only what the protocol layer needs.

use siparse::scan;

use crate::message::{Method, header::value::HeaderValue};

/// A parsed `CSeq` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSeq {
    /// The sequence number, which RFC 3261 section 8.1.1.5 limits to 32
    /// bits.
    pub number: u32,
    /// The method.
    pub method: Method,
}

impl CSeq {
    /// Parses `1*DIGIT LWS Method` (RFC 3261 section 25.1).
    ///
    /// Known methods are recognized only in uppercase, as
    /// [`Method::from_bytes`] does. Any other `token` is an extension
    /// method, so a lowercase `invite` is one, and does not equal
    /// [`Method::INVITE`].
    pub fn parse(value: &HeaderValue) -> Option<CSeq> {
        let rest = scan::sws(value.as_str());
        let (digits, rest) = scan::digits(rest)?;
        // The digits have no sign, so this only fails above `u32::MAX`.
        let number = digits.parse().ok()?;
        let rest = scan::lws(rest)?;
        let (method, rest) = scan::token(rest)?;
        // siparse keeps trailing whitespace, including a trailing fold.
        if !scan::sws(rest).is_empty() {
            return None;
        }
        let method = Method::from_bytes(method.as_bytes()).ok()?;
        Some(CSeq { number, method })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &'static str) -> Option<CSeq> {
        CSeq::parse(&HeaderValue::from_static(value))
    }

    #[test]
    fn parses_a_number_and_a_method() {
        assert_eq!(
            parse("314159 INVITE"),
            Some(CSeq { number: 314159, method: Method::INVITE })
        );
        assert_eq!(
            parse("1 X-VENDOR"),
            Some(CSeq { number: 1, method: "X-VENDOR".parse().unwrap() })
        );
    }

    #[test]
    fn accepts_folds_and_extra_whitespace() {
        let expected = Some(CSeq { number: 7, method: Method::ACK });
        assert_eq!(parse(" 7 \t ACK"), expected);
        assert_eq!(parse("7\r\n ACK"), expected);
        assert_eq!(parse("7 ACK \r\n "), expected);
    }

    #[test]
    fn accepts_leading_zeros_and_the_largest_number() {
        assert_eq!(parse("007 BYE").unwrap().number, 7);
        assert_eq!(parse("4294967295 BYE").unwrap().number, u32::MAX);
    }

    #[test]
    fn a_lowercase_method_is_an_extension() {
        let cseq = parse("1 invite").unwrap();
        assert_ne!(cseq.method, Method::INVITE);
        assert_eq!(cseq.method, "invite");
    }

    #[test]
    fn rejects_malformed_values() {
        for value in [
            "",
            "INVITE",
            "1",
            "1 ",
            "1INVITE",
            "-1 INVITE",
            "+1 INVITE",
            "4294967296 INVITE",
            "1 INVITE extra",
            "1 IN VITE",
            "1 IN@VITE",
            "1.0 INVITE",
        ] {
            assert_eq!(parse(value), None, "{value:?}");
        }
    }
}
