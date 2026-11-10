/*!
The headers a UA core reads, and only as far as it needs them.

signa-core keeps header values opaque, and its own address and CSeq readers
are private to it. This module reads From, To, Call-ID, CSeq, Contact, Route,
Record-Route and Require on top of the element scans of [`siparse::scan`], so that
the grammar of RFC 3261 section 25.1 is followed rather than approximated by
splitting at `,` or `;`. It is not a general typed-header API.

What it returns borrows the message. Values are returned as written, with
case, parameters and their order intact. A dialog keeps its own copy of what
it needs.
*/

use signa_core::{
    HeaderMap,
    message::header::{
        CALL_ID, CONTACT, CSEQ, EXPIRES, FROM, HeaderName, RECORD_ROUTE,
        REQUIRE, TO,
    },
};
use siparse::scan;

pub(crate) use self::address::addresses;

mod address;

/// A header the UA needs that is missing, repeated or malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Malformed(pub(crate) Field);

/// The header a [`Malformed`] is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Field {
    CallId,
    From,
    To,
    CSeq,
    Contact,
    RecordRoute,
    Require,
    Expires,
}

/// The URI and tag of a From or To value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Party<'a> {
    pub(crate) uri: &'a str,
    /// `None` for a value without a tag, which RFC 3261 section 12.1 treats
    /// as a null tag.
    pub(crate) tag: Option<&'a str>,
}

/// Returns the one value of `name`. Call-ID, From, To and CSeq are not
/// lists, so a second row is as malformed as a missing one.
fn single(
    headers: &HeaderMap,
    name: HeaderName,
    field: Field,
) -> Result<&str, Malformed> {
    let mut rows = headers.get_all(name);
    match (rows.next(), rows.next()) {
        (Some(value), None) => Ok(value.as_str()),
        _ => Err(Malformed(field)),
    }
}

/// Returns the Call-ID, without the whitespace around it.
///
/// RFC 3261 section 20.8 compares Call-IDs byte by byte, so the value is
/// returned exactly as written and only checked against `callid = word
/// ["@" word]` of section 25.1.
pub(crate) fn call_id(headers: &HeaderMap) -> Result<&str, Malformed> {
    let value = single(headers, CALL_ID, Field::CallId)?;
    let value = scan::sws(value).trim_end_matches([' ', '\t']);

    let mut words = value.splitn(2, '@');
    let valid =
        words.all(|word| !word.is_empty() && word.bytes().all(is_word));
    if valid { Ok(value) } else { Err(Malformed(Field::CallId)) }
}

/// `word` of RFC 3261 section 25.1, without the `@` that splits a Call-ID.
fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || b"-.!%*_+`'~()<>:\\\"/[]?{}".contains(&byte)
}

/// Returns the URI and tag of the From value.
pub(crate) fn from(headers: &HeaderMap) -> Result<Party<'_>, Malformed> {
    party(single(headers, FROM, Field::From)?, Field::From)
}

/// Returns the URI and tag of the To value.
pub(crate) fn to(headers: &HeaderMap) -> Result<Party<'_>, Malformed> {
    party(single(headers, TO, Field::To)?, Field::To)
}

fn party(value: &str, field: Field) -> Result<Party<'_>, Malformed> {
    let mut list = addresses(value);
    let (Some(Ok(address)), None) = (list.next(), list.next()) else {
        return Err(Malformed(field));
    };

    // A tag is a token (RFC 3261 section 25.1). A valueless or repeated tag
    // leaves the dialog identity ambiguous, so it is malformed.
    let tag = match address.parameter("tag") {
        Ok(None) => None,
        Ok(Some(Some(tag))) if scan::token(tag) == Some((tag, "")) => {
            Some(tag)
        }
        _ => return Err(Malformed(field)),
    };
    Ok(Party { uri: address.uri, tag })
}

/// Returns the URI of the one Contact address, or `None` without Contact.
///
/// RFC 3261 section 8.1.1.8 allows exactly one URI in the Contact of a
/// request that forms a dialog, and a target refresh carries one too. Rows
/// and comma-separated values count alike, since RFC 3261 section 7.3.1 makes
/// them the same list.
pub(crate) fn contact(headers: &HeaderMap) -> Result<Option<&str>, Malformed> {
    let mut found = None;

    for value in headers.get_all(CONTACT) {
        for address in addresses(value.as_str()) {
            let address = address.map_err(|_| Malformed(Field::Contact))?;
            if found.replace(address.uri).is_some() {
                return Err(Malformed(Field::Contact));
            }
        }
    }

    Ok(found)
}

/// Returns the sequence number and method of the CSeq value.
///
/// The number is read as a `u32`, the range RFC 3261 section 8.1.1.5 gives
/// it. The method is returned as written. RFC 3261 section 20.16 makes the
/// method of a CSeq case-sensitive, so it is compared exactly.
pub(crate) fn cseq(headers: &HeaderMap) -> Result<(u32, &str), Malformed> {
    let malformed = Malformed(Field::CSeq);
    let rest = scan::sws(single(headers, CSEQ, Field::CSeq)?);
    let (digits, rest) = scan::digits(rest).ok_or(malformed)?;
    // The digits have no sign, so this only fails above `u32::MAX`.
    let number = digits.parse().map_err(|_| malformed)?;
    let rest = scan::lws(rest).ok_or(malformed)?;
    let (method, rest) = scan::token(rest).ok_or(malformed)?;

    if scan::sws(rest).is_empty() {
        Ok((number, method))
    } else {
        Err(malformed)
    }
}

/// Returns the seconds of the Expires value, if there is one.
///
/// RFC 3261 section 20.19 makes it a number of seconds from 0 to 2^32 - 1,
/// `delta-seconds` in section 25.1. A larger number is malformed rather than
/// cut down, since the value is not one an RFC 3261 element writes.
pub(crate) fn expires(headers: &HeaderMap) -> Result<Option<u32>, Malformed> {
    let malformed = Malformed(Field::Expires);
    let mut rows = headers.get_all(EXPIRES);
    let Some(value) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(malformed);
    }

    let rest = scan::sws(value.as_str());
    let (digits, rest) = scan::digits(rest).ok_or(malformed)?;
    if !scan::sws(rest).is_empty() {
        return Err(malformed);
    }
    digits.parse().map(Some).map_err(|_| malformed)
}

/// Says whether the request asks for SIPS on the way back to its sender: a
/// SIPS URI in the top Record-Route value, or in the Contact when there is
/// no Record-Route. RFC 3261 section 12.1.1 then requires a SIPS Contact in
/// the response. The Request-URI is the caller's to check.
pub(crate) fn sips_on_the_way_back(
    headers: &HeaderMap,
) -> Result<bool, Malformed> {
    let top = match headers.get(RECORD_ROUTE) {
        Some(value) => match addresses(value.as_str()).next() {
            Some(address) => {
                Some(address.map_err(|_| Malformed(Field::RecordRoute))?.uri)
            }
            None => None,
        },
        None => contact(headers)?,
    };
    Ok(top.is_some_and(is_sips))
}

/// Says whether a URI has the SIPS scheme, in any letter case.
pub(crate) fn is_sips(uri: &str) -> bool {
    uri.get(..5).is_some_and(|scheme| scheme.eq_ignore_ascii_case("sips:"))
}

/// Says whether the request requires any extension.
///
/// Each Require row is a comma-separated list of option tags, which are
/// tokens (RFC 3261 sections 20.32 and 25.1). The tags themselves do not
/// matter yet, since this user agent supports none of them.
pub(crate) fn requires_extension(
    headers: &HeaderMap,
) -> Result<bool, Malformed> {
    let malformed = Malformed(Field::Require);
    let mut any = false;

    for value in headers.get_all(REQUIRE) {
        let mut rest = scan::sws(value.as_str());
        loop {
            let (_, after) = scan::token(rest).ok_or(malformed)?;
            any = true;
            rest = scan::sws(after);
            match rest.strip_prefix(',') {
                Some(after) => rest = scan::sws(after),
                None if rest.is_empty() => break,
                None => return Err(malformed),
            }
        }
    }

    Ok(any)
}

#[cfg(test)]
mod tests {
    use signa_core::HeaderValue;

    use super::*;

    fn headers(rows: &[(HeaderName, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in rows {
            headers.append(name.clone(), HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn call_ids_are_kept_as_written() {
        for (value, expected) in [
            (
                "a84b4c76e66710@pc33.atlanta.com",
                "a84b4c76e66710@pc33.atlanta.com",
            ),
            ("  f81d4fae-7dec-11d0 ", "f81d4fae-7dec-11d0"),
            ("CaseMatters", "CaseMatters"),
        ] {
            let headers = headers(&[(CALL_ID, value)]);
            assert_eq!(call_id(&headers), Ok(expected), "{value}");
        }

        for value in ["", "two words", "a@b@c", "@host", "a,b"] {
            let headers = headers(&[(CALL_ID, value)]);
            assert!(call_id(&headers).is_err(), "{value}");
        }

        let twice = headers(&[(CALL_ID, "a"), (CALL_ID, "a")]);
        assert_eq!(call_id(&twice), Err(Malformed(Field::CallId)));
    }

    #[test]
    fn parties_carry_their_uri_and_tag() {
        let headers = headers(&[
            (FROM, "\"Alice, A.\" <sip:alice@atlanta.com>;tag=1928301774"),
            (TO, "sip:bob@biloxi.com"),
        ]);

        assert_eq!(
            from(&headers),
            Ok(Party {
                uri: "sip:alice@atlanta.com",
                tag: Some("1928301774")
            }),
        );
        assert_eq!(
            to(&headers),
            Ok(Party { uri: "sip:bob@biloxi.com", tag: None })
        );
    }

    #[test]
    fn a_tag_inside_the_uri_is_not_the_header_tag() {
        let headers = headers(&[(TO, "<sip:bob@biloxi.com;tag=uri>")]);

        assert_eq!(to(&headers).unwrap().tag, None);
    }

    #[test]
    fn an_ambiguous_tag_is_malformed() {
        for value in [
            "<sip:bob@biloxi.com>;tag=a;tag=b",
            "<sip:bob@biloxi.com>;tag",
            "<sip:bob@biloxi.com>;tag=\"quoted\"",
            "<sip:bob@biloxi.com>, <sip:carol@chicago.com>",
        ] {
            let headers = headers(&[(TO, value)]);
            assert_eq!(to(&headers), Err(Malformed(Field::To)), "{value}");
        }
    }

    #[test]
    fn contact_holds_one_uri() {
        let none = headers(&[]);
        assert_eq!(contact(&none), Ok(None));

        let one = headers(&[(
            CONTACT,
            "\"Bob\" <sip:bob@192.0.2.4;transport=tcp>;expires=60",
        )]);
        assert_eq!(contact(&one), Ok(Some("sip:bob@192.0.2.4;transport=tcp")));

        for rows in [
            &[(CONTACT, "<sip:a@192.0.2.4>, <sip:b@192.0.2.4>")][..],
            &[(CONTACT, "<sip:a@192.0.2.4>"), (CONTACT, "<sip:b@192.0.2.4>")],
            &[(CONTACT, "<sip:a@192.0.2.4")],
        ] {
            assert_eq!(
                contact(&headers(rows)),
                Err(Malformed(Field::Contact))
            );
        }
    }

    #[test]
    fn cseq_has_a_number_and_a_method() {
        let invite = headers(&[(CSEQ, "4711 INVITE")]);
        assert_eq!(cseq(&invite), Ok((4711, "INVITE")));

        for value in
            ["INVITE", "4711", "-1 INVITE", "4294967296 INVITE", "1 INVITE x"]
        {
            let headers = headers(&[(CSEQ, value)]);
            assert!(cseq(&headers).is_err(), "{value}");
        }
    }

    #[test]
    fn require_lists_option_tags() {
        assert_eq!(requires_extension(&headers(&[])), Ok(false));
        for rows in [
            &[(REQUIRE, "100rel")][..],
            &[(REQUIRE, " 100rel , timer ")],
            &[(REQUIRE, "100rel"), (REQUIRE, "timer")],
        ] {
            assert_eq!(
                requires_extension(&headers(rows)),
                Ok(true),
                "{rows:?}"
            );
        }

        for value in ["", "100rel,", ",100rel", "100rel timer", "a;b"] {
            assert_eq!(
                requires_extension(&headers(&[(REQUIRE, value)])),
                Err(Malformed(Field::Require)),
                "{value}",
            );
        }
    }

    #[test]
    fn expires_is_a_number_of_seconds() {
        assert_eq!(expires(&headers(&[])), Ok(None));
        for (value, seconds) in
            [("0", 0), (" 180 ", 180), ("4294967295", u32::MAX)]
        {
            assert_eq!(
                expires(&headers(&[(EXPIRES, value)])),
                Ok(Some(seconds)),
                "{value}",
            );
        }

        for rows in [
            &[(EXPIRES, "4294967296")][..],
            &[(EXPIRES, "-1")],
            &[(EXPIRES, "10 s")],
            &[(EXPIRES, "")],
            &[(EXPIRES, "10"), (EXPIRES, "20")],
        ] {
            assert_eq!(
                expires(&headers(rows)),
                Err(Malformed(Field::Expires)),
                "{rows:?}",
            );
        }
    }

    #[test]
    fn sips_on_the_way_back_reads_the_top_record_route_or_the_contact() {
        let cases = [
            (&[(CONTACT, "<sips:a@192.0.2.1>")][..], true),
            (&[(CONTACT, "<sip:a@192.0.2.1>")], false),
            (
                &[
                    (RECORD_ROUTE, "<sips:p1.example.com;lr>, <sip:p2;lr>"),
                    (CONTACT, "<sip:a@192.0.2.1>"),
                ],
                true,
            ),
            (
                &[
                    (RECORD_ROUTE, "<sip:p1.example.com;lr>"),
                    (RECORD_ROUTE, "<sips:p2.example.com;lr>"),
                    (CONTACT, "<sips:a@192.0.2.1>"),
                ],
                false,
            ),
            (&[], false),
        ];

        for (rows, sips) in cases {
            assert_eq!(
                sips_on_the_way_back(&headers(rows)),
                Ok(sips),
                "{rows:?}"
            );
        }
    }
}
