/*!
The headers a UA core reads, and only as far as it needs them.

signa-core keeps header values opaque, and its own address and CSeq readers
are private to it. This module reads From, To, Call-ID, CSeq, Contact, Route,
Record-Route, Require and the Content headers of a body. [`siparse::value`]
reads the productions of RFC 3261 section 25.1 that they are built from, and
[`siparse::scan`] the token lists that no production covers, so that the
grammar is followed rather than approximated by splitting at `,` or `;`.
What is left here is the meaning: which header takes which production, the
numbers, and what a UA does with a repeated parameter. It is not a general
typed-header API.

What it returns borrows the message. Values are returned as written, with
case, parameters and their order intact. A dialog keeps its own copy of what
it needs.
*/

use signa_core::{
    HeaderMap,
    message::header::{
        CALL_ID, CONTACT, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_TYPE,
        CSEQ, EXPIRES, FROM, HeaderName, RECORD_ROUTE, REQUIRE, TO,
    },
};
use siparse::{
    scan,
    value::{self, Param, Params},
};

pub(crate) use siparse::value::addresses;

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
    ContentType,
    ContentDisposition,
    ContentEncoding,
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
/// returned exactly as written.
pub(crate) fn call_id(headers: &HeaderMap) -> Result<&str, Malformed> {
    let value = single(headers, CALL_ID, Field::CallId)?;
    value::call_id(value).map_err(|_| Malformed(Field::CallId))
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
    let address = value::address(value).map_err(|_| Malformed(field))?;

    // A tag is a token (RFC 3261 section 25.1). A valueless or repeated tag
    // leaves the dialog identity ambiguous, so it is malformed.
    let tag = match parameter(address.params, "tag") {
        Ok(None) => None,
        Ok(Some(Param { value: Some(tag), .. }))
            if scan::token(tag) == Some((tag, "")) =>
        {
            Some(tag)
        }
        _ => return Err(Malformed(field)),
    };
    Ok(Party { uri: address.uri, tag })
}

/// A header parameter appears more than once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ambiguous;

/// Looks up a header parameter by name, ignoring ASCII case.
///
/// A name that appears twice is an error, since no occurrence is the right
/// one to pick.
fn parameter<'a>(
    params: Params<'a>,
    name: &str,
) -> Result<Option<Param<'a>>, Ambiguous> {
    let mut found = None;

    for param in params {
        if param.name.eq_ignore_ascii_case(name)
            && found.replace(param).is_some()
        {
            return Err(Ambiguous);
        }
    }

    Ok(found)
}

/// Returns the URI of the one Contact address, or `None` without Contact.
///
/// RFC 3261 section 8.1.1.8 allows exactly one URI in the Contact of a
/// request that forms a dialog, and a target refresh carries one too. Rows
/// and comma-separated values count alike, since RFC 3261 section 7.3.1 makes
/// them the same list. A Contact of `*` is malformed, since only a REGISTER
/// may carry one (RFC 3261 section 10.2.2), and [`addresses`] rejects it.
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
    let cseq = value::cseq(single(headers, CSEQ, Field::CSeq)?)
        .map_err(|_| malformed)?;
    // The digits have no sign, so this only fails above `u32::MAX`.
    let number = cseq.number.parse().map_err(|_| malformed)?;
    Ok((number, cseq.method))
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
        Some(value) => addresses(value.as_str())
            .next()
            .transpose()
            .map_err(|_| Malformed(Field::RecordRoute))?
            .map(|address| address.uri),
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

/// The type and subtype of a Content-Type, as written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MediaType<'a> {
    pub(crate) kind: &'a str,
    pub(crate) subtype: &'a str,
}

impl MediaType<'_> {
    /// Says whether this is `kind/subtype`. Both are compared without
    /// regard to case (RFC 3261 section 7.3.1).
    pub(crate) fn is(&self, kind: &str, subtype: &str) -> bool {
        self.kind.eq_ignore_ascii_case(kind)
            && self.subtype.eq_ignore_ascii_case(subtype)
    }
}

/// Returns the media type of the Content-Type, or `None` without one.
///
/// `media-type` of RFC 3261 section 25.1 is a type, a slash and a subtype,
/// all tokens, then parameters, which are checked and left alone.
pub(crate) fn content_type(
    headers: &HeaderMap,
) -> Result<Option<MediaType<'_>>, Malformed> {
    if headers.get(CONTENT_TYPE).is_none() {
        return Ok(None);
    }

    let value = single(headers, CONTENT_TYPE, Field::ContentType)?;
    media_type(value).map(Some)
}

/// Reads a `media-type` value, as [`content_type`] does.
pub(crate) fn media_type(value: &str) -> Result<MediaType<'_>, Malformed> {
    let malformed = Malformed(Field::ContentType);
    let (kind, rest) = scan::token(scan::sws(value)).ok_or(malformed)?;
    let rest = scan::separator(rest, '/').ok_or(malformed)?;
    let (subtype, rest) = scan::token(rest).ok_or(malformed)?;
    parameters(rest).ok_or(malformed)?;
    Ok(MediaType { kind, subtype })
}

/// Returns the disposition type of the Content-Disposition, such as
/// `session`, or `None` without one.
///
/// `Content-Disposition` of RFC 3261 section 20.11 is a token and then
/// parameters. The `handling` parameter is not read. Whether a body that is
/// not a session description is required or optional only matters to whoever
/// handles that body, which is not the UA.
pub(crate) fn content_disposition(
    headers: &HeaderMap,
) -> Result<Option<&str>, Malformed> {
    let malformed = Malformed(Field::ContentDisposition);
    if headers.get(CONTENT_DISPOSITION).is_none() {
        return Ok(None);
    }

    let value =
        single(headers, CONTENT_DISPOSITION, Field::ContentDisposition)?;
    let (kind, rest) = scan::token(scan::sws(value)).ok_or(malformed)?;
    parameters(rest).ok_or(malformed)?;
    Ok(Some(kind))
}

/// Says whether the body has a content coding other than `identity`, which
/// would have to be undone before the body means anything (RFC 3261 section
/// 20.12). Each Content-Encoding row is a list of tokens.
pub(crate) fn encoded(headers: &HeaderMap) -> Result<bool, Malformed> {
    let malformed = Malformed(Field::ContentEncoding);
    let mut any = false;

    for value in headers.get_all(CONTENT_ENCODING) {
        let mut rest = scan::sws(value.as_str());
        loop {
            let (coding, after) = scan::token(rest).ok_or(malformed)?;
            any |= !coding.eq_ignore_ascii_case("identity");
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

/// Checks `*(SEMI generic-param)` to the end of the value.
///
/// A Content-Type's `m-parameter` is narrower, a token and a value that is
/// a token or a quoted string. I check it as a `generic-param` all the same,
/// since the UA reads none of these parameters.
fn parameters(rest: &str) -> Option<()> {
    let (_, rest) = value::params(rest).ok()?;
    scan::sws(rest).is_empty().then_some(())
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
            // A value that ends in a fold, which a header value keeps.
            ("abc\r\n ", "abc"),
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
    fn a_repeated_parameter_is_ambiguous() {
        let address = value::address("<sip:bob@biloxi.com>;x=1;X=2").unwrap();

        assert_eq!(parameter(address.params, "x"), Err(Ambiguous));
        assert_eq!(parameter(address.params, "y"), Ok(None));
    }

    #[test]
    fn addresses_follow_rfc_3261_strictly() {
        for value in [
            // An unquoted display name is `*(token LWS)`, so whitespace has
            // to come before the `<`.
            "Bob<sip:bob@biloxi.com>",
            // Nothing sits between the angle brackets and the URI.
            "<sip:bob@biloxi.com >",
            // Every `addr-spec` starts with a scheme.
            "bob@biloxi.com",
            // A URI keeps to the URI characters of RFC 3261 section 25.1.
            "<sip:b\u{e9}b@biloxi.com>",
        ] {
            assert_eq!(
                from(&headers(&[(FROM, value)])),
                Err(Malformed(Field::From)),
                "{value}",
            );
            assert_eq!(
                contact(&headers(&[(CONTACT, value)])),
                Err(Malformed(Field::Contact)),
                "{value}",
            );
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
            &[(CONTACT, "*")],
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
    #[test]
    fn content_type_has_a_type_and_a_subtype() {
        assert_eq!(content_type(&headers(&[])), Ok(None));
        let sdp =
            headers(&[(CONTENT_TYPE, " Application/SDP ; charset=utf-8")]);
        let media = content_type(&sdp).unwrap().unwrap();
        assert_eq!(media, MediaType { kind: "Application", subtype: "SDP" });
        assert!(media.is("application", "sdp"));

        for value in ["application", "application/", "/sdp", "a/b c", "a/b;"] {
            assert_eq!(
                content_type(&headers(&[(CONTENT_TYPE, value)])),
                Err(Malformed(Field::ContentType)),
                "{value}",
            );
        }
        let twice = headers(&[(CONTENT_TYPE, "a/b"), (CONTENT_TYPE, "a/b")]);
        assert!(content_type(&twice).is_err());
    }

    #[test]
    fn content_disposition_has_a_type_and_parameters() {
        assert_eq!(content_disposition(&headers(&[])), Ok(None));
        for (value, kind) in [
            ("session", "session"),
            ("render;handling=optional", "render"),
            ("icon ; x=\"a;b\"", "icon"),
        ] {
            assert_eq!(
                content_disposition(&headers(&[(CONTENT_DISPOSITION, value)])),
                Ok(Some(kind)),
                "{value}",
            );
        }

        for value in ["", ";handling=optional", "session handling", "a;b=\""] {
            assert_eq!(
                content_disposition(&headers(&[(CONTENT_DISPOSITION, value)])),
                Err(Malformed(Field::ContentDisposition)),
                "{value}",
            );
        }
    }

    #[test]
    fn only_identity_leaves_a_body_unencoded() {
        assert_eq!(encoded(&headers(&[])), Ok(false));
        assert_eq!(
            encoded(&headers(&[(CONTENT_ENCODING, "Identity")])),
            Ok(false)
        );
        assert_eq!(
            encoded(&headers(&[(CONTENT_ENCODING, "identity, gzip")])),
            Ok(true)
        );
        assert!(
            encoded(&headers(&[(CONTENT_ENCODING, "gzip deflate")])).is_err()
        );
    }
}
