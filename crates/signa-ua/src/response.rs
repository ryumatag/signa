/*!
The responses to an incoming INVITE, as the application plans them, and the
checks the UA makes of a plan before it takes it.

The rules a plan follows are in the documentation of [`RejectPlan`], which
has the most of them. Those of the headers apply to every plan. The bounds,
[`MAX_ROWS`] and [`MAX_BYTES`], and the status rules are my policy where the
RFC leaves the choice open, as their documentation says.
*/
// Only the runtime takes a plan, and without it nothing here is reachable.
#![cfg_attr(not(feature = "tokio"), allow(unreachable_pub, dead_code))]

use bytes::Bytes;
use signa_core::{
    HeaderValue, StatusCode, Uri,
    message::header::{
        ACCEPT, ACCEPT_ENCODING, ALERT_INFO, ALLOW, AUTHENTICATION_INFO,
        AUTHORIZATION, CALL_ID, CONTACT, CONTENT_DISPOSITION,
        CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, CSEQ, DATE,
        ERROR_INFO, EXPIRES, FROM, HeaderName, IN_REPLY_TO, MAX_FORWARDS,
        MIME_VERSION, MIN_EXPIRES, MIN_SE, ORGANIZATION, PRIORITY,
        PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, PROXY_REQUIRE, RACK,
        RECORD_ROUTE, REPLY_TO, REQUIRE, RETRY_AFTER, ROUTE, RSEQ, SERVER,
        SESSION_EXPIRES, SUBJECT, SUPPORTED, TIMESTAMP, TO, UNSUPPORTED,
        USER_AGENT, VIA, WWW_AUTHENTICATE,
    },
};

use crate::{
    negotiation::Description,
    routing::{Place, allowed_in},
};

/// The headers a response plan may not set: those the UA writes, those of
/// extensions it does not have, and those a status gets from a field of its
/// own. Max-Forwards, Route and the credentials are a request's.
const OWNED: [HeaderName; 29] = [
    VIA,
    FROM,
    TO,
    CALL_ID,
    CSEQ,
    CONTACT,
    RECORD_ROUTE,
    ROUTE,
    MAX_FORWARDS,
    CONTENT_TYPE,
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_LENGTH,
    ALLOW,
    ACCEPT,
    ACCEPT_ENCODING,
    SUPPORTED,
    REQUIRE,
    PROXY_REQUIRE,
    UNSUPPORTED,
    RSEQ,
    RACK,
    SESSION_EXPIRES,
    MIN_SE,
    AUTHORIZATION,
    PROXY_AUTHORIZATION,
    WWW_AUTHENTICATE,
    PROXY_AUTHENTICATE,
    RETRY_AFTER,
];

/// Headers of RFC 3261 that a response does not carry: those of a request
/// alone, and the Min-Expires of a 423, which the UA refuses (Table 2 of
/// RFC 3261 section 20).
const NOT_IN_RESPONSES: [HeaderName; 4] =
    [IN_REPLY_TO, PRIORITY, SUBJECT, MIN_EXPIRES];

/// Headers of RFC 3261 with a single value, which a response carries once.
const SINGLE: [HeaderName; 8] = [
    DATE,
    EXPIRES,
    MIME_VERSION,
    ORGANIZATION,
    REPLY_TO,
    SERVER,
    TIMESTAMP,
    USER_AGENT,
];

/// The most rows a plan adds to a response, its Contact and challenges
/// included. The UA's own rows come on top, and signa-core reads no more
/// than 100 rows in a message.
pub(crate) const MAX_ROWS: usize = 32;

/// The most bytes the rows a plan adds may take together, counting each
/// row's name and value.
pub(crate) const MAX_BYTES: usize = 8 * 1024;

/// The statuses whose response may carry a Retry-After (Table 2 of RFC 3261
/// section 20).
const RETRY_AFTER_STATUSES: [u16; 8] =
    [404, 413, 480, 486, 500, 503, 600, 603];

/// The header rows a response gets from its plan, in order, which the UA
/// adds to those it writes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Fields(Vec<(HeaderName, HeaderValue)>);

impl Fields {
    fn push(&mut self, name: HeaderName, value: HeaderValue) {
        self.0.push((name, value));
    }

    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.0.iter().map(|(name, value)| (name, value))
    }

    /// Says whether a response with `status` can carry the rows: none is
    /// one the UA writes or a response does not carry, each goes where
    /// Table 2 of RFC 3261 section 20 lets it, and a header with a single
    /// value comes once.
    fn fit(&self, status: StatusCode) -> bool {
        let code = status.as_u16();
        let placed = |name: &HeaderName| {
            if *name == ALERT_INFO {
                code == 180
            } else if *name == ERROR_INFO {
                (300..=699).contains(&code)
            } else if *name == AUTHENTICATION_INFO {
                status.is_success()
            } else {
                !OWNED.contains(name) && !NOT_IN_RESPONSES.contains(name)
            }
        };
        let once = SINGLE.iter().all(|single| {
            self.0.iter().filter(|(name, _)| name == single).count() <= 1
        });

        once && self.0.iter().all(|(name, _)| placed(name))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// The bytes of the rows, each name and value.
    fn bytes(&self) -> usize {
        self.0
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum()
    }
}

/// Says whether `rows` rows of `bytes` bytes stay within [`MAX_ROWS`] and
/// [`MAX_BYTES`].
fn bounded(rows: usize, bytes: usize) -> bool {
    rows <= MAX_ROWS && bytes <= MAX_BYTES
}

/// Says whether `value` is a challenge (RFC 3261 section 25.1) a caller can
/// answer. A Digest challenge has a realm (section 22.4) and a nonce (RFC
/// 2617 section 3.2.1).
fn answerable(value: &HeaderValue) -> bool {
    let Ok(challenge) = siparse::value::challenge(value.as_str()) else {
        return false;
    };
    if !challenge.scheme.eq_ignore_ascii_case("Digest") {
        return true;
    }

    let has = |wanted: &str| {
        challenge
            .params
            .iter()
            .any(|param| param.name.eq_ignore_ascii_case(wanted))
    };
    has("realm") && has("nonce")
}

/// A provisional response, from 101 to 199, to an incoming INVITE.
///
/// The endpoint sends the 100 itself. A provisional response may carry a
/// preview of the answer to the INVITE's offer, for early media, which the
/// 2xx then has to repeat (RFC 3261 section 13.2.1). Its headers follow the
/// rules of every plan, which [`RejectPlan`] lists.
#[derive(Clone, Debug)]
pub struct ProvisionalPlan {
    status: StatusCode,
    preview: Option<Description>,
    headers: Fields,
}

impl ProvisionalPlan {
    /// Plans a provisional response with `status`.
    pub fn new(status: StatusCode) -> ProvisionalPlan {
        ProvisionalPlan { status, preview: None, headers: Fields::default() }
    }

    /// Has the response carry `answer`, the answer to the INVITE's offer,
    /// ahead of the 2xx.
    pub fn preview(mut self, answer: Description) -> ProvisionalPlan {
        self.preview = Some(answer);
        self
    }

    /// Adds a header of the application's own, such as the Alert-Info of a
    /// 180.
    pub fn header(
        mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> ProvisionalPlan {
        self.headers.push(name, value);
        self
    }

    /// Returns the status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn preview_ref(&self) -> Option<&Description> {
        self.preview.as_ref()
    }

    /// Says whether the UA can send the plan: a status from 101 to 199, a
    /// preview with a body, and no header the UA writes.
    pub(crate) fn is_valid(&self) -> bool {
        (101..=199).contains(&self.status.as_u16())
            && self
                .preview
                .as_ref()
                .is_none_or(|preview| !preview.body().is_empty())
            && self.headers.fit(self.status)
            && bounded(self.headers.len(), self.headers.bytes())
    }

    pub(crate) fn into_parts(
        self,
    ) -> (StatusCode, Option<Description>, Fields) {
        (self.status, self.preview, self.headers)
    }
}

impl From<StatusCode> for ProvisionalPlan {
    fn from(status: StatusCode) -> ProvisionalPlan {
        ProvisionalPlan::new(status)
    }
}

/// The 200 that accepts an incoming INVITE, with the answer to its offer, or
/// an offer of the application's when it had none. Its headers follow the
/// rules of every plan, which [`RejectPlan`] lists.
#[derive(Clone, Debug)]
pub struct AcceptPlan {
    answer: Description,
    headers: Fields,
}

impl AcceptPlan {
    /// Plans a 200 that carries `answer`.
    pub fn new(answer: Description) -> AcceptPlan {
        AcceptPlan { answer, headers: Fields::default() }
    }

    /// Adds a header of the application's own, such as a Server.
    pub fn header(
        mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> AcceptPlan {
        self.headers.push(name, value);
        self
    }

    /// Returns the answer, or the offer, the 200 carries.
    pub fn answer(&self) -> &Description {
        &self.answer
    }

    /// Says whether the UA can send the plan: an answer with a body, and no
    /// header the UA writes.
    pub(crate) fn is_valid(&self) -> bool {
        !self.answer.body().is_empty()
            && self.headers.fit(StatusCode::OK)
            && bounded(self.headers.len(), self.headers.bytes())
    }

    pub(crate) fn into_parts(self) -> (Description, Fields) {
        (self.answer, self.headers)
    }
}

impl From<Description> for AcceptPlan {
    fn from(answer: Description) -> AcceptPlan {
        AcceptPlan::new(answer)
    }
}

/// The final response, from 300 to 699, that rejects an incoming INVITE,
/// with what its status calls for.
///
/// The UA checks a plan when it is submitted, and hands one it refuses back
/// with the INVITE, with nothing sent.
///
/// # What a status calls for
///
/// Each comes from a field of its own, which goes only where Table 2 of RFC
/// 3261 section 20 lets it:
///
/// * A redirection's Contact, from [`RejectPlan::contact`], for a 3xx or a
///   485. A 300, 301 or 302 needs one at least, and a 305 exactly one
///   (section 21.3). Section 21.3.1 has a 300 list its choices as Contacts
///   only as a SHOULD, but no body type is defined for them, so I require
///   one.
/// * The challenge of a 401 in WWW-Authenticate and of a 407 in
///   Proxy-Authenticate (sections 21.4.2, 21.4.8 and 22.1), from
///   [`RejectPlan::www_authenticate`] and [`RejectPlan::proxy_authenticate`].
///   Either may carry the other's too.
/// * A Retry-After, from [`RejectPlan::retry_after`], for a 404, 413, 480,
///   486, 500, 503, 600 or 603.
///
/// The UA adds the Accept and Accept-Encoding of a 415 (section 21.4.13)
/// itself, from what it takes, so that an application cannot advertise what
/// the UA does not do. It refuses a 405, whose Allow would have to leave out
/// the INVITE that the UA takes (section 21.4.6), and a 420, 421, 422 or 423,
/// which carry headers of the UA's own or are not for an INVITE.
///
/// # Headers
///
/// These rules apply to every plan. The UA writes what identifies the
/// response, what the dialog and its capabilities say, and the Content
/// headers of the session description, and refuses a plan that sets any of
/// it: the Via, From, To, Call-ID, CSeq, Record-Route and Contact, the Allow,
/// Accept, Accept-Encoding, Supported, Require, Proxy-Require and
/// Unsupported, the headers of extensions it does not have, such as RSeq,
/// RAck, Session-Expires and Min-SE, and those of a field above.
///
/// A header of the application's own goes where Table 2 lets it: an
/// Alert-Info in a 180, an Error-Info in a 3xx to 6xx, an Authentication-Info
/// in a 2xx, and none that only a request carries, such as Subject or
/// Priority. A header with a single value, such as Server or Date, comes
/// once. Any other header, an extension's included, is the application's to
/// choose.
///
/// A plan adds 32 rows at most, of 8 KiB together, its fields included, so
/// that the response stays one a peer can read. signa-core reads no more
/// than 100 rows in a message, and the UA's own rows come on top.
#[derive(Clone, Debug)]
pub struct RejectPlan {
    status: StatusCode,
    contacts: Vec<Uri>,
    challenges: Vec<HeaderValue>,
    proxy_challenges: Vec<HeaderValue>,
    retry_after: Option<u32>,
    headers: Fields,
}

impl RejectPlan {
    /// Plans a rejection with `status`.
    pub fn new(status: StatusCode) -> RejectPlan {
        RejectPlan {
            status,
            contacts: Vec::new(),
            challenges: Vec::new(),
            proxy_challenges: Vec::new(),
            retry_after: None,
            headers: Fields::default(),
        }
    }

    /// Adds `uri` to the Contact of a redirection, where the caller may send
    /// the INVITE again (RFC 3261 section 21.3), or one of the choices of a
    /// 485 (section 21.4.23). It is a SIP or SIPS URI with what Table 1 of
    /// section 19.1.1 allows in a redirection, which leaves out `method` and
    /// `lr` and lets headers in. A URI of another scheme, such as `tel:`, is
    /// not taken, and the Contact carries no `q` or `expires` parameter.
    pub fn contact(mut self, uri: Uri) -> RejectPlan {
        self.contacts.push(uri);
        self
    }

    /// Adds a WWW-Authenticate challenge, for a 401 (RFC 3261 section 22.1),
    /// or a 407. The UA checks its syntax (section 25.1), and that a Digest
    /// challenge has a realm and a nonce, which a caller needs to answer it,
    /// and nothing more. Choosing and checking the credentials an INVITE sent
    /// again brings is the application's.
    pub fn www_authenticate(mut self, challenge: HeaderValue) -> RejectPlan {
        self.challenges.push(challenge);
        self
    }

    /// Adds a Proxy-Authenticate challenge, for a 407 (RFC 3261 section
    /// 22.3), or a 401, as [`RejectPlan::www_authenticate`] does.
    pub fn proxy_authenticate(mut self, challenge: HeaderValue) -> RejectPlan {
        self.proxy_challenges.push(challenge);
        self
    }

    /// Says when the caller may try again, in seconds (RFC 3261 section
    /// 20.33).
    pub fn retry_after(mut self, seconds: u32) -> RejectPlan {
        self.retry_after = Some(seconds);
        self
    }

    /// Adds a header of the application's own, such as a Reason or a
    /// Warning.
    pub fn header(
        mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> RejectPlan {
        self.headers.push(name, value);
        self
    }

    /// Returns the status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Says whether the UA can send the plan, as the module documentation
    /// says.
    pub(crate) fn is_valid(&self) -> bool {
        let status = self.status.as_u16();
        let redirection = (300..=399).contains(&status) || status == 485;
        let contacts = match status {
            305 => self.contacts.len() == 1,
            300..=302 => !self.contacts.is_empty(),
            _ => redirection || self.contacts.is_empty(),
        };
        let challenged = matches!(status, 401 | 407);
        let challenges = match status {
            401 => !self.challenges.is_empty(),
            407 => !self.proxy_challenges.is_empty(),
            _ => {
                self.challenges.is_empty() && self.proxy_challenges.is_empty()
            }
        };
        let retry = self.retry_after.is_none()
            || RETRY_AFTER_STATUSES.contains(&status);

        let rows = self.rows();

        (300..=699).contains(&status)
            && !matches!(status, 405 | 420..=423)
            && contacts
            && self
                .contacts
                .iter()
                .all(|uri| allowed_in(uri.as_str(), Place::Redirect))
            && challenges
            && (!challenged
                || self
                    .challenges
                    .iter()
                    .chain(&self.proxy_challenges)
                    .all(answerable))
            && retry
            && self.headers.fit(self.status)
            && bounded(rows.len(), rows.bytes())
    }

    /// Returns the status and the rows the plan adds.
    pub(crate) fn into_parts(self) -> (StatusCode, Fields) {
        (self.status, self.rows())
    }

    /// Returns the rows the plan adds: the Contact, the challenges and the
    /// Retry-After, then the application's headers.
    fn rows(&self) -> Fields {
        let mut fields = Fields::default();
        for uri in &self.contacts {
            let value = format!("<{}>", uri.as_str());
            let value = HeaderValue::from_shared(Bytes::from(value))
                .expect("a URI is a valid header value in brackets");
            fields.push(CONTACT, value);
        }
        for challenge in &self.challenges {
            fields.push(WWW_AUTHENTICATE, challenge.clone());
        }
        for challenge in &self.proxy_challenges {
            fields.push(PROXY_AUTHENTICATE, challenge.clone());
        }
        if let Some(seconds) = self.retry_after {
            let value =
                HeaderValue::from_shared(Bytes::from(seconds.to_string()))
                    .expect("digits are a valid header value");
            fields.push(RETRY_AFTER, value);
        }
        fields.0.extend(self.headers.0.iter().cloned());
        fields
    }
}

/// A plan of the status alone, which a 3xx that needs a Contact and a 401
/// or 407 cannot be.
impl From<StatusCode> for RejectPlan {
    fn from(status: StatusCode) -> RejectPlan {
        RejectPlan::new(status)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use signa_core::{
        HeaderValue, StatusCode,
        message::header::{
            ALERT_INFO, AUTHENTICATION_INFO, CONTACT, ERROR_INFO, HeaderName,
            RETRY_AFTER, SERVER, WARNING,
        },
    };

    use super::*;

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    fn value(text: &'static str) -> HeaderValue {
        HeaderValue::from_static(text)
    }

    const DIGEST: &str = "Digest realm=\"atlanta.example.com\", \
                          nonce=\"84a4cc6f3082121f32b42a2187831a9e\"";

    /// Each status that calls for a field gets it from the plan, and only
    /// the statuses Table 2 of RFC 3261 section 20 allows it in take it.
    #[test]
    fn a_rejection_carries_what_its_status_calls_for() {
        let target = || "sip:bob@192.0.2.4".parse().unwrap();
        let plan = |code| RejectPlan::new(status(code));

        for code in [300, 301, 302] {
            assert!(!plan(code).is_valid(), "{code} without a Contact");
            assert!(plan(code).contact(target()).is_valid(), "{code}");
        }
        assert!(plan(305).contact(target()).is_valid());
        assert!(!plan(305).contact(target()).contact(target()).is_valid());
        assert!(
            plan(380).is_valid() && plan(380).contact(target()).is_valid()
        );
        assert!(plan(485).contact(target()).is_valid());
        assert!(!plan(486).contact(target()).is_valid());

        assert!(!plan(401).is_valid());
        assert!(plan(401).www_authenticate(value(DIGEST)).is_valid());
        assert!(!plan(401).proxy_authenticate(value(DIGEST)).is_valid());
        assert!(!plan(407).www_authenticate(value(DIGEST)).is_valid());
        assert!(plan(407).proxy_authenticate(value(DIGEST)).is_valid());
        let both = plan(407).proxy_authenticate(value(DIGEST));
        assert!(both.www_authenticate(value(DIGEST)).is_valid());
        assert!(!plan(403).www_authenticate(value(DIGEST)).is_valid());
        assert!(!plan(401).www_authenticate(value("Digest")).is_valid());
        let realmless = value("Digest nonce=\"84a4cc6f\"");
        assert!(!plan(401).www_authenticate(realmless).is_valid());
        let other = value("Bearer realm=\"example.com\"");
        assert!(plan(401).www_authenticate(other).is_valid());

        for code in [404, 413, 480, 486, 500, 503, 600, 603] {
            assert!(plan(code).retry_after(30).is_valid(), "{code}");
        }
        assert!(!plan(488).retry_after(30).is_valid());

        for code in [405, 420, 421, 422, 423] {
            assert!(!plan(code).is_valid(), "{code}");
        }
        for code in [100, 200, 299] {
            assert!(!plan(code).is_valid(), "{code}");
        }
        assert!(plan(415).is_valid());
    }

    /// A redirection's Contact is a SIP or SIPS URI with what Table 1 of RFC
    /// 3261 section 19.1.1 allows there: headers, but no `method` or `lr`.
    #[test]
    fn a_redirection_takes_what_table_1_allows() {
        let redirect = |uri: &str| {
            RejectPlan::new(status(302)).contact(uri.parse().unwrap())
        };

        assert!(
            redirect("sip:bob@192.0.2.4;transport=tcp?Subject=x").is_valid()
        );
        assert!(
            redirect("sips:bob@biloxi.example.com;maddr=192.0.2.4").is_valid()
        );
        assert!(!redirect("sip:bob@192.0.2.4;method=INVITE").is_valid());
        assert!(!redirect("sip:bob@192.0.2.4;lr").is_valid());
        assert!(!redirect("tel:+15551234567").is_valid());
    }

    /// No plan sets a header the UA writes or a response does not carry,
    /// whatever its spelling, and the list below names every one of them.
    #[test]
    fn a_plan_sets_no_header_of_the_uas() {
        let refused = [
            "Via",
            "v",
            "VIA",
            "From",
            "f",
            "To",
            "t",
            "Call-ID",
            "i",
            "CSeq",
            "Contact",
            "m",
            "contact",
            "Record-Route",
            "Route",
            "Max-Forwards",
            "Content-Type",
            "c",
            "Content-Disposition",
            "Content-Encoding",
            "e",
            "Content-Length",
            "l",
            "Allow",
            "Accept",
            "Accept-Encoding",
            "Supported",
            "k",
            "Require",
            "Proxy-Require",
            "Unsupported",
            "RSeq",
            "RAck",
            "Session-Expires",
            "x",
            "Min-SE",
            "Authorization",
            "Proxy-Authorization",
            "WWW-Authenticate",
            "Proxy-Authenticate",
            "Retry-After",
            "In-Reply-To",
            "Priority",
            "Subject",
            "s",
            "Min-Expires",
        ];
        let names: Vec<HeaderName> =
            refused.iter().map(|name| name.parse().unwrap()).collect();
        for owned in OWNED.iter().chain(&NOT_IN_RESPONSES) {
            assert!(names.contains(owned), "{owned:?} untested");
        }
        for name in names {
            let reject =
                RejectPlan::new(status(486)).header(name.clone(), value("x"));
            let accept = AcceptPlan::new(description())
                .header(name.clone(), value("x"));
            let ringing = ProvisionalPlan::new(status(180))
                .header(name.clone(), value("x"));
            assert!(!reject.is_valid(), "{name:?}");
            assert!(!accept.is_valid(), "{name:?}");
            assert!(!ringing.is_valid(), "{name:?}");
        }

        let free =
            [WARNING, "Reason".parse().unwrap(), "X-Account".parse().unwrap()];
        for name in free {
            let reject =
                RejectPlan::new(status(486)).header(name.clone(), value("x"));
            assert!(reject.is_valid(), "{name:?}");
        }
    }

    /// A header of the application's goes where Table 2 of RFC 3261 section
    /// 20 lets it, and one with a single value comes once.
    #[test]
    fn a_header_goes_where_table_2_lets_it() {
        let alert = |code| {
            ProvisionalPlan::new(status(code))
                .header(ALERT_INFO, value("<http://example.com/ring.wav>"))
        };
        let info = |name: HeaderName| (name, value("<sip:info@192.0.2.4>"));

        assert!(alert(180).is_valid() && !alert(183).is_valid());
        let (name, row) = info(ALERT_INFO);
        assert!(!RejectPlan::new(status(486)).header(name, row).is_valid());
        let (name, row) = info(ERROR_INFO);
        assert!(RejectPlan::new(status(486)).header(name, row).is_valid());
        let (name, row) = info(ERROR_INFO);
        assert!(!AcceptPlan::new(description()).header(name, row).is_valid());
        let (name, row) = info(ERROR_INFO);
        assert!(
            !ProvisionalPlan::new(status(183)).header(name, row).is_valid()
        );
        let (name, row) = info(AUTHENTICATION_INFO);
        assert!(AcceptPlan::new(description()).header(name, row).is_valid());
        let (name, row) = info(AUTHENTICATION_INFO);
        assert!(!RejectPlan::new(status(486)).header(name, row).is_valid());

        let server = || value("pbx/1.0");
        let once = AcceptPlan::new(description()).header(SERVER, server());
        assert!(once.clone().is_valid());
        assert!(!once.header(SERVER, server()).is_valid());
    }

    /// A plan adds 32 rows at most, of 8 KiB together, its fields included.
    #[test]
    fn a_plan_stays_within_its_bounds() {
        let rows = |count: usize| {
            (0..count).fold(RejectPlan::new(status(486)), |plan, _| {
                plan.header(WARNING, value("399 pbx \"busy\""))
            })
        };
        assert!(rows(MAX_ROWS).is_valid());
        assert!(!rows(MAX_ROWS + 1).is_valid());

        let contacts =
            (0..MAX_ROWS).fold(RejectPlan::new(status(300)), |plan, n| {
                plan.contact(format!("sip:bob{n}@192.0.2.4").parse().unwrap())
            });
        assert!(contacts.clone().is_valid());
        let over = contacts.header(WARNING, value("399 pbx \"choose\""));
        assert!(!over.is_valid());

        let long =
            HeaderValue::from_shared(Bytes::from("x".repeat(MAX_BYTES)))
                .unwrap();
        let name: HeaderName = "X-Long".parse().unwrap();
        assert!(!RejectPlan::new(status(486)).header(name, long).is_valid());
    }

    /// The rows go out in a fixed order: the Contact, the challenges and the
    /// Retry-After, then the application's.
    #[test]
    fn a_rejection_lists_its_rows_in_order() {
        let (code, fields) = RejectPlan::new(status(302))
            .header(WARNING, value("399 example \"moved\""))
            .contact("sip:bob@192.0.2.4".parse().unwrap())
            .into_parts();
        let rows: Vec<_> = fields
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().to_owned()))
            .collect();

        assert_eq!(code, status(302));
        assert_eq!(
            rows,
            [
                (CONTACT, "<sip:bob@192.0.2.4>".to_owned()),
                (WARNING, "399 example \"moved\"".to_owned()),
            ],
        );
        let (_, fields) =
            RejectPlan::new(status(503)).retry_after(120).into_parts();
        let row = fields.iter().next().unwrap();
        assert_eq!((row.0, row.1.as_str()), (&RETRY_AFTER, "120"));
    }

    /// A provisional response has a status from 101 to 199, and a preview
    /// with a body.
    #[test]
    fn a_provisional_plan_is_from_101_to_199() {
        for code in [101, 180, 183, 199] {
            assert!(ProvisionalPlan::new(status(code)).is_valid(), "{code}");
        }
        for code in [100, 200, 486] {
            assert!(!ProvisionalPlan::new(status(code)).is_valid(), "{code}");
        }
        let empty = Description::new(value("application/sdp"), Bytes::new());
        assert!(
            !ProvisionalPlan::new(status(183))
                .preview(empty.clone())
                .is_valid()
        );
        assert!(!AcceptPlan::new(empty).is_valid());
    }

    fn description() -> Description {
        Description::new(
            value("application/sdp"),
            Bytes::from_static(b"v=0\r\n"),
        )
    }
}
