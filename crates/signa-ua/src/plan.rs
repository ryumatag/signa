/*!
The initial INVITE a UAC sends, as the application plans it.

The application says where the INVITE goes, who sends it, what it offers and
which headers of its own it carries. The UA writes the rest, which is what
identifies the dialogs the INVITE may form and what RFC 3261 asks of every
INVITE:

* the From tag, the Call-ID and the first CSeq number, which it picks itself
  (RFC 3261 sections 8.1.1.3 to 8.1.1.5),
* its Contact (section 8.1.1.8), a Max-Forwards of 70 (section 8.1.1.6) and
  an Allow of the methods it takes (section 13.2.1).

There is no Supported. This UA supports no extension, and an INVITE without
Supported says the same. A plan always carries an offer, since the UA cannot
supply the answer an ACK would owe for an offer in the 2xx.
*/

use bytes::Bytes;
use signa_core::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Uri,
    message::header::{
        ALLOW, CALL_ID, CONTACT, CONTENT_LENGTH, CONTENT_TYPE, CSEQ, FROM,
        MAX_FORWARDS, PROXY_REQUIRE, RECORD_ROUTE, REQUIRE, ROUTE, SUPPORTED,
        TO, Tag, VIA,
    },
};

use crate::negotiation::Description;

/// The methods this UA takes, as an Allow value.
///
/// TODO: Add CANCEL and BYE once the UA answers them.
pub(crate) const ALLOWED: &str = "INVITE, ACK";

/// The headers the UA writes itself. A plan that sets one of them is
/// refused. Require and Proxy-Require are among them, since they would ask
/// for an extension this UA does not have.
const OWNED: [HeaderName; 15] = [
    VIA,
    FROM,
    TO,
    CALL_ID,
    CSEQ,
    CONTACT,
    MAX_FORWARDS,
    ROUTE,
    RECORD_ROUTE,
    CONTENT_TYPE,
    CONTENT_LENGTH,
    ALLOW,
    SUPPORTED,
    REQUIRE,
    PROXY_REQUIRE,
];

/// An initial INVITE to send, with the offer it carries.
///
/// The UA picks the From tag, the Call-ID and the first CSeq number, and adds
/// its Contact, Max-Forwards and Allow. Everything else comes from the plan.
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub struct InvitePlan {
    request_uri: Uri,
    from: Uri,
    to: Option<Uri>,
    display_name: Option<Box<str>>,
    routes: Vec<Uri>,
    headers: HeaderMap,
    offer: Description,
}

// Only the runtime makes a plan.
#[cfg_attr(not(feature = "tokio"), allow(dead_code, unreachable_pub))]
impl InvitePlan {
    /// Plans an INVITE to `request_uri` from `from`, the address of record of
    /// the caller, with `offer` as its body. The To is `request_uri` unless
    /// [`InvitePlan::to`] sets another (RFC 3261 section 8.1.1.2).
    pub fn new(request_uri: Uri, from: Uri, offer: Description) -> InvitePlan {
        InvitePlan {
            request_uri,
            from,
            to: None,
            display_name: None,
            routes: Vec::new(),
            headers: HeaderMap::new(),
            offer,
        }
    }

    /// Sets the URI of the To.
    pub fn to(mut self, to: Uri) -> InvitePlan {
        self.to = Some(to);
        self
    }

    /// Sets the display name of the From, which the UA quotes.
    pub fn display_name(mut self, name: &str) -> InvitePlan {
        self.display_name = Some(name.into());
        self
    }

    /// Adds `route` to the end of the INVITE's route set, such as an outbound
    /// proxy (RFC 3261 section 8.1.1.1). The UA sends the INVITE to the first
    /// route, or to the Request-URI without one.
    pub fn route(mut self, route: Uri) -> InvitePlan {
        self.routes.push(route);
        self
    }

    /// Adds a header of the application's own, such as a User-Agent.
    pub fn header(
        mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> InvitePlan {
        self.headers.append(name, value);
        self
    }

    /// Says whether the UA can send the plan: each URI is a SIP or SIPS URI,
    /// no header is one the UA writes, the offer has a body, and the display
    /// name can be quoted.
    pub(crate) fn is_valid(&self) -> bool {
        let uris = [&self.request_uri, &self.from]
            .into_iter()
            .chain(&self.to)
            .chain(&self.routes);
        let sip = |uri: &Uri| matches!(uri.sip(), Ok(Some(_)));

        uris.into_iter().all(sip)
            && self.headers.iter().all(|(name, _)| !OWNED.contains(name))
            && !self.offer.body().is_empty()
            && self.display_name.as_deref().is_none_or(quotable)
    }

    /// Builds the INVITE, with `identity` and `contact` as the UA's parts.
    /// Returns `None` for a plan that [`InvitePlan::is_valid`] refuses.
    pub(crate) fn build(
        &self,
        identity: &Identity,
        contact: &str,
    ) -> Option<Request<Bytes>> {
        if !self.is_valid() {
            return None;
        }

        let to = self.to.as_ref().unwrap_or(&self.request_uri);
        let from = match &self.display_name {
            Some(name) => {
                format!("{} <{}>;tag={}", quote(name), self.from, identity.tag)
            }
            None => format!("<{}>;tag={}", self.from, identity.tag),
        };

        let mut request = Request::builder()
            .method(Method::INVITE)
            .uri(self.request_uri.clone())
            .header(TO, format!("<{to}>").as_str())
            .header(FROM, from.as_str())
            .header(CALL_ID, identity.call_id.as_ref())
            .header(CSEQ, format!("{} INVITE", identity.cseq).as_str())
            .header(MAX_FORWARDS, "70")
            .header(CONTACT, format!("<{contact}>").as_str());
        for route in &self.routes {
            request = request.header(ROUTE, format!("<{route}>").as_str());
        }
        request = request.header(ALLOW, ALLOWED);
        for (name, value) in self.headers.iter() {
            request = request.header(name.clone(), value.clone());
        }

        request
            .header(CONTENT_TYPE, self.offer.content_type().clone())
            .body(self.offer.body().clone())
            .ok()
    }
}

/// What the UA picks for an INVITE it sends: the Call-ID, the From tag and
/// the first CSeq number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) call_id: Box<str>,
    pub(crate) tag: Tag,
    pub(crate) cseq: u32,
}

/// Says whether a display name fits a quoted string (RFC 3261 section
/// 25.1). A quoted pair cannot carry a line break, and the UA refuses every
/// other control character too, rather than escape what no display name
/// needs.
fn quotable(name: &str) -> bool {
    !name.chars().any(char::is_control)
}

/// Quotes a display name, escaping its quotes and backslashes.
fn quote(name: &str) -> String {
    let mut quoted = String::with_capacity(name.len() + 2);
    quoted.push('"');
    for c in name.chars() {
        if matches!(c, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use signa_core::message::header::USER_AGENT;

    use super::*;

    fn uri(text: &str) -> Uri {
        text.parse().unwrap()
    }

    fn plan() -> InvitePlan {
        InvitePlan::new(
            uri("sip:bob@biloxi.example.com"),
            uri("sip:alice@atlanta.example.com"),
            Description::new(
                HeaderValue::from_static("application/sdp"),
                Bytes::from_static(b"v=0\r\n"),
            ),
        )
    }

    fn identity() -> Identity {
        Identity {
            call_id: "a84b4c76e66710".into(),
            tag: "1928301774".parse().unwrap(),
            cseq: 314159,
        }
    }

    #[test]
    fn the_ua_writes_what_identifies_the_dialog() {
        let request = plan()
            .display_name("Alice \"A.\"")
            .route(uri("sip:p1.example.com;lr"))
            .route(uri("sip:p2.example.com;lr"))
            .header(USER_AGENT, HeaderValue::from_static("test"))
            .build(&identity(), "sip:alice@192.0.2.1")
            .unwrap();
        let headers = request.headers();
        let rows = |name| {
            headers
                .get_all(name)
                .map(|value| value.as_str())
                .collect::<Vec<_>>()
        };

        assert_eq!(request.method(), &Method::INVITE);
        assert_eq!(request.uri().as_str(), "sip:bob@biloxi.example.com");
        assert_eq!(rows(TO), ["<sip:bob@biloxi.example.com>"]);
        assert_eq!(
            rows(FROM),
            [
                r#""Alice \"A.\"" <sip:alice@atlanta.example.com>;tag=1928301774"#
            ],
        );
        assert_eq!(rows(CALL_ID), ["a84b4c76e66710"]);
        assert_eq!(rows(CSEQ), ["314159 INVITE"]);
        assert_eq!(rows(MAX_FORWARDS), ["70"]);
        assert_eq!(rows(CONTACT), ["<sip:alice@192.0.2.1>"]);
        assert_eq!(
            rows(ROUTE),
            ["<sip:p1.example.com;lr>", "<sip:p2.example.com;lr>"],
        );
        assert_eq!(rows(ALLOW), [ALLOWED]);
        assert_eq!(rows(USER_AGENT), ["test"]);
        assert_eq!(rows(CONTENT_TYPE), ["application/sdp"]);
        assert!(rows(SUPPORTED).is_empty());
        assert_eq!(request.body().as_ref(), b"v=0\r\n");
    }

    #[test]
    fn the_to_can_differ_from_the_request_uri() {
        let request = plan()
            .to(uri("sip:bob@example.com"))
            .build(&identity(), "sip:alice@192.0.2.1")
            .unwrap();

        assert_eq!(
            request.headers().get(TO).unwrap(),
            "<sip:bob@example.com>"
        );
        assert_eq!(request.uri().as_str(), "sip:bob@biloxi.example.com");
    }

    #[test]
    fn what_the_ua_cannot_send_is_refused() {
        let empty = InvitePlan::new(
            uri("sip:bob@biloxi.example.com"),
            uri("sip:alice@atlanta.example.com"),
            Description::new(
                HeaderValue::from_static("application/sdp"),
                Bytes::new(),
            ),
        );
        let refused = [
            empty,
            plan().header(CALL_ID, HeaderValue::from_static("mine")),
            plan().header(REQUIRE, HeaderValue::from_static("100rel")),
            plan().route(uri("tel:+15551234567")),
            plan().to(uri("mailto:bob@example.com")),
            plan().display_name("Alice\r\nVia: x"),
        ];

        for plan in refused {
            assert!(!plan.is_valid(), "{plan:?}");
            assert!(plan.build(&identity(), "sip:a@192.0.2.1").is_none());
        }
        assert!(plan().is_valid());
    }
}
