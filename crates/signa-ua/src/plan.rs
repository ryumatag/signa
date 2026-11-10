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
        ALLOW, AUTHORIZATION, CALL_ID, CONTACT, CONTENT_LENGTH, CONTENT_TYPE,
        CSEQ, FROM, MAX_FORWARDS, PROXY_AUTHORIZATION, PROXY_REQUIRE,
        RECORD_ROUTE, REQUIRE, ROUTE, SUPPORTED, TO, Tag, VIA,
    },
};

use crate::{
    negotiation::Description,
    routing::{
        Place, RemoteTarget, RouteSet, allowed_in, party_uri, request_target,
    },
};

/// The methods this UA takes, as an Allow value.
///
/// TODO: Add CANCEL and BYE once the UA answers them.
pub(crate) const ALLOWED: &str = "INVITE, ACK, OPTIONS";

/// The headers the UA writes itself. A plan that sets one of them is
/// refused. Require and Proxy-Require are among them, since they would ask
/// for an extension this UA does not have. So are Authorization and
/// Proxy-Authorization, since the ACK of a 2xx has to carry the INVITE's
/// credentials (RFC 3261 section 13.2.2.4), and the UA builds that ACK from
/// the dialog without them.
///
/// TODO: Take credentials, and copy them into the ACK, once the UA answers
/// a challenge.
const OWNED: [HeaderName; 17] = [
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
    AUTHORIZATION,
    PROXY_AUTHORIZATION,
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
    ///
    /// A first route without `lr` is a strict router, which takes the request
    /// with itself as the Request-URI. The UA builds the INVITE as RFC 3261
    /// section 12.2.1.1 builds a request in a dialog then, with the
    /// Request-URI last in Route, as section 8.1.1.1 asks.
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

    /// Says whether the UA can send the plan: each URI is a SIP or SIPS URI
    /// with only what Table 1 of RFC 3261 section 19.1.1 allows where it goes,
    /// no header is one the UA writes, the offer has a body, and the display
    /// name can be quoted.
    pub(crate) fn is_valid(&self) -> bool {
        let fits = |uri: &Uri, place| allowed_in(uri.as_str(), place);
        let parties = [&self.from]
            .into_iter()
            .chain(&self.to)
            .all(|uri| fits(uri, Place::Party));

        fits(&self.request_uri, Place::RequestUri)
            && parties
            && self.routes.iter().all(|uri| fits(uri, Place::Dialog))
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
    ) -> Option<PlannedInvite> {
        if !self.is_valid() {
            return None;
        }

        // A To taken from the Request-URI leaves out what a To may not have,
        // such as the port.
        let to = match &self.to {
            Some(to) => to.as_str().to_owned(),
            None => party_uri(self.request_uri.as_str()),
        };
        let routes =
            RouteSet::from_uris(self.routes.iter().map(Uri::as_str)).ok()?;
        let target = RemoteTarget::new(self.request_uri.as_str()).ok()?;
        let target = request_target(&routes, &target, false);
        let from = match &self.display_name {
            Some(name) => {
                format!("{} <{}>;tag={}", quote(name), self.from, identity.tag)
            }
            None => format!("<{}>;tag={}", self.from, identity.tag),
        };

        let mut request = Request::builder()
            .method(Method::INVITE)
            .uri(target.request_uri.as_str())
            .header(TO, format!("<{to}>").as_str())
            .header(FROM, from.as_str())
            .header(CALL_ID, identity.call_id.as_ref())
            .header(CSEQ, format!("{} INVITE", identity.cseq).as_str())
            .header(MAX_FORWARDS, "70")
            .header(CONTACT, format!("<{contact}>").as_str());
        for route in &target.route {
            request = request.header(ROUTE, format!("<{route}>").as_str());
        }
        request = request.header(ALLOW, ALLOWED);
        for (name, value) in self.headers.iter() {
            request = request.header(name.clone(), value.clone());
        }

        let request = request
            .header(CONTENT_TYPE, self.offer.content_type().clone())
            .body(self.offer.body().clone())
            .ok()?;
        Some(PlannedInvite {
            request,
            next_hop: target.next_hop,
            secure: target.secure,
        })
    }
}

/// An INVITE built from a plan, and where its first hop goes.
///
/// The hop comes from the route set, as RFC 3261 section 8.1.2 picks it, and
/// goes with the request so that nothing reads it back from the headers. Past
/// a strict router, section 12.2.1.1 puts the router in the Request-URI and
/// the rest of the route set in Route, and the top Route value may then be a
/// loose router that is not the first hop. The SIPS requirement is likewise
/// that of the planned target and routes, which the Request-URI may no longer
/// show.
#[derive(Debug)]
pub(crate) struct PlannedInvite {
    pub(crate) request: Request<Bytes>,
    /// The URI to resolve for the first hop.
    pub(crate) next_hop: Box<str>,
    /// Whether the first hop must be secured.
    pub(crate) secure: bool,
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
            .unwrap()
            .request;
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
            .unwrap()
            .request;

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
            plan().header(AUTHORIZATION, HeaderValue::from_static("Digest x")),
            plan().header(PROXY_AUTHORIZATION, HeaderValue::from_static("x")),
            // What Table 1 of RFC 3261 section 19.1.1 does not allow.
            plan().to(uri("sip:bob@example.com:5070")),
            plan().to(uri("sip:bob@example.com;transport=tcp")),
            plan().to(uri("sip:bob@example.com?Subject=x")),
            plan().route(uri("sip:p1.example.com;lr;method=INVITE")),
            plan().route(uri("sip:p1.example.com;lr?Subject=x")),
        ];

        for plan in refused {
            assert!(!plan.is_valid(), "{plan:?}");
            assert!(plan.build(&identity(), "sip:a@192.0.2.1").is_none());
        }
        assert!(plan().is_valid());
    }

    /// A first route without `lr` takes the Request-URI, and the planned
    /// Request-URI goes last in Route (RFC 3261 sections 8.1.1.1 and
    /// 12.2.1.1), so that the INVITE reaches the strict router first.
    #[test]
    fn a_strict_router_takes_the_request_uri() {
        let planned = plan()
            .route(uri("sip:192.0.2.10"))
            .route(uri("sip:p2.example.com;lr"))
            .build(&identity(), "sip:alice@192.0.2.1")
            .unwrap();
        let request = &planned.request;
        let routes: Vec<_> = request
            .headers()
            .get_all(ROUTE)
            .map(|value| value.as_str())
            .collect();

        assert_eq!(request.uri().as_str(), "sip:192.0.2.10");
        assert_eq!(
            routes,
            ["<sip:p2.example.com;lr>", "<sip:bob@biloxi.example.com>"]
        );
        assert_eq!(
            request.headers().get(TO).unwrap(),
            "<sip:bob@biloxi.example.com>"
        );
        // RFC 3261 section 8.1.2 resolves the Request-URI past a strict
        // router, though the top Route value is a loose router.
        assert_eq!(&*planned.next_hop, "sip:192.0.2.10");
        assert!(!planned.secure);
    }

    /// A SIPS target behind a strict router that is a SIP URI keeps its
    /// need for TLS, though strict routing leaves a SIP Request-URI and next
    /// hop (RFC 3261 section 26.2.2).
    #[test]
    fn a_sips_target_behind_a_strict_router_stays_secure() {
        let planned = InvitePlan::new(
            uri("sips:bob@biloxi.example.com"),
            uri("sips:alice@atlanta.example.com"),
            plan().offer,
        )
        .route(uri("sip:192.0.2.10"))
        .build(&identity(), "sip:alice@192.0.2.1")
        .unwrap();

        assert_eq!(planned.request.uri().as_str(), "sip:192.0.2.10");
        assert_eq!(&*planned.next_hop, "sip:192.0.2.10");
        assert!(planned.secure);
    }

    /// A To taken from the Request-URI leaves out what Table 1 of RFC 3261
    /// section 19.1.1 does not allow in a To, and keeps the rest.
    #[test]
    fn a_to_from_the_request_uri_drops_what_a_to_may_not_have() {
        let request = InvitePlan::new(
            uri("sip:bob@192.0.2.4:5070;transport=tcp;user=phone;x=y"),
            uri("sip:alice@atlanta.example.com"),
            plan().offer,
        )
        .build(&identity(), "sip:alice@192.0.2.1")
        .unwrap()
        .request;

        assert_eq!(
            request.uri().as_str(),
            "sip:bob@192.0.2.4:5070;transport=tcp;user=phone;x=y"
        );
        assert_eq!(
            request.headers().get(TO).unwrap(),
            "<sip:bob@192.0.2.4;user=phone;x=y>"
        );
    }
}
