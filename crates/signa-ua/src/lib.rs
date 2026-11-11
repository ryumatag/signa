/*!
Dialogs and INVITE usage for SIP user agents, on signa-core.

signa-ua is the UA core of RFC 3261 sections 12 and 13 on top of signa-core's
transactions. It keeps the dialogs an INVITE forms, acknowledges each 2xx, and
answers what the application leaves unanswered. Call policy, SDP and media
stay with the application.

The runtime, with the `tokio` feature, attaches a UA to a dedicated signa-core
endpoint.
*/
#![cfg_attr(
    feature = "tokio",
    doc = "See [`attach`] for its parts, and how submitting, events and \
           dropping work.\n\n"
)]
/*!
# What it does not do yet

This is an early stage of the crate, and much of a UA core is missing:

* The UA reads no session description. It knows where offers and answers go,
  and has the application's `Negotiate` prepare the answer an ACK owes, but
  whether an answer suits its offer is for the application to judge. Only a
  UA with a `Negotiate` sends an INVITE without an offer.
* A multipart body is not taken apart, so an INVITE with one gets a 415, and
  one in a response or an ACK counts as no session description.
* There is no reliable provisional response (RFC 3262), so a session
  description in a provisional response is only a preview.
* A 2xx that cannot form a dialog, such as one without a Contact, gets no
  ACK. One beyond the UA's limits gets its ACK and a BYE, while the room
  kept for that lasts.
* In a dialog, the UA takes BYE itself. Other requests than INVITE are
  answered as outside a dialog, without asking the application.
* Outside a dialog, OPTIONS gets a 200 with the methods, body type and
  coding the UA takes, without asking the application, and other requests
  but INVITE a 405 or a 501.
* A re-INVITE of the UA's own cannot be cancelled. A session description in
  a provisional response to one is not kept, and its 2xx has to carry the
  answer. A re-INVITE asked for while the last 2xx of the session waits for
  its ACK is refused rather than held until then. A re-INVITE that gets a 491
  goes once more, and no more.
* There is no TLS, so a request that asks for SIPS is refused, and the UA
  sends none.
* The UA neither answers a challenge nor sends credentials.
* Next hops resolve from IP literals and a fixed table, with no DNS.
* A request without an RFC 3261 branch, as an RFC 2543 element sends, gets
  no answer, since signa-core keeps no transaction for it.
*/
#![cfg_attr(
    not(feature = "tokio"),
    doc = "\n\nWithout the `tokio` feature, the crate has no public API."
)]
#![deny(unreachable_pub, rustdoc::broken_intra_doc_links)]
#![warn(missing_docs, missing_debug_implementations)]
// TODO: Drive the rest of the state model from the runtime: the stages of an
// operation for a snapshot.
// Until then only the tests use those parts, and without the `tokio` feature
// only the tests use any.
#![cfg_attr(not(test), allow(dead_code))]

#[cfg(feature = "tokio")]
pub use self::ua::{
    AttachError, AttemptId, AttemptResult, AttemptSnapshot, CancelResult,
    Config, Description, EndReason, Error, Event, IncomingInvite,
    InvalidContact, InviteAttempt, InviteId, InvitePlan, Negotiate,
    NegotiationState, NoNegotiator, Offer, Operation, Query, ReinvitePlan,
    Resolve, ResolveError, Session, SessionId, SessionPhase, SessionSnapshot,
    ShutdownMode, ShutdownOutcome, ShutdownReport, StaticResolver,
    SubmitError, Ua, UaDriver, UaEvents, UaHandle, UaShutdown, WireEffect,
    attach,
};

// The private state model. `dialog` knows nothing of `invite`, so other
// usages can share it later. `docs/signa-ua-rfc-test-map.md` maps the rules
// these modules keep to their tests.
mod capability;
mod dialog;
mod error;
mod invite;
mod model;
mod negotiation;
mod operation;
mod plan;
mod protocol;
mod retention;
mod routing;
mod slot;
mod timer;
#[cfg(feature = "tokio")]
mod ua;

// Entry points for the fuzz targets in `fuzz/`. Unstable and not part of
// the public API.
#[cfg(feature = "__fuzz")]
#[doc(hidden)]
pub mod fuzz;

/// Messages and records the tests of several modules share.
#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use signa_core::{Request, Response};

    use crate::dialog::Dialog;

    /// The INVITE of RFC 3261 section 24.2, with a Record-Route the example
    /// proxies would have added, and addresses from the documentation
    /// ranges.
    pub(crate) const INVITE: &str = "\
INVITE sip:bob@biloxi.example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@biloxi.example.com>
From: \"Alice, A.\" <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@192.0.2.1>
Record-Route: <sip:p1.example.com;lr>, <sip:p2.example.com;lr>
Record-Route: <sip:p3.example.com;lr>

";

    /// Parses a request written with bare line feeds.
    pub(crate) fn request(text: &str) -> Request<Bytes> {
        Request::from_bytes(text.replace('\n', "\r\n").as_bytes()).unwrap()
    }

    /// Parses a response written with bare line feeds.
    pub(crate) fn response(text: &str) -> Response<Bytes> {
        Response::from_bytes(text.replace('\n', "\r\n").as_bytes()).unwrap()
    }

    /// The INVITE with another Call-ID.
    pub(crate) fn invite(call_id: &str) -> Request<Bytes> {
        request(
            &INVITE
                .replace("a84b4c76e66710@pc33.atlanta.example.com", call_id),
        )
    }

    /// A response to the INVITE, with `tag` on its To, `contact` as its
    /// Contact, and `extra` as further header lines, each ending in a line
    /// feed.
    pub(crate) fn reply(
        status: &str,
        tag: &str,
        contact: &str,
        extra: &str,
    ) -> Response<Bytes> {
        response(&format!(
            "SIP/2.0 {status}
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK776asdhds
To: Bob <sip:bob@biloxi.example.com>;tag={tag}
From: \"Alice, A.\" <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: 314159 INVITE
Contact: <{contact}>
{extra}
"
        ))
    }

    /// The dialog a UAS forms from the INVITE, with `a6c85cf` as its tag.
    pub(crate) fn dialog() -> Dialog {
        Dialog::uas(&request(INVITE), "a6c85cf".parse().unwrap(), 8).unwrap()
    }

    /// `dialog` must stay usable without `invite`. The compiler would allow
    /// a path from one to the other, so this test looks for one.
    #[test]
    fn dialog_does_not_refer_to_invite() {
        let source = include_str!("dialog.rs");

        for path in ["crate::invite", "super::invite", "invite::{"] {
            assert!(!source.contains(path), "dialog.rs mentions {path}");
        }
    }
}
