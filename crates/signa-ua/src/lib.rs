/*!
Dialogs and INVITE usage for SIP user agents, on signa-core.

This crate has no API yet. It is to track the dialogs an INVITE creates, send
the ACK for each 2xx, retransmit a UAS 2xx until its ACK, and serialize
CANCEL, BYE and re-INVITE against them, leaving call policy, SDP and media to
the application.
*/

#![deny(unreachable_pub, rustdoc::broken_intra_doc_links)]
#![warn(missing_docs, missing_debug_implementations)]
// TODO: Drive the state model from a runtime on the endpoint. Until that
// exists, only the tests call it.
#![cfg_attr(not(test), allow(dead_code))]

// The private state model. `dialog` knows nothing of `invite`, so other
// usages can share it later. `docs/signa-ua-rfc-test-map.md` maps the rules
// these modules keep to their tests.
mod dialog;
mod error;
mod invite;
mod model;
mod negotiation;
mod operation;
mod protocol;
mod retention;
mod routing;
mod slot;

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
