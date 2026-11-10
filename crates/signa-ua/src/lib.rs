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
mod retention;
mod slot;

#[cfg(test)]
mod tests {
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
