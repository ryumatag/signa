/*!
Dialogs and INVITE usage for SIP user agents, on signa-core.

This crate has no API yet. It is to track the dialogs an INVITE creates, send
the ACK for each 2xx, retransmit a UAS 2xx until its ACK, and serialize
CANCEL, BYE and re-INVITE against them, leaving call policy, SDP and media to
the application.
*/

#![deny(unreachable_pub, rustdoc::broken_intra_doc_links)]
#![warn(missing_docs, missing_debug_implementations)]
