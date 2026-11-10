/*!
A low-level SIP library for Rust that handles transactions, down to the last
retransmission.

This crate is the front of signa. It re-exports [signa-core], which carries
SIP messages over UDP and TCP and runs the RFC 3261 transactions up to the
transaction-user boundary. The items are signa-core's own, not copies, so a
`signa::Request<Bytes>` is a `signa_core::Request<Bytes>`. signa-core's crate
documentation has the transaction-user API, the lifetimes it keeps apart, and
the RFC scope section by section.

# Features

* `tokio`, on by default, enables the `endpoint` module and its sockets.
  Without it the message types, transaction timer configuration and transport
  metadata stay available without a runtime.

signa-ua, which is to hold dialogs and INVITE usage, has no API yet. This
crate re-exports it behind a feature once it has one.

The minimum supported Rust version is 1.85.

[signa-core]: https://docs.rs/signa-core
*/

#![deny(unreachable_pub, rustdoc::broken_intra_doc_links)]
#![warn(missing_docs, missing_debug_implementations)]

#[doc(inline)]
pub use signa_core::{
    Extensions, HeaderMap, HeaderName, HeaderValue, Message, Method,
    ReasonPhrase, Request, Response, StatusCode, Uri, Version,
};

#[cfg(feature = "tokio")]
#[doc(inline)]
pub use signa_core::endpoint;
#[doc(inline)]
pub use signa_core::{message, transaction, transport};

// Runs the README's quick start with the doctests, so it cannot drift from the
// API. Miri has no sockets to run it on.
#[cfg(all(doctest, feature = "tokio", not(miri)))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
