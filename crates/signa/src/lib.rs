/*!
A low-level SIP library for Rust that handles transactions, down to the last
retransmission.

This crate is the front of signa. It re-exports [signa-core], which carries
SIP messages over UDP and TCP and runs the RFC 3261 transactions up to the
transaction-user boundary, and, behind the `ua` feature, [signa-ua], which
keeps dialogs and INVITE usage on top of it. The items are their own, not
copies, so a `signa::Request<Bytes>` is a `signa_core::Request<Bytes>` and a
`signa::ua::Ua` is a `signa_ua::Ua`. signa-core's crate documentation has the
transaction-user API, the lifetimes it keeps apart, and the RFC scope section
by section. signa-ua's has the UA, what it does and what it leaves out.

# Features

* `tokio`, on by default, enables the `endpoint` module and its sockets.
  Without it the message types, transaction timer configuration and transport
  metadata stay available without a runtime.
* `ua` adds signa-ua as the `ua` module, and turns `tokio` on, since a UA
  runs on an endpoint.

The minimum supported Rust version is 1.85.

[signa-core]: https://docs.rs/signa-core
[signa-ua]: https://docs.rs/signa-ua
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
#[cfg(feature = "ua")]
#[doc(inline)]
pub use signa_ua as ua;

// Runs the README's quick start with the doctests, so it cannot drift from the
// API.
#[cfg(all(doctest, feature = "tokio"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
