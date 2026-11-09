/*!
signa is a fast and correct low-level SIP library.

It does for SIP roughly what `hyper` does for HTTP. It carries messages over
UDP and TCP, runs the RFC 3261 transactions, and hands requests and responses
to application code at the transaction-user boundary. It is a base for user
agents, proxies, registrars and B2BUAs, not one of them.

Its design draws heavily on the [`http`] and [`hyper`] crates.

*/
// The transaction-user API lives in `endpoint`, which needs the `tokio`
// feature, and so do the links of this section.
#![cfg_attr(feature = "tokio", doc = include_str!("doc/transaction_user.md"))]
#![cfg_attr(
    not(feature = "tokio"),
    doc = "The transaction-user API, `endpoint`, needs the `tokio` \
           feature.\n\n"
)]
/*!
# What this release covers

* SIP message types modeled on the [`http`] crate. [`Request`] and [`Response`]
  are generic over the body, and their parts include [`Method`], [`Uri`],
  [`StatusCode`], [`ReasonPhrase`], [`HeaderMap`], and [`Extensions`].
* Parsing the bytes of one complete message with [`Request::from_bytes`],
  [`Response::from_bytes`], or [`Message::from_bytes`], and their `from_shared`
  forms, which take [`Bytes`] and do not copy it. [siparse] parses the head.
* Encoding a message into bytes with [`Request::encode`], [`Response::encode`],
  or [`Message::encode`]. The start-line and header values are written as
  stored. Header names come out in their long form, and `Content-Length` is
  always computed from the body. A response without a reason phrase gets the
  standard one for its code.
* An endpoint, with the `tokio` feature, that carries messages over UDP and
  TCP, frames TCP streams by `Content-Length`, answers RFC 5626 keepalives,
  and runs the INVITE and non-INVITE client and server transactions of
  RFC 3261 section 17 as updated by RFC 6026 and RFC 4320. It exposes the
  transaction-user API, bounds the work it holds, and drains that work in a
  graceful shutdown.
* Stateless reception over UDP for a stateless proxy (RFC 3261 section 16.11).
  Every request and response arrives as an event without a transaction. The
  application forwards requests with a branch it computed, and responses by
  their remaining Via. `examples/stateless_proxy.rs` shows the pieces.

# Supported RFC scope

signa implements the parts of each RFC listed here, and each item listed as
supported or partial has tests, which the [RFC and test map] names. A section
listed is the basis for one behavior, not a claim that the RFC, or even the
whole section, is implemented. "The TU's" means that signa provides the events
and operations, and the application does the rest.

### RFC 3261

Supported:

* Message parsing and encoding, and `Content-Length` framing on TCP
  ([section 7], [18.3]).
* The INVITE and non-INVITE client and server transactions, with Timers A to K
  on UDP and TCP ([17.1], [17.2]), and their matching ([17.1.3], [17.2.3]).
* The ACK of a non-2xx ([17.1.1.3]). CANCEL built from its INVITE as a
  transaction of its own, sent after a provisional response, with a 64 T1
  deadline, and CANCEL matching on the server ([9.1], [9.2]).
* Response routing by the connection or local address a request came in on,
  `received`, and a fallback to `sent-by` ([18.2.1], [18.2.2]). A UDP request
  above 1300 bytes is refused ([18.1.1]).
* Stateless forwarding primitives over UDP: a caller-chosen branch, and
  response forwarding by the next Via ([16.11]).

Partial:

* Transports. UDP and TCP only, see below.
* A new request beyond admission gets a stateless 503, without a reproducible
  To tag yet ([8.2.7], [21.5.4]).
* `sips:` ([8.1.2]). The endpoint refuses to send a `sips:` Request-URI.
  Nothing else about SIPS is checked, see RFC 5630 below.

The TU's:

* Dialogs, the ACK for a 2xx, and retransmitting a 2xx until its ACK ([12],
  [13.2.2.4], [13.3.1.4]).
* Answering a CANCEL, and a pending INVITE with a 487 ([9.2]).
* Proxy behavior beyond the primitives above: validation, Route, Record-Route,
  targets, forking, the best response and Timer C ([16]).
* Registration, authentication, and picking the next hop from the URIs ([10],
  [22], [8.1.2]).

Not supported:

* RFC 2543 fallback matching. A request without the magic cookie in its
  branch gets no transaction and arrives as an untracked event ([17.2.3]).
* TLS and so SIPS transport, multicast and `maddr`, and other transports
  ([18]).
* Stateless reception over TCP, and stateful and stateless reception on one
  endpoint.

### RFC 6026

Supported:

* Accepted on the client until Timer M, delivering every 2xx, and on the
  server until Timer L, taking further 2xx and passing their ACKs to the TU
  ([8.4], [8.7]).
* An INVITE server keeps its state after a transport error ([8.8]).
* A stateful endpoint discards a response that matches no transaction
  ([8.9]).

Partial:

* A stateful proxy forwards only through a live transaction ([7.3], [8.3]).
  The responder refuses a response its transaction no longer allows. No
  loopback test sends one after Timer L.

The TU's:

* Retransmitting a UAS 2xx and acknowledging each 2xx ([8.1]).

### RFC 4320

Supported ([section 4]):

* Over UDP a non-INVITE gets the driver's 100 Trying when it is due, and an
  earlier 100 from the TU is refused. Other provisional responses and 408 are
  refused.
* A response that arrives after its client transaction ended is discarded, so
  a stateful proxy cannot forward it.

### RFC 3581

Supported ([section 4][3581-4]):

* A received request's top Via gets `received`, and `rport` gets the source
  port. Responses go to that address and port, and a stateless proxy forwards
  responses by them too.

### RFC 5626

Partial: a double CRLF on TCP gets a CRLF back ([section 4.4.1]). There is no
flow or keepalive policy.

### RFC 3263 and RFC 5630

Not supported. The application resolves each next hop into an explicit
target, without RFC 3263's lookups or failover ([3263 section 4]). signa has no
TLS, so it must not carry a request that needs it, and it checks only part of
that:

* A `sips:` Request-URI is refused in any letter case. This guards against
  part of what plaintext cannot do. It is not SIPS support.
* Route and the target are sent as given and not compared. A `sips:` route
  needs TLS too ([5630 section 5.1.1]), and catching that, like any other TLS
  requirement that comes from routing, is the caller's.
* A `sip:` Request-URI does not make plaintext safe for the request.

# Deliberate omissions

These can be built above signa with its current API:

* A complete UA, PBX, registrar, proxy or B2BUA, and dialog and call state.
  The examples show the TU parts each needs.
* RFC 3263 resolution and failover, which pick a target and start the next
  transaction.
* Authentication policy, SDP and media.
* Proxy Timer C, best-response selection, and Route and Record-Route
  processing. The header API cannot yet remove only the first value of a
  header, so the proxy examples rebuild those rows.
* A helper for UAS 2xx retransmission. `examples/invite_uas.rs` has the loop.
  I keep it out of signa because it has to fit the TU's dialog ACK dispatch,
  duplicate ACKs, an answer carried in the ACK, and the application's
  lifetimes.

Reliable provisional responses and PRACK (RFC 3262) and session timers
(RFC 4028) are neither designed nor tested on signa. They need designs of
their own.

These are limited by signa itself:

* TLS, and so SIPS. The transport interface is private, so a transport cannot
  be added from outside.
* Stateless reception over TCP. Binding refuses it, since a response's Via
  does not identify the upstream connection.
* Stateful and stateless reception on one endpoint. Two endpoints on two
  addresses work. A stateful proxy that forwards an unmatched CANCEL
  statelessly (RFC 3261 section 16.10) needs the second one.
* Multicast. A request whose top Via has `maddr` is dropped, and a multicast
  target is refused.
* RFC 2543 transactions, which arrive untracked.

# Features

The `tokio` feature, on by default, enables the endpoint and socket I/O.
Without it, message types, transaction timer configuration, and transport
metadata and receive limits remain available without a runtime. Endpoint
examples are omitted when this feature is disabled.

The minimum supported Rust version is 1.71.

# Modules

- [`message`] owns message values, builders, parsing and encoding. The crate
  root re-exports the principal types. Parts, header constants and construction
  errors use paths such as [`message::request::Parts`], [`message::header`]
  and [`message::BuildError`]. [`message::uri::SipUri`] provides validated,
  borrowed SIP/SIPS structure on demand.
- [`transaction`] exposes transaction timer configuration. Its state machines
  are internal protocol machinery.
- [`transport`] exposes [`transport::Flow`], [`transport::Transport`] and
  [`transport::MessageLimits`]. Socket and framing implementations are private.
- The `endpoint` module, enabled by `tokio`, provides running protocol
  operations and their handles.

[RFC and test map]: https://github.com/ryumatag/signa/blob/main/docs/rfc-test-map.md
[section 7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-7
[8.1.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.2
[8.2.7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.2.7
[9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
[9.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2
[10]: https://www.rfc-editor.org/rfc/rfc3261.html#section-10
[12]: https://www.rfc-editor.org/rfc/rfc3261.html#section-12
[13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
[13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
[16]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16
[16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
[17.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1
[17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
[17.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.3
[17.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2
[17.2.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.3
[18]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18
[18.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1
[18.2.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.1
[18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
[18.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.3
[21.5.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-21.5.4
[22]: https://www.rfc-editor.org/rfc/rfc3261.html#section-22
[7.3]: https://www.rfc-editor.org/rfc/rfc6026.html#section-7.3
[8.1]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.1
[8.3]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.3
[8.4]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
[8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
[8.8]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.8
[8.9]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.9
[section 4]: https://www.rfc-editor.org/rfc/rfc4320.html#section-4
[3581-4]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
[section 4.4.1]: https://www.rfc-editor.org/rfc/rfc5626.html#section-4.4.1
[3263 section 4]: https://www.rfc-editor.org/rfc/rfc3263.html#section-4
[5630 section 5.1.1]: https://www.rfc-editor.org/rfc/rfc5630.html#section-5.1.1

# Examples
*/
// The endpoint examples exist only with the `tokio` feature, since the
// doctests would not compile without it.
#![cfg_attr(feature = "tokio", doc = include_str!("doc/endpoint_examples.md"))]
/*!
### The message layer alone

Parsing a datagram and answering it, without the endpoint. This is what the
endpoint does inside.

```
use bytes::Bytes;
use signa::{Message, Method, Response, StatusCode};

let datagram = Bytes::from_static(
    b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
      Max-Forwards: 70\r\n\
      To: <sip:carol@chicago.example.com>\r\n\
      From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
      Call-ID: a84b4c76e66710\r\n\
      CSeq: 63104 OPTIONS\r\n\
      Content-Length: 0\r\n\
      \r\n",
);

let Message::Request(request) = Message::from_shared(datagram)? else {
    return Ok(());
};
assert_eq!(request.method(), Method::OPTIONS);

// A real UAS would also add a tag to `To`.
let response = Response::reply_to(&request)
    .status(StatusCode::OK)
    .body(Bytes::new())?;

let bytes = response.to_bytes();
assert!(bytes.starts_with(b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP pc33"));
assert!(bytes.ends_with(b"Content-Length: 0\r\n\r\n"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

# Validation

Message token constructors accept exactly what [siparse] accepts in a head,
using its [`check`](siparse::check) functions, except for [`StatusCode`].
[`StatusCode`] only takes `100..=699`, the classes RFC 3261 defines, while
siparse accepts any three digits. A message parsed from the wire can always be
rebuilt from its parts, and a value built by hand is never one that the parser
would reject.

Parsing does not check a value a second time, except the method and status
code. The [`Uri`], [`ReasonPhrase`], and header values share the input buffer
instead of copying it. [`Uri::sip`] separately validates SIP/SIPS structure
when requested. It does not add validation or allocations to message parsing.

Header values are checked only against the envelope that every header field
shares, not against the grammar of each field. Typed header parsing belongs
in a higher layer.

[Tower]: https://docs.rs/tower
[`http`]: https://docs.rs/http
[`hyper`]: https://docs.rs/hyper
[`Bytes`]: bytes::Bytes
*/

#![allow(
    // My preference.
    clippy::use_self,
    clippy::needless_lifetimes,
)]
#![deny(
    unreachable_pub,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    rustdoc::broken_intra_doc_links
)]
#![warn(missing_docs, missing_debug_implementations)]

#[doc(inline)]
pub use self::message::{
    Extensions, HeaderMap, HeaderName, HeaderValue, Message, Method,
    ReasonPhrase, Request, Response, StatusCode, Uri, Version,
};

#[cfg(feature = "tokio")]
pub mod endpoint;
pub mod message;
pub mod transaction;
pub mod transport;

// Runs the README's quick start with the doctests, so it cannot drift from the
// API.
#[cfg(all(doctest, feature = "tokio"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// Entry points for signa-bench. Unstable and not part of the public API.
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench {
    #[cfg(feature = "tokio")]
    pub use crate::{
        endpoint::reply_driver,
        transport::{tcp, udp},
    };
    pub use crate::{
        message::header::{cseq::CSeq, via::Via},
        transaction::{
            invite,
            key::{ClientKey, ServerKey},
            non_invite::{ClientEvent, ClientTransaction, ServerTransaction},
            Timers,
        },
        transport::{
            framing::{DecodeError, Decoder, Frame, Role},
            Flow, MessageLimits, Transport,
        },
    };
}
