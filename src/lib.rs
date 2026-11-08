/*!
signa is a fast and correct low-level SIP library.

It does for SIP roughly what `hyper` does for HTTP. It carries messages over
UDP and TCP, runs the RFC 3261 transactions, and hands requests to application
code through owned transaction-user envelopes.

Its design draws heavily on the [`http`] and [`hyper`] crates.

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
* An `Endpoint` that carries messages over UDP and TCP, splits TCP streams into
  messages by `Content-Length` and answers RFC 5626 keepalives, runs the
  INVITE and non-INVITE client and server transactions of RFC 3261 section 17
  as updated by RFC 6026 and RFC 4320, and exposes incoming events, server
  responders and independent transaction observation. `Endpoint::start`
  returns client control and a bounded response stream after transport
  preparation and driver acceptance. The transaction acknowledges a non-2xx
  INVITE response. An INVITE is cancelled through its client control, and a
  received CANCEL or ACK for a 2xx arrives as an event. `Endpoint::send_request`
  sends the application's ACK for a 2xx once. Application code owns server
  dispatch and handler tasks. These operations live in `endpoint`. A graceful
  shutdown answers new requests with a 503 and waits for the ones in hand up
  to a deadline.

# What it does not cover yet

* Dialogs and the rest of a UA core: building the ACK for a 2xx,
  retransmitting a 2xx until its ACK, and deciding what a received CANCEL
  means. signa gives the application the events, routes and operations for
  them. Reliable provisional responses (RFC 3262) are not implemented.
* Stateless reception and forwarding, and draining INVITEs in Accepted when
  the endpoint shuts down. `send_request` takes only an ACK so far.
* Choosing a next hop. RFC 3263 resolution belongs to a layer above, which
  selects an explicit `Target` for each request. [`Uri::sip`] exposes SIP/SIPS
  components without selecting a destination or transport.
* TLS. signa can build and parse `sips:` URIs, but it sends over UDP and TCP
  only, so it cannot carry a request that requires TLS. `Endpoint::start`
  refuses a `sips:` Request-URI and does not check Route or the target. Its
  routing section says what that leaves to the caller.
* Dialogs, registration, proxying, and the rest of what an application does
  with messages. Those belong in crates built on signa.

# Features

The `tokio` feature, on by default, enables the endpoint and socket I/O.
Without it, message types, transaction timer configuration, and transport
metadata and receive limits remain available without a runtime. Endpoint
examples are omitted when this feature is disabled.

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
