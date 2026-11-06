/*!
signa is a fast and correct low-level SIP library.

It does for SIP roughly what `hyper` does for HTTP. It carries messages over
UDP and TCP, runs the RFC 3261 transactions, and hands requests to application
code through a [Tower] `Service`. Its design draws heavily on the [`http`] and
[`hyper`] crates.

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
  non-INVITE client and server transactions of RFC 3261 section 17 as updated
  by RFC 4320, and hands each request to a Tower `Service`. Its `Client` sends
  requests to one next hop and is a `Service` too, so Tower middleware fits on
  both sides. Both live in the `endpoint` module. A graceful shutdown answers
  new requests with a 503 and waits for the ones in hand up to a deadline.

# What it does not cover yet

* INVITE, ACK, and CANCEL transactions, and with them provisional responses
  other than the 100 the endpoint sends itself. An INVITE gets a 501 and a
  CANCEL a 481. They are planned for 0.3.0, with RFC 6026.
* Choosing a next hop. RFC 3263 resolution, and the structured view of a
  [`Uri`] it needs, belong to a layer above, which holds one `Client` per hop.
* TLS, and anything that would make `sips:` mean what it says.
* Dialogs, registration, proxying, and the rest of what an application does
  with messages. Those belong in crates built on signa.

# Features

The `tokio` feature, on by default, pulls in tokio for the `endpoint` module.
With `default-features = false` only the message layer is built, and the
examples below that use the endpoint are left out of these docs.

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

Every value type except [`StatusCode`] accepts exactly what [siparse] accepts
in a head, using its [`check`](siparse::check) functions. [`StatusCode`] only
takes `100..=699`, the classes RFC 3261 defines, while siparse accepts any
three digits. A message parsed from the wire can always be rebuilt from its
parts, and a value built by hand is never one that the parser would reject.
Parsing does not check a value a second time, except the method and status
code. The [`Uri`], [`ReasonPhrase`], and header values share the input buffer
instead of copying it.

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
pub use self::{
    error::Error,
    extensions::Extensions,
    header::{HeaderMap, HeaderName, HeaderValue},
    message::Message,
    method::Method,
    reason::ReasonPhrase,
    request::Request,
    response::Response,
    status::StatusCode,
    uri::Uri,
    version::Version,
};

mod encode;
#[cfg(feature = "tokio")]
pub mod endpoint;
pub mod error;
mod extensions;
// Everything `pub` in `frame` exists for the `__bench` feature, which
// re-exports it. Without the feature nothing reaches it, which
// `unreachable_pub` would otherwise flag. The TCP transport is the only
// user, so without `tokio` the module is dead.
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
#[cfg_attr(not(any(feature = "__bench", feature = "tokio")), allow(dead_code))]
mod frame;
pub mod header;
mod message;
mod method;
mod parse;
mod reason;
pub mod request;
pub mod response;
mod status;
// The machines are crate-private, driven by the endpoint. `pub` items exist
// for the `__bench` feature, as in `frame`. Without `tokio` nothing drives
// them, so the module is dead.
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
#[cfg_attr(
    not(any(feature = "__bench", feature = "tokio")),
    allow(dead_code, unused_imports)
)]
mod transaction;
// The transports run on tokio and are crate-private, driven by the endpoint,
// with `pub` items for the `__bench` feature, as in `frame`.
#[cfg(feature = "tokio")]
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
mod transport;
mod uri;
mod util;
mod version;

/// Entry points for the `signa-bench` crate, behind the `__bench` feature.
///
/// Nothing here is part of the public API, and the feature can change or go
/// away in any release.
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench {
    #[cfg(feature = "tokio")]
    #[doc(hidden)]
    pub use crate::{
        endpoint::reply_driver,
        transport::{tcp, udp, Flow, Transport},
    };
    #[doc(hidden)]
    pub use crate::{
        frame::{DecodeError, Decoder, Frame, Limits, Role},
        header::{cseq::CSeq, via::Via},
        transaction::invite,
        transaction::{
            ClientEvent, ClientKey, ClientTransaction, ServerKey,
            ServerTransaction, Timers,
        },
    };
}
