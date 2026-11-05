/*!
signa is a fast and correct low-level SIP library. It aims to do for SIP
roughly what `hyper` does for HTTP. It will carry messages over UDP and TCP,
run the RFC 3261 transactions, and hand requests to application code through a
[Tower] `Service`. Its design draws heavily on the [`http`] and [`hyper`]
crates.

This release provides the message layer that the rest will build on. It does
not do any I/O yet.

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

# What it does not cover yet

Parsing takes exactly one message, such as one UDP datagram. Nothing here
splits a TCP stream into messages, sends or receives anything, or runs
transactions. I plan stream framing, UDP and TCP I/O, non-INVITE transactions,
and the `Service` boundary for 0.2.0, and INVITE, ACK, and CANCEL transactions
for 0.3.0.

# Example

A UAS answering an `OPTIONS` request received in a datagram:

```
use bytes::Bytes;
use signa::{
    header::{CALL_ID, CSEQ, FROM, TO, VIA},
    Message, Method, Response, StatusCode,
};

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

// A response copies these fields from the request (RFC 3261 section 8.2.6.2).
// A real UAS would also add a tag to `To`.
let mut response = Response::builder().status(StatusCode::OK);
for name in [VIA, FROM, TO, CALL_ID, CSEQ] {
    for value in request.headers().get_all(&name) {
        response = response.header(name.clone(), value.clone());
    }
}
let response = response.body(Bytes::new())?;

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
pub mod error;
mod extensions;
// Everything `pub` in `frame` exists for the `__bench` feature, which
// re-exports it. Without the feature nothing reaches it, which
// `unreachable_pub` would otherwise flag.
// TODO: Drop `dead_code` once the TCP transport uses the decoder.
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub, dead_code))]
mod frame;
pub mod header;
mod message;
mod method;
mod parse;
mod reason;
pub mod request;
pub mod response;
mod status;
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
    #[doc(hidden)]
    pub use crate::frame::{DecodeError, Decoder, Frame, Limits, Role};
    pub use crate::header::{cseq::CSeq, via::Via};
}
