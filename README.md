<div align="center">

signa
=====
A fast and correct low-level SIP library in Rust.

[![Build status](https://github.com/ryumatag/signa/actions/workflows/ci.yml/badge.svg)](https://github.com/ryumatag/signa/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/signa.svg)](https://crates.io/crates/signa)
[![Docs.rs](https://img.shields.io/docsrs/signa)](https://docs.rs/signa)

</div>

<br>

signa does for SIP roughly what **hyper** does for HTTP. It carries messages
over UDP and TCP, runs the RFC 3261 transactions, and hands requests to
application code through owned transaction-user events.

Its design draws heavily on the [hyper] and [http] crates.

The current development API has request and response types modeled on the http
crate, parsing with [**siparse**] and encoding, and an endpoint that carries
messages over UDP and TCP, runs INVITE and non-INVITE transactions with the
Accepted states of RFC 6026, and exposes incoming requests, responders and
independent transaction observation. Client requests start asynchronously and
return split control and bounded response streams. An INVITE is cancelled
through its control, the transaction acknowledges a non-2xx, and the
application sends the ACK for a 2xx once, without a transaction. ACKs for a 2xx
and CANCELs reach the application as events of their own. The endpoint
supports graceful shutdown. Stateless forwarding, draining INVITEs in Accepted
at shutdown, TLS and next-hop selection are later work. signa is not a
complete UA or proxy. Dialogs, 2xx retransmission and the meaning of a CANCEL
stay with the application.

The [API documentation on docs.rs] says what is covered in detail.

[hyper]: https://docs.rs/hyper
[http]: https://docs.rs/http
[**siparse**]: https://docs.rs/siparse
[API documentation on docs.rs]: https://docs.rs/signa

### Modules

`message` contains the SIP message model, construction, parsing and encoding.
The main types remain available at the crate root, such as `signa::Request`.
Use `signa::message::request::Parts`, `signa::message::header::VIA` and
`signa::message::BuildError` for detailed message APIs.
`Uri::sip()` and `message::uri::SipUri::parse()` provide borrowed SIP/SIPS
components on demand, preserving the original text and escapes.

`transaction::Timers` configures transaction deadlines.
`transport::{Flow, Transport, MessageLimits}` describes transport metadata and
stream receive limits. These APIs are runtime independent. The `tokio` feature
enables the endpoint and sockets. State machines, sockets and framing remain
internal implementation details.

### Example

A UAS for non-INVITE requests receives owned requests and responds through
their transaction. `to_tag` adds a fresh To tag to an initial request's
response and keeps the tag of a request within a dialog. A failed submission is
logged rather than returned, since leaving the loop would drop `incoming` and
shut the endpoint down.

```rust
use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent},
    message::header::Tag,
    Method, Response,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_endpoint, mut incoming) = Endpoint::builder()
        .udp("0.0.0.0:5060".parse()?)
        .tcp("0.0.0.0:5060".parse()?)
        .bind()?;

    while let Some(event) = incoming.recv().await {
        if let IncomingEvent::Request(envelope) = event {
            // A 2xx to an INVITE starts a dialog, whose 2xx retransmissions and
            // ACK this loop does not handle.
            let status = if envelope.request.method() == Method::INVITE {
                501
            } else {
                200
            };
            let (responder, _) = envelope.transaction.into_parts();
            let response = Response::reply_to(&envelope.request)
                .status(status)
                .to_tag(Tag::random())
                .body(Bytes::new())?;

            if let Err(error) = responder.respond(response).await {
                eprintln!("response not accepted: {error}");
            }
        }
    }

    Ok(())
}
```

`examples/options.rs` runs both endpoints over UDP and TCP.

`examples/server_adapter.rs` demonstrates a responder wrapper and bounded,
application-owned Tower dispatch with a non-Clone service. The endpoint starts
no application handler tasks. Response acceptance is distinct from local write
completion and transaction termination. Dropping an unanswered responder
requests a 500. A stateless endpoint mode remains planned.

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.
