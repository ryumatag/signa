<div align="center">

signa
=====
A low-level SIP library for Rust that handles transactions, down to the last
retransmission.

[![Build status](https://github.com/ryumatag/signa/actions/workflows/ci.yml/badge.svg)](https://github.com/ryumatag/signa/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/signa.svg)](https://crates.io/crates/signa)
[![Docs.rs](https://img.shields.io/docsrs/signa)](https://docs.rs/signa)

</div>

<br>

**signa** does for SIP roughly what **hyper** does for HTTP. It carries
messages over UDP and TCP, runs the RFC 3261 transactions, and hands requests
and responses to application code at the transaction-user boundary of
[RFC 3261 section 17]. It is a base for user agents, proxies, registrars and
B2BUAs. It is not one of them, and it is not a PBX.

Its design draws heavily on the [hyper] and [http] crates.

The repository is a Cargo workspace of three crates:

* `signa`, the crate to depend on. It re-exports signa-core, and signa-ua
  behind its `ua` feature, and is to become the front of a SIP application
  framework.
* `signa-core`, the messages, transports and transactions described below.
* `signa-ua`, dialogs and INVITE usage for user agents, on the public API of
  signa-core. See [Dialogs and INVITE usage](#dialogs-and-invite-usage).

signa-ua depends on signa-core, which depends on neither of the others.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[hyper]: https://docs.rs/hyper
[http]: https://docs.rs/http

### What signa does

* SIP request and response types modeled on the http crate, parsed with
  [siparse] and encoded with a computed `Content-Length`.
* UDP and TCP transport. TCP streams are framed by `Content-Length`, and
  responses go back over the connection or local address their request came in
  on, with `received` and `rport` (RFC 3581).
* INVITE and non-INVITE client and server transactions: matching,
  retransmissions and timers, the Accepted states and Timers L and M of
  RFC 6026, and the non-INVITE changes of RFC 4320.
* The ACK of a non-2xx final response, and CANCEL as a transaction of its own.
* UDP stateless reception and forwarding primitives for a stateless proxy.
* Bounded protocol work, explicit errors, and a graceful shutdown that waits
  for transactions and for work the application registers with a guard.

### What the application does

On signa-core, the application is the transaction user (TU). It owns dialogs
and calls, the ACK for a 2xx, retransmitting its own 2xx until the ACK, what a
received CANCEL means, proxy routing and forking decisions, Timer C, next-hop
selection (RFC 3263), authentication, registration, SDP and media, and handler
dispatch. The examples below show several of these on top of signa. signa-ua
takes on the dialogs and the INVITE sessions of a user agent, as described
below.

The TU is not a Rust trait. signa has no service trait. An ordinary receive
loop uses the API directly, and a Tower adapter can be built outside signa.

### Transaction-user API

The `endpoint` module, behind the default `tokio` feature, is the whole TU
API:

* `Endpoint::builder()` binds UDP and TCP and returns a cloneable `Endpoint`
  and one `Incoming` event receiver. The endpoint spawns no handler tasks.
* `Incoming::recv` yields an `IncomingEvent`: a new request with its server
  transaction, a matched CANCEL, an ACK for a 2xx, an unmatched CANCEL, an
  untracked request, or, on a stateless endpoint, any request or response.
* A `ServerTransaction` splits into a `Responder`, which submits responses,
  and `ServerEvents`, which reports write failures and termination.
* `Endpoint::start` sends a request to an explicit `Target` and returns a
  `ClientControl`, which can cancel an INVITE, and a `Responses` stream.
* `Endpoint::send_request`, `Endpoint::forward_response` and
  `ReplyRoute::send` send one message without a transaction.
* `Endpoint::shutdown` drains and reports `Drained` or `DeadlineExpired`.
  `Endpoint::work_guard` holds it for the TU's own work.

Reception is fixed per endpoint. `Reception::Stateful`, the default, runs
transactions over UDP and TCP. `Reception::Stateless` delivers every message
over UDP without transactions, for a stateless proxy.

### Dialogs and INVITE usage

signa-ua keeps the dialogs that INVITEs form and the INVITE session of each,
on top of signa-core's transactions. It acknowledges each 2xx that forms a
dialog, within its limits, sends its own 2xx again until the ACK, and answers
what the application leaves unanswered. The application decides each incoming INVITE, says when to call, hang up or
change a session, and owns SDP, media and call policy.

* Initial INVITEs both ways, with the offer in the INVITE or in the 2xx. A
  UA sends an INVITE without an offer only with a `Negotiate` provider, which
  prepares the answer each ACK carries.
* A session of its own for each fork, and an ACK for each 2xx of a dialog.
* CANCEL, BYE either way, and re-INVITE either way with target refresh.
* Limits on the UA's tables, queues and jobs, and a shutdown in two phases.

`signa::ua::attach` starts a UA on an endpoint of its own and returns a
handle for operations, a receiver of events, and the driver future that
runs it. Its documentation says what submitting, the event queue, a
shutdown and dropping each part do, and `Config` the limits.

signa-ua is at an early stage. It implements parts of RFC 3261 and RFC 6141,
claims conformance to neither as a whole, and is not a complete UA. It has no
reliable provisional responses, UPDATE, REFER or session timers, no
authentication and no DNS, and a rejection carries no header of its own,
such as the Contact of a 3xx. Its [crate documentation](https://docs.rs/signa-ua)
lists what it does not do yet.
[`docs/signa-ua-rfc-test-map.md`](docs/signa-ua-rfc-test-map.md) says which
tests show each rule, and which rules are partial or not supported. Beyond its
own tests, it has run against SIPp alone, by hand: a call, a CANCEL and a
re-INVITE from SIPp, and a call to SIPp, over UDP and TCP.

### Quick start

A UAS and a UAC on the loopback. The UAS answers an OPTIONS through its server
transaction, the UAC reads the response from its client transaction, and both
shut down gracefully.

```rust
use std::time::Duration;

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent, Target},
    message::header::Tag,
    transport::Transport,
    Request, Response, StatusCode,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Port 0 lets the system pick one. Keep each `Incoming`, since dropping
    // it shuts its endpoint down.
    let (uas, mut uas_incoming) =
        Endpoint::builder().tcp("127.0.0.1:0".parse()?).bind()?;
    let (uac, _uac_incoming) =
        Endpoint::builder().tcp("127.0.0.1:0".parse()?).bind()?;

    // The UAC picks the next hop itself. signa does no RFC 3263 lookup.
    let target = Target::new(Transport::Tcp, uas.tcp_addr().unwrap());
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@127.0.0.1")
        .header("From", "<sip:alice@127.0.0.1>;tag=1928301774")
        .header("To", "<sip:bob@127.0.0.1>")
        .header("Call-ID", "a84b4c76e66710")
        .header("CSeq", "1 OPTIONS")
        .header("Max-Forwards", "70")
        .body(Bytes::new())?;
    let (_control, mut responses) =
        uac.start(request, target).await?.into_parts();

    // The UAS takes the request with its server transaction and answers it.
    // `IncomingEvent` is non-exhaustive, so a real loop also has a `_` arm.
    if let Some(IncomingEvent::Request(envelope)) = uas_incoming.recv().await {
        let (responder, _events) = envelope.transaction.into_parts();
        let response = Response::reply_to(&envelope.request)
            .status(StatusCode::OK)
            .to_tag(Tag::random())
            .body(Bytes::new())?;
        // Accepted by the driver, which is not the same as received.
        responder.respond(response).await?;
    }

    let response = responses.next().await.expect("a final response")?;
    assert_eq!(response.status(), StatusCode::OK);

    // Over TCP both transactions end with the final response. Over UDP the
    // drain would wait for Timers J and K, 32 and 5 seconds by default.
    assert!(uac.shutdown(Duration::from_secs(5)).await.is_drained());
    assert!(uas.shutdown(Duration::from_secs(5)).await.is_drained());

    Ok(())
}
```

### Examples

Each example runs on the loopback, checks its own outcome, and says which TU
duties it takes on and which it leaves out. Each is a workspace of its own
that builds on the `signa` crate, so it runs with its manifest:

```sh
cargo run --manifest-path examples/options/Cargo.toml
```

CI runs them with RFC 3261's timers. `--t1-ms 50` makes most of them quicker.

* [`examples/options`](examples/options): a non-INVITE responder over
  UDP and TCP, with transaction observation and a drained shutdown.
* [`examples/invite-uas`](examples/invite-uas): an INVITE UAS that
  retransmits its 2xx until the ACK under a work guard, answers CANCEL, and
  compares a drained shutdown with a forced one.
* [`examples/invite-uac`](examples/invite-uac): an INVITE UAC that
  acknowledges forked and retransmitted 2xx and cancels calls, including a
  CANCEL that loses to a 2xx.
* [`examples/fork-proxy`](examples/fork-proxy): a stateful proxy that
  forks an INVITE to two UASes, relays every 2xx, and cancels the other
  branches.
* [`examples/stateless-proxy`](examples/stateless-proxy): a UDP
  stateless proxy with a stable branch for an INVITE, its CANCEL and its ACK.

The `ua-` examples build on signa-ua instead, through the facade's `ua`
feature. The UA takes on the dialogs and the INVITE usage, and the example
plays the application:

* [`examples/ua-call`](examples/ua-call): two UAs call each other. The
  callee rings, answers and hangs up, and its UA holds the BYE until the
  ACK.
* [`examples/ua-late-offer`](examples/ua-late-offer): an INVITE without an
  offer, answered in the ACK by a `Negotiate` provider.
* [`examples/ua-fork`](examples/ua-fork): a caller that takes a 2xx from
  each of two forks, keeps one session and ends the other.
* [`examples/ua-shutdown`](examples/ua-shutdown): a UA that shuts down with
  a call up and one ringing, and ends both.

signa-core's [`tests/tower_fixture.rs`](crates/signa-core/tests/tower_fixture.rs)
builds a Tower adapter and a bounded dispatcher outside signa, against its
public API only. signa has no Tower dependency.

### Supported RFC scope

signa implements parts of these RFCs and tests each of them. It does not claim
conformance to any of them as a whole.

* RFC 3261: message parsing and encoding, TCP framing, client and server
  transactions and their matching, the non-2xx ACK, CANCEL, UDP and TCP
  response routing, and stateless forwarding primitives over UDP.
* RFC 6026: the Accepted states, Timers L and M, every 2xx to the TU, and
  discarding stray responses.
* RFC 4320: the automatic 100 Trying and the responses a non-INVITE may not
  send.
* RFC 3581: `received` and `rport`.

The [crate documentation] lists what is supported, partial, left to the TU and
unsupported, section by section. [`docs/rfc-test-map.md`](docs/rfc-test-map.md)
maps each requirement to its tests. signa-ua's scope is above, and in its own
map.

### Deliberate omissions

signa-core has no dialog or call layer, which signa-ua adds for INVITE
sessions. Neither has TLS, and so SIPS, nor RFC 3263 resolution, PRACK,
session timers, authentication, SDP or media, and neither has proxy routing
logic. Stateless reception is UDP-only and cannot share an endpoint with
stateful reception. RFC 2543 transactions are not matched. signa-core refuses
`sips:` Request-URIs, but checks nothing else about SIPS, Route or the target,
which signa-ua does for the requests it sends. A `sip:` URI does not make
plaintext safe.

### Features and MSRV

* `tokio`, on by default, enables the endpoint and its sockets. Without it the
  message types, transaction timer configuration and transport metadata stay
  available without a runtime.
* `ua` adds signa-ua as the `signa::ua` module, and turns on `tokio`, since a
  UA runs on an endpoint.

The minimum supported Rust version is 1.85.

### Documentation

* [API documentation on docs.rs](https://docs.rs/signa), with the TU boundary,
  the lifetimes it separates, and the RFC scope in the crate documentation.
* [`docs/rfc-test-map.md`](docs/rfc-test-map.md), requirements and their
  tests.
* [signa-ua's documentation](https://docs.rs/signa-ua), with what the UA does
  and how to run it, and
  [`docs/signa-ua-rfc-test-map.md`](docs/signa-ua-rfc-test-map.md), its
  requirements and their tests.
* [siparse], the SIP message head parser signa builds on.

[siparse]: https://docs.rs/siparse
[crate documentation]: https://docs.rs/signa

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.
