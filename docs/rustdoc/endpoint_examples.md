### Quick start

A UAS and a UAC on the loopback. The UAS answers an OPTIONS through its server
transaction, the UAC reads the response from its client transaction, and both
shut down gracefully.

```
use std::time::Duration;

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent, Target},
    message::header::Tag,
    transport::Transport,
    Request, Response, StatusCode,
};

# #[cfg(miri)] // Miri has no sockets.
# fn main() {}
# #[cfg(not(miri))]
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
// Port 0 lets the system pick one. Keep each `Incoming`, since dropping it
// shuts its endpoint down.
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
let (_control, mut responses) = uac.start(request, target).await?.into_parts();

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

// Over TCP both transactions end with the final response. Over UDP the drain
// would wait for Timers J and K, 32 and 5 seconds by default.
assert!(uac.shutdown(Duration::from_secs(5)).await.is_drained());
assert!(uas.shutdown(Duration::from_secs(5)).await.is_drained());
# Ok(())
# }
```

The [`endpoint`] module has the details of reception, admission and shutdown,
and [`IncomingEvent`](endpoint::IncomingEvent) a receive loop over every
event.

### Protocol examples

The repository's `examples/` directory has complete programs. Each runs on the
loopback, checks its own outcome, and says which TU duties it takes on and
which it leaves out:

* [`options.rs`]: a non-INVITE responder over UDP and TCP, with transaction
  observation and a drained shutdown.
* [`invite_uas.rs`]: an INVITE UAS that retransmits its 2xx until the ACK
  under a [`WorkGuard`](endpoint::WorkGuard), answers CANCEL, and compares a
  drained shutdown with a forced one.
* [`invite_uac.rs`]: an INVITE UAC that acknowledges forked and retransmitted
  2xx and cancels calls, including a CANCEL that loses to a 2xx.
* [`fork_proxy.rs`]: a stateful proxy that forks an INVITE to two UASes,
  relays every 2xx, and cancels the other branches.
* [`stateless_proxy.rs`]: a UDP stateless proxy with a stable branch for an
  INVITE, its CANCEL and its ACK.

[`tower_fixture.rs`] builds a Tower adapter and a bounded dispatcher against
the public API only, as a crate outside signa would.

[`options.rs`]: https://github.com/ryumatag/signa/blob/main/examples/options.rs
[`invite_uas.rs`]: https://github.com/ryumatag/signa/blob/main/examples/invite_uas.rs
[`invite_uac.rs`]: https://github.com/ryumatag/signa/blob/main/examples/invite_uac.rs
[`fork_proxy.rs`]: https://github.com/ryumatag/signa/blob/main/examples/fork_proxy.rs
[`stateless_proxy.rs`]: https://github.com/ryumatag/signa/blob/main/examples/stateless_proxy.rs
[`tower_fixture.rs`]: https://github.com/ryumatag/signa/blob/main/tests/tower_fixture.rs

