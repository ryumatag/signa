<div align="center">

signa
=====
A fast and correct low-level SIP library in Rust.

[![Build status](https://github.com/ryumatag/signa/actions/workflows/ci.yml/badge.svg)](https://github.com/ryumatag/signa/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/signa.svg)](https://crates.io/crates/signa)
[![Docs.rs](https://img.shields.io/docsrs/signa)](https://docs.rs/signa)

</div>

<br>

signa does for SIP roughly what `hyper` does for HTTP. It carries messages over
UDP and TCP, runs the RFC 3261 transactions, and hands requests to application
code through a Tower `Service`. Its design draws heavily on the [`http`] and
[`hyper`] crates.

The current release has request and response types modeled on the `http` crate,
parsing with [siparse] and encoding, and an endpoint that carries messages over
UDP and TCP, runs the non-INVITE transactions, and serves requests through a
Tower `Service`. Its client sends requests to one next hop and is a `Service`
too, and the endpoint shuts down gracefully. INVITE, ACK, and CANCEL
transactions are planned for the next release, and TLS and next-hop selection
are later work. The [crate docs] say what is covered in detail.

[`http`]: https://docs.rs/http
[`hyper`]: https://docs.rs/hyper
[siparse]: https://docs.rs/siparse
[crate docs]: https://docs.rs/signa

### Modules

`message` contains the SIP message model, construction, parsing and encoding.
The main types remain available at the crate root, such as `signa::Request`.
Use `signa::message::request::Parts`, `signa::message::header::VIA` and
`signa::message::BuildError` for detailed message APIs.

`transaction::Timers` configures transaction deadlines.
`transport::{Flow, Transport, MessageLimits}` describes transport metadata and
stream receive limits. These APIs are runtime independent. The `tokio` feature
enables the endpoint and sockets. State machines, sockets and framing remain
internal implementation details.

### Example

A UAS that answers every request with a 200:

```rust
use std::convert::Infallible;

use bytes::Bytes;
use signa::{endpoint::Endpoint, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let endpoint = Endpoint::builder()
        .udp("0.0.0.0:5060".parse().unwrap())
        .tcp("0.0.0.0:5060".parse().unwrap())
        .serve(tower::service_fn(|request: Request<Bytes>| async move {
            // The response carries the header fields the endpoint routes
            // it by, copied from the request.
            let response = Response::reply_to(&request)
                .status(StatusCode::OK)
                .body(Bytes::new())
                .expect("the status is set");
            Ok::<_, Infallible>(response)
        }))?;

    // The endpoint runs as long as a handle to it exists.
    std::future::pending::<()>().await;
    drop(endpoint);
    Ok(())
}
```

`examples/options.rs` has both sides, a server and a client that sends it an
`OPTIONS` over UDP and over TCP.

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.
