<div align="center">

signa
=====
A fast and correct low-level SIP library in Rust.

[![Build status](https://github.com/ryumatag/signa/actions/workflows/ci.yml/badge.svg)](https://github.com/ryumatag/signa/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/signa.svg)](https://crates.io/crates/signa)
[![Docs.rs](https://img.shields.io/docsrs/signa)](https://docs.rs/signa)

</div>

<br>

signa aims to do for SIP roughly what `hyper` does for HTTP. It will carry
messages over UDP and TCP, run the RFC 3261 transactions, and hand requests to
application code through a Tower `Service`. Its design draws heavily on the
[`http`] and [`hyper`] crates.

The current release provides the message layer. It has request and response
types modeled on the `http` crate, parses one complete message from bytes with
[siparse], and encodes messages back to bytes. It does not frame streams, do
I/O, or run transactions yet. Those are planned for the next releases.

[`http`]: https://docs.rs/http
[`hyper`]: https://docs.rs/hyper
[siparse]: https://docs.rs/siparse

### Example

```rust
use bytes::Bytes;
use signa::{header::CALL_ID, Message, Method};

let datagram = Bytes::from_static(
    b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n\
      Call-ID: a84b4c76e66710\r\n\
      Content-Length: 0\r\n\
      \r\n",
);

let Message::Request(request) = Message::from_shared(datagram)? else {
    return Ok(());
};
assert_eq!(request.method(), Method::OPTIONS);
assert_eq!(request.headers().get(CALL_ID).unwrap(), "a84b4c76e66710");

// Encoding writes the start-line and header values as stored. Header
// names come out in their long form, and `Content-Length` is computed
// from the body.
assert!(request.to_bytes().starts_with(b"OPTIONS sip:carol@"));
```

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.
