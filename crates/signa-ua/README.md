<div align="center">

signa-ua
========
Dialogs and INVITE usage for SIP user agents, on [signa-core].

</div>

<br>

It keeps the dialogs that INVITEs form and the INVITE session of each, on top
of signa-core's transactions. It acknowledges each 2xx that forms a dialog,
within its limits, sends its own 2xx again until the ACK, and answers what the
application leaves unanswered. Call policy, SDP and media stay with the
application. It is at an early stage,
implements parts of RFC 3261 and RFC 6141, claims conformance to neither as a
whole, and is not a complete UA.

The [signa] crate re-exports it as `signa::ua` behind its `ua` feature, and
most code depends on that instead. The [repository README] has the examples,
the [crate documentation] what the UA does, what it does not do yet and how to
run it, and the [RFC and test map] which tests show each rule.

[signa-core]: https://docs.rs/signa-core
[signa]: https://docs.rs/signa
[repository README]: https://github.com/ryumatag/signa
[crate documentation]: https://docs.rs/signa-ua
[RFC and test map]: https://github.com/ryumatag/signa/blob/main/docs/signa-ua-rfc-test-map.md

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.
