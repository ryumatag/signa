<div align="center">

signa-core
==========
The SIP messages, transports and transactions of [signa], down to the last
retransmission.


</div>

<br>

It carries messages over UDP and TCP, runs the RFC 3261 transactions with the
changes of RFC 6026 and RFC 4320, and hands requests and responses to
application code at the transaction-user boundary. The [signa] crate re-exports
it, and most code depends on that instead. [signa-ua] keeps dialogs and INVITE
usage on its public API, and signa-core does not depend on it.

The [repository README] has the quick start and the examples, and the
[crate documentation] the RFC scope.

[signa]: https://docs.rs/signa
[signa-ua]: https://docs.rs/signa-ua
[repository README]: https://github.com/ryumatag/signa
[crate documentation]: https://docs.rs/signa-core

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.
