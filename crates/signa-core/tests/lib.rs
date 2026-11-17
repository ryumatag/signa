/*!
The endpoint through its public API only, as any crate built on signa-core
sees it.

* `reply_routing`: where a stateful endpoint sends its responses, over
  loopback sockets.
* `datagram`: an endpoint whose UDP datagrams travel over a backend of the
  application's own, and ports that several endpoints share.
* `tower`: an external Tower adapter and a bounded dispatcher for the
  transaction-user API, against endpoints on loopback.

`support` holds what more than one of them uses.
*/

mod datagram;
mod reply_routing;
mod support;
mod tower;
