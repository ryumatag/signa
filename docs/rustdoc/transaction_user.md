# The transaction user

[RFC 3261 section 17] divides a SIP element into a transaction layer and the
transaction user (TU) above it. The transaction layer matches messages to
transactions, retransmits, runs the timers and passes responses up. The TU is
the rest of the element, such as the core of a UA, a registrar, a proxy or a
B2BUA.

signa is the transaction layer and the transport under it. The [`endpoint`]
module is its side of the boundary, as owned events, handles and operations:

* [`Incoming::recv`] yields each [`IncomingEvent`]: a new request with its
  [`ServerTransaction`], a CANCEL with its target, an ACK for a 2xx, and
  requests that get no transaction.
* A [`ServerTransaction`] splits into a [`Responder`], which submits
  responses, and [`ServerEvents`], which observes what becomes of them.
* [`Endpoint::start`] returns a [`ClientTransaction`], which splits into a
  [`ClientControl`], which can cancel an INVITE, and its [`Responses`].
* [`Endpoint::send_request`], [`Endpoint::forward_response`] and
  [`ReplyRoute::send`] send one message without a transaction.
* [`Endpoint::shutdown`] drains the endpoint, and a [`WorkGuard`] holds the
  drain for the TU's own work.

The TU is whatever code uses these. It is not a trait, and signa defines no
service trait for it to implement. A receive loop is enough. An adapter to
Tower or another framework lives outside signa, and `tests/tower_fixture.rs`
builds one against the public API.

signa:

* parses, frames and encodes messages,
* matches requests and responses to transactions, retransmits, absorbs
  retransmissions and times transactions out,
* sends 100 Trying for an INVITE, and for a non-INVITE when RFC 4320 says so,
* acknowledges a non-2xx final response to an INVITE,
* keeps an INVITE that got a 2xx in Accepted for Timer L or M,
* routes responses by the connection or local address a request came in on,
  and by Via, `received` and `rport`,
* bounds the work it holds and drains it at shutdown.

The TU:

* keeps dialogs and calls,
* sends the ACK for each 2xx, with [`Endpoint::send_request`],
* retransmits its own 2xx until the ACK, through a [`ReplyRoute`], over TCP
  too,
* decides what a CANCEL means: a 200 and a 487 for a UAS, cancelled branches
  for a proxy,
* does a proxy's validation, Route and Record-Route processing, target
  selection, forking, best-response choice and Timer C,
* picks each request's next hop, RFC 3263 resolution included, as a
  [`Target`],
* does authentication, registration, SDP and media,
* dispatches requests to handlers, bounds them, and times them out.

# Lifetimes

Four lifetimes meet at the boundary. Each ends for its own reason, and the
end of one does not imply the end of another.

| Lifetime | Owner | Ends when | The TU sees it through |
| --- | --- | --- | --- |
| Transport submission | The transport | The local write succeeds or fails | A one-shot send's future, [`ServerEvent::TransportFailure`], [`Error::is_transport`] |
| SIP transaction | The driver | Its machine reaches Terminated on its timers | [`ServerEvent::Terminated`] |
| TU work | The application | The application is done with it | Nothing, unless it holds a [`WorkGuard`] |
| Dialog or call | A layer above signa | Its own policy, such as a BYE | Nothing in signa |

In particular:

* **A local write is not delivery.** [`Responder::respond`] and
  [`Endpoint::start`] return once the driver accepts the operation, and the
  one-shot sends once the local write finishes. [`ClientControl::cancel`]
  waits for a provisional response, then returns once the CANCEL has its own
  transaction. A TCP write can fail after part of it went out. Only a SIP
  response shows that a peer got a request.
* **A final response does not end its transaction.** Over UDP a non-INVITE
  stays for Timer J or K, and an INVITE with a non-2xx for Timer D, or
  Timers H and I on the server. An INVITE with a 2xx stays in Accepted for
  Timer L or M, 64 T1 on UDP and TCP, to take further 2xx, including other
  forks', and their ACKs ([RFC 6026 section 8.4]). Its [`Responses`] keeps
  yielding 2xx until Timer M.
* **An application timeout is not a SIP timeout.** signa's Timers B and F
  end a client transaction with [`Error::is_timeout`]. A timeout around the
  application's own work changes no SIP timer. If it drops an unanswered
  [`Responder`], signa sends its 500.
* **Dropping a future or a handle is not CANCEL.** Only
  [`ClientControl::cancel`] sends one, and the CANCEL is a transaction of its
  own. Dropping [`ClientControl`], [`Responses`] or the future of
  [`Endpoint::start`] leaves the INVITE running, and a 2xx to it then goes
  unacknowledged.
* **A handler returning does not end its transaction.** The transaction ends
  on its timers, whether its handles are still held or not.
* **A graceful shutdown is not a dialog teardown.**
  [`ShutdownOutcome::Drained`] means that signa's transactions, writes and
  connects, and every [`WorkGuard`], finished before the deadline. It sends
  no BYE, does not wait for tasks the TU did not guard, and says nothing about
  what a peer received.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 6026 section 8.4]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
[`Incoming::recv`]: endpoint::Incoming::recv
[`IncomingEvent`]: endpoint::IncomingEvent
[`ServerTransaction`]: endpoint::ServerTransaction
[`Responder`]: endpoint::Responder
[`Responder::respond`]: endpoint::Responder::respond
[`ServerEvents`]: endpoint::ServerEvents
[`ServerEvent::TransportFailure`]: endpoint::ServerEvent::TransportFailure
[`ServerEvent::Terminated`]: endpoint::ServerEvent::Terminated
[`Endpoint::start`]: endpoint::Endpoint::start
[`Endpoint::send_request`]: endpoint::Endpoint::send_request
[`Endpoint::forward_response`]: endpoint::Endpoint::forward_response
[`Endpoint::shutdown`]: endpoint::Endpoint::shutdown
[`ClientTransaction`]: endpoint::ClientTransaction
[`ClientControl`]: endpoint::ClientControl
[`ClientControl::cancel`]: endpoint::ClientControl::cancel
[`Responses`]: endpoint::Responses
[`ReplyRoute`]: endpoint::ReplyRoute
[`ReplyRoute::send`]: endpoint::ReplyRoute::send
[`Target`]: endpoint::Target
[`WorkGuard`]: endpoint::WorkGuard
[`ShutdownOutcome::Drained`]: endpoint::ShutdownOutcome::Drained
[`Error::is_timeout`]: endpoint::Error::is_timeout
[`Error::is_transport`]: endpoint::Error::is_transport
