/*!
SIP transactions, sans-IO.

RFC 3261 section 17 defines a transaction as one request, its retransmissions,
and the responses to it. The client side retransmits over an unreliable
transport until a response arrives, and the server side answers retransmissions
with the last response instead of handing them up again. The INVITE machines
apply RFC 6026. The endpoint currently drives only the non-INVITE machines.
Matching follows sections 17.1.3 and 17.2.3.

The machines keep no timers and do no I/O. Each takes the current time with
every event, reports its next deadline, and says what to send or hand up. A
driver on any runtime, and a test with a fixed clock, can run them the same
way.

RFC 4320 changes what a non-INVITE server sends. No provisional response other
than 100, no 100 over an unreliable transport before the client's Timer E would
reach T2, a 100 after that time if nothing else was sent, and no 408 at all.
The server machine applies all four, so the transaction user only ever supplies
a final response.
*/

pub(crate) use self::server::bare_response;
pub use self::{
    client::{ClientEvent, ClientTransaction},
    key::{ClientKey, ServerKey},
    server::ServerTransaction,
    timers::{InvalidTimers, Timers, TimersBuilder},
};

mod client;
// These machines are wired into the endpoint in the INVITE endpoint item.
#[cfg_attr(not(feature = "__bench"), allow(dead_code, unused_imports))]
pub mod invite;
mod key;
mod server;
mod timers;
