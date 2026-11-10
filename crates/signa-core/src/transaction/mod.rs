/*!
SIP transaction timer configuration.

[`Timers`] sets the RFC transaction intervals used by the endpoint. The
state machines and transaction keys remain internal protocol machinery.

RFC 3261 section 17 defines a transaction as one request, its retransmissions,
and the responses to it. The client side retransmits over an unreliable
transport until a response arrives, and the server side answers retransmissions
with the last response instead of handing them up again. The INVITE machines
apply RFC 6026. The endpoint drives both kinds. Matching follows sections
17.1.3 and 17.2.3, and a CANCEL finds its target as section 9.2 says.

The machines own no runtime timers and do no I/O. Each takes the current time
with every event, reports its next deadline, and says what to send or hand up.
A driver on any runtime, and a test with a fixed clock, can run them the same
way.

RFC 4320 changes what a non-INVITE server sends. No provisional response other
than 100, no 100 over an unreliable transport before the client's Timer E would
reach T2, a 100 after that time if nothing else was sent, and no 408 at all.
The server machine applies all four, so the transaction user only ever supplies
a final response.
*/

pub use self::timers::{InvalidTimers, Timers, TimersBuilder};

#[cfg(all(any(feature = "tokio", test), not(feature = "__bench")))]
#[allow(unreachable_pub, dead_code, unused_imports)]
pub(crate) mod invite;
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod invite;
#[cfg(any(feature = "tokio", feature = "__bench", test))]
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
pub(crate) mod key;
#[cfg(all(any(feature = "tokio", test), not(feature = "__bench")))]
#[allow(unreachable_pub)]
#[cfg_attr(not(feature = "tokio"), allow(dead_code, unused_imports))]
pub(crate) mod non_invite;
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod non_invite;
mod timers;
