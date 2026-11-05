/*!
Non-INVITE transactions, sans-IO.

RFC 3261 section 17 defines a transaction as one request, its retransmissions,
and the responses to it. The client side retransmits over an unreliable
transport until a response arrives, and the server side answers retransmissions
with the last response instead of handing them up again. This module has the
non-INVITE state machines (sections 17.1.2 and 17.2.2) and the keys that match
a message to a transaction (sections 17.1.3 and 17.2.3). INVITE transactions
wait for 0.3.0.

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

mod client;
mod key;
mod server;

use std::time::Duration;

pub use self::{
    client::{ClientEvent, ClientTransaction},
    key::{ClientKey, ServerKey},
    server::ServerTransaction,
};

/// The timer values of RFC 3261 section 17.1.2.2.
///
/// `t1` is the round-trip time estimate, `t2` the longest interval between
/// retransmissions of a non-INVITE request, and `t4` how long a message stays
/// in the network. The transaction timeout, Timer F on the client and Timer J
/// on the server, is 64 times `t1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timers {
    /// T1, 500 ms by default.
    pub t1: Duration,
    /// T2, 4 s by default.
    pub t2: Duration,
    /// T4, 5 s by default.
    pub t4: Duration,
}

impl Default for Timers {
    fn default() -> Timers {
        Timers {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
        }
    }
}

impl Timers {
    /// Timer F and Timer J.
    fn transaction_timeout(&self) -> Duration {
        self.t1 * 64
    }

    /// How long a server waits before it answers a non-INVITE request with a
    /// 100 of its own.
    ///
    /// RFC 4320 section 4.1 forbids a 100 over an unreliable transport before
    /// the client's Timer E would be reset to T2, and requires one after that
    /// time if nothing else was sent. Timer E starts at T1 and doubles after
    /// each retransmission until it reaches T2, so that moment comes after the
    /// intervals below T2 have all passed. With the defaults that is
    /// T1 + 2 T1 + 4 T1, or 3.5 s.
    fn trying_after(&self) -> Duration {
        let mut total = Duration::ZERO;
        let mut interval = self.t1;
        while !interval.is_zero() && interval < self.t2 {
            total += interval;
            interval *= 2;
        }

        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trying_after_is_when_timer_e_reaches_t2() {
        let timers = Timers::default();
        assert_eq!(timers.trying_after(), Duration::from_millis(3500));
        assert_eq!(timers.transaction_timeout(), Duration::from_secs(32));

        // E starts at T2, so the first retransmission already uses it.
        let flat = Timers { t1: Duration::from_secs(4), ..timers };
        assert_eq!(flat.trying_after(), Duration::ZERO);

        // A zero T1 is nonsense, but must not loop forever.
        let zero = Timers { t1: Duration::ZERO, ..timers };
        assert_eq!(zero.trying_after(), Duration::ZERO);
    }
}
