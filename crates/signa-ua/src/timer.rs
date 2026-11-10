/*!
The UA core's own timers.

None of them is a transaction timer. Timers A to M stay in signa-core. These
are the timers RFC 3261 gives the UA core around an INVITE, and the deadlines
of my own policy:

* the deadline for the application's decision on an incoming INVITE,
* the provisional response a UAS sends again every minute while it rings
  ([RFC 3261 section 13.3.1.1]),
* the retransmission of a 2xx this user agent sent, and the deadline for its
  ACK ([RFC 3261 section 13.3.1.4]).

The queue keeps one entry per timer that is set, sorted by when it is due. The
record a timer is for holds that instant, so cancelling it finds the entry, and
no entry outlives its record. The queue is therefore bounded by the tables of
the records it serves.

[RFC 3261 section 13.3.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.1
[RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
*/

use std::{collections::BTreeSet, time::Instant};

use crate::{invite::ExchangeKey, retention::ReplayKey};

/// What a timer is for.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Timer {
    /// The application has not decided an incoming INVITE in time.
    Decision(ExchangeKey),
    /// An incoming INVITE expired, as its Expires said.
    Expires(ExchangeKey),
    /// The provisional response of an incoming INVITE is due again.
    Provisional(ExchangeKey),
    /// The 2xx of an incoming INVITE is due again.
    Retransmit(ReplayKey),
    /// The ACK of a 2xx this user agent sent is overdue.
    AckDeadline(ReplayKey),
}

/// The timers that are set, by when they are due.
#[derive(Debug, Default)]
pub(crate) struct TimerQueue {
    entries: BTreeSet<(Instant, Timer)>,
}

impl TimerQueue {
    pub(crate) fn set(&mut self, at: Instant, timer: Timer) {
        self.entries.insert((at, timer));
    }

    /// Cancels a timer set for `at`. Cancelling one that already fired or
    /// was never set does nothing.
    pub(crate) fn cancel(&mut self, at: Instant, timer: Timer) {
        self.entries.remove(&(at, timer));
    }

    /// Returns when the next timer is due.
    pub(crate) fn next(&self) -> Option<Instant> {
        self.entries.first().map(|&(at, _)| at)
    }

    /// Takes the earliest timer due by `now`, with the instant it was set
    /// for.
    pub(crate) fn pop_due(
        &mut self,
        now: Instant,
    ) -> Option<(Instant, Timer)> {
        let &(at, _) = self.entries.first()?;
        if at > now {
            return None;
        }
        self.entries.pop_first()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{invite::InviteExchange, slot::Slots};

    #[test]
    fn timers_fire_in_order_and_once() {
        let mut slots = Slots::new(2);
        let first = slots.insert(InviteExchange::outgoing(1)).unwrap();
        let second = slots.insert(InviteExchange::outgoing(2)).unwrap();
        let start = Instant::now();
        let mut queue = TimerQueue::default();

        queue.set(start + Duration::from_secs(2), Timer::Decision(first));
        queue.set(start + Duration::from_secs(1), Timer::Provisional(second));
        queue.set(start + Duration::from_secs(3), Timer::Decision(second));
        queue.cancel(start + Duration::from_secs(3), Timer::Decision(second));

        assert_eq!(queue.next(), Some(start + Duration::from_secs(1)));
        assert_eq!(queue.pop_due(start), None);
        let due = start + Duration::from_secs(2);
        assert_eq!(
            queue.pop_due(due),
            Some((start + Duration::from_secs(1), Timer::Provisional(second))),
        );
        assert_eq!(queue.pop_due(due), Some((due, Timer::Decision(first))));
        assert_eq!(queue.pop_due(due + Duration::from_secs(9)), None);
        assert_eq!(queue.len(), 0);
    }
}
