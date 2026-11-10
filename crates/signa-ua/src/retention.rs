/*!
What the UA keeps of a 2xx after its usage moves on.

A 2xx to an INVITE leaves an ACK obligation and a window in which copies of it
keep arriving. For a sent INVITE, the peer retransmits the 2xx until it sees
the ACK, and the core delivers each copy until Timer M ends the response
collection ([RFC 6026 section 7.2]). For a received one, this user agent
retransmits the 2xx until the ACK or its deadline
([RFC 3261 section 13.3.1.4]). Neither window cares whether the session is
still up. A BYE can end the usage while the window is open, and the duplicates
must still be answered with the ACK already sent, not taken for a new
session.

A [`ReplayContext`] holds that state, keyed by what identifies a 2xx on the
wire: the dialog, the INVITE's CSeq and the direction. It keeps the `DialogId`
itself rather than the dialog's key, so it can outlive the dialog record.

[RFC 6026 section 7.2]: https://www.rfc-editor.org/rfc/rfc6026.html#section-7.2
[RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
*/

use crate::{
    dialog::DialogId,
    invite::{AttemptKey, Direction, ExchangeKey, UsageKey},
    slot::Key,
};

pub(crate) type ReplayKey = Key<ReplayContext>;

/// What identifies a 2xx and its ACK on the wire.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReplayId {
    pub(crate) dialog: DialogId,
    pub(crate) cseq: u32,
    pub(crate) direction: Direction,
}

/// Where the ACK of a 2xx stands.
///
/// A context exists only for a 2xx, so there is always an obligation of some
/// kind. The ACK of a non-2xx is the core's and never appears here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckObligation {
    /// This user agent owes the ACK of a 2xx it received.
    NeedToSend,
    /// This user agent sent the 2xx and waits for the peer's ACK.
    AwaitingPeer,
    /// The ACK was written, or received.
    Satisfied,
    /// The ACK could not be written, or did not arrive by its deadline.
    Failed,
}

/// Whether a replay context is still needed, and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Retention {
    /// Its usage is up, and duplicates may still arrive.
    Live,
    /// Its usage ended, and duplicates may still arrive.
    ReplayOnly,
    /// No more duplicates can arrive. The model drops it.
    Reclaimable,
}

/// Where the duplicates of a 2xx come from, which says when they stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// A 2xx to an attempt this user agent sent. Duplicates stop when the
    /// core finishes the attempt's response collection.
    Attempt(AttemptKey),
    /// A 2xx this user agent sent for an exchange. Its retransmissions stop
    /// at the ACK or the ACK deadline.
    Exchange(ExchangeKey),
}

/// The state needed to answer the duplicates of one 2xx.
///
/// TODO: Keep the 2xx this user agent sent with its reply route, and the ACK
/// it sent for a received 2xx. That ACK is fixed when first sent and reused
/// for each duplicate, as RFC 3261 section 13.2.2.4 has the UAC core pass
/// each retransmitted 2xx to the ACK it already built.
#[derive(Debug)]
pub(crate) struct ReplayContext {
    pub(crate) id: ReplayId,
    pub(crate) source: Source,
    pub(crate) usage: UsageKey,
    pub(crate) ack: AckObligation,
    usage_ended: bool,
    duplicates_end: bool,
}

impl ReplayContext {
    pub(crate) fn new(
        id: ReplayId,
        source: Source,
        usage: UsageKey,
    ) -> ReplayContext {
        let ack = match id.direction {
            Direction::Outgoing => AckObligation::NeedToSend,
            Direction::Incoming => AckObligation::AwaitingPeer,
        };

        ReplayContext {
            id,
            source,
            usage,
            ack,
            usage_ended: false,
            duplicates_end: false,
        }
    }

    /// Records that the usage ended. The context stays while duplicates can
    /// still arrive.
    pub(crate) fn usage_ended(&mut self) {
        self.usage_ended = true;
    }

    /// Records that no more duplicates can arrive.
    pub(crate) fn duplicates_ended(&mut self) {
        self.duplicates_end = true;
    }

    /// Derived from the two facts above, so it cannot disagree with them.
    pub(crate) fn retention(&self) -> Retention {
        match (self.duplicates_end, self.usage_ended) {
            (true, _) => Retention::Reclaimable,
            (false, true) => Retention::ReplayOnly,
            (false, false) => Retention::Live,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        invite::{InviteExchange, InviteUsage},
        negotiation::Negotiation,
        slot::Slots,
    };

    fn context(direction: Direction) -> ReplayContext {
        let record = crate::tests::dialog();
        let dialog = record.id().clone();
        let dialog_key = Slots::new(1).insert(record).unwrap();
        let usage = Slots::new(1)
            .insert(InviteUsage::established(
                dialog_key,
                direction,
                Negotiation::Stable,
            ))
            .unwrap();
        let exchange =
            Slots::new(1).insert(InviteExchange::outgoing(1)).unwrap();

        ReplayContext::new(
            ReplayId { dialog, cseq: 1, direction },
            Source::Exchange(exchange),
            usage,
        )
    }

    #[test]
    fn the_direction_sets_who_owes_the_ack() {
        assert_eq!(
            context(Direction::Outgoing).ack,
            AckObligation::NeedToSend
        );
        assert_eq!(
            context(Direction::Incoming).ack,
            AckObligation::AwaitingPeer
        );
    }

    #[test]
    fn retention_follows_the_duplicates_not_the_usage() {
        let mut replay = context(Direction::Outgoing);
        assert_eq!(replay.retention(), Retention::Live);

        replay.usage_ended();
        assert_eq!(replay.retention(), Retention::ReplayOnly);

        replay.duplicates_ended();
        assert_eq!(replay.retention(), Retention::Reclaimable);
    }

    #[test]
    fn a_live_usage_does_not_keep_a_finished_context() {
        let mut replay = context(Direction::Incoming);

        replay.duplicates_ended();
        assert_eq!(replay.retention(), Retention::Reclaimable);
    }
}
