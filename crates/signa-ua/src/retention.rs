/*!
What the UA keeps of a 2xx after its usage moves on.

A 2xx to an INVITE leaves an ACK obligation and a window in which copies of it
keep arriving. For a sent INVITE, the peer retransmits the 2xx until it sees
the ACK, and the core delivers each copy until Timer M ends the response
collection ([RFC 6026 section 8.4]). For a received one, this user agent
retransmits the 2xx until the ACK or its deadline
([RFC 3261 section 13.3.1.4]). Neither window cares whether the session is
still up. A BYE can end the usage while the window is open, and the duplicates
must still be answered with the ACK already sent, not taken for a new
session.

A [`ReplayContext`] holds that state, keyed by what identifies a 2xx on the
wire: the dialog, the INVITE's CSeq and the direction. It keeps the `DialogId`
itself rather than the dialog's key, so it can outlive the dialog record. It
only answers duplicates. Nothing waits for it to go, so the core keeping the
INVITE transaction in Accepted holds up no request in the dialog.

A 2xx to a sent INVITE that the UA does not keep as a session gets a context
too, a cleanup. RFC 3261 section 13.2.2.4 asks for the ACK of every 2xx, and
for a BYE after it for each dialog the UAC does not want, as for a fork beyond
the UA's limits. A cleanup has no usage. It holds the dialog that no table
does, to build the ACK and the BYE from, and stays until both the duplicates
and the BYE are done with.

[RFC 6026 section 8.4]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
[RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
*/

use std::time::{Duration, Instant};

use crate::{
    dialog::{Dialog, DialogId},
    invite::{AttemptKey, Direction, ExchangeKey, UsageKey},
    negotiation::Description,
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

/// What the ACK of a received 2xx carries.
///
/// An ACK carries the answer when its 2xx carried the offer (RFC 3261 section
/// 13.2.1), and the answer is fixed once it is in. Every copy of the ACK
/// carries the same one, and a copy of the 2xx asks for no new answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AckBody {
    /// No session description, as when the 2xx carried the answer.
    Empty,
    /// The ACK waits for the answer to the 2xx's offer, which the runtime
    /// prepares outside the driver.
    Preparing,
    /// The answer to the 2xx's offer.
    Answer(Description),
    /// No answer could be had for the 2xx's offer, so the ACK goes without
    /// one. It still stops the 2xx's retransmissions, but it does not
    /// complete the exchange, and the dialog ends with a BYE after it.
    Unanswered,
}

/// Where the BYE of a cleanup stands.
///
/// RFC 3261 section 13.2.2.4 has the UAC send the BYE after it acknowledged
/// the 2xx, so the BYE waits for the first try of the ACK, whether or not
/// that got out. A copy of the 2xx brings the ACK again, not the BYE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Bye {
    /// The BYE goes once the ACK has had its first try.
    Owed,
    /// The runtime is sending the BYE.
    Sending,
    /// The BYE went to the core, or could not.
    Done,
}

/// Whether a replay context is still needed, and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Retention {
    /// Its usage is up, and duplicates may still arrive.
    Live,
    /// Its usage ended, or it never had one, and duplicates may still
    /// arrive or its BYE is still to go.
    ReplayOnly,
    /// No more duplicates can arrive and no BYE is owed. The model drops it.
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

/// The retransmission of a 2xx this user agent sent, until its ACK.
///
/// RFC 3261 section 13.3.1.4 starts the interval at T1 and doubles it up to
/// T2. The deadline is 64 T1 after the UA learned that the core took the
/// 2xx, and stays there whatever the retransmissions do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Retransmission {
    /// When the 2xx goes out again, or `None` once the next copy would not
    /// fall before `deadline`.
    pub(crate) next: Option<Instant>,
    /// The interval that ends at `next`. The one after it is twice as long,
    /// up to T2.
    pub(crate) interval: Duration,
    pub(crate) deadline: Instant,
}

/// The state needed to answer the duplicates of one 2xx.
///
/// The messages themselves stay with the runtime: the 2xx this user agent
/// sent, with its responder, and the ACK it sent for a received 2xx, fixed
/// when first sent and reused for each duplicate.
#[derive(Debug)]
pub(crate) struct ReplayContext {
    pub(crate) id: ReplayId,
    pub(crate) source: Source,
    /// The session the 2xx formed, or `None` for a cleanup.
    pub(crate) usage: Option<UsageKey>,
    pub(crate) ack: AckObligation,
    /// What the ACK of a received 2xx carries. A 2xx this user agent sent
    /// keeps `Empty`.
    pub(crate) ack_body: AckBody,
    /// Set for a 2xx this user agent sent, while it awaits the ACK.
    pub(crate) retransmission: Option<Retransmission>,
    /// The dialog of a cleanup, until its BYE is built. A session's dialog
    /// is in the dialog table instead.
    pub(crate) dialog: Option<Box<Dialog>>,
    /// Set for a cleanup only. A session's BYE is its usage's.
    pub(crate) bye: Option<Bye>,
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
            usage: Some(usage),
            ack,
            ack_body: AckBody::Empty,
            retransmission: None,
            dialog: None,
            bye: None,
            usage_ended: false,
            duplicates_end: false,
        }
    }

    /// Creates the context of a 2xx to `attempt` that the UA acknowledges
    /// and then ends with a BYE, built from `dialog`, without a session.
    pub(crate) fn cleanup(
        id: ReplayId,
        attempt: AttemptKey,
        dialog: Dialog,
    ) -> ReplayContext {
        debug_assert_eq!(id.direction, Direction::Outgoing);

        ReplayContext {
            id,
            source: Source::Attempt(attempt),
            usage: None,
            ack: AckObligation::NeedToSend,
            ack_body: AckBody::Empty,
            retransmission: None,
            dialog: Some(Box::new(dialog)),
            bye: Some(Bye::Owed),
            usage_ended: true,
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

    /// Derived from the facts above, so it cannot disagree with them.
    ///
    /// The first ACK of a received 2xx holds the context too, until its
    /// first try is over, and so does an answer it waits for. The ACK is owed
    /// whether or not copies of the 2xx still come, and what follows it, such
    /// as a BYE that waits for it, goes from its record.
    pub(crate) fn retention(&self) -> Retention {
        let bye_owed = matches!(self.bye, Some(Bye::Owed | Bye::Sending));
        let ack_owed = self.ack_body == AckBody::Preparing
            || self.ack == AckObligation::NeedToSend;
        let done = self.duplicates_end && !bye_owed && !ack_owed;
        match (done, self.usage_ended) {
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
        dialog::Origin,
        invite::{InviteAttempt, InviteExchange, InviteUsage},
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

    fn cleanup() -> ReplayContext {
        let request = crate::tests::request(crate::tests::INVITE);
        let origin = Origin::from_request(&request).unwrap();
        let exchange =
            Slots::new(1).insert(InviteExchange::outgoing(1)).unwrap();
        let attempt = Slots::new(1)
            .insert(InviteAttempt::new(origin, true, exchange))
            .unwrap();
        let dialog = crate::tests::dialog();
        let id = ReplayId {
            dialog: dialog.id().clone(),
            cseq: 1,
            direction: Direction::Outgoing,
        };

        ReplayContext::cleanup(id, attempt, dialog)
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
        replay.ack = AckObligation::Satisfied;
        assert_eq!(replay.retention(), Retention::Live);

        replay.usage_ended();
        assert_eq!(replay.retention(), Retention::ReplayOnly);

        replay.duplicates_ended();
        assert_eq!(replay.retention(), Retention::Reclaimable);
    }

    #[test]
    fn an_ack_not_yet_tried_holds_the_context() {
        let mut replay = context(Direction::Outgoing);
        replay.ack_body = AckBody::Preparing;

        replay.usage_ended();
        replay.duplicates_ended();
        assert_eq!(replay.retention(), Retention::ReplayOnly);

        replay.ack_body = AckBody::Unanswered;
        assert_eq!(replay.retention(), Retention::ReplayOnly);

        replay.ack = AckObligation::Failed;
        assert_eq!(replay.retention(), Retention::Reclaimable);
    }

    #[test]
    fn a_live_usage_does_not_keep_a_finished_context() {
        let mut replay = context(Direction::Incoming);

        replay.duplicates_ended();
        assert_eq!(replay.retention(), Retention::Reclaimable);
    }

    /// A cleanup has no usage to wait for, but stays until its BYE is done
    /// with, even once no more duplicates can arrive.
    #[test]
    fn a_cleanup_waits_for_its_bye() {
        let mut replay = cleanup();
        replay.ack = AckObligation::Failed;
        assert_eq!(replay.usage, None);
        assert_eq!(replay.retention(), Retention::ReplayOnly);

        replay.duplicates_ended();
        assert_eq!(replay.retention(), Retention::ReplayOnly);
        replay.bye = Some(Bye::Sending);
        assert_eq!(replay.retention(), Retention::ReplayOnly);

        replay.bye = Some(Bye::Done);
        assert_eq!(replay.retention(), Retention::Reclaimable);
    }
}
