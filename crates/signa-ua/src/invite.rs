/*!
INVITE attempts, usages and exchanges.

One INVITE is several things with different lifetimes, and the model keeps them
apart:

* An [`InviteAttempt`] is an initial INVITE this user agent sent. It lives
  until the core stops collecting its responses (Timer M), and may form several
  dialogs, one per forked 2xx. It has no `DialogId` of its own.
* An [`InviteUsage`] is the INVITE usage of one dialog ([RFC 5057]), the
  session the application sees. It can end long before the INVITE's
  retransmissions stop.
* An [`InviteExchange`] is one INVITE transaction and its final response, seen
  from this user agent.

The ACK of each 2xx and the retransmissions around it belong to neither. They
live in a [`ReplayContext`](crate::retention::ReplayContext), which outlives
the usage.

The transaction behind an exchange is the core's. Its timers A to M, the ACK
of a non-2xx and the CANCEL transaction stay there. The model only reacts
to what the core reports, such as a final submission it took or the end of a
response collection.

[RFC 5057]: https://www.rfc-editor.org/rfc/rfc5057.html
*/

use std::time::Instant;

use signa_core::StatusCode;

use crate::{
    dialog::{Dialog, DialogKey, Origin},
    error::Error,
    negotiation::{Description, Negotiation},
    operation::OperationId,
    plan::PlannedInvite,
    slot::Key,
};

pub(crate) type AttemptKey = Key<InviteAttempt>;
pub(crate) type UsageKey = Key<InviteUsage>;
pub(crate) type ExchangeKey = Key<InviteExchange>;

/// Which way an INVITE went.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Direction {
    /// Sent by this user agent, as a UAC.
    Outgoing,
    /// Received by this user agent, as a UAS.
    Incoming,
}

/// An initial INVITE this user agent sent.
///
/// The model drops it when the core finishes collecting its responses. Its
/// key then goes stale, so no later branch can attach to it.
///
/// Each dialog its responses form is a fork of its own, with its own usage,
/// negotiation and ACK, none preferred over another. The attempt only lists
/// them. Ending one ends neither the attempt nor the other forks.
#[derive(Debug)]
pub(crate) struct InviteAttempt {
    /// What the INVITE says about the dialogs its responses form.
    pub(crate) origin: Origin,
    /// Whether the INVITE carried an offer. Each forked dialog starts its
    /// negotiation from it.
    pub(crate) offer_in_request: bool,
    pub(crate) exchange: ExchangeKey,
    /// The INVITE and its first hop, until the runtime takes them to send.
    pub(crate) request: Option<Box<PlannedInvite>>,
    /// The operation that sent the INVITE, until it is in the core.
    pub(crate) operation: Option<OperationId>,
    /// What the INVITE came to, once its first final response or failure
    /// is in.
    pub(crate) result: Option<AttemptResult>,
    /// The usage of each dialog the attempt's responses formed and the UA
    /// kept, in the order they formed. A usage that ends stays listed, so
    /// the length counts the forks the attempt took against its limit.
    pub(crate) forks: Vec<UsageKey>,
    /// Whether every response the core took for the INVITE reached the UA
    /// and became part of a session. A response overflow in the core, or a
    /// dialog the UA had no room to keep, clears it for good.
    pub(crate) complete: bool,
    /// Whether the UA had to leave a 2xx without its ACK and BYE, since even
    /// the room for ending dialogs it does not keep was full.
    pub(crate) degraded: bool,
    /// Whether the application gave the attempt up, so that a 2xx that
    /// comes later is acknowledged and ended rather than kept.
    pub(crate) abandoned: bool,
}

impl InviteAttempt {
    pub(crate) fn new(
        origin: Origin,
        offer_in_request: bool,
        exchange: ExchangeKey,
    ) -> InviteAttempt {
        InviteAttempt {
            origin,
            offer_in_request,
            exchange,
            request: None,
            operation: None,
            result: None,
            forks: Vec::new(),
            complete: true,
            degraded: false,
            abandoned: false,
        }
    }
}

/// What an INVITE this user agent sent came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub enum AttemptResult {
    /// A 2xx came, and formed a session. Others may have come from other
    /// forks.
    Answered,
    /// No 2xx came, for the reason given, such as
    /// [`Error::RemoteFailure`] for a final response other than a 2xx.
    Failed(Error),
}

/// Where an INVITE usage is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UsagePhase {
    /// The dialog is early and the INVITE has no 2xx yet.
    Establishing,
    /// A 2xx confirmed the dialog.
    Established,
    /// The application asked to end the session, and the BYE waits for its
    /// turn, such as the ACK of a 2xx this user agent sent.
    Ending,
    /// The session is over. The phase is final.
    Ended,
}

/// The INVITE usage of one dialog.
#[derive(Debug)]
pub(crate) struct InviteUsage {
    pub(crate) dialog: DialogKey,
    pub(crate) direction: Direction,
    phase: UsagePhase,
    /// Kept per usage, so that each fork negotiates on its own.
    pub(crate) negotiation: Negotiation,
    /// The last session description the peer sent in this usage: the offer
    /// of an INVITE this user agent took, or the answer in the 2xx of one it
    /// sent.
    pub(crate) remote: Option<Description>,
}

impl InviteUsage {
    /// Creates the usage of an early dialog, formed by a provisional
    /// response with a To tag.
    pub(crate) fn early(
        dialog: DialogKey,
        direction: Direction,
        negotiation: Negotiation,
    ) -> InviteUsage {
        InviteUsage {
            dialog,
            direction,
            phase: UsagePhase::Establishing,
            negotiation,
            remote: None,
        }
    }

    pub(crate) fn established(
        dialog: DialogKey,
        direction: Direction,
        negotiation: Negotiation,
    ) -> InviteUsage {
        InviteUsage {
            dialog,
            direction,
            phase: UsagePhase::Established,
            negotiation,
            remote: None,
        }
    }

    pub(crate) fn phase(&self) -> UsagePhase {
        self.phase
    }

    /// Records the 2xx of an early usage. A usage that is already ending
    /// stays so, since the application's intent to end it still holds.
    pub(crate) fn establish(&mut self) {
        if self.phase == UsagePhase::Establishing {
            self.phase = UsagePhase::Established;
        }
    }

    /// Records the intent to end a usage that cannot send its BYE yet.
    pub(crate) fn begin_ending(&mut self) {
        if self.phase != UsagePhase::Ended {
            self.phase = UsagePhase::Ending;
        }
    }

    pub(crate) fn end(&mut self) {
        self.phase = UsagePhase::Ended;
    }
}

/// What an exchange belongs to.
#[derive(Debug)]
pub(crate) enum Scope {
    /// The initial INVITE of the attempt that holds this exchange's key.
    Outgoing,
    /// An initial INVITE this user agent received.
    Incoming {
        /// The dialog a 2xx would form, read from the request when it
        /// arrived, so that a request that cannot form one is refused before
        /// the application sees it. The local tag in it is chosen then too,
        /// so every response of the exchange carries the same To tag. It
        /// moves to the dialog table when the 2xx is committed.
        dialog: Option<Box<Dialog>>,
        /// The INVITE's offer. It moves to the usage the 2xx forms.
        offer: Option<Description>,
        /// What finds a merged copy of the INVITE while the exchange lives.
        merge: MergeKey,
        /// When the application's decision is due, while it is.
        decision_due: Option<Instant>,
        /// When the INVITE expires, if its Expires gave a time, while no
        /// final is under way.
        expires_due: Option<Instant>,
        /// The last provisional response the application chose, and when it
        /// is due again, while no final is under way.
        provisional: Option<(StatusCode, Instant)>,
    },
}

/// What RFC 3261 section 8.2.2.2 compares to tell a merged request: the From
/// tag, the Call-ID and the CSeq. A request without a To tag that matches an
/// ongoing transaction on these, but is not that transaction's, reached this
/// user agent twice by different paths, as through a forking proxy.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct MergeKey {
    pub(crate) call_id: Box<str>,
    pub(crate) from_tag: Option<Box<str>>,
    pub(crate) cseq: u32,
}

/// Where an INVITE transaction's final response stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExchangeState {
    /// No final response yet.
    Pending,
    /// A final response was handed to the core and its verdict has not come
    /// back. Nothing may submit a competing final meanwhile. `operation` is
    /// `None` for a final the UA sends on its own.
    FinalSubmissionPending {
        operation: Option<OperationId>,
        status: StatusCode,
    },
    /// A final response was received, or the core took the one this user
    /// agent sent.
    FinalObserved,
    /// Nothing more is expected of the exchange. For a received INVITE, the
    /// 2xx was acknowledged or its ACK deadline passed. For a sent one, the
    /// core finished collecting responses.
    Complete,
}

/// One INVITE transaction and its final response.
#[derive(Debug)]
pub(crate) struct InviteExchange {
    pub(crate) scope: Scope,
    pub(crate) cseq: u32,
    state: ExchangeState,
    /// An ACK that arrived while the 2xx was handed to the core and its
    /// verdict had not come back, and whether it carried an answer. The core
    /// takes the 2xx before it sends it, so the ACK is for this 2xx, and it
    /// applies once the verdict is in.
    pub(crate) early_ack: Option<bool>,
}

/// The final response of an exchange is already decided or under way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AlreadyFinalized(pub(crate) ExchangeState);

impl InviteExchange {
    pub(crate) fn outgoing(cseq: u32) -> InviteExchange {
        InviteExchange {
            scope: Scope::Outgoing,
            cseq,
            state: ExchangeState::Pending,
            early_ack: None,
        }
    }

    pub(crate) fn incoming(
        dialog: Dialog,
        merge: MergeKey,
        offer: Option<Description>,
        decision_due: Option<Instant>,
        expires_due: Option<Instant>,
    ) -> InviteExchange {
        let cseq = merge.cseq;
        InviteExchange {
            scope: Scope::Incoming {
                dialog: Some(Box::new(dialog)),
                offer,
                merge,
                decision_due,
                expires_due,
                provisional: None,
            },
            cseq,
            state: ExchangeState::Pending,
            early_ack: None,
        }
    }

    pub(crate) fn state(&self) -> ExchangeState {
        self.state
    }

    /// Claims the final response for `operation`. Only one final can be in
    /// flight or decided.
    pub(crate) fn submit_final(
        &mut self,
        operation: Option<OperationId>,
        status: StatusCode,
    ) -> Result<(), AlreadyFinalized> {
        if self.state != ExchangeState::Pending {
            return Err(AlreadyFinalized(self.state));
        }

        self.state =
            ExchangeState::FinalSubmissionPending { operation, status };
        Ok(())
    }

    /// Records that the core took the final response in flight, and returns
    /// the operation that submitted it and its status.
    pub(crate) fn final_committed(
        &mut self,
    ) -> Option<(Option<OperationId>, StatusCode)> {
        let ExchangeState::FinalSubmissionPending { operation, status } =
            self.state
        else {
            return None;
        };

        self.state = ExchangeState::FinalObserved;
        Some((operation, status))
    }

    /// Records that the core refused the final response in flight, which
    /// leaves the exchange pending, and returns what
    /// [`InviteExchange::final_committed`] would have.
    pub(crate) fn final_refused(
        &mut self,
    ) -> Option<(Option<OperationId>, StatusCode)> {
        let ExchangeState::FinalSubmissionPending { operation, status } =
            self.state
        else {
            return None;
        };

        self.state = ExchangeState::Pending;
        Some((operation, status))
    }

    /// Records a final response from the peer. Forked 2xx responses arrive
    /// after the first one, so this can repeat.
    pub(crate) fn final_received(&mut self) {
        if self.state == ExchangeState::Pending {
            self.state = ExchangeState::FinalObserved;
        }
    }

    pub(crate) fn complete(&mut self) {
        self.state = ExchangeState::Complete;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::Slots;

    fn operation() -> OperationId {
        Slots::new(1).insert(Default::default()).unwrap()
    }

    #[test]
    fn one_final_at_a_time() {
        let mut exchange = InviteExchange::outgoing(1);
        let first = Some(operation());

        exchange.submit_final(first, StatusCode::OK).unwrap();
        assert_eq!(
            exchange.submit_final(None, StatusCode::OK),
            Err(AlreadyFinalized(ExchangeState::FinalSubmissionPending {
                operation: first,
                status: StatusCode::OK,
            })),
        );

        assert_eq!(exchange.final_committed(), Some((first, StatusCode::OK)));
        assert_eq!(exchange.final_committed(), None);
        assert!(exchange.submit_final(first, StatusCode::OK).is_err());
        assert_eq!(exchange.state(), ExchangeState::FinalObserved);
    }

    #[test]
    fn a_refused_final_leaves_the_exchange_pending() {
        let mut exchange = InviteExchange::outgoing(1);
        let busy = StatusCode::from_u16(486).unwrap();

        exchange.submit_final(None, busy).unwrap();
        assert_eq!(exchange.final_refused(), Some((None, busy)));
        assert_eq!(exchange.final_refused(), None);

        assert_eq!(exchange.state(), ExchangeState::Pending);
        exchange.submit_final(None, StatusCode::OK).unwrap();
    }

    #[test]
    fn forked_finals_keep_the_exchange_observed() {
        let mut exchange = InviteExchange::outgoing(1);

        exchange.final_received();
        exchange.final_received();
        assert_eq!(exchange.state(), ExchangeState::FinalObserved);

        exchange.complete();
        exchange.final_received();
        assert_eq!(exchange.state(), ExchangeState::Complete);
    }

    fn dialog() -> DialogKey {
        Slots::new(1).insert(crate::tests::dialog()).unwrap()
    }

    #[test]
    fn a_usage_ending_before_its_2xx_stays_ending() {
        let mut usage = InviteUsage::early(
            dialog(),
            Direction::Outgoing,
            Negotiation::LocalOfferOutstanding,
        );
        let mut ending = InviteUsage::early(
            dialog(),
            Direction::Outgoing,
            Negotiation::LocalOfferOutstanding,
        );

        usage.establish();
        ending.begin_ending();
        ending.establish();

        assert_eq!(usage.phase(), UsagePhase::Established);
        assert_eq!(ending.phase(), UsagePhase::Ending);
    }

    #[test]
    fn an_ended_usage_does_not_return_to_ending() {
        let mut usage = InviteUsage::established(
            dialog(),
            Direction::Incoming,
            Negotiation::Stable,
        );

        usage.begin_ending();
        assert_eq!(usage.phase(), UsagePhase::Ending);
        usage.end();
        usage.begin_ending();
        assert_eq!(usage.phase(), UsagePhase::Ended);
    }
}
