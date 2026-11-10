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

use crate::{
    dialog::{Dialog, DialogKey, Origin},
    negotiation::Negotiation,
    operation::OperationId,
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
#[derive(Debug)]
pub(crate) struct InviteAttempt {
    /// What the INVITE says about the dialogs its responses form.
    pub(crate) origin: Origin,
    /// Whether the INVITE carried an offer. Each forked dialog starts its
    /// negotiation from it.
    pub(crate) offer_in_request: bool,
    pub(crate) exchange: ExchangeKey,
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
        offer_in_request: bool,
    },
}

/// Where an INVITE transaction's final response stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExchangeState {
    /// No final response yet.
    Pending,
    /// A final response was handed to the core and its verdict has not come
    /// back. Nothing may submit a competing final meanwhile.
    FinalSubmissionPending { operation: OperationId },
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
        }
    }

    pub(crate) fn incoming(
        dialog: Dialog,
        cseq: u32,
        offer_in_request: bool,
    ) -> InviteExchange {
        InviteExchange {
            scope: Scope::Incoming {
                dialog: Some(Box::new(dialog)),
                offer_in_request,
            },
            cseq,
            state: ExchangeState::Pending,
        }
    }

    pub(crate) fn state(&self) -> ExchangeState {
        self.state
    }

    /// Claims the final response for `operation`. Only one final can be in
    /// flight or decided.
    pub(crate) fn submit_final(
        &mut self,
        operation: OperationId,
    ) -> Result<(), AlreadyFinalized> {
        if self.state != ExchangeState::Pending {
            return Err(AlreadyFinalized(self.state));
        }

        self.state = ExchangeState::FinalSubmissionPending { operation };
        Ok(())
    }

    /// Records that the core took the final response in flight, and returns
    /// the operation that submitted it.
    pub(crate) fn final_committed(&mut self) -> Option<OperationId> {
        let ExchangeState::FinalSubmissionPending { operation } = self.state
        else {
            return None;
        };

        self.state = ExchangeState::FinalObserved;
        Some(operation)
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
        let first = operation();

        exchange.submit_final(first).unwrap();
        assert_eq!(
            exchange.submit_final(first),
            Err(AlreadyFinalized(ExchangeState::FinalSubmissionPending {
                operation: first,
            })),
        );

        assert_eq!(exchange.final_committed(), Some(first));
        assert_eq!(exchange.final_committed(), None);
        assert!(exchange.submit_final(first).is_err());
        assert_eq!(exchange.state(), ExchangeState::FinalObserved);
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
