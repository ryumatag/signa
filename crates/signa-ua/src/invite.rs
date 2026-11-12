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
  from this user agent: an initial INVITE, or a re-INVITE in the dialog of a
  usage ([RFC 3261 section 14]). A re-INVITE shares the machinery of the
  initial INVITE, the 2xx and its ACK, but not its lifecycle. Its failure
  leaves the session as it was, and its 2xx forms no dialog.

The ACK of each 2xx and the retransmissions around it belong to neither. They
live in a [`ReplayContext`](crate::retention::ReplayContext), which outlives
the usage.

The transaction behind an exchange is the core's. Its timers A to M, the ACK
of a non-2xx and the CANCEL transaction stay there. The model only reacts
to what the core reports, such as a final submission it took or the end of a
response collection.

[RFC 5057]: https://www.rfc-editor.org/rfc/rfc5057.html
[RFC 3261 section 14]: https://www.rfc-editor.org/rfc/rfc3261.html#section-14
*/

use std::time::Instant;

use signa_core::{StatusCode, transport::Flow};

use crate::{
    dialog::{Dialog, DialogId, DialogKey, Origin, Outgoing},
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
    /// Where the CANCEL of the INVITE stands. There is one at most, as the
    /// core allows.
    pub(crate) cancel: CancelIntent,
    /// Each early dialog of the attempt that this user agent ended with a
    /// BYE, with the last CSeq number it gave out. The callee may have sent
    /// a 2xx before the BYE reached it, and goes on sending it until its ACK
    /// (RFC 3261 section 13.3.1.4), so the 2xx can arrive after the BYE's
    /// response, when the dialog itself is gone. Such a 2xx is acknowledged
    /// and ended, not taken for a new session, and a late provisional forms
    /// nothing. Each entry was a fork, so `forks` bounds them, and they go
    /// with the attempt, when no more responses can arrive.
    pub(crate) ended_early: Vec<(DialogId, Option<u32>)>,
}

/// Where the CANCEL of an INVITE this user agent sent stands.
///
/// The CANCEL itself is the core's. It waits for a provisional response
/// and goes as a transaction of its own (RFC 3261 section 9.1). The UA only
/// asks for it once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelIntent {
    /// Nobody asked for one.
    None,
    /// Asked for before the INVITE reached the core. It is asked of the core
    /// once the core has the INVITE, for the operation, if any.
    Waiting(Option<OperationId>),
    /// Asked of the core.
    Asked,
}

/// What asking for the CANCEL of an INVITE came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub enum CancelResult {
    /// The endpoint has the CANCEL, as a transaction of its own. That is not
    /// the end of the INVITE. A 2xx can still come, and the UA acknowledges
    /// it as any other (RFC 3261 section 9.1).
    Sent,
    /// The INVITE had its final response, or never reached the endpoint, so
    /// there was nothing to cancel and nothing was sent.
    NotNeeded,
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub enum EndReason {
    /// This UA ended it with a BYE, which reached the endpoint. The BYE may
    /// have been the application's, or the UA's own for an attempt given
    /// up. RFC 3261 section 15.1.1 ends the session then, whatever the
    /// response to the BYE. An application's BYE that waited for the ACK of
    /// this UA's 2xx until the ACK deadline ends the session even if it could
    /// not reach the endpoint.
    LocalBye,
    /// The peer ended it with a BYE (RFC 3261 section 15.1.2).
    #[non_exhaustive]
    RemoteBye {
        /// Where the BYE arrived.
        flow: Flow,
    },
    /// No ACK came for this UA's 2xx in time, so the UA ended the session
    /// with a BYE, as RFC 3261 section 13.3.1.4 recommends, or without one if the
    /// BYE could not reach the endpoint. A session whose BYE was asked for
    /// while it waited for the ACK ends with that BYE's reason instead.
    AckTimeout,
    /// Its early dialog ended without a 2xx: the INVITE got another final
    /// response or failed, or its responses stopped (RFC 3261 section 12.3).
    Unconfirmed,
    /// The offer/answer exchange of its INVITE failed, so the UA ended the
    /// session with a BYE. The 2xx or the ACK lacked the answer or offer it
    /// owed (RFC 3261 section 13.2.1), or no answer could be had for the
    /// offer of a 2xx. [`Event::NegotiationFailed`] said so before.
    ///
    /// [`Event::NegotiationFailed`]: crate::Event::NegotiationFailed
    NegotiationFailed,
    /// A re-INVITE of this UA's failed in a way that ends the session (RFC
    /// 3261 sections 12.2.1.2 and 14.1). With
    /// [`Error::RemoteFailure`] and a 481, the peer has no such dialog, so
    /// the session ended without a BYE (RFC 5057 section 5.1). With a 408,
    /// or [`Error::Timeout`] when no response came, the UA ended it with a
    /// BYE.
    ReinviteFailed(Error),
    /// The UA ended it because it shut down with
    /// [`ShutdownMode::Terminate`]: with a BYE that reached the endpoint, or
    /// without one if the BYE could not reach it. In the second case the peer
    /// may still have the session, and [`ShutdownReport::failed_byes`]
    /// counts it.
    ///
    /// [`ShutdownMode::Terminate`]: crate::ShutdownMode::Terminate
    /// [`ShutdownReport::failed_byes`]: crate::ShutdownReport::failed_byes
    Shutdown,
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
            cancel: CancelIntent::None,
            ended_early: Vec::new(),
        }
    }

    /// Returns the last number an early dialog this user agent ended gave
    /// out, if `id` is one.
    pub(crate) fn ended_early(&self, id: &DialogId) -> Option<Option<u32>> {
        self.ended_early
            .iter()
            .find(|(ended, _)| ended == id)
            .map(|&(_, numbered)| numbered)
    }

    /// Says whether the core has the INVITE, after which it can cancel it.
    pub(crate) fn started(&self) -> bool {
        self.operation.is_none()
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
    /// of an INVITE this user agent took and the answer in its ACK, or what
    /// the provisional responses and the 2xx of one it sent carried. A
    /// preview an unreliable provisional gave of the answer stays, whatever
    /// the 2xx carries, since the UAC takes the first description as the
    /// answer (RFC 3261 section 13.2.1).
    pub(crate) remote: Option<Description>,
    /// The BYE that is to end the usage, once asked for.
    pub(crate) bye: ByeIntent,
    /// The INVITE transaction of the usage's dialog that has no final
    /// response yet, in either direction. RFC 3261 section 14.1 lets no new
    /// INVITE start in a dialog while there is one, and section 14.2 answers
    /// one that comes anyway with a 491 or a 500. It is let go at the final
    /// response, not when the core stops keeping the transaction, so a copy
    /// of an old 2xx holds up no new exchange.
    pub(crate) exchange: Option<ExchangeKey>,
    /// A re-INVITE that got a 491 and waits to go once more.
    pub(crate) retry: Option<Box<Retry>>,
    /// How many offer/answer exchanges of the usage completed, the session
    /// revision. It moves apart from the dialog's target revision.
    pub(crate) revision: u32,
}

/// A re-INVITE that waits to go once more after a 491 (RFC 3261 section
/// 14.1).
#[derive(Debug)]
pub(crate) struct Retry {
    /// The application's, if it waits for the outcome.
    pub(crate) operation: Option<OperationId>,
    /// What the re-INVITE offered, which the next one offers again.
    pub(crate) offer: Option<Description>,
    pub(crate) due: Instant,
    /// The session revision when the 491 came. Another exchange that
    /// completed meanwhile changed what the offer was made against, so the
    /// re-INVITE does not go again then.
    pub(crate) revision: u32,
}

/// Where the BYE that ends a usage stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ByeIntent {
    /// Nobody asked to end the usage.
    None,
    /// The BYE waits for an ACK. A callee waits for the ACK of its 2xx,
    /// since RFC 3261 section 15 keeps it from sending a BYE before that ACK
    /// or the end of its server transaction. A caller waits for its own ACK
    /// to go when the ACK has to carry an answer still being prepared, so
    /// that the BYE does not overtake it. `operation` is the application's,
    /// if it asked, and `reason` what the session ends with.
    Deferred { operation: Option<OperationId>, reason: EndReason },
    /// The BYE is on its way to the core.
    Sending,
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
            bye: ByeIntent::None,
            exchange: None,
            retry: None,
            revision: 0,
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
            bye: ByeIntent::None,
            exchange: None,
            retry: None,
            revision: 0,
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

    /// Takes back the intent to end a usage whose BYE never reached the
    /// core, which leaves the usage as it was before, in `phase`.
    pub(crate) fn resume(&mut self, phase: UsagePhase) {
        debug_assert_ne!(phase, UsagePhase::Ended);
        if self.phase == UsagePhase::Ending {
            self.phase = phase;
            self.bye = ByeIntent::None;
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
    /// An INVITE this user agent received.
    Incoming {
        /// Whether it is an initial INVITE or a re-INVITE.
        kind: Received,
        /// The INVITE's offer. It moves to the usage the 2xx forms or
        /// updates.
        offer: Option<Description>,
        /// When the application's decision is due, while it is.
        decision_due: Option<Instant>,
        /// When the INVITE expires, if its Expires gave a time, while no
        /// final is under way.
        expires_due: Option<Instant>,
        /// The last provisional response the application chose, and when it
        /// is due again, while no final is under way. It may carry a preview
        /// of the answer, so it is boxed to keep the scope small.
        provisional: Option<Box<Provisional>>,
        /// How the caller gave the INVITE up before it had a final response,
        /// if it did. It is rare, and a BYE's flow is large, so it is boxed.
        withdrawn: Option<Box<Withdrawal>>,
    },
    /// A re-INVITE this user agent sent.
    Reinvite(Box<SentReinvite>),
}

/// What kind of INVITE an incoming exchange is for.
#[derive(Debug)]
pub(crate) enum Received {
    /// An initial INVITE.
    Initial {
        /// The dialog a 2xx would form, read from the request when it
        /// arrived, so that a request that cannot form one is refused before
        /// the application sees it. The local tag in it is chosen then too,
        /// so every response of the exchange carries the same To tag. It
        /// moves to the dialog table when the 2xx is committed.
        dialog: Option<Box<Dialog>>,
        /// What finds a merged copy of the INVITE while the exchange lives.
        merge: MergeKey,
    },
    /// A re-INVITE in the dialog of `usage`, whose identity is `dialog`. Its
    /// responses carry the dialog's local tag. The identity stays here, so
    /// that a 2xx committed after the usage ended still gets its ACK.
    Reinvite {
        usage: UsageKey,
        dialog: DialogId,
        /// The URI of the re-INVITE's Contact, the new remote target, which
        /// its 2xx commits (RFC 6141 section 4.6).
        contact: Option<Box<str>>,
    },
}

/// A re-INVITE this user agent sent in the dialog of a usage (RFC 3261
/// section 14.1).
///
/// The record lives until the core finishes collecting the re-INVITE's
/// responses, so that a copy of its 2xx finds its ACK. The usage lets go of
/// it at the final response, so that the next re-INVITE need not wait for
/// that.
#[derive(Debug)]
pub(crate) struct SentReinvite {
    pub(crate) usage: UsageKey,
    /// The dialog's identity, for the replay context of the 2xx.
    pub(crate) dialog: DialogId,
    /// The application's, until it has its outcome.
    pub(crate) operation: Option<OperationId>,
    /// The offer, kept for a second try after a 491.
    pub(crate) offer: Option<Description>,
    /// The request and where it goes, until the runtime takes it to send.
    pub(crate) request: Option<Box<Outgoing>>,
    /// Whether this is the try after a 491, which gets no other.
    pub(crate) retried: bool,
    /// Whether the slot of the 2xx's replay context is still set aside.
    pub(crate) reserved: bool,
    /// Whether the core dropped responses to it for want of room.
    pub(crate) incomplete: bool,
    /// The dialog, once its usage ended and no table keeps it, so that a 2xx
    /// that comes late can still be acknowledged (RFC 5407 section 3.2.3).
    pub(crate) kept: Option<Box<Dialog>>,
}

/// A provisional response the UA sends again until a final is under way
/// (RFC 3261 section 13.3.1.1).
#[derive(Debug)]
pub(crate) struct Provisional {
    pub(crate) status: StatusCode,
    /// The preview of the answer it carried, if any.
    pub(crate) preview: Option<Description>,
    pub(crate) due: Instant,
}

/// How a caller gives up an INVITE that has no final response yet.
///
/// Either way, a UAS that has not decided answers the INVITE with a 487. A
/// final under way when it arrives goes on, and decides. A CANCEL then has
/// no effect (RFC 3261 section 9.2), while a BYE still ends the session the
/// 2xx forms (section 15.1.2, and the BYE in the early dialog of RFC 5407
/// section 3.1.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Withdrawal {
    Cancel,
    /// A BYE in the early dialog, which arrived on `flow`. RFC 3261 section
    /// 15 lets the caller send one, and section 15.1.2 has the UAS answer
    /// the INVITE it leaves pending with a 487.
    Bye {
        flow: Flow,
    },
    /// The session of a re-INVITE ended, by a BYE in either direction. RFC
    /// 3261 section 15.1.2 recommends a 487 for each request the dialog
    /// leaves pending, and I answer one of this user agent's own BYE the
    /// same way.
    Ended,
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
    /// verdict had not come back, with the session description it carried,
    /// if any. The core takes the 2xx before it sends it, so the ACK is for
    /// this 2xx, and it applies once the verdict is in.
    pub(crate) early_ack: Option<Option<Description>>,
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

    pub(crate) fn reinvite(
        cseq: u32,
        reinvite: SentReinvite,
    ) -> InviteExchange {
        InviteExchange {
            scope: Scope::Reinvite(Box::new(reinvite)),
            cseq,
            state: ExchangeState::Pending,
            early_ack: None,
        }
    }

    /// Returns the usage of a re-INVITE, in either direction, or `None` for
    /// an initial INVITE.
    pub(crate) fn reinvite_usage(&self) -> Option<UsageKey> {
        match &self.scope {
            Scope::Incoming {
                kind: Received::Reinvite { usage, .. }, ..
            } => Some(*usage),
            Scope::Reinvite(reinvite) => Some(reinvite.usage),
            Scope::Incoming { .. } | Scope::Outgoing => None,
        }
    }

    pub(crate) fn incoming(
        kind: Received,
        cseq: u32,
        offer: Option<Description>,
        decision_due: Option<Instant>,
        expires_due: Option<Instant>,
    ) -> InviteExchange {
        InviteExchange {
            scope: Scope::Incoming {
                kind,
                offer,
                decision_due,
                expires_due,
                provisional: None,
                withdrawn: None,
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
            Negotiation::LocalOfferOutstanding { cseq: 1 },
        );
        let mut ending = InviteUsage::early(
            dialog(),
            Direction::Outgoing,
            Negotiation::LocalOfferOutstanding { cseq: 1 },
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
