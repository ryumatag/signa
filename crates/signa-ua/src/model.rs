/*!
The single writer of UA state.

The model owns every table and is the only thing that changes them. Each
input is a method that takes the state, the input and, where it matters, the
time, and leaves the new state and a list of [`Effect`]s behind. It awaits
nothing and does no I/O. A runtime is to feed it core events and commands,
carry out the effects, and report their results back as further inputs. Tests
drive it the same way with a fake clock and a deterministic [`Random`], so no
protocol test depends on real time.

The model keeps no transaction timer. Timers A to M, the ACK of a non-2xx and
CANCEL retransmission belong to the transaction layer in signa-core
([RFC 3261 section 17], [RFC 6026 section 7]). The times the model takes are
for timers of the UA core, which so far is only how long an outcome nobody
waits for is kept.

TODO: Only the tables, the axes of state, admission and outcomes, and the
transitions their tests need are here. The rest of the UAS and UAC paths,
early dialogs and forks, CANCEL and BYE, and offer/answer are still to come.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 6026 section 7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-7
*/

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use signa_core::{StatusCode, message::header::Tag};

use crate::{
    dialog::{Dialog, DialogId, DialogKey},
    error::Error,
    invite::{
        AttemptKey, Direction, ExchangeKey, ExchangeState, InviteAttempt,
        InviteExchange, InviteUsage, Scope, UsageKey,
    },
    negotiation::Negotiation,
    operation::{Completion, OperationId, Operations, Stage, SubmitError},
    retention::{
        AckObligation, ReplayContext, ReplayId, ReplayKey, Retention, Source,
    },
    slot::Slots,
};

/// A source of randomness for tags and Call-IDs, and later the retry timer
/// of a 491.
///
/// RFC 3261 section 19.3 asks for at least 32 bits of cryptographic
/// randomness in a tag. The runtime's source has to meet that. Tests pass a
/// deterministic one.
pub(crate) trait Random {
    fn next_u64(&mut self) -> u64;
}

/// How much the model holds. Every table is bounded.
///
/// TODO: Give these finite defaults, checked when the UA is built, and tune
/// them by measurement.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) attempts: usize,
    pub(crate) exchanges: usize,
    pub(crate) dialogs: usize,
    pub(crate) usages: usize,
    pub(crate) replays: usize,
    pub(crate) operations: usize,
    /// Commands admitted and not yet run.
    pub(crate) commands: usize,
    /// How long an outcome nobody waits for is kept.
    pub(crate) outcome_retention: Duration,
}

/// The authority to decide the final response of an incoming INVITE.
///
/// There is one per exchange, and it is neither `Clone` nor `Copy`, so the
/// application cannot submit two finals. Submitting a decision moves it into
/// the command. A command the UA refuses comes back whole, authority
/// included, so a full queue does not cost the application its decision.
///
/// TODO: When this drops without a decision, set a flag reserved for the
/// exchange, so that the driver sends a 500 unless a CANCEL or a final got
/// there first. The 500 is my policy. No RFC rule picks it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Authority {
    exchange: ExchangeKey,
}

/// What the application asks of the UA.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Command {
    /// Accept an incoming INVITE with a 2xx.
    Accept { authority: Authority },
}

/// What the runtime does on the model's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    /// Submit the final response of an incoming INVITE through its
    /// responder, then report the verdict with [`Model::final_committed`].
    SubmitFinal { exchange: ExchangeKey, status: StatusCode },
    /// Send the ACK of a received 2xx, then report the write with
    /// [`Model::ack_written`].
    SendAck { replay: ReplayKey },
    /// Send the ACK already sent for a 2xx again, for a copy of that 2xx.
    ResendAck { replay: ReplayKey },
    /// Tell the application.
    Notify(Event),
}

/// What the application is told. Losing one of these loses no protocol
/// state or terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// A 2xx confirmed the dialog. The ACK may still be owed, and the
    /// session descriptions may not be settled.
    DialogConfirmed { dialog: DialogKey, usage: UsageKey },
    /// The offer/answer exchange of a usage completed.
    NegotiationCompleted { usage: UsageKey },
    /// The usage ended.
    UsageEnded { usage: UsageKey },
}

/// The UA's state.
pub(crate) struct Model<R> {
    limits: Limits,
    random: R,
    attempts: Slots<InviteAttempt>,
    exchanges: Slots<InviteExchange>,
    dialogs: Slots<Dialog>,
    usages: Slots<InviteUsage>,
    replays: Slots<ReplayContext>,
    /// Finds the replay context of a 2xx or ACK from the wire.
    replay_index: HashMap<ReplayId, ReplayKey>,
    operations: Operations,
    commands: VecDeque<(OperationId, Command)>,
    effects: Vec<Effect>,
}

impl<R: Random> Model<R> {
    pub(crate) fn new(limits: Limits, random: R) -> Model<R> {
        Model {
            limits,
            random,
            attempts: Slots::new(limits.attempts),
            exchanges: Slots::new(limits.exchanges),
            dialogs: Slots::new(limits.dialogs),
            usages: Slots::new(limits.usages),
            replays: Slots::new(limits.replays),
            replay_index: HashMap::new(),
            operations: Operations::new(
                limits.operations,
                limits.outcome_retention,
            ),
            commands: VecDeque::new(),
            effects: Vec::new(),
        }
    }

    /// Returns the effects of the inputs so far, in order.
    pub(crate) fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// Makes a tag from 64 random bits, as 16 hexadecimal digits.
    fn tag(&mut self) -> Tag {
        let tag = format!("{:016x}", self.random.next_u64());
        Tag::try_from(tag).expect("hexadecimal digits are a token")
    }
}

/// Commands and operations.
impl<R: Random> Model<R> {
    /// Admits a command, or hands it back with nothing changed.
    pub(crate) fn try_submit(
        &mut self,
        command: Command,
    ) -> Result<OperationId, SubmitError<Command>> {
        if self.commands.len() >= self.limits.commands {
            return Err(SubmitError { error: Error::Busy, command });
        }
        let Some(operation) = self.operations.admit() else {
            return Err(SubmitError { error: Error::Busy, command });
        };

        self.commands.push_back((operation, command));
        Ok(operation)
    }

    /// Runs the admitted commands in order.
    pub(crate) fn run_commands(&mut self, now: Instant) {
        while let Some((operation, command)) = self.commands.pop_front() {
            match command {
                Command::Accept { authority } => {
                    self.accept(operation, authority.exchange, now)
                }
            }
        }
    }

    pub(crate) fn waiter_dropped(
        &mut self,
        operation: OperationId,
        now: Instant,
    ) {
        self.operations.drop_waiter(operation, now);
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        self.operations.expire(now);
    }
}

/// Initial INVITEs this user agent receives.
impl<R: Random> Model<R> {
    /// Takes in an initial INVITE and returns the authority to decide it.
    pub(crate) fn receive_invite(
        &mut self,
        call_id: Box<str>,
        remote_tag: Tag,
        cseq: u32,
        offer_in_request: bool,
    ) -> Result<Authority, Error> {
        let dialog = DialogId::new(call_id, self.tag(), remote_tag);
        let exchange =
            InviteExchange::incoming(dialog, cseq, offer_in_request);

        match self.exchanges.insert(exchange) {
            Ok(exchange) => Ok(Authority { exchange }),
            Err(_) => Err(Error::CapacityExceeded),
        }
    }

    fn accept(
        &mut self,
        operation: OperationId,
        key: ExchangeKey,
        now: Instant,
    ) {
        let Some(exchange) = self.exchanges.get(key) else {
            self.operations.complete(
                operation,
                Err(Error::StaleDecision),
                now,
            );
            return;
        };
        if exchange.state() != ExchangeState::Pending {
            self.operations.complete(
                operation,
                Err(Error::AlreadyFinalized),
                now,
            );
            return;
        }

        // The dialog, the usage and the replay context are set aside before
        // the 2xx goes out, so it never goes out without them.
        // `final_committed` uses them.
        //
        // TODO: Give them back when the core refuses the 2xx.
        if !self.reserve_session() {
            // TODO: Send the exchange's final through the abandonment path.
            // Its authority went with the command, so nobody else can.
            self.operations.complete(
                operation,
                Err(Error::CapacityExceeded),
                now,
            );
            return;
        }

        self.exchanges
            .get_mut(key)
            .expect("checked above")
            .submit_final(operation)
            .expect("checked to be pending");
        self.effects.push(Effect::SubmitFinal {
            exchange: key,
            status: StatusCode::OK,
        });
    }

    /// Records the core's acceptance of a final response in flight.
    pub(crate) fn final_committed(&mut self, key: ExchangeKey, now: Instant) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        let Some(operation) = exchange.final_committed() else {
            return;
        };
        let Scope::Incoming { dialog: id, offer_in_request } =
            exchange.scope.clone()
        else {
            unreachable!("only incoming exchanges submit finals");
        };

        // The 2xx carries the answer to the INVITE's offer, or an offer of
        // its own whose answer comes in the ACK.
        let mut negotiation = Negotiation::Stable;
        if offer_in_request {
            negotiation.offer_received().expect("stable");
            negotiation.answer_sent().expect("the offer is outstanding");
        } else {
            negotiation.offer_sent().expect("stable");
        }

        let replay = ReplayId {
            dialog: id.clone(),
            cseq: exchange.cseq,
            direction: Direction::Incoming,
        };
        let (_, usage) = self.establish(
            id,
            Direction::Incoming,
            negotiation,
            replay,
            Source::Exchange(key),
        );

        self.operations.advance(operation, Stage::Committed);
        self.operations.complete(
            operation,
            Ok(Completion::Session(usage)),
            now,
        );
    }

    /// Takes in an ACK. An ACK that matches no 2xx this user agent sent is
    /// dropped without a response or a change of state.
    pub(crate) fn receive_ack(
        &mut self,
        dialog: &DialogId,
        cseq: u32,
        answer: bool,
    ) {
        let id = ReplayId {
            dialog: dialog.clone(),
            cseq,
            direction: Direction::Incoming,
        };
        let Some(&key) = self.replay_index.get(&id) else {
            return;
        };
        let replay = self.replays.get_mut(key).expect("indexed");
        if replay.ack != AckObligation::AwaitingPeer {
            return;
        }

        replay.ack = AckObligation::Satisfied;
        replay.duplicates_ended();
        let (usage, source) = (replay.usage, replay.source);

        if let Source::Exchange(exchange) = source {
            if let Some(mut exchange) = self.exchanges.remove(exchange) {
                exchange.complete();
            }
        }
        if let Some(record) = self.usages.get_mut(usage) {
            // TODO: Treat an ACK without the answer it owes as a negotiation
            // failure. RFC 3261 section 13.2.1 requires the answer in the
            // ACK when the 2xx carried the offer.
            if answer && record.negotiation.answer_received().is_ok() {
                self.effects.push(Effect::Notify(
                    Event::NegotiationCompleted { usage },
                ));
            }
        }
        self.reclaim_replay(key);
    }
}

/// Initial INVITEs this user agent sends.
impl<R: Random> Model<R> {
    /// Opens an attempt for an initial INVITE about to go to the core.
    pub(crate) fn start_attempt(
        &mut self,
        call_id: Box<str>,
        cseq: u32,
        offer_in_request: bool,
    ) -> Result<AttemptKey, Error> {
        let local_tag = self.tag();
        let exchange = self
            .exchanges
            .insert(InviteExchange::outgoing(cseq))
            .map_err(|_| Error::CapacityExceeded)?;
        let attempt = InviteAttempt {
            call_id,
            local_tag,
            cseq,
            offer_in_request,
            exchange,
        };

        self.attempts.insert(attempt).map_err(|_| {
            self.exchanges.remove(exchange);
            Error::CapacityExceeded
        })
    }

    /// Takes in a 2xx to an attempt. A copy of a 2xx seen before is answered
    /// with the same ACK and makes no new usage, whether or not its usage is
    /// still up. RFC 3261 section 13.2.2.4 passes each retransmission of a
    /// 2xx to the UAC core, which answers it with the ACK again.
    pub(crate) fn receive_2xx(
        &mut self,
        key: AttemptKey,
        remote_tag: Tag,
    ) -> Result<(), Error> {
        let Some(attempt) = self.attempts.get(key) else {
            return Err(Error::StaleDecision);
        };
        let id = DialogId::new(
            attempt.call_id.clone(),
            attempt.local_tag.clone(),
            remote_tag,
        );
        let replay = ReplayId {
            dialog: id.clone(),
            cseq: attempt.cseq,
            direction: Direction::Outgoing,
        };
        let (exchange, offer_in_request) =
            (attempt.exchange, attempt.offer_in_request);

        if let Some(&replay) = self.replay_index.get(&replay) {
            self.effects.push(Effect::ResendAck { replay });
            return Ok(());
        }

        // TODO: Still send the ACK and a BYE for a branch that does not fit,
        // from a cleanup budget, and report the response set as incomplete.
        // RFC 3261 section 13.2.2.4 asks for the ACK of every 2xx, and a BYE
        // for each dialog the UAC does not keep.
        if !self.reserve_session() {
            return Err(Error::CapacityExceeded);
        }

        self.exchanges
            .get_mut(exchange)
            .expect("an attempt keeps its exchange")
            .final_received();

        // With an offer in the INVITE, the 2xx carries the answer. Without
        // one, it carries the offer and the ACK owes the answer.
        let mut negotiation = Negotiation::Stable;
        if offer_in_request {
            negotiation.offer_sent().expect("stable");
            negotiation.answer_received().expect("the offer is outstanding");
        } else {
            negotiation.offer_received().expect("stable");
        }

        let (replay, _) = self.establish(
            id,
            Direction::Outgoing,
            negotiation,
            replay,
            Source::Attempt(key),
        );

        self.effects.push(Effect::SendAck { replay });
        Ok(())
    }

    /// Records whether the ACK of a received 2xx was written.
    pub(crate) fn ack_written(&mut self, key: ReplayKey, written: bool) {
        let Some(replay) = self.replays.get_mut(key) else {
            return;
        };

        if replay.ack == AckObligation::NeedToSend {
            replay.ack = if written {
                AckObligation::Satisfied
            } else {
                AckObligation::Failed
            };
        }
    }

    /// Records that the core finished collecting the attempt's responses.
    /// Copies of its 2xx can no longer arrive.
    pub(crate) fn response_collection_finished(&mut self, key: AttemptKey) {
        let Some(attempt) = self.attempts.remove(key) else {
            return;
        };

        if let Some(mut exchange) = self.exchanges.remove(attempt.exchange) {
            exchange.complete();
        }
        let replays: Vec<ReplayKey> = self
            .replays
            .iter()
            .filter(|(_, replay)| replay.source == Source::Attempt(key))
            .map(|(replay, _)| replay)
            .collect();
        for replay in replays {
            self.replays.get_mut(replay).expect("listed").duplicates_ended();
            self.reclaim_replay(replay);
        }
    }
}

/// Usages.
impl<R: Random> Model<R> {
    /// Ends a usage, as when its BYE goes to the core or the peer's BYE is
    /// accepted. The dialog ends with it. The replay contexts of its 2xx
    /// stay until copies of the 2xx can no longer arrive.
    pub(crate) fn end_usage(&mut self, key: UsageKey) {
        let Some(mut usage) = self.usages.remove(key) else {
            return;
        };
        usage.end();

        if let Some(mut dialog) = self.dialogs.remove(usage.dialog) {
            dialog.terminate();
        }
        let replays: Vec<ReplayKey> = self
            .replays
            .iter()
            .filter(|(_, replay)| replay.usage == key)
            .map(|(replay, _)| replay)
            .collect();
        for replay in replays {
            self.replays.get_mut(replay).expect("listed").usage_ended();
            self.reclaim_replay(replay);
        }

        self.effects.push(Effect::Notify(Event::UsageEnded { usage: key }));
    }

    /// Sets aside a dialog, a usage and a replay context, or nothing.
    fn reserve_session(&mut self) -> bool {
        if !self.dialogs.reserve() {
            return false;
        }
        if !self.usages.reserve() {
            self.dialogs.release();
            return false;
        }
        if !self.replays.reserve() {
            self.dialogs.release();
            self.usages.release();
            return false;
        }
        true
    }

    /// Stores the confirmed dialog, usage and replay context of a 2xx in the
    /// slots [`Model::reserve_session`] set aside, and tells the application.
    fn establish(
        &mut self,
        id: DialogId,
        direction: Direction,
        negotiation: Negotiation,
        replay: ReplayId,
        source: Source,
    ) -> (ReplayKey, UsageKey) {
        let dialog = self.dialogs.insert_reserved(Dialog::confirmed(id));
        let usage = self.usages.insert_reserved(InviteUsage::established(
            dialog,
            direction,
            negotiation,
        ));
        let context = ReplayContext::new(replay.clone(), source, usage);
        let key = self.replays.insert_reserved(context);
        self.replay_index.insert(replay, key);

        self.effects
            .push(Effect::Notify(Event::DialogConfirmed { dialog, usage }));
        if negotiation == Negotiation::Stable {
            self.effects
                .push(Effect::Notify(Event::NegotiationCompleted { usage }));
        }
        (key, usage)
    }

    fn reclaim_replay(&mut self, key: ReplayKey) {
        let reclaimable = self.replays.get(key).is_some_and(|replay| {
            replay.retention() == Retention::Reclaimable
        });

        if reclaimable {
            let replay = self.replays.remove(key).expect("checked");
            self.replay_index.remove(&replay.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dialog::DialogPhase, error::WireEffect, invite::UsagePhase,
        operation::Snapshot,
    };

    const RETENTION: Duration = Duration::from_secs(32);

    /// Counts up from one, so each tag is predictable.
    struct Counter(u64);

    impl Random for Counter {
        fn next_u64(&mut self) -> u64 {
            self.0 += 1;
            self.0
        }
    }

    /// Time that moves only when a test moves it.
    struct Clock(Instant);

    impl Clock {
        fn now(&self) -> Instant {
            self.0
        }

        fn advance(&mut self, by: Duration) {
            self.0 += by;
        }
    }

    fn limits() -> Limits {
        Limits {
            attempts: 4,
            exchanges: 4,
            dialogs: 4,
            usages: 4,
            replays: 4,
            operations: 4,
            commands: 4,
            outcome_retention: RETENTION,
        }
    }

    fn model(limits: Limits) -> Model<Counter> {
        Model::new(limits, Counter(0))
    }

    fn tag(src: &str) -> Tag {
        src.parse().unwrap()
    }

    impl<R> Model<R> {
        /// Checks what must hold between the tables after every input.
        fn check(&self) {
            for (key, replay) in self.replays.iter() {
                assert_eq!(self.replay_index.get(&replay.id), Some(&key));
                assert_ne!(replay.retention(), Retention::Reclaimable);
                if let Some(usage) = self.usages.get(replay.usage) {
                    assert_eq!(usage.direction, replay.id.direction);
                }
            }
            assert_eq!(self.replay_index.len(), self.replays.len());

            for (_, usage) in self.usages.iter() {
                let dialog = self.dialogs.get(usage.dialog).unwrap();
                assert_ne!(dialog.phase(), DialogPhase::Terminated);
                assert_ne!(usage.phase(), UsagePhase::Ended);
            }
            assert_eq!(self.dialogs.len(), self.usages.len());

            for (_, exchange) in self.exchanges.iter() {
                if let ExchangeState::FinalSubmissionPending { operation } =
                    exchange.state()
                {
                    let snapshot = self.operations.snapshot(operation);
                    assert_eq!(snapshot.unwrap().outcome, None);
                }
            }
        }

        fn replay(&self, effects: &[Effect]) -> &ReplayContext {
            let replay = effects.iter().find_map(|effect| match effect {
                Effect::SendAck { replay } => Some(*replay),
                _ => None,
            });
            self.replays.get(replay.unwrap()).unwrap()
        }
    }

    fn confirmed(effects: &[Effect]) -> (DialogKey, UsageKey) {
        effects
            .iter()
            .find_map(|effect| match effect {
                Effect::Notify(Event::DialogConfirmed { dialog, usage }) => {
                    Some((*dialog, *usage))
                }
                _ => None,
            })
            .unwrap()
    }

    fn negotiated(effects: &[Effect]) -> bool {
        effects.iter().any(|effect| {
            matches!(
                effect,
                Effect::Notify(Event::NegotiationCompleted { .. })
            )
        })
    }

    /// A UAS takes an INVITE without an offer and accepts it. The 2xx
    /// carries the offer, so its answer comes in the ACK. Once the core has
    /// the 2xx, the dialog is confirmed, but the ACK is still awaited and the
    /// negotiation open. The ACK settles both.
    #[test]
    fn dialog_confirmed_is_not_ack_received_or_media_ready() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite("call".into(), tag("caller"), 1, false)
            .unwrap();
        let exchange = authority.exchange;

        model.try_submit(Command::Accept { authority }).unwrap();
        model.run_commands(clock.now());
        assert_eq!(
            model.take_effects(),
            [Effect::SubmitFinal { exchange, status: StatusCode::OK }],
        );
        model.final_committed(exchange, clock.now());
        model.check();

        let effects = model.take_effects();
        let (dialog, usage) = confirmed(&effects);
        let id = model.dialogs.get(dialog).unwrap().id().clone();
        let replay_key = model.replay_index[&ReplayId {
            dialog: id.clone(),
            cseq: 1,
            direction: Direction::Incoming,
        }];
        assert_eq!(
            model.dialogs.get(dialog).unwrap().phase(),
            DialogPhase::Confirmed,
        );
        assert_eq!(
            model.replays.get(replay_key).unwrap().ack,
            AckObligation::AwaitingPeer,
        );
        assert_eq!(
            model.usages.get(usage).unwrap().negotiation,
            Negotiation::LocalOfferOutstanding,
        );
        assert!(!negotiated(&effects));

        model.receive_ack(&id, 1, true);
        model.check();

        assert_eq!(
            model.take_effects(),
            [Effect::Notify(Event::NegotiationCompleted { usage })],
        );
        assert_eq!(
            model.usages.get(usage).unwrap().negotiation,
            Negotiation::Stable,
        );
        assert!(model.replays.get(replay_key).is_none(), "ACK received");
        assert!(model.exchanges.get(exchange).is_none(), "exchange complete");
    }

    /// A UAC gets a 2xx, sends its ACK and then ends the usage with a BYE.
    /// The peer retransmits the 2xx afterwards, as it does until it sees the
    /// ACK. The copy gets the same ACK again and no new usage. The context
    /// goes only when the core stops collecting responses.
    #[test]
    fn usage_termination_does_not_destroy_needed_replay() {
        let mut model = model(limits());
        let attempt = model.start_attempt("call".into(), 1, true).unwrap();

        model.receive_2xx(attempt, tag("callee")).unwrap();
        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        let replay_key = match effects.last() {
            Some(Effect::SendAck { replay }) => *replay,
            other => panic!("no ACK: {other:?}"),
        };
        assert_eq!(model.replay(&effects).ack, AckObligation::NeedToSend);
        model.ack_written(replay_key, true);

        model.end_usage(usage);
        model.check();
        assert_eq!(
            model.take_effects(),
            [Effect::Notify(Event::UsageEnded { usage })],
        );
        let replay = model.replays.get(replay_key).unwrap();
        assert_eq!(replay.retention(), Retention::ReplayOnly);
        assert_eq!(replay.ack, AckObligation::Satisfied);
        assert_eq!(model.usages.len(), 0);
        assert_eq!(model.dialogs.len(), 0);

        model.receive_2xx(attempt, tag("callee")).unwrap();
        model.check();
        assert_eq!(
            model.take_effects(),
            [Effect::ResendAck { replay: replay_key }],
        );
        assert_eq!(model.usages.len(), 0, "no new usage for a copy");

        model.response_collection_finished(attempt);
        model.check();
        assert!(model.replays.get(replay_key).is_none());
        assert_eq!(
            model.receive_2xx(attempt, tag("callee")),
            Err(Error::StaleDecision),
        );
        assert!(model.take_effects().is_empty());
    }

    /// The application accepts and stops waiting before the command runs.
    /// The command still runs, and its outcome is kept for a snapshot until
    /// the retention time has passed.
    #[test]
    fn accepted_command_survives_waiter_drop() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite("call".into(), tag("caller"), 1, true)
            .unwrap();
        let exchange = authority.exchange;

        let operation =
            model.try_submit(Command::Accept { authority }).unwrap();
        model.waiter_dropped(operation, clock.now());
        clock.advance(RETENTION);
        model.expire(clock.now());

        model.run_commands(clock.now());
        assert_eq!(
            model.take_effects(),
            [Effect::SubmitFinal { exchange, status: StatusCode::OK }],
        );
        model.final_committed(exchange, clock.now());
        model.check();

        let (_, usage) = confirmed(&model.take_effects());
        assert_eq!(
            model.operations.snapshot(operation),
            Some(Snapshot {
                stage: Stage::Committed,
                outcome: Some(Ok(Completion::Session(usage))),
            }),
        );

        clock.advance(RETENTION - Duration::from_millis(1));
        model.expire(clock.now());
        assert!(model.operations.snapshot(operation).is_some());
        clock.advance(Duration::from_millis(1));
        model.expire(clock.now());
        assert_eq!(model.operations.snapshot(operation), None);
    }

    /// With the command queue full, an accept comes back with its authority.
    /// Nothing changed, and the same authority goes through once there is
    /// room.
    #[test]
    fn unsent_busy_command_preserves_decision_authority() {
        let clock = Clock(Instant::now());
        let mut model = model(Limits { commands: 1, ..limits() });
        let first = model
            .receive_invite("one".into(), tag("caller"), 1, true)
            .unwrap();
        let second = model
            .receive_invite("two".into(), tag("caller"), 1, true)
            .unwrap();
        let exchange = second.exchange;
        model.try_submit(Command::Accept { authority: first }).unwrap();

        let refused = model
            .try_submit(Command::Accept { authority: second })
            .unwrap_err();

        assert_eq!(refused.error, Error::Busy);
        assert_eq!(refused.error.wire_effect(), WireEffect::None);
        assert_eq!(
            model.exchanges.get(exchange).unwrap().state(),
            ExchangeState::Pending,
        );
        assert!(model.take_effects().is_empty());

        model.run_commands(clock.now());
        model.take_effects();
        model.try_submit(refused.command).unwrap();
        model.run_commands(clock.now());
        model.check();

        assert_eq!(
            model.take_effects(),
            [Effect::SubmitFinal { exchange, status: StatusCode::OK }],
        );
    }

    /// An accept that loses to another final gets `AlreadyFinalized`, and
    /// one for an exchange that is gone gets `StaleDecision`. Neither goes
    /// on the wire.
    #[test]
    fn a_losing_or_stale_decision_has_no_wire_effect() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite("call".into(), tag("caller"), 1, true)
            .unwrap();
        let exchange = authority.exchange;
        let forged = Authority { exchange };
        model.try_submit(Command::Accept { authority }).unwrap();
        let losing = model.try_submit(Command::Accept { authority: forged });

        model.run_commands(clock.now());

        assert_eq!(model.take_effects().len(), 1);
        assert_eq!(
            model.operations.snapshot(losing.unwrap()).unwrap().outcome,
            Some(Err(Error::AlreadyFinalized)),
        );

        model.exchanges.remove(exchange);
        let stale = model
            .try_submit(Command::Accept { authority: Authority { exchange } })
            .unwrap();
        model.run_commands(clock.now());

        assert!(model.take_effects().is_empty());
        assert_eq!(
            model.operations.snapshot(stale).unwrap().outcome,
            Some(Err(Error::StaleDecision)),
        );
    }

    /// The dialog, usage and replay context of a 2xx are set aside before
    /// it is submitted. Without room, the 2xx does not go out.
    #[test]
    fn no_2xx_without_room_for_its_session() {
        let clock = Clock(Instant::now());
        let mut model = model(Limits { replays: 0, ..limits() });
        let authority = model
            .receive_invite("call".into(), tag("caller"), 1, true)
            .unwrap();
        let exchange = authority.exchange;

        let operation =
            model.try_submit(Command::Accept { authority }).unwrap();
        model.run_commands(clock.now());
        model.check();

        assert!(model.take_effects().is_empty());
        assert_eq!(
            model.operations.snapshot(operation).unwrap().outcome,
            Some(Err(Error::CapacityExceeded)),
        );
        assert_eq!(
            model.exchanges.get(exchange).unwrap().state(),
            ExchangeState::Pending,
        );
        assert!(model.dialogs.reserve(), "the reservation was given back");
    }

    /// An ACK that matches no 2xx this user agent sent, such as one with the
    /// wrong CSeq or tags, changes nothing and gets no response.
    #[test]
    fn an_unknown_ack_changes_nothing() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite("call".into(), tag("caller"), 1, true)
            .unwrap();
        let exchange = authority.exchange;
        model.try_submit(Command::Accept { authority }).unwrap();
        model.run_commands(clock.now());
        model.final_committed(exchange, clock.now());
        let (dialog, _) = confirmed(&model.take_effects());
        let id = model.dialogs.get(dialog).unwrap().id().clone();
        let swapped = DialogId::new(
            id.call_id().into(),
            id.remote_tag().clone(),
            id.local_tag().clone(),
        );

        model.receive_ack(&id, 2, false);
        model.receive_ack(&swapped, 1, false);
        model.check();

        assert!(model.take_effects().is_empty());
        assert_eq!(model.replays.len(), 1);
        assert_eq!(
            model.exchanges.get(exchange).unwrap().state(),
            ExchangeState::FinalObserved,
        );
    }

    /// Tags come from the injected randomness, so a test sees the same ones
    /// on every run.
    #[test]
    fn tags_come_from_the_injected_randomness() {
        let mut model = model(limits());

        let attempt = model.start_attempt("call".into(), 1, true).unwrap();

        let attempt = model.attempts.get(attempt).unwrap();
        assert_eq!(attempt.local_tag.as_str(), "0000000000000001");
    }
}
