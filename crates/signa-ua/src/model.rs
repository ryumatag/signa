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
for timers of the UA core, in [`crate::timer`], and for how long an outcome
nobody waits for is kept.

Two timers end at 64 T1 after a UAS sends a 2xx, and they are not the same.
The core's Timer L keeps the INVITE transaction in Accepted, so that it
absorbs copies of the INVITE and takes the 2xx of other forks
([RFC 6026 section 8.7]). The model's ACK deadline stops retransmitting the
2xx and ends the session that never got its ACK
([RFC 3261 section 13.3.1.4]). Neither waits for the other.

TODO: CANCEL and BYE, re-INVITEs, and the answer an ACK owes are still to
come.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 6026 section 7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-7
[RFC 6026 section 8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
[RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
*/

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use signa_core::{
    Method, Request, Response, StatusCode, message::header::Tag,
};

use crate::{
    dialog::{
        Dialog, DialogError, DialogId, DialogKey, Origin, Outgoing, Sequence,
        request_dialog, response_tag,
    },
    error::Error,
    invite::{
        AttemptKey, AttemptResult, Direction, ExchangeKey, ExchangeState,
        InviteAttempt, InviteExchange, InviteUsage, MergeKey, Scope, UsageKey,
        UsagePhase,
    },
    negotiation::{Description, Negotiation},
    operation::{Completion, OperationId, Operations, Stage, SubmitError},
    plan::{Identity, InvitePlan, PlannedInvite},
    protocol::{self, Field, Malformed},
    retention::{
        AckObligation, Bye, ReplayContext, ReplayId, ReplayKey, Retention,
        Retransmission, Source,
    },
    slot::Slots,
    timer::{Timer, TimerQueue},
};

/// How often a UAS that rings sends its provisional response again.
///
/// RFC 3261 section 13.3.1.1 lets a proxy cancel an INVITE after three
/// minutes without a response, and has the UAS send a non-100 provisional
/// every minute so that a lost one does not cost the call.
const PROVISIONAL_INTERVAL: Duration = Duration::from_secs(60);

/// A source of randomness for tags and Call-IDs, and later the retry timer
/// of a 491.
///
/// RFC 3261 section 19.3 asks for at least 32 bits of cryptographic
/// randomness in a tag. The runtime's source has to meet that. Tests pass a
/// deterministic one.
pub(crate) trait Random {
    /// Returns 64 random bits, or `None` when the source fails, which the
    /// model meets by refusing what needed them.
    fn next_u64(&mut self) -> Option<u64>;
}

/// How much the model holds. Every table is bounded. The runtime sets these
/// from its configuration.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) attempts: usize,
    /// Exchanges of incoming INVITEs. Those of attempts come on top, one
    /// each, so that incoming INVITEs cannot take the room of attempts.
    pub(crate) incoming: usize,
    pub(crate) dialogs: usize,
    pub(crate) usages: usize,
    /// Replay contexts of sessions, including those whose usage ended.
    pub(crate) replays: usize,
    /// Dialogs one attempt may form and keep, early or confirmed, so that a
    /// forking proxy cannot take the room of every other call.
    pub(crate) forks: usize,
    /// Replay contexts of 2xx responses the UA acknowledges and ends with a
    /// BYE rather than keep, as for a fork beyond the limits. They have room
    /// of their own, apart from the sessions', so that the 2xx a full table
    /// turns away still gets its ACK and BYE.
    pub(crate) cleanups: usize,
    /// URIs in the route set of one dialog.
    pub(crate) routes: usize,
    pub(crate) operations: usize,
    /// Commands admitted and not yet run.
    pub(crate) commands: usize,
    /// T1 and T2 of RFC 3261 section 17, which pace the retransmission of a
    /// 2xx this user agent sends and set its ACK deadline.
    pub(crate) t1: Duration,
    pub(crate) t2: Duration,
    /// How long the application may take to decide an incoming INVITE.
    pub(crate) decision_timeout: Duration,
}

/// The authority to decide the final response of an incoming INVITE.
///
/// There is one per exchange, and it is neither `Clone` nor `Copy`, so the
/// application cannot submit two finals. Submitting a decision moves it into
/// the command. A command the UA refuses comes back whole, authority
/// included, so a full queue does not cost the application its decision.
///
/// Dropping it without a decision is not the model's to see. The runtime
/// reports it with [`Model::abandon`].
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Authority {
    exchange: ExchangeKey,
}

impl Authority {
    pub(crate) fn exchange(&self) -> ExchangeKey {
        self.exchange
    }
}

/// What the application asks of the UA.
#[derive(Debug)]
pub(crate) enum Command {
    /// Accept an incoming INVITE with a 2xx that carries `answer`.
    Accept { authority: Authority, answer: Description },
    /// Send a provisional response from 101 to 199 for an incoming INVITE.
    /// It takes no authority, since it decides nothing.
    Provisional { exchange: ExchangeKey, status: StatusCode },
    /// Reject an incoming INVITE with a final response from 300 to 699.
    Reject { authority: Authority, status: StatusCode },
    /// Send an initial INVITE built from a plan, which carries an offer.
    Invite { plan: Box<InvitePlan> },
}

/// What the runtime does on the model's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    /// Submit the final response of an incoming INVITE through its
    /// responder, with `to_tag` on its To and `body` as its body, then report
    /// the verdict with [`Model::final_committed`] or
    /// [`Model::final_refused`]. The runtime keeps a 2xx it submitted, for
    /// [`Effect::Resend2xx`].
    SubmitFinal {
        exchange: ExchangeKey,
        status: StatusCode,
        to_tag: Tag,
        body: Option<Description>,
    },
    /// Submit a provisional response of an incoming INVITE through its
    /// responder, with `to_tag` on its To, then report the verdict with
    /// [`Model::provisional_done`]. `operation` is `None` when the UA sends
    /// it again on its own.
    SubmitProvisional {
        exchange: ExchangeKey,
        status: StatusCode,
        to_tag: Tag,
        operation: Option<OperationId>,
    },
    /// Send the 2xx of an incoming INVITE again, as it was first submitted,
    /// through the INVITE's reply route. Nothing reports back. A copy that
    /// does not get out is covered by the next one.
    Resend2xx { exchange: ExchangeKey },
    /// Send the INVITE of an attempt, which [`Model::take_invite`] hands
    /// over, then report the outcome with [`Model::invite_started`] or
    /// [`Model::invite_failed`].
    StartInvite { attempt: AttemptKey },
    /// Send the ACK of a received 2xx, then report the write with
    /// [`Model::ack_written`].
    SendAck { replay: ReplayKey },
    /// Send the ACK already sent for a 2xx again, for a copy of that 2xx.
    ResendAck { replay: ReplayKey },
    /// Send the BYE of a cleanup, which [`Model::bye_request`] builds, then
    /// report with [`Model::bye_done`] once the core has it or cannot take
    /// it. Nothing waits for the BYE's response.
    SendBye { replay: ReplayKey },
    /// Tell the application what an attempt came to, now that the core has
    /// finished collecting its responses. This cannot be lost, so the
    /// runtime sets room aside for it when it sends the INVITE.
    AttemptEnded {
        attempt: AttemptKey,
        result: AttemptResult,
        complete: bool,
        degraded: bool,
        /// The sessions the attempt formed that are still up, in the order
        /// they formed.
        sessions: Vec<UsageKey>,
    },
    /// Tell the application.
    Notify(Event),
    /// Hand the outcome of an operation to its waiter, if it still has one.
    OperationEnded { operation: OperationId },
    /// Drop what the runtime keeps for a record the model has reclaimed.
    Released(Released),
}

/// A record the model has reclaimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Released {
    /// An attempt whose INVITE never reached the core.
    Attempt(AttemptKey),
    Exchange(ExchangeKey),
    Replay(ReplayKey),
}

/// How an incoming request relates to this user agent's dialogs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Incoming {
    /// It has no To tag, so it is outside any dialog.
    Initial,
    /// It belongs to this dialog.
    InDialog(DialogKey),
    /// It has a To tag that matches no dialog.
    NoDialog,
}

/// Why an incoming request is refused before the application sees it.
///
/// Each reason maps to the status of the response that refuses it. The
/// mapping is the rule of the RFC named, or my policy where it says so.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    /// A header the UA needs is missing or malformed. A 400 (RFC 3261
    /// section 21.4.1).
    Malformed(Field),
    /// It is tagged for a dialog this user agent does not have. A 481 (RFC
    /// 3261 section 12.2.2).
    NoDialog,
    /// It is a merged copy of an INVITE this user agent is handling. A 482
    /// (RFC 3261 section 8.2.2.2).
    Merged,
    /// It requires an extension, and this user agent supports none. A 420
    /// whose Unsupported lists the request's Require tags (RFC 3261 section
    /// 8.2.2.3).
    BadExtension,
    /// Its route set is longer than the limit. A 500, by my policy, since no
    /// status says that the request is too long to keep state for.
    RouteSetTooLong,
    /// There is no room for it. A 503 (RFC 3261 section 21.5.4).
    Busy,
    /// It is something this user agent does not take yet. A 500.
    Unsupported,
    /// Its Request-URI is a SIPS URI, which needs TLS, and this user agent
    /// has none. A 416, which RFC 3261 section 8.2.2.1 gives a scheme the
    /// UAS does not support.
    SipsRequestUri,
    /// It asks for SIPS on the way back, which would need a SIPS Contact in
    /// the response (RFC 3261 section 12.1.1), and so TLS. A 480 with the
    /// warning 380 "SIPS Not Allowed" of a UAS that is not reached over SIPS
    /// (RFC 5630 section 5.1.2).
    SipsNotAllowed,
    /// The UA failed in itself, such as its source of randomness. A 500.
    Internal,
}

impl Refusal {
    pub(crate) fn status(self) -> StatusCode {
        let code = match self {
            Refusal::Malformed(_) => 400,
            Refusal::SipsRequestUri => 416,
            Refusal::BadExtension => 420,
            Refusal::SipsNotAllowed => 480,
            Refusal::NoDialog => 481,
            Refusal::Merged => 482,
            Refusal::RouteSetTooLong
            | Refusal::Unsupported
            | Refusal::Internal => 500,
            Refusal::Busy => 503,
        };
        StatusCode::from_u16(code).expect("a final status")
    }
}

impl From<Malformed> for Refusal {
    fn from(Malformed(field): Malformed) -> Refusal {
        Refusal::Malformed(field)
    }
}

impl From<DialogError> for Refusal {
    fn from(error: DialogError) -> Refusal {
        match error {
            DialogError::Malformed(field) => Refusal::Malformed(field),
            DialogError::RouteSetTooLong => Refusal::RouteSetTooLong,
            DialogError::Terminated => Refusal::NoDialog,
        }
    }
}

/// What the application is told. Losing one of these loses no protocol
/// state, and the outcome of an operation reaches its waiter apart from them.
///
/// TODO: Keep why a usage ended for a while after it is reclaimed, so that a
/// snapshot can tell an ACK timeout whose notification was lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// A provisional response formed an early dialog.
    EarlyDialog { dialog: DialogKey, usage: UsageKey },
    /// A 2xx confirmed the dialog. The ACK may still be owed, and the
    /// session descriptions may not be settled.
    DialogConfirmed { dialog: DialogKey, usage: UsageKey },
    /// The offer/answer exchange of a usage completed.
    NegotiationCompleted { usage: UsageKey },
    /// No ACK came for the 2xx of an incoming INVITE by its deadline. The
    /// usage ends next.
    AckTimeout { usage: UsageKey },
    /// The usage ended.
    UsageEnded { usage: UsageKey },
    /// An attempt got a final response other than a 2xx, or its transaction
    /// failed, which ended its early dialogs.
    AttemptFailed { attempt: AttemptKey, error: Error },
}

/// What an attempt has come to so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttemptState {
    /// What the first final response or failure decided, once it is in.
    pub(crate) result: Option<AttemptResult>,
    pub(crate) complete: bool,
    pub(crate) degraded: bool,
    /// The sessions of the dialogs it formed that are still up, in the order
    /// they formed.
    pub(crate) sessions: Vec<UsageKey>,
}

/// The UA's state.
pub(crate) struct Model<R> {
    limits: Limits,
    /// The Contact URI of every INVITE this user agent sends.
    contact: Box<str>,
    random: R,
    attempts: Slots<InviteAttempt>,
    exchanges: Slots<InviteExchange>,
    dialogs: Slots<Dialog>,
    usages: Slots<InviteUsage>,
    /// The replay contexts of sessions and cleanups, each kind within its
    /// own limit.
    replays: Slots<ReplayContext>,
    /// How many of `replays` are cleanups.
    cleanups: usize,
    /// Finds a dialog from the identity a message carries.
    dialog_index: HashMap<DialogId, DialogKey>,
    /// Finds the replay context of a 2xx or ACK from the wire.
    replay_index: HashMap<ReplayId, ReplayKey>,
    /// Finds the incoming exchange a merged INVITE is a copy of.
    merge_index: HashMap<MergeKey, ExchangeKey>,
    timers: TimerQueue,
    operations: Operations,
    commands: VecDeque<(OperationId, Command)>,
    effects: Vec<Effect>,
}

impl<R: Random> Model<R> {
    pub(crate) fn new(
        limits: Limits,
        contact: Box<str>,
        random: R,
    ) -> Model<R> {
        Model {
            limits,
            contact,
            random,
            attempts: Slots::new(limits.attempts),
            exchanges: Slots::new(
                limits.incoming.saturating_add(limits.attempts),
            ),
            dialogs: Slots::new(limits.dialogs),
            usages: Slots::new(limits.usages),
            replays: Slots::new(
                limits.replays.saturating_add(limits.cleanups),
            ),
            cleanups: 0,
            dialog_index: HashMap::new(),
            replay_index: HashMap::new(),
            merge_index: HashMap::new(),
            timers: TimerQueue::default(),
            operations: Operations::new(limits.operations),
            commands: VecDeque::new(),
            effects: Vec::new(),
        }
    }

    /// Returns the effects of the inputs so far, in order.
    pub(crate) fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// Makes a tag from 64 random bits, as 16 hexadecimal digits.
    fn tag(&mut self) -> Option<Tag> {
        let tag = format!("{:016x}", self.random.next_u64()?);
        Some(Tag::try_from(tag).expect("hexadecimal digits are a token"))
    }

    /// Sets the outcome of an operation and tells the runtime.
    fn complete(
        &mut self,
        operation: OperationId,
        outcome: Result<Completion, Error>,
    ) {
        if self.operations.complete(operation, outcome) {
            self.effects.push(Effect::OperationEnded { operation });
        }
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
    pub(crate) fn run_commands(&mut self) {
        while let Some((operation, command)) = self.commands.pop_front() {
            match command {
                Command::Accept { authority, answer } => self.submit_final(
                    Some(operation),
                    authority.exchange,
                    StatusCode::OK,
                    Some(answer),
                ),
                Command::Reject { authority, status } => {
                    if (300..=699).contains(&status.as_u16()) {
                        self.submit_final(
                            Some(operation),
                            authority.exchange,
                            status,
                            None,
                        );
                    } else {
                        self.complete(operation, Err(Error::InvalidInput));
                    }
                }
                Command::Provisional { exchange, status } => {
                    self.provisional(operation, exchange, status)
                }
                Command::Invite { plan } => self.invite(operation, *plan),
            }
        }
    }

    /// Hands an outcome to its waiter, or drops it when nobody waits for it,
    /// and reclaims the operation.
    pub(crate) fn take_outcome(
        &mut self,
        operation: OperationId,
    ) -> Option<Result<Completion, Error>> {
        self.operations.take(operation)
    }

    /// Returns when [`Model::fire_timers`] has something to do next.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.timers.next()
    }

    /// Runs the timers due by `now`.
    pub(crate) fn fire_timers(&mut self, now: Instant) {
        while let Some((at, timer)) = self.timers.pop_due(now) {
            match timer {
                Timer::Decision(exchange) => self.decision_due(exchange),
                Timer::Expires(exchange) => self.expired(exchange),
                Timer::Provisional(exchange) => {
                    self.provisional_due(exchange, at, now)
                }
                Timer::Retransmit(replay) => {
                    self.retransmission_due(replay, at, now)
                }
                Timer::AckDeadline(replay) => self.ack_overdue(replay),
            }
        }
    }

    /// Returns where a usage stands, or `None` once it has been reclaimed.
    pub(crate) fn usage_state(
        &self,
        usage: UsageKey,
    ) -> Option<(UsagePhase, Negotiation, Option<Description>)> {
        let usage = self.usages.get(usage)?;
        Some((usage.phase(), usage.negotiation, usage.remote.clone()))
    }
}

/// Initial INVITEs this user agent receives.
impl<R: Random> Model<R> {
    /// Says whether a request is outside any dialog or in which one.
    ///
    /// A request with a To tag belongs to a dialog (RFC 3261 section 12.2.2).
    /// If none of this user agent's dialogs matches it, it is not taken for a
    /// new initial request. It is tagged for a dialog this user agent does not
    /// have, perhaps one it lost in a restart, and such a request gets a 481.
    pub(crate) fn classify<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Incoming, Refusal> {
        let Some(id) = request_dialog(request)? else {
            return Ok(Incoming::Initial);
        };
        Ok(match self.dialog_index.get(&id) {
            Some(&dialog) => Incoming::InDialog(dialog),
            None => Incoming::NoDialog,
        })
    }

    /// Takes in an INVITE and returns the authority to decide it, or the
    /// reason to refuse it before the application sees it.
    ///
    /// The checks follow the order of RFC 3261 section 8.2.2: the To tag and
    /// the Request-URI, a merged request, then Require. Then come the
    /// headers the dialog needs, and its Expires (section 13.3.1). `offer` is the session description of
    /// the body, if it is an offer. Telling that is the job of the body
    /// adapter, not of this model. The application's decision is due one decision timeout after
    /// `now`.
    pub(crate) fn receive_invite<B>(
        &mut self,
        request: &Request<B>,
        offer: Option<Description>,
        now: Instant,
    ) -> Result<Authority, Refusal> {
        match self.classify(request)? {
            Incoming::Initial => {}
            Incoming::NoDialog => return Err(Refusal::NoDialog),
            // TODO: Take re-INVITEs into their usage's exchange.
            Incoming::InDialog(_) => return Err(Refusal::Unsupported),
        }
        if protocol::is_sips(request.uri().as_str()) {
            return Err(Refusal::SipsRequestUri);
        }

        let headers = request.headers();
        let merge = MergeKey {
            call_id: protocol::call_id(headers)?.into(),
            from_tag: protocol::from(headers)?.tag.map(Into::into),
            cseq: protocol::cseq(headers)?.0,
        };
        // The core absorbs a retransmission in the INVITE's transaction, so a
        // request that reaches the UA with the identity of an exchange it
        // holds came by another path.
        if self.merge_index.contains_key(&merge) {
            return Err(Refusal::Merged);
        }
        if protocol::requires_extension(headers)? {
            return Err(Refusal::BadExtension);
        }

        if protocol::sips_on_the_way_back(headers)? {
            return Err(Refusal::SipsNotAllowed);
        }
        let expires = protocol::expires(headers)?;

        let Some(local_tag) = self.tag() else {
            return Err(Refusal::Internal);
        };
        let dialog = Dialog::uas(request, local_tag, self.limits.routes)?;
        // A time too far off to add to the clock sets no deadline, rather
        // than overflow.
        let decision_due = now.checked_add(self.limits.decision_timeout);
        let expires_due = expires.and_then(|seconds| {
            now.checked_add(Duration::from_secs(seconds.into()))
        });
        let exchange = InviteExchange::incoming(
            dialog,
            merge.clone(),
            offer,
            decision_due,
            expires_due,
        );

        // The merge index holds one entry for each incoming exchange.
        if self.merge_index.len() >= self.limits.incoming {
            return Err(Refusal::Busy);
        }
        let Ok(exchange) = self.exchanges.insert(exchange) else {
            return Err(Refusal::Busy);
        };
        self.merge_index.insert(merge, exchange);
        if let Some(due) = decision_due {
            self.timers.set(due, Timer::Decision(exchange));
        }
        if let Some(due) = expires_due {
            self.timers.set(due, Timer::Expires(exchange));
        }
        Ok(Authority { exchange })
    }

    /// Sends the final response of an exchange that has none yet.
    ///
    /// `operation` is `None` for a final the UA sends on its own, such as the
    /// 500 of an abandoned INVITE.
    fn submit_final(
        &mut self,
        operation: Option<OperationId>,
        key: ExchangeKey,
        status: StatusCode,
        body: Option<Description>,
    ) {
        let Some(exchange) = self.exchanges.get(key) else {
            if let Some(operation) = operation {
                self.complete(operation, Err(Error::StaleDecision));
            }
            return;
        };
        if exchange.state() != ExchangeState::Pending {
            if let Some(operation) = operation {
                self.complete(operation, Err(Error::AlreadyFinalized));
            }
            return;
        }
        let Scope::Incoming { dialog: Some(dialog), .. } = &exchange.scope
        else {
            unreachable!("a pending incoming exchange keeps its dialog");
        };
        let to_tag = dialog.id().local_tag().clone();

        // The dialog, the usage and the replay context of a 2xx are set
        // aside before it goes out, so it never goes out without them.
        // `final_committed` uses them, and `final_refused` gives them back.
        if status.is_success() && !self.reserve_session() {
            if let Some(operation) = operation {
                self.complete(operation, Err(Error::CapacityExceeded));
            }
            // The authority went with the command, so nobody else can answer
            // the INVITE. The UA does, with the 503 of a server without room
            // (RFC 3261 section 21.5.4). Answering at all is my policy.
            let unavailable = StatusCode::from_u16(503).expect("a status");
            self.submit_final(None, key, unavailable, None);
            return;
        }

        self.stop_exchange_timers(key);
        self.exchanges
            .get_mut(key)
            .expect("checked above")
            .submit_final(operation, status)
            .expect("checked to be pending");
        self.effects.push(Effect::SubmitFinal {
            exchange: key,
            status,
            to_tag,
            body,
        });
    }

    /// Answers an INVITE with a final response of the UA's own, unless a
    /// final is already decided or under way.
    pub(crate) fn reject(
        &mut self,
        exchange: ExchangeKey,
        status: StatusCode,
    ) {
        let pending = self.exchanges.get(exchange).is_some_and(|exchange| {
            exchange.state() == ExchangeState::Pending
        });

        if pending {
            self.submit_final(None, exchange, status, None);
        }
    }

    /// Answers an INVITE whose authority was dropped without a decision.
    ///
    /// The UA sends a 500 unless a final is already decided or under way, so
    /// that no INVITE stays unanswered once nobody can decide it. The 500 is
    /// my policy. No RFC rule picks the status.
    pub(crate) fn abandon(&mut self, exchange: ExchangeKey) {
        let error = StatusCode::from_u16(500).expect("a final status");
        self.reject(exchange, error);
    }

    /// Answers an INVITE the application has not decided in time, as an
    /// abandoned one. The deadline is my policy, so that an application that
    /// loses track of a decision does not leave the caller waiting for
    /// Timer C of every proxy on the way. The application keeps the
    /// authority. A decision it submits later gets `AlreadyFinalized` while
    /// the 500 is under way, and `StaleDecision` once the exchange is gone.
    fn decision_due(&mut self, exchange: ExchangeKey) {
        if let Some(InviteExchange {
            scope: Scope::Incoming { decision_due, .. },
            ..
        }) = self.exchanges.get_mut(exchange)
        {
            *decision_due = None;
        }
        self.abandon(exchange);
    }

    /// Answers an INVITE that expired before a final response with a 487
    /// (RFC 3261 section 13.3.1). The application keeps the authority, and a
    /// decision it submits later fails as one after the decision timeout.
    fn expired(&mut self, exchange: ExchangeKey) {
        if let Some(InviteExchange {
            scope: Scope::Incoming { expires_due, .. },
            ..
        }) = self.exchanges.get_mut(exchange)
        {
            *expires_due = None;
        }
        let terminated = StatusCode::from_u16(487).expect("a final status");
        self.reject(exchange, terminated);
    }

    /// Sends a provisional response the application chose.
    fn provisional(
        &mut self,
        operation: OperationId,
        key: ExchangeKey,
        status: StatusCode,
    ) {
        let Some(exchange) = self.exchanges.get(key) else {
            self.complete(operation, Err(Error::StaleDecision));
            return;
        };
        if exchange.state() != ExchangeState::Pending {
            self.complete(operation, Err(Error::AlreadyFinalized));
            return;
        }
        let Scope::Incoming { dialog: Some(dialog), .. } = &exchange.scope
        else {
            unreachable!("a pending incoming exchange keeps its dialog");
        };
        // A 100 is the core's to send (RFC 3261 section 17.2.1).
        if !(101..=199).contains(&status.as_u16()) {
            self.complete(operation, Err(Error::InvalidInput));
            return;
        }

        let to_tag = dialog.id().local_tag().clone();
        self.effects.push(Effect::SubmitProvisional {
            exchange: key,
            status,
            to_tag,
            operation: Some(operation),
        });
    }

    /// Records the core's verdict on a provisional response.
    ///
    /// The last provisional the application got into the core is the one the
    /// UA sends again a minute later, and every minute after, until a final
    /// is under way. RFC 3261 section 13.3.1.1 asks for that of a UAS that
    /// takes long to answer. The UA does not pick a provisional of its own,
    /// since only the application knows whether the phone rings.
    pub(crate) fn provisional_done(
        &mut self,
        key: ExchangeKey,
        status: StatusCode,
        operation: Option<OperationId>,
        result: Result<(), Error>,
        now: Instant,
    ) {
        let Some(operation) = operation else {
            return;
        };
        if let Err(error) = result {
            self.complete(operation, Err(error));
            return;
        }
        self.operations.advance(operation, Stage::Committed);
        self.complete(operation, Ok(Completion::Done));

        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        if exchange.state() != ExchangeState::Pending {
            return;
        }
        let Scope::Incoming { provisional, .. } = &mut exchange.scope else {
            return;
        };
        if let Some((_, at)) = provisional.take() {
            self.timers.cancel(at, Timer::Provisional(key));
        }
        let at = now + PROVISIONAL_INTERVAL;
        *provisional = Some((status, at));
        self.timers.set(at, Timer::Provisional(key));
    }

    /// Sends the last provisional response again, and sets the next time.
    fn provisional_due(
        &mut self,
        key: ExchangeKey,
        at: Instant,
        now: Instant,
    ) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        if exchange.state() != ExchangeState::Pending {
            return;
        }
        let Scope::Incoming {
            dialog: Some(dialog),
            provisional: Some((status, due)),
            ..
        } = &mut exchange.scope
        else {
            return;
        };

        let next = after(at, PROVISIONAL_INTERVAL, now);
        *due = next;
        self.timers.set(next, Timer::Provisional(key));
        self.effects.push(Effect::SubmitProvisional {
            exchange: key,
            status: *status,
            to_tag: dialog.id().local_tag().clone(),
            operation: None,
        });
    }

    /// Cancels the decision deadline and the provisional replay of an
    /// incoming exchange, as when a final is under way.
    fn stop_exchange_timers(&mut self, key: ExchangeKey) {
        let Some(InviteExchange {
            scope:
                Scope::Incoming { decision_due, expires_due, provisional, .. },
            ..
        }) = self.exchanges.get_mut(key)
        else {
            return;
        };

        if let Some(at) = decision_due.take() {
            self.timers.cancel(at, Timer::Decision(key));
        }
        if let Some(at) = expires_due.take() {
            self.timers.cancel(at, Timer::Expires(key));
        }
        if let Some((_, at)) = provisional.take() {
            self.timers.cancel(at, Timer::Provisional(key));
        }
    }

    /// Removes an incoming exchange with its timers and its place in the
    /// merge index, and has the runtime let go of its responder.
    fn drop_exchange(&mut self, key: ExchangeKey) {
        self.stop_exchange_timers(key);
        let Some(exchange) = self.exchanges.remove(key) else {
            return;
        };

        if let Scope::Incoming { merge, .. } = &exchange.scope {
            if self.merge_index.get(merge) == Some(&key) {
                self.merge_index.remove(merge);
            }
        }
        self.effects.push(Effect::Released(Released::Exchange(key)));
    }

    /// Records the core's acceptance of a final response in flight.
    ///
    /// For a 2xx, RFC 3261 section 13.3.1.4 counts the retransmissions and
    /// the ACK deadline from its first transmission. The model counts from
    /// `now`, when the runtime learns that the core took it, which is the
    /// nearest time it knows and never earlier. The deadline can therefore
    /// fall a little after the core's Timer L, never before.
    pub(crate) fn final_committed(&mut self, key: ExchangeKey, now: Instant) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        let Some((operation, status)) = exchange.final_committed() else {
            return;
        };

        // The core acknowledges a non-2xx itself (RFC 3261 section
        // 17.2.1), so nothing is left for the UA once it takes one.
        if !status.is_success() {
            self.drop_exchange(key);
            if let Some(operation) = operation {
                self.complete(operation, Ok(Completion::Done));
            }
            return;
        }

        let cseq = exchange.cseq;
        let Scope::Incoming { dialog, offer, .. } = &mut exchange.scope else {
            unreachable!("only incoming exchanges submit finals");
        };
        let offer = offer.take();
        let offer_in_request = offer.is_some();
        let mut dialog = *dialog.take().expect("a 2xx forms the dialog once");

        // The 2xx carries the answer to the INVITE's offer, or an offer of
        // its own whose answer comes in the ACK (RFC 3261 section 13.2.1).
        let mut negotiation = Negotiation::Stable;
        if offer_in_request {
            negotiation.offer_received().expect("stable");
            negotiation.answer_sent().expect("the offer is outstanding");
        } else {
            negotiation.offer_sent().expect("stable");
        }

        dialog.confirm().expect("a pending dialog has not ended");
        let replay_dialog = dialog.id().clone();
        let replay = ReplayId {
            dialog: replay_dialog.clone(),
            cseq,
            direction: Direction::Incoming,
        };
        let (replay, usage) = self.establish(
            dialog,
            Direction::Incoming,
            negotiation,
            replay,
            Source::Exchange(key),
        );
        self.usages.get_mut(usage).expect("just made").remote = offer;

        // RFC 3261 section 13.3.1.4 has the 2xx go out again T1 later, and
        // gives up on its ACK 64 T1 after the first.
        let (t1, deadline) = (self.limits.t1, now + self.limits.t1 * 64);
        let next = (now + t1 < deadline).then_some(now + t1);
        self.replays.get_mut(replay).expect("just made").retransmission =
            Some(Retransmission { next, interval: t1, deadline });
        if let Some(next) = next {
            self.timers.set(next, Timer::Retransmit(replay));
        }
        self.timers.set(deadline, Timer::AckDeadline(replay));

        if let Some(operation) = operation {
            self.operations.advance(operation, Stage::Committed);
            self.complete(operation, Ok(Completion::Session(usage)));
        }

        let early_ack = self
            .exchanges
            .get_mut(key)
            .and_then(|exchange| exchange.early_ack.take());
        if let Some(answer) = early_ack {
            self.receive_ack(&replay_dialog, cseq, answer);
        }
    }

    /// Keeps an ACK for a 2xx whose submission the core has not confirmed
    /// yet, so that the race between the two does not lose it. An ACK that
    /// matches no 2xx in flight is dropped.
    fn hold_early_ack(&mut self, dialog: &DialogId, cseq: u32, answer: bool) {
        let in_flight = self.exchanges.iter_mut().find(|(_, exchange)| {
            exchange.cseq == cseq
                && matches!(
                    exchange.state(),
                    ExchangeState::FinalSubmissionPending { status, .. }
                        if status.is_success()
                )
                && matches!(
                    &exchange.scope,
                    Scope::Incoming { dialog: Some(pending), .. }
                        if pending.id() == dialog
                )
        });

        if let Some((_, exchange)) = in_flight {
            // A copy of the ACK carries what the first one did, so a copy
            // without a body does not undo an answer that came before it.
            exchange.early_ack =
                Some(exchange.early_ack == Some(true) || answer);
        }
    }

    /// Records that the core refused a final response in flight.
    ///
    /// Unless `closed`, the core left the transaction as it was, so the
    /// exchange is pending again. Nobody holds its authority any more, so
    /// the UA answers it as an abandoned one, and does not submit the
    /// refused final again. When `closed`, nobody knows
    /// whether the core took the response, and the endpoint is going away,
    /// so nothing more is sent.
    pub(crate) fn final_refused(&mut self, key: ExchangeKey, closed: bool) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        let Some((operation, status)) = exchange.final_refused() else {
            return;
        };

        if status.is_success() {
            self.dialogs.release();
            self.usages.release();
            self.replays.release();
        }
        if let Some(operation) = operation {
            let error = if closed {
                Error::DriverStopped
            } else {
                Error::CoreSubmissionRejected
            };
            self.complete(operation, Err(error));
        }

        if closed {
            self.drop_exchange(key);
        } else if operation.is_some() {
            self.abandon(key);
        } else {
            // The UA's own final was refused. I do not retry it, since no
            // RFC rule asks for more than a final response, and signa-core
            // gives one. Dropping the exchange drops its responder, and
            // signa-core sends its 500 for an unanswered one.
            self.drop_exchange(key);
        }
    }

    /// Takes in an ACK as received. `answer` says whether it carries the
    /// answer to an offer in the 2xx. An ACK without the dialog headers is
    /// dropped. Nothing answers an ACK, since the ACK of a 2xx goes outside
    /// any transaction (RFC 3261 section 13.2.2.4).
    pub(crate) fn receive_ack_request<B>(
        &mut self,
        request: &Request<B>,
        answer: bool,
    ) {
        let (Ok(Some(id)), Ok((cseq, _))) =
            (request_dialog(request), protocol::cseq(request.headers()))
        else {
            return;
        };

        self.receive_ack(&id, cseq, answer);
    }

    /// Takes in an ACK. An ACK that matches no 2xx this user agent sent is
    /// dropped without a response or a change of state. One that matches
    /// stops the 2xx's retransmissions (RFC 3261 section 13.3.1.4), whatever
    /// its body says.
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
            self.hold_early_ack(dialog, cseq, answer);
            return;
        };
        let replay = self.replays.get_mut(key).expect("indexed");
        if replay.ack != AckObligation::AwaitingPeer {
            return;
        }

        replay.ack = AckObligation::Satisfied;
        replay.duplicates_ended();
        let (usage, source) = (replay.usage, replay.source);

        self.stop_retransmission(key);
        if let Source::Exchange(exchange) = source {
            self.drop_exchange(exchange);
        }
        if let Some((usage, record)) =
            usage.and_then(|usage| Some((usage, self.usages.get_mut(usage)?)))
        {
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

    /// Sends a 2xx again and sets the next time, its interval doubled up to
    /// T2 (RFC 3261 section 13.3.1.4). No copy is scheduled at or after the
    /// deadline.
    fn retransmission_due(
        &mut self,
        key: ReplayKey,
        at: Instant,
        now: Instant,
    ) {
        let Some(replay) = self.replays.get_mut(key) else {
            return;
        };
        let (Some(retransmission), Source::Exchange(exchange)) =
            (&mut replay.retransmission, replay.source)
        else {
            return;
        };

        retransmission.interval =
            (retransmission.interval * 2).min(self.limits.t2);
        let next = after(at, retransmission.interval, now);
        retransmission.next = (next < retransmission.deadline).then_some(next);
        if let Some(next) = retransmission.next {
            self.timers.set(next, Timer::Retransmit(key));
        }
        self.effects.push(Effect::Resend2xx { exchange });
    }

    /// Cancels what is left of a 2xx's retransmission.
    fn stop_retransmission(&mut self, key: ReplayKey) {
        let Some(retransmission) = self
            .replays
            .get_mut(key)
            .and_then(|replay| replay.retransmission.take())
        else {
            return;
        };

        if let Some(next) = retransmission.next {
            self.timers.cancel(next, Timer::Retransmit(key));
        }
        self.timers.cancel(retransmission.deadline, Timer::AckDeadline(key));
    }

    /// Gives up on the ACK of a 2xx this user agent sent.
    ///
    /// RFC 3261 section 13.3.1.4 leaves the dialog confirmed and has the
    /// session end with a BYE. A late ACK finds nothing afterwards, so it
    /// brings back neither the usage nor the retransmissions.
    ///
    /// TODO: Send that BYE. Until then the usage ends here without one, and
    /// the application is told why.
    fn ack_overdue(&mut self, key: ReplayKey) {
        let Some(replay) = self.replays.get_mut(key) else {
            return;
        };
        if replay.ack != AckObligation::AwaitingPeer {
            return;
        }

        replay.ack = AckObligation::Failed;
        replay.duplicates_ended();
        let (usage, source) = (replay.usage, replay.source);

        self.stop_retransmission(key);
        if let Source::Exchange(exchange) = source {
            self.drop_exchange(exchange);
        }
        if let Some(usage) =
            usage.filter(|&usage| self.usages.get(usage).is_some())
        {
            self.effects.push(Effect::Notify(Event::AckTimeout { usage }));
            self.end_usage(usage);
        }
        self.reclaim_replay(key);
    }
}

/// Returns `interval` after `at`, the time a timer was due, or after `now`
/// when that has passed too, so that a late driver sends one copy rather
/// than a burst to catch up.
fn after(at: Instant, interval: Duration, now: Instant) -> Instant {
    let next = at + interval;
    if next > now { next } else { now + interval }
}

/// Initial INVITEs this user agent sends.
impl<R: Random> Model<R> {
    /// Opens an attempt for an initial INVITE about to go to the core.
    pub(crate) fn start_attempt<B>(
        &mut self,
        request: &Request<B>,
        offer_in_request: bool,
    ) -> Result<AttemptKey, Error> {
        let origin =
            Origin::from_request(request).map_err(|_| Error::InvalidInput)?;
        let exchange = self
            .exchanges
            .insert(InviteExchange::outgoing(origin.cseq()))
            .map_err(|_| Error::CapacityExceeded)?;
        let attempt = InviteAttempt::new(origin, offer_in_request, exchange);

        self.attempts.insert(attempt).map_err(|_| {
            self.exchanges.remove(exchange);
            Error::CapacityExceeded
        })
    }

    /// Builds the INVITE of a plan, opens an attempt for it, and has the
    /// runtime send it.
    fn invite(&mut self, operation: OperationId, plan: InvitePlan) {
        let Some(identity) = self.identity() else {
            self.complete(operation, Err(Error::Internal));
            return;
        };
        let Some(planned) = plan.build(&identity, &self.contact) else {
            self.complete(operation, Err(Error::InvalidInput));
            return;
        };
        let attempt = match self.start_attempt(&planned.request, true) {
            Ok(attempt) => attempt,
            Err(error) => {
                self.complete(operation, Err(error));
                return;
            }
        };

        let record = self.attempts.get_mut(attempt).expect("just opened");
        record.request = Some(Box::new(planned));
        record.operation = Some(operation);
        self.effects.push(Effect::StartInvite { attempt });
    }

    /// Picks the Call-ID, the From tag and the first CSeq number of an
    /// INVITE.
    ///
    /// The Call-ID is 128 random bits, which RFC 3261 section 8.1.1.4
    /// recommends to make it unique without a host name. The first number
    /// is below 2^16, as a UAS picks its own (`Dialog::uas`), which leaves the
    /// dialog nearly all of the room below the 2^31 that section 8.1.1.5
    /// allows an initial request.
    fn identity(&mut self) -> Option<Identity> {
        let call_id = format!(
            "{:016x}{:016x}",
            self.random.next_u64()?,
            self.random.next_u64()?
        );
        let tag = self.tag()?;
        let cseq = (self.random.next_u64()? & 0xffff) as u32 + 1;
        Some(Identity { call_id: call_id.into(), tag, cseq })
    }

    /// Hands the runtime the INVITE of an attempt to send, with its first
    /// hop.
    pub(crate) fn take_invite(
        &mut self,
        attempt: AttemptKey,
    ) -> Option<PlannedInvite> {
        let request = self.attempts.get_mut(attempt)?.request.take()?;
        Some(*request)
    }

    /// Records that the core took the INVITE of an attempt.
    pub(crate) fn invite_started(&mut self, attempt: AttemptKey) {
        let Some(operation) = self
            .attempts
            .get_mut(attempt)
            .and_then(|attempt| attempt.operation.take())
        else {
            return;
        };

        self.operations.advance(operation, Stage::Committed);
        self.complete(operation, Ok(Completion::Attempt(attempt)));
    }

    /// Records that the INVITE of an attempt never reached the core, and
    /// closes the attempt.
    pub(crate) fn invite_failed(&mut self, attempt: AttemptKey, error: Error) {
        let Some(record) = self.attempts.remove(attempt) else {
            return;
        };

        self.exchanges.remove(record.exchange);
        self.effects.push(Effect::Released(Released::Attempt(attempt)));
        if let Some(operation) = record.operation {
            self.complete(operation, Err(error));
        }
    }

    /// Returns what an attempt came to so far, or `None` once it has ended.
    pub(crate) fn attempt_state(
        &self,
        attempt: AttemptKey,
    ) -> Option<AttemptState> {
        let attempt = self.attempts.get(attempt)?;
        let sessions = attempt
            .forks
            .iter()
            .copied()
            .filter(|&usage| self.usages.get(usage).is_some())
            .collect();

        Some(AttemptState {
            result: attempt.result,
            complete: attempt.complete,
            degraded: attempt.degraded,
            sessions,
        })
    }

    /// Gives an attempt up, as the application intends. Each 2xx that comes
    /// for it from now on, also one for an early dialog, gets its ACK and a
    /// BYE that ends its dialog, and forms no session (RFC 3261 section
    /// 13.2.2.4). The sessions it formed before are left alone.
    ///
    /// TODO: Cancel the INVITE while it is pending, and end the sessions it
    /// formed, once the UA has CANCEL and the BYE of a usage. Until then
    /// nothing but the model gives an attempt up.
    pub(crate) fn abandon_attempt(&mut self, attempt: AttemptKey) {
        if let Some(record) = self.attempts.get_mut(attempt) {
            record.abandoned = true;
        }
    }

    /// Takes in the end of an attempt without a 2xx: a final response other
    /// than a 2xx, or the failure of its transaction, such as a timeout.
    ///
    /// RFC 3261 section 12.3 ends every early dialog of the request then.
    /// The first failure decides the attempt's result, unless a 2xx came
    /// before it.
    pub(crate) fn attempt_failed(
        &mut self,
        attempt: AttemptKey,
        error: Error,
    ) {
        let Some(record) = self.attempts.get_mut(attempt) else {
            return;
        };
        let first = record.result.is_none();
        if first {
            record.result = Some(AttemptResult::Failed(error));
        }

        if let Some(exchange) = self.exchanges.get_mut(record.exchange) {
            exchange.final_received();
        }
        self.end_early_usages(attempt);
        if first {
            self.effects
                .push(Effect::Notify(Event::AttemptFailed { attempt, error }));
        }
    }

    /// Records that the core dropped responses to an attempt for want of
    /// room. The attempt's set of responses can no longer be complete.
    pub(crate) fn responses_lost(&mut self, attempt: AttemptKey) {
        if let Some(record) = self.attempts.get_mut(attempt) {
            record.complete = false;
        }
    }

    /// Ends the early usages an attempt formed.
    fn end_early_usages(&mut self, attempt: AttemptKey) {
        let Some(record) = self.attempts.get(attempt) else {
            return;
        };
        let early: Vec<UsageKey> = record
            .forks
            .iter()
            .copied()
            .filter(|&usage| {
                self.usages.get(usage).is_some_and(|usage| {
                    usage.phase() == UsagePhase::Establishing
                })
            })
            .collect();

        for usage in early {
            self.end_usage(usage);
        }
    }

    /// Says whether the model still keeps a replay context.
    #[cfg(test)]
    pub(crate) fn has_replay(&self, replay: ReplayKey) -> bool {
        self.replays.get(replay).is_some()
    }

    /// Builds the ACK of the 2xx a replay context is for, from its dialog
    /// (RFC 3261 section 13.2.2.4). A cleanup builds it from the dialog it
    /// holds, which no table does.
    pub(crate) fn ack_request(
        &mut self,
        replay: ReplayKey,
    ) -> Option<Outgoing> {
        let context = self.replays.get_mut(replay)?;
        let cseq = context.id.cseq;
        if let Some(dialog) = &mut context.dialog {
            return dialog.request(Method::ACK, Sequence::Of(cseq)).ok();
        }
        let dialog = *self.dialog_index.get(&context.id.dialog)?;

        self.dialogs
            .get_mut(dialog)?
            .request(Method::ACK, Sequence::Of(cseq))
            .ok()
    }

    /// Builds the BYE of a cleanup from its dialog, as any request in a
    /// dialog is built (RFC 3261 section 15.1.1). The dialog goes with it,
    /// so the BYE is built once, and the next number after the INVITE's is
    /// its own.
    pub(crate) fn bye_request(
        &mut self,
        replay: ReplayKey,
    ) -> Option<Outgoing> {
        let mut dialog = self.replays.get_mut(replay)?.dialog.take()?;

        // A UAC's dialog numbers on from its INVITE, so it needs no seed.
        dialog.request(Method::BYE, Sequence::Next { seed: 0 }).ok()
    }

    /// Records that the BYE of a cleanup went to the core, or could not go.
    ///
    /// Nothing waits for its response. RFC 3261 section 15.1.1 has the UAC
    /// take the session as ended once the BYE is in its client transaction,
    /// and whatever the response says, this dialog was never a session of
    /// the application's.
    pub(crate) fn bye_done(&mut self, replay: ReplayKey) {
        let Some(context) = self.replays.get_mut(replay) else {
            return;
        };

        context.bye = Some(Bye::Done);
        context.dialog = None;
        self.reclaim_replay(replay);
    }

    /// Takes in a provisional response to an attempt.
    ///
    /// A 100 changes nothing. A 101 to 199 with a To tag forms an early
    /// dialog (RFC 3261 section 12.1). A later one for the same dialog
    /// changes nothing. It is not reliable, so it refreshes neither the
    /// remote target ([RFC 6141 section 4.9]) nor the route set, which RFC
    /// 3261 section 13.2.2.4 recomputes from the 2xx.
    ///
    /// An early dialog beyond the attempt's forks or the UA's tables is not
    /// formed, which leaves the attempt's set of responses incomplete. Nor is
    /// one of an abandoned attempt. A 2xx for either is acknowledged and its
    /// dialog ended, as a fork the UA does not keep.
    ///
    /// [RFC 6141 section 4.9]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4.9
    pub(crate) fn receive_provisional<B>(
        &mut self,
        key: AttemptKey,
        response: &Response<B>,
    ) -> Result<(), Error> {
        let Some(attempt) = self.attempts.get(key) else {
            return Err(Error::StaleDecision);
        };
        if response.status().as_u16() == 100 {
            return Ok(());
        }
        if !attempt.origin.answered_by(response) {
            return Err(Error::InvalidInput);
        }
        let Some(remote_tag) =
            response_tag(response).map_err(|_| Error::InvalidInput)?
        else {
            return Ok(());
        };
        let id = attempt.origin.dialog_id(Some(remote_tag));
        // RFC 3261 section 13.2.2.1 forms an early dialog only for a dialog
        // ID that matches none. A tag whose 2xx is in, kept as a session or
        // cleaned up, has its dialog, even once the session ended and its
        // record went, so a provisional that comes late for it forms nothing.
        let answered = ReplayId {
            dialog: id.clone(),
            cseq: attempt.origin.cseq(),
            direction: Direction::Outgoing,
        };
        if attempt.abandoned
            || self.dialog_index.contains_key(&id)
            || self.replay_index.contains_key(&answered)
        {
            return Ok(());
        }

        let dialog =
            Dialog::uac(&attempt.origin, response, self.limits.routes)
                .map_err(|_| Error::InvalidInput)?;
        let negotiation = if attempt.offer_in_request {
            Negotiation::LocalOfferOutstanding
        } else {
            Negotiation::Stable
        };
        let mut inserted = None;
        if attempt.forks.len() < self.limits.forks && self.usages.reserve() {
            inserted = self.dialogs.insert(dialog).ok();
            if inserted.is_none() {
                self.usages.release();
            }
        }
        let Some(dialog) = inserted else {
            let attempt = self.attempts.get_mut(key).expect("checked above");
            attempt.complete = false;
            return Err(Error::CapacityExceeded);
        };
        let usage = self.usages.insert_reserved(InviteUsage::early(
            dialog,
            Direction::Outgoing,
            negotiation,
        ));
        self.dialog_index.insert(id, dialog);
        let attempt = self.attempts.get_mut(key).expect("checked above");
        attempt.forks.push(usage);

        self.effects
            .push(Effect::Notify(Event::EarlyDialog { dialog, usage }));
        Ok(())
    }

    /// Takes in a 2xx to an attempt, and the session description it
    /// carries. A copy of a 2xx seen before is answered with the same ACK
    /// and makes no new usage, whether or not its usage is still up. RFC 3261
    /// section 13.2.2.4 passes each retransmission of a 2xx to the UAC core,
    /// which answers it with the ACK again.
    ///
    /// A 2xx for an early dialog confirms it, and one for a new remote tag
    /// forms a confirmed dialog of its own, as RFC 3261 section 13.2.2.4
    /// requires of a fork. So does one whose early dialog ended before it,
    /// as at a non-2xx from another fork, since its dialog ID then matches
    /// no dialog. No 2xx is preferred over another. Each one is a
    /// session of its own for the application to keep or end, and the ACK
    /// goes whatever the application makes of it.
    ///
    /// A fork beyond the attempt's limit or the UA's tables, or any 2xx of
    /// an abandoned attempt, forms no session. The UA acknowledges it and
    /// ends its dialog with a BYE, which section 13.2.2.4 asks of a UAC that
    /// does not want the dialog, from room kept for that alone. Without that
    /// room the 2xx gets neither, and the attempt says it is degraded.
    ///
    /// A 2xx with the INVITE's identity answered the INVITE, kept or not.
    /// One the UA does not keep for want of room, or cannot form a dialog
    /// from, such as one without a Contact, leaves the attempt's set of
    /// responses incomplete, since the attempt cannot report it as a
    /// session. One that cannot form a dialog gets no ACK, since the ACK is
    /// built from the dialog (section 13.2.2.4).
    pub(crate) fn receive_2xx<B>(
        &mut self,
        key: AttemptKey,
        response: &Response<B>,
        description: Option<Description>,
    ) -> Result<(), Error> {
        let Some(attempt) = self.attempts.get_mut(key) else {
            return Err(Error::StaleDecision);
        };
        if !attempt.origin.answered_by(response) {
            attempt.complete = false;
            return Err(Error::InvalidInput);
        }
        attempt.result.get_or_insert(AttemptResult::Answered);
        self.exchanges
            .get_mut(attempt.exchange)
            .expect("an attempt keeps its exchange")
            .final_received();

        let result = self.take_2xx(key, response, description);
        if result.is_err() {
            let attempt = self.attempts.get_mut(key).expect("checked above");
            attempt.complete = false;
        }
        result
    }

    /// Does what [`Model::receive_2xx`] says for a 2xx with the INVITE's
    /// identity. Every path that leaves an ACK to send queues it.
    fn take_2xx<B>(
        &mut self,
        key: AttemptKey,
        response: &Response<B>,
        description: Option<Description>,
    ) -> Result<(), Error> {
        let attempt = self.attempts.get(key).expect("checked by the caller");
        let remote_tag =
            response_tag(response).map_err(|_| Error::InvalidInput)?;
        let id = attempt.origin.dialog_id(remote_tag);
        let replay = ReplayId {
            dialog: id.clone(),
            cseq: attempt.origin.cseq(),
            direction: Direction::Outgoing,
        };

        // The 2xx and its copies share one context. A copy, of a session or
        // of a cleanup, gets the ACK again, and neither a new session nor a
        // second BYE.
        if let Some(&replay) = self.replay_index.get(&replay) {
            self.effects.push(Effect::ResendAck { replay });
            return Ok(());
        }
        if let Some(dialog) = self.dialog_index.get(&id).copied() {
            return self.confirm_early(
                key,
                dialog,
                response,
                replay,
                description,
            );
        }

        let (abandoned, forks) = (attempt.abandoned, attempt.forks.len());
        let offer_in_request = attempt.offer_in_request;
        let dialog =
            Dialog::uac(&attempt.origin, response, self.limits.routes)
                .map_err(|_| Error::InvalidInput)?;
        if abandoned {
            return self
                .clean_up(key, dialog, replay)
                .then_some(())
                .ok_or(Error::CapacityExceeded);
        }
        if forks >= self.limits.forks || !self.reserve_session() {
            self.clean_up(key, dialog, replay);
            return Err(Error::CapacityExceeded);
        }

        // With an offer in the INVITE, the 2xx carries the answer. Without
        // one, it carries the offer and the ACK owes the answer (RFC 3261
        // section 13.2.1). Each fork starts from the INVITE's offer and
        // goes on alone, since each answer comes from another peer.
        let mut negotiation = if offer_in_request {
            Negotiation::LocalOfferOutstanding
        } else {
            Negotiation::Stable
        };
        settle_at_2xx(&mut negotiation, description.is_some());
        let (replay, usage) = self.establish(
            dialog,
            Direction::Outgoing,
            negotiation,
            replay,
            Source::Attempt(key),
        );
        self.usages.get_mut(usage).expect("just made").remote = description;
        self.attempts.get_mut(key).expect("checked above").forks.push(usage);
        self.effects.push(Effect::SendAck { replay });
        Ok(())
    }

    /// Confirms an early dialog with its 2xx and makes the replay context for
    /// the 2xx's ACK.
    ///
    /// For an abandoned attempt, or without room for the context, the early
    /// session ends instead, and the 2xx is cleaned up with the dialog it
    /// confirmed. The dialog keeps what it had, such as the numbers of
    /// requests sent in it while early, which section 13.2.2.4 does not
    /// recompute. Without room for the cleanup either, nothing changes and
    /// the attempt is degraded, so that a copy of the 2xx tries again with
    /// the early dialog as it was.
    fn confirm_early<B>(
        &mut self,
        attempt: AttemptKey,
        dialog: DialogKey,
        response: &Response<B>,
        replay: ReplayId,
        description: Option<Description>,
    ) -> Result<(), Error> {
        let record =
            self.attempts.get(attempt).expect("checked by the caller");
        let abandoned = record.abandoned;
        let usage = record
            .forks
            .iter()
            .copied()
            .find(|&usage| {
                self.usages
                    .get(usage)
                    .is_some_and(|usage| usage.dialog == dialog)
            })
            .expect("an early dialog has its usage");
        let room = !abandoned && self.reserve_replay();
        if !room && self.cleanups >= self.limits.cleanups {
            let record = self.attempts.get_mut(attempt).expect("checked");
            record.degraded = true;
            return Err(Error::CapacityExceeded);
        }
        let record = self.dialogs.get_mut(dialog).expect("indexed");
        if record.confirm_with(response, self.limits.routes).is_err() {
            if room {
                self.replays.release();
            }
            return Err(Error::InvalidInput);
        }

        if !room {
            let record = self.dialogs.remove(dialog).expect("indexed");
            self.dialog_index.remove(record.id());
            self.end_usage(usage);
            let cleaned = self.clean_up(attempt, record, replay);
            debug_assert!(cleaned, "the room was checked above");
            return if abandoned {
                Ok(())
            } else {
                Err(Error::CapacityExceeded)
            };
        }

        let record = self.usages.get_mut(usage).expect("found above");
        record.establish();
        settle_at_2xx(&mut record.negotiation, description.is_some());
        record.remote = description;
        let settled = record.negotiation == Negotiation::Stable;

        let context = ReplayContext::new(
            replay.clone(),
            Source::Attempt(attempt),
            usage,
        );
        let key = self.replays.insert_reserved(context);
        self.replay_index.insert(replay, key);

        self.effects
            .push(Effect::Notify(Event::DialogConfirmed { dialog, usage }));
        if settled {
            self.effects
                .push(Effect::Notify(Event::NegotiationCompleted { usage }));
        }
        self.effects.push(Effect::SendAck { replay: key });
        Ok(())
    }

    /// Keeps a 2xx the UA does not keep as a session, so that it gets its
    /// ACK, and a BYE after it that ends its dialog (RFC 3261 section
    /// 13.2.2.4). Returns whether there was room.
    ///
    /// Without room the 2xx gets neither, and the attempt is degraded. The
    /// peer then retransmits the 2xx until it gives up on the ACK, and ends
    /// the dialog itself with a BYE (section 13.3.1.4). A cleanup makes no
    /// session, so the application hears nothing of it but what the attempt
    /// reports.
    ///
    /// TODO: Carry the answer in the ACK of a 2xx that holds an offer, which
    /// section 13.2.2.4 asks of a dialog the UAC ends too. The UA sends no
    /// INVITE without an offer yet, so each 2xx it gets holds an answer.
    fn clean_up(
        &mut self,
        attempt: AttemptKey,
        dialog: Dialog,
        replay: ReplayId,
    ) -> bool {
        let key = if self.cleanups < self.limits.cleanups {
            let context =
                ReplayContext::cleanup(replay.clone(), attempt, dialog);
            self.replays.insert(context).ok()
        } else {
            None
        };
        let Some(key) = key else {
            if let Some(record) = self.attempts.get_mut(attempt) {
                record.degraded = true;
            }
            return false;
        };

        self.cleanups += 1;
        self.replay_index.insert(replay, key);
        self.effects.push(Effect::SendAck { replay: key });
        true
    }

    /// Records whether an ACK of a received 2xx was written.
    ///
    /// A failure is not final. The next copy of the 2xx gets the ACK again
    /// (RFC 3261 section 13.2.2.4), and a write that succeeds then satisfies
    /// the obligation.
    ///
    /// The first try of a cleanup's ACK, whatever came of it, lets its BYE
    /// go, since the BYE follows the ACK.
    pub(crate) fn ack_written(&mut self, key: ReplayKey, written: bool) {
        let Some(replay) = self.replays.get_mut(key) else {
            return;
        };

        match (replay.ack, written) {
            (AckObligation::NeedToSend | AckObligation::Failed, true) => {
                replay.ack = AckObligation::Satisfied;
            }
            (AckObligation::NeedToSend, false) => {
                replay.ack = AckObligation::Failed;
            }
            _ => {}
        }
        if replay.bye == Some(Bye::Owed) {
            replay.bye = Some(Bye::Sending);
            self.effects.push(Effect::SendBye { replay: key });
        }
    }

    /// Records that the core finished collecting the attempt's responses,
    /// and reports what the attempt came to, with the sessions that outlive
    /// it. Copies of its 2xx can no longer arrive, and an early dialog no
    /// response confirmed can no longer be confirmed.
    ///
    /// An attempt that ends without a final response or a failure, as when
    /// the endpoint stops, failed with `DriverStopped`, or with
    /// `ObservationIncomplete` if the core dropped responses that may have
    /// been the final one.
    pub(crate) fn response_collection_finished(&mut self, key: AttemptKey) {
        self.end_early_usages(key);
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

        let result = attempt.result.unwrap_or(AttemptResult::Failed(
            if attempt.complete {
                Error::DriverStopped
            } else {
                Error::ObservationIncomplete
            },
        ));
        // The end of the attempt is the event that cannot be lost, so it
        // lists the sessions that outlive it. An application that missed
        // the notification of one finds it here, after the attempt's
        // snapshot is gone.
        let sessions = attempt
            .forks
            .into_iter()
            .filter(|&usage| self.usages.get(usage).is_some())
            .collect();
        self.effects.push(Effect::AttemptEnded {
            attempt: key,
            result,
            complete: attempt.complete,
            degraded: attempt.degraded,
            sessions,
        });
    }
}

/// Moves a sent INVITE's negotiation past its 2xx, which carries the answer
/// to the INVITE's offer, or an offer when the INVITE had none (RFC 3261
/// section 13.2.1). `description` says whether the 2xx carries one.
///
/// TODO: Treat a 2xx without the answer it owes as a negotiation failure.
/// Until then the offer stays outstanding, and the session never reports a
/// completed negotiation.
fn settle_at_2xx(negotiation: &mut Negotiation, description: bool) {
    if !description {
        return;
    }
    match negotiation {
        Negotiation::LocalOfferOutstanding => {
            negotiation.answer_received().expect("the offer is outstanding")
        }
        Negotiation::Stable => negotiation.offer_received().expect("stable"),
        // An offer from the peer is already outstanding, so the 2xx holds
        // no new one.
        Negotiation::RemoteOfferOutstanding => {}
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
            self.dialog_index.remove(dialog.id());
        }
        let replays: Vec<ReplayKey> = self
            .replays
            .iter()
            .filter(|(_, replay)| replay.usage == Some(key))
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
        if !self.reserve_replay() {
            self.dialogs.release();
            self.usages.release();
            return false;
        }
        true
    }

    /// Sets aside a replay context for a session. The cleanups' room is in
    /// the same table, and a session does not take it.
    fn reserve_replay(&mut self) -> bool {
        let sessions =
            self.replays.len() - self.cleanups + self.replays.reserved();
        sessions < self.limits.replays && self.replays.reserve()
    }

    /// Stores a confirmed dialog, its usage and the replay context of its 2xx
    /// in the slots [`Model::reserve_session`] set aside, and tells the
    /// application.
    fn establish(
        &mut self,
        dialog: Dialog,
        direction: Direction,
        negotiation: Negotiation,
        replay: ReplayId,
        source: Source,
    ) -> (ReplayKey, UsageKey) {
        let id = dialog.id().clone();
        let dialog = self.dialogs.insert_reserved(dialog);
        self.dialog_index.insert(id, dialog);
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
            if replay.usage.is_none() {
                self.cleanups -= 1;
            }
            self.replay_index.remove(&replay.id);
            self.effects.push(Effect::Released(Released::Replay(key)));
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        dialog::DialogPhase,
        error::WireEffect,
        invite::UsagePhase,
        operation::Snapshot,
        tests::{INVITE, invite, reply, request, response},
    };

    const T1: Duration = Duration::from_millis(500);
    const T2: Duration = Duration::from_secs(4);
    const DECISION: Duration = Duration::from_secs(180);

    /// Counts up from one, so each tag is predictable.
    struct Counter(u64);

    impl Random for Counter {
        fn next_u64(&mut self) -> Option<u64> {
            self.0 += 1;
            Some(self.0)
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
            incoming: 4,
            dialogs: 4,
            usages: 4,
            replays: 4,
            forks: 4,
            cleanups: 4,
            routes: 8,
            operations: 4,
            commands: 4,
            t1: T1,
            t2: T2,
            decision_timeout: DECISION,
        }
    }

    /// An offer in an INVITE, which the model passes on without reading.
    fn offer() -> Option<Description> {
        Some(answer())
    }

    /// An answer, which the model passes on without reading.
    fn answer() -> Description {
        Description::new(
            signa_core::HeaderValue::from_static("application/sdp"),
            Bytes::from_static(b"v=0\r\n"),
        )
    }

    fn model(limits: Limits) -> Model<Counter> {
        Model::new(limits, "sip:ua@192.0.2.1".into(), Counter(0))
    }

    /// The 2xx of the callee, with the tag `callee`.
    fn callee() -> Response<Bytes> {
        reply("200 OK", "callee", "sip:bob@192.0.2.4", "")
    }

    /// The 2xx of the callee, with `from` replaced by `to` in its text.
    fn callee_with(from: &str, to: &str) -> Response<Bytes> {
        let text = String::from_utf8(callee().to_bytes().to_vec()).unwrap();
        response(&text.replace("\r\n", "\n").replace(from, to))
    }

    impl<R> Model<R> {
        /// Checks what must hold between the tables after every input.
        fn check(&self) {
            let mut cleanups = 0;
            for (key, replay) in self.replays.iter() {
                assert_eq!(self.replay_index.get(&replay.id), Some(&key));
                assert_ne!(replay.retention(), Retention::Reclaimable);
                match replay.usage {
                    Some(usage) => {
                        assert_eq!(replay.bye, None);
                        if let Some(usage) = self.usages.get(usage) {
                            assert_eq!(usage.direction, replay.id.direction);
                        }
                    }
                    None => {
                        cleanups += 1;
                        assert!(replay.bye.is_some());
                        assert_eq!(replay.id.direction, Direction::Outgoing);
                    }
                }
            }
            assert_eq!(self.replay_index.len(), self.replays.len());
            assert_eq!(self.cleanups, cleanups);
            assert!(cleanups <= self.limits.cleanups);
            assert!(self.replays.len() - cleanups <= self.limits.replays);
            for (_, attempt) in self.attempts.iter() {
                assert!(attempt.forks.len() <= self.limits.forks);
            }

            for (_, usage) in self.usages.iter() {
                let dialog = self.dialogs.get(usage.dialog).unwrap();
                assert_ne!(dialog.phase(), DialogPhase::Terminated);
                assert_ne!(usage.phase(), UsagePhase::Ended);
            }
            assert_eq!(self.dialogs.len(), self.usages.len());

            // Each timer that is set belongs to a record that holds its
            // instant, so none outlives its record.
            let mut timers = 0;
            let mut incoming = 0;
            for (key, exchange) in self.exchanges.iter() {
                if let ExchangeState::FinalSubmissionPending {
                    operation: Some(operation),
                    ..
                } = exchange.state()
                {
                    let snapshot = self.operations.snapshot(operation);
                    assert_eq!(snapshot.unwrap().outcome, None);
                }
                if let Scope::Incoming {
                    merge,
                    decision_due,
                    expires_due,
                    provisional,
                    ..
                } = &exchange.scope
                {
                    incoming += 1;
                    assert_eq!(self.merge_index.get(merge), Some(&key));
                    timers += usize::from(decision_due.is_some());
                    timers += usize::from(expires_due.is_some());
                    timers += usize::from(provisional.is_some());
                    if exchange.state() != ExchangeState::Pending {
                        assert!(
                            decision_due.is_none()
                                && expires_due.is_none()
                                && provisional.is_none()
                        );
                    }
                }
            }
            for (_, replay) in self.replays.iter() {
                if let Some(retransmission) = replay.retransmission {
                    assert_eq!(replay.ack, AckObligation::AwaitingPeer);
                    timers += 1 + usize::from(retransmission.next.is_some());
                }
            }
            assert_eq!(self.merge_index.len(), incoming);
            assert_eq!(self.timers.len(), timers);
        }

        fn replay(&self, effects: &[Effect]) -> &ReplayContext {
            let replay = effects.iter().find_map(|effect| match effect {
                Effect::SendAck { replay } => Some(*replay),
                _ => None,
            });
            self.replays.get(replay.unwrap()).unwrap()
        }
    }

    /// Returns the final responses among `effects`, which must be all there
    /// is.
    fn finals(effects: Vec<Effect>) -> Vec<(ExchangeKey, u16)> {
        effects
            .into_iter()
            .map(|effect| match effect {
                Effect::SubmitFinal { exchange, status, .. } => {
                    (exchange, status.as_u16())
                }
                other => panic!("not a final: {other:?}"),
            })
            .collect()
    }

    /// Returns what `effects` tell the application.
    fn notices(effects: &[Effect]) -> Vec<Event> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Notify(event) => Some(*event),
                _ => None,
            })
            .collect()
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

    /// Has the UAS take the INVITE, accept it and the core take the 2xx at
    /// the clock's time, and returns the exchange, the replay context and the
    /// usage.
    fn accepted(
        model: &mut Model<Counter>,
        clock: &Clock,
    ) -> (ExchangeKey, ReplayKey, UsageKey) {
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.final_committed(exchange, clock.now());

        let (dialog, usage) = confirmed(&model.take_effects());
        let id = model.dialogs.get(dialog).unwrap().id().clone();
        let replay = model.replay_index[&ReplayId {
            dialog: id,
            cseq: 314159,
            direction: Direction::Incoming,
        }];
        (exchange, replay, usage)
    }

    /// The dialog of the INVITE, as the UAS of [`accepted`] sees it.
    fn uas_dialog() -> DialogId {
        DialogId::new(
            "a84b4c76e66710@pc33.atlanta.example.com".into(),
            "0000000000000001".parse().unwrap(),
            Some("1928301774".parse().unwrap()),
        )
    }

    /// Moves the clock to `to` and runs the timers due by then.
    fn advance_to(
        model: &mut Model<Counter>,
        clock: &mut Clock,
        to: Instant,
    ) -> Vec<Effect> {
        clock.0 = to;
        model.fire_timers(clock.now());
        model.check();
        model.take_effects()
    }

    /// A UAS takes an INVITE without an offer and accepts it. The 2xx
    /// carries the offer, so its answer comes in the ACK. Once the core has
    /// the 2xx, the dialog is confirmed, but the ACK is still awaited and the
    /// negotiation open. The ACK settles both.
    #[test]
    fn dialog_confirmed_is_not_ack_received_or_media_ready() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority =
            model.receive_invite(&request(INVITE), None, clock.now()).unwrap();
        let exchange = authority.exchange;

        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        assert_eq!(finals(model.take_effects()), [(exchange, 200)]);
        model.final_committed(exchange, clock.now());
        model.check();

        let effects = model.take_effects();
        let (dialog, usage) = confirmed(&effects);
        let id = model.dialogs.get(dialog).unwrap().id().clone();
        let replay_key = model.replay_index[&ReplayId {
            dialog: id.clone(),
            cseq: 314159,
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

        model.receive_ack(&id, 314159, true);
        model.check();

        assert_eq!(
            notices(&model.take_effects()),
            [Event::NegotiationCompleted { usage }],
        );
        assert_eq!(
            model.usages.get(usage).unwrap().negotiation,
            Negotiation::Stable,
        );
        assert!(model.replays.get(replay_key).is_none(), "ACK received");
        assert!(model.exchanges.get(exchange).is_none(), "exchange complete");
    }

    /// An ACK that could not be written leaves the obligation failed, not
    /// over. The next copy of the 2xx asks for the ACK again, and a write
    /// that succeeds then satisfies it.
    #[test]
    fn a_failed_ack_goes_out_again_with_the_next_2xx() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        let effects = model.take_effects();
        let replay = match effects.last() {
            Some(Effect::SendAck { replay }) => *replay,
            other => panic!("no ACK: {other:?}"),
        };

        model.ack_written(replay, false);
        assert_eq!(
            model.replays.get(replay).unwrap().ack,
            AckObligation::Failed
        );
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        assert_eq!(model.take_effects(), [Effect::ResendAck { replay }]);
        model.ack_written(replay, true);

        model.check();
        let context = model.replays.get(replay).unwrap();
        assert_eq!(context.ack, AckObligation::Satisfied);
        model.ack_written(replay, false);
        let context = model.replays.get(replay).unwrap();
        assert_eq!(context.ack, AckObligation::Satisfied, "a copy failing");
    }

    /// A UAC gets a 2xx, sends its ACK and then ends the usage with a BYE.
    /// The peer retransmits the 2xx afterwards, as it does until it sees the
    /// ACK. The copy gets the same ACK again and no new usage. The context
    /// goes only when the core stops collecting responses.
    #[test]
    fn usage_termination_does_not_destroy_needed_replay() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
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
        assert!(model.has_replay(replay_key));
        let replay = model.replays.get(replay_key).unwrap();
        assert_eq!(replay.retention(), Retention::ReplayOnly);
        assert_eq!(replay.ack, AckObligation::Satisfied);
        assert_eq!(model.usages.len(), 0);
        assert_eq!(model.dialogs.len(), 0);

        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        model.check();
        assert_eq!(
            model.take_effects(),
            [Effect::ResendAck { replay: replay_key }],
        );
        assert_eq!(model.usages.len(), 0, "no new usage for a copy");

        model.response_collection_finished(attempt);
        model.check();
        assert_eq!(
            model.take_effects(),
            [
                Effect::Released(Released::Replay(replay_key)),
                Effect::AttemptEnded {
                    attempt,
                    result: AttemptResult::Answered,
                    complete: true,
                    degraded: false,
                    sessions: vec![],
                },
            ],
        );
        assert!(!model.has_replay(replay_key));
        assert_eq!(
            model.receive_2xx(attempt, &callee(), Some(answer())),
            Err(Error::StaleDecision),
        );
        assert!(model.take_effects().is_empty());
    }

    /// The application accepts and stops waiting before the command runs.
    /// The model hears nothing of it, the command still runs to its outcome,
    /// and the runtime reclaims the outcome unread.
    #[test]
    fn accepted_command_survives_waiter_drop() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;

        let operation = model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        assert_eq!(finals(model.take_effects()), [(exchange, 200)]);
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
        assert!(model.take_outcome(operation).is_some());
        assert_eq!(model.operations.snapshot(operation), None);
        assert!(model.usage_state(usage).is_some(), "the session goes on");
    }

    /// With the command queue full, an accept comes back with its authority.
    /// Nothing changed, and the same authority goes through once there is
    /// room.
    #[test]
    fn unsent_busy_command_preserves_decision_authority() {
        let clock = Clock(Instant::now());
        let mut model = model(Limits { commands: 1, ..limits() });
        let first = model
            .receive_invite(&invite("one@example.com"), offer(), clock.now())
            .unwrap();
        let second = model
            .receive_invite(&invite("two@example.com"), offer(), clock.now())
            .unwrap();
        let exchange = second.exchange;
        model
            .try_submit(Command::Accept { authority: first, answer: answer() })
            .unwrap();

        let refused = model
            .try_submit(Command::Accept {
                authority: second,
                answer: answer(),
            })
            .unwrap_err();

        assert_eq!(refused.error, Error::Busy);
        assert_eq!(refused.error.wire_effect(), WireEffect::None);
        assert_eq!(
            model.exchanges.get(exchange).unwrap().state(),
            ExchangeState::Pending,
        );
        assert!(model.take_effects().is_empty());

        model.run_commands();
        model.take_effects();
        model.try_submit(refused.command).unwrap();
        model.run_commands();
        model.check();

        assert_eq!(finals(model.take_effects()), [(exchange, 200)]);
    }

    /// An accept that loses to another final gets `AlreadyFinalized`, and
    /// one for an exchange that is gone gets `StaleDecision`. Neither goes
    /// on the wire.
    #[test]
    fn a_losing_or_stale_decision_has_no_wire_effect() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        let forged = Authority { exchange };
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        let losing = model.try_submit(Command::Accept {
            authority: forged,
            answer: answer(),
        });

        model.run_commands();

        let losing = losing.unwrap();
        assert_eq!(
            model.take_effects(),
            [
                Effect::SubmitFinal {
                    exchange,
                    status: StatusCode::OK,
                    to_tag: "0000000000000001".parse().unwrap(),
                    body: Some(answer()),
                },
                Effect::OperationEnded { operation: losing },
            ],
        );
        assert_eq!(
            model.operations.snapshot(losing).unwrap().outcome,
            Some(Err(Error::AlreadyFinalized)),
        );

        model.exchanges.remove(exchange);
        let stale = model
            .try_submit(Command::Accept {
                authority: Authority { exchange },
                answer: answer(),
            })
            .unwrap();
        model.run_commands();

        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation: stale }],
        );
        assert_eq!(
            model.operations.snapshot(stale).unwrap().outcome,
            Some(Err(Error::StaleDecision)),
        );
    }

    /// The dialog, usage and replay context of a 2xx are set aside before
    /// it is submitted. Without room, the 2xx does not go out, and the UA
    /// answers the INVITE with a 503 in its place, since the authority went
    /// with the accept.
    #[test]
    fn no_2xx_without_room_for_its_session() {
        let clock = Clock(Instant::now());
        let mut model = model(Limits { replays: 0, ..limits() });
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;

        let operation = model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.check();

        let effects = model.take_effects();
        assert_eq!(effects[0], Effect::OperationEnded { operation });
        assert_eq!(finals(effects[1..].to_vec()), [(exchange, 503)]);
        assert_eq!(
            model.operations.snapshot(operation).unwrap().outcome,
            Some(Err(Error::CapacityExceeded)),
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
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.final_committed(exchange, clock.now());
        let (dialog, _) = confirmed(&model.take_effects());
        let id = model.dialogs.get(dialog).unwrap().id().clone();
        let swapped = DialogId::new(
            id.call_id().into(),
            id.remote_tag().unwrap().clone(),
            Some(id.local_tag().clone()),
        );

        model.receive_ack(&id, 314160, false);
        model.receive_ack(&swapped, 314159, false);
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
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;

        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.final_committed(exchange, clock.now());

        let (dialog, _) = confirmed(&model.take_effects());
        let id = model.dialogs.get(dialog).unwrap().id();
        assert_eq!(id.local_tag().as_str(), "0000000000000001");
    }

    /// An INVITE with a To tag for a dialog this user agent does not have is
    /// refused with a 481. It is not taken for a new call, which would make
    /// a second dialog with the same Call-ID.
    #[test]
    fn unknown_tagged_request_is_not_new_initial_invite() {
        let mut model = model(limits());
        let clock = Clock(Instant::now());
        let tagged = INVITE.replace(
            "To: Bob <sip:bob@biloxi.example.com>",
            "To: Bob <sip:bob@biloxi.example.com>;tag=lost",
        );

        let refusal = model
            .receive_invite(&request(&tagged), offer(), clock.now())
            .unwrap_err();

        assert_eq!(refusal, Refusal::NoDialog);
        assert_eq!(refusal.status().as_u16(), 481);
        assert_eq!(model.exchanges.len(), 0);
        assert!(model.take_effects().is_empty());
    }

    /// Once a dialog exists, a request carrying its identity is found in it,
    /// with the tags read from this user agent's side.
    #[test]
    fn a_tagged_request_finds_its_dialog() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.final_committed(exchange, clock.now());
        let (dialog, _) = confirmed(&model.take_effects());

        let bye = INVITE
            .replace(
                "INVITE sip:bob@biloxi.example.com",
                "BYE sip:bob@192.0.2.4",
            )
            .replace(
                "To: Bob <sip:bob@biloxi.example.com>",
                "To: Bob <sip:bob@biloxi.example.com>;tag=0000000000000001",
            )
            .replace("314159 INVITE", "314160 BYE");

        assert_eq!(
            model.classify(&request(&bye)),
            Ok(Incoming::InDialog(dialog)),
        );
        let other = bye.replace("tag=1928301774", "tag=other");
        assert_eq!(model.classify(&request(&other)), Ok(Incoming::NoDialog));
    }

    /// An INVITE that cannot form a dialog is refused with a 400 before the
    /// application sees it.
    #[test]
    fn an_invite_without_contact_is_refused() {
        let mut model = model(limits());
        let clock = Clock(Instant::now());
        let text = INVITE.replace("Contact: <sip:alice@192.0.2.1>\n", "");

        let refusal = model
            .receive_invite(&request(&text), offer(), clock.now())
            .unwrap_err();

        assert_eq!(refusal, Refusal::Malformed(Field::Contact));
        assert_eq!(refusal.status().as_u16(), 400);
        assert_eq!(model.exchanges.len(), 0);
    }

    /// A 180 forms an early dialog. A second 180 with a new Contact refreshes
    /// nothing, and the 2xx confirms the same dialog with its own route set
    /// and target.
    #[test]
    fn an_unreliable_provisional_does_not_refresh_the_target() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let ringing = |contact| {
            reply(
                "180 Ringing",
                "callee",
                contact,
                "Record-Route: <sip:p1.example.com;lr>\n",
            )
        };

        model
            .receive_provisional(attempt, &ringing("sip:bob@192.0.2.4"))
            .unwrap();
        let (dialog, usage) = match model.take_effects()[..] {
            [Effect::Notify(Event::EarlyDialog { dialog, usage })] => {
                (dialog, usage)
            }
            ref other => panic!("no early dialog: {other:?}"),
        };
        model
            .receive_provisional(attempt, &ringing("sip:bob@192.0.2.5"))
            .unwrap();
        model.check();

        assert!(model.take_effects().is_empty());
        let record = model.dialogs.get(dialog).unwrap();
        assert_eq!(record.phase(), DialogPhase::Early);
        assert_eq!(record.target().uri(), "sip:bob@192.0.2.4");
        assert_eq!(
            model.usages.get(usage).unwrap().phase(),
            UsagePhase::Establishing
        );

        let ok = reply(
            "200 OK",
            "callee",
            "sip:bob@192.0.2.6",
            "Record-Route: <sip:p2.example.com;lr>, <sip:p1.example.com;lr>\n",
        );
        model.receive_2xx(attempt, &ok, Some(answer())).unwrap();
        model.check();

        let effects = model.take_effects();
        assert_eq!(confirmed(&effects), (dialog, usage));
        assert!(negotiated(&effects));
        let record = model.dialogs.get(dialog).unwrap();
        assert_eq!(record.phase(), DialogPhase::Confirmed);
        assert_eq!(record.target().uri(), "sip:bob@192.0.2.6");
        let routes: Vec<&str> =
            record.routes().iter().map(|route| route.uri()).collect();
        assert_eq!(routes, ["sip:p1.example.com;lr", "sip:p2.example.com;lr"]);
        assert_eq!(
            model.usages.get(usage).unwrap().phase(),
            UsagePhase::Established
        );
        assert_eq!(model.dialogs.len(), 1);
    }

    /// A 2xx with another tag is a fork. It forms a dialog of its own, beside
    /// the early dialog of the first tag.
    #[test]
    fn a_fork_forms_a_dialog_of_its_own() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model
            .receive_provisional(
                attempt,
                &reply("180 Ringing", "first", "sip:bob@192.0.2.4", ""),
            )
            .unwrap();

        model
            .receive_2xx(
                attempt,
                &reply("200 OK", "second", "sip:bob@192.0.2.5", ""),
                Some(answer()),
            )
            .unwrap();
        model.check();

        assert_eq!(model.dialogs.len(), 2);
        let phases: Vec<DialogPhase> =
            model.dialogs.iter().map(|(_, dialog)| dialog.phase()).collect();
        assert_eq!(phases, [DialogPhase::Early, DialogPhase::Confirmed]);
    }

    /// A rejection goes out as the status the application chose, and its
    /// operation completes once the core has it. Nothing is kept afterwards,
    /// since the core acknowledges a non-2xx itself.
    #[test]
    fn a_rejection_leaves_nothing_behind() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        let busy = StatusCode::from_u16(486).unwrap();

        let operation = model
            .try_submit(Command::Reject { authority, status: busy })
            .unwrap();
        model.run_commands();
        assert_eq!(finals(model.take_effects()), [(exchange, 486)]);
        model.final_committed(exchange, clock.now());
        model.check();

        assert_eq!(
            model.take_effects(),
            [
                Effect::Released(Released::Exchange(exchange)),
                Effect::OperationEnded { operation },
            ],
        );
        assert_eq!(model.take_outcome(operation), Some(Ok(Completion::Done)));
        assert_eq!(model.exchanges.len(), 0);
        assert_eq!(model.dialogs.len(), 0);
    }

    /// A rejection needs a status from 300 to 699.
    #[test]
    fn a_rejection_with_a_2xx_is_invalid() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();

        let operation = model
            .try_submit(Command::Reject { authority, status: StatusCode::OK })
            .unwrap();
        model.run_commands();

        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation }],
        );
        assert_eq!(
            model.take_outcome(operation),
            Some(Err(Error::InvalidInput))
        );
    }

    /// An INVITE whose authority is dropped gets the UA's own 500, unless a
    /// final is already under way.
    #[test]
    fn an_abandoned_invite_gets_a_500() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let abandoned = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let decided = model
            .receive_invite(
                &invite("decided@example.com"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let (abandoned, decided_exchange) =
            (abandoned.exchange(), decided.exchange());
        model
            .try_submit(Command::Accept {
                authority: decided,
                answer: answer(),
            })
            .unwrap();
        model.run_commands();
        model.take_effects();

        model.abandon(abandoned);
        model.abandon(decided_exchange);

        assert_eq!(finals(model.take_effects()), [(abandoned, 500)]);
        model.final_committed(abandoned, clock.now());
        assert!(model.exchanges.get(abandoned).is_none());
    }

    /// When the core refuses a 2xx, what was set aside for it goes back, the
    /// operation fails, and the INVITE gets the UA's own 500. When the core
    /// closed, nothing more goes out.
    #[test]
    fn a_refused_2xx_gives_back_its_reservation() {
        let clock = Clock(Instant::now());
        let mut model = model(Limits { dialogs: 1, usages: 1, ..limits() });
        for (call, closed) in
            [("refused@example.com", false), ("closed@example.com", true)]
        {
            let authority = model
                .receive_invite(&invite(call), offer(), clock.now())
                .unwrap();
            let exchange = authority.exchange;
            let operation = model
                .try_submit(Command::Accept { authority, answer: answer() })
                .unwrap();
            model.run_commands();
            model.take_effects();

            model.final_refused(exchange, closed);
            model.check();

            let effects = model.take_effects();
            let expected = if closed {
                Error::DriverStopped
            } else {
                Error::CoreSubmissionRejected
            };
            assert_eq!(model.take_outcome(operation), Some(Err(expected)));
            let finals: Vec<u16> = effects
                .iter()
                .filter_map(|effect| match effect {
                    Effect::SubmitFinal { status, .. } => {
                        Some(status.as_u16())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(finals, if closed { vec![] } else { vec![500] });
            assert!(model.dialogs.reserve(), "the dialog slot is free again");
            model.dialogs.release();
        }
    }

    /// A plan for the callee of the INVITE, from its caller.
    fn plan() -> Box<InvitePlan> {
        let uri = |text: &str| text.parse().unwrap();
        Box::new(InvitePlan::new(
            uri("sip:bob@biloxi.example.com"),
            uri("sip:alice@atlanta.example.com"),
            answer(),
        ))
    }

    /// An INVITE command builds the INVITE with an identity from the
    /// injected randomness, opens an attempt and hands the request over. Its
    /// operation completes with the attempt once the core has it, or fails
    /// and closes the attempt.
    #[test]
    fn an_invite_command_starts_an_attempt() {
        let mut model = model(limits());

        let started =
            model.try_submit(Command::Invite { plan: plan() }).unwrap();
        model.run_commands();
        let [Effect::StartInvite { attempt }] = model.take_effects()[..]
        else {
            panic!("no INVITE to send");
        };
        let request = model.take_invite(attempt).unwrap().request;
        let header = |name| request.headers().get(name).unwrap().as_str();
        assert_eq!(request.method(), &Method::INVITE);
        assert_eq!(header("Call-ID"), "00000000000000010000000000000002");
        assert_eq!(
            header("From"),
            "<sip:alice@atlanta.example.com>;tag=0000000000000003",
        );
        assert_eq!(header("CSeq"), "5 INVITE");
        assert_eq!(header("Contact"), "<sip:ua@192.0.2.1>");
        assert!(model.take_invite(attempt).is_none());
        model.invite_started(attempt);
        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation: started }],
        );
        assert_eq!(
            model.take_outcome(started),
            Some(Ok(Completion::Attempt(attempt))),
        );

        let failed =
            model.try_submit(Command::Invite { plan: plan() }).unwrap();
        model.run_commands();
        let [Effect::StartInvite { attempt }] = model.take_effects()[..]
        else {
            panic!("no INVITE to send");
        };
        model.invite_failed(attempt, Error::Unroutable);
        assert_eq!(model.take_outcome(failed), Some(Err(Error::Unroutable)));
        assert!(model.attempts.get(attempt).is_none());
        assert_eq!(model.exchanges.len(), 1);
    }

    /// A non-2xx final ends the early dialogs of its attempt (RFC 3261
    /// section 12.3) and leaves the attempt open for a 2xx from another fork.
    #[test]
    fn a_failure_ends_the_early_dialogs_of_its_attempt() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let ringing = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        model.receive_provisional(attempt, &ringing).unwrap();
        let usage = match model.take_effects()[..] {
            [Effect::Notify(Event::EarlyDialog { usage, .. })] => usage,
            ref other => panic!("no early dialog: {other:?}"),
        };
        let busy = StatusCode::from_u16(486).unwrap();

        model.attempt_failed(attempt, Error::RemoteFailure(busy));
        model.check();

        assert_eq!(
            notices(&model.take_effects()),
            [
                Event::UsageEnded { usage },
                Event::AttemptFailed {
                    attempt,
                    error: Error::RemoteFailure(busy)
                },
            ],
        );
        assert_eq!(model.dialogs.len(), 0);
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        assert_eq!(model.dialogs.len(), 1);
    }

    /// The ACK of a 2xx comes from its dialog, numbered as the INVITE.
    #[test]
    fn an_ack_is_built_from_its_dialog() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        let replay = match model.take_effects().last() {
            Some(Effect::SendAck { replay }) => *replay,
            other => panic!("no ACK: {other:?}"),
        };

        let ack = model.ack_request(replay).unwrap();

        assert_eq!(ack.request.method(), &Method::ACK);
        assert_eq!(ack.request.uri().as_str(), "sip:bob@192.0.2.4");
        assert_eq!(ack.request.headers().get("CSeq").unwrap(), "314159 ACK");
    }

    /// An ACK as received finds its 2xx by the dialog and CSeq it carries.
    #[test]
    fn a_received_ack_finds_its_2xx() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority =
            model.receive_invite(&request(INVITE), None, clock.now()).unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.final_committed(exchange, clock.now());
        model.take_effects();
        let ack = INVITE
            .replace(
                "INVITE sip:bob@biloxi.example.com",
                "ACK sip:bob@192.0.2.4",
            )
            .replace(
                "To: Bob <sip:bob@biloxi.example.com>",
                "To: Bob <sip:bob@biloxi.example.com>;tag=0000000000000001",
            )
            .replace("314159 INVITE", "314159 ACK");

        model.receive_ack_request(&request(&ack), true);
        model.check();

        assert!(model.exchanges.get(exchange).is_none());
        assert!(negotiated(&model.take_effects()));
    }

    /// Without randomness for a tag, an INVITE is refused with a 500.
    #[test]
    fn no_randomness_refuses_the_invite() {
        struct Broken;

        impl Random for Broken {
            fn next_u64(&mut self) -> Option<u64> {
                None
            }
        }

        let mut model =
            Model::new(limits(), "sip:ua@192.0.2.1".into(), Broken);
        let clock = Clock(Instant::now());

        let refusal = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap_err();

        assert_eq!(refusal, Refusal::Internal);
        assert_eq!(refusal.status().as_u16(), 500);
    }

    /// A snapshot of a usage shows its phase and negotiation, and nothing
    /// once it is gone.
    #[test]
    fn usage_state_follows_the_usage() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        let (_, usage) = confirmed(&model.take_effects());

        assert_eq!(
            model.usage_state(usage),
            Some((
                UsagePhase::Established,
                Negotiation::Stable,
                Some(answer())
            )),
        );
        model.end_usage(usage);
        assert_eq!(model.usage_state(usage), None);
    }

    /// The ACK can reach the driver before the core's verdict on the 2xx
    /// does. It is kept and applied once the 2xx is committed, rather than
    /// dropped as matching nothing (RFC 3261 section 13.3.1.4 stops the 2xx
    /// at its ACK). No retransmission is left set. The INVITE carries the
    /// offer, as every INVITE the runtime lets through does, so the ACK owes
    /// no answer.
    #[test]
    fn ack_arriving_before_submission_completion_is_not_lost() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.take_effects();

        // One ACK for another INVITE, and the one for this 2xx, twice.
        model.receive_ack(&uas_dialog(), 314160, false);
        model.receive_ack(&uas_dialog(), 314159, false);
        model.receive_ack(&uas_dialog(), 314159, false);
        model.final_committed(exchange, clock.now());
        model.check();

        assert!(model.exchanges.get(exchange).is_none(), "the ACK applied");
        assert_eq!(model.replays.len(), 0);
        assert_eq!(model.timers.len(), 0);
        let effects = model.take_effects();
        assert!(negotiated(&effects), "the 2xx carried the answer");
        assert!(!effects.iter().any(|effect| matches!(
            effect,
            Effect::Resend2xx { .. }
                | Effect::Notify(Event::AckTimeout { .. })
        )));
    }

    /// The same race for an INVITE without an offer, whose ACK carries the
    /// answer. A copy of the ACK without a body does not undo the answer of
    /// the first.
    #[test]
    fn an_early_ack_keeps_the_answer_it_carried() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority =
            model.receive_invite(&request(INVITE), None, clock.now()).unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.take_effects();

        model.receive_ack(&uas_dialog(), 314159, true);
        model.receive_ack(&uas_dialog(), 314159, false);
        model.final_committed(exchange, clock.now());
        model.check();

        assert!(model.exchanges.get(exchange).is_none(), "the ACK applied");
        assert!(negotiated(&model.take_effects()));
    }

    /// An INVITE whose Expires passes before a final response gets a 487
    /// (RFC 3261 section 13.3.1), and a decision after it changes nothing.
    #[test]
    fn an_expired_invite_gets_a_487() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let expiring = INVITE
            .replace("Max-Forwards: 70\n", "Max-Forwards: 70\nExpires: 10\n");
        let authority = model
            .receive_invite(&request(&expiring), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;

        clock.advance(Duration::from_secs(10) - Duration::from_millis(1));
        model.fire_timers(clock.now());
        assert!(model.take_effects().is_empty());
        clock.advance(Duration::from_millis(1));
        model.fire_timers(clock.now());
        assert_eq!(finals(model.take_effects()), [(exchange, 487)]);
        model.check();

        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.check();
        let effects = model.take_effects();
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::SubmitFinal { .. })),
            "{effects:?}",
        );
    }

    /// A final under way stops the Expires timer, so an accepted INVITE does
    /// not also get a 487. A malformed Expires is a 400.
    #[test]
    fn a_final_stops_the_expires_timer() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let expiring = INVITE
            .replace("Max-Forwards: 70\n", "Max-Forwards: 70\nExpires: 10\n");
        let authority = model
            .receive_invite(&request(&expiring), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.check();

        clock.advance(Duration::from_secs(10));
        model.fire_timers(clock.now());
        assert_eq!(finals(model.take_effects()), [(exchange, 200)]);

        let malformed = INVITE
            .replace("Max-Forwards: 70\n", "Max-Forwards: 70\nExpires: ten\n")
            .replace("a84b4c76e66710", "malformed");
        let refusal = model
            .receive_invite(&request(&malformed), offer(), clock.now())
            .unwrap_err();
        assert_eq!(refusal.status().as_u16(), 400);
    }

    /// Without TLS, a SIPS Request-URI gets a 416 (RFC 3261 section
    /// 8.2.2.1), and a SIPS top Record-Route, or Contact without one, a 480
    /// (RFC 5630 section 5.1.2), rather than a dialog whose Contact would
    /// have to be SIPS (RFC 3261 section 12.1.1).
    #[test]
    fn a_sips_invite_is_refused_without_tls() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let cases = [
            (
                INVITE.replace("INVITE sip:bob", "INVITE sips:bob"),
                Refusal::SipsRequestUri,
            ),
            (
                INVITE.replace("<sip:p1.example.com;lr>", "<sips:p1.example.com;lr>"),
                Refusal::SipsNotAllowed,
            ),
            (
                INVITE
                    .replace("Record-Route: <sip:p1.example.com;lr>, <sip:p2.example.com;lr>\n", "")
                    .replace("Record-Route: <sip:p3.example.com;lr>\n", "")
                    .replace("<sip:alice@192.0.2.1>", "<SIPS:alice@192.0.2.1>"),
                Refusal::SipsNotAllowed,
            ),
        ];

        for (text, expected) in cases {
            let refusal = model
                .receive_invite(&request(&text), offer(), clock.now())
                .unwrap_err();
            assert_eq!(refusal, expected, "{text}");
        }
        assert_eq!(Refusal::SipsRequestUri.status().as_u16(), 416);
        assert_eq!(Refusal::SipsNotAllowed.status().as_u16(), 480);

        // A SIPS Contact behind a SIP Record-Route asks for nothing secure
        // of this UA.
        let contact =
            INVITE.replace("<sip:alice@192.0.2.1>", "<sips:alice@192.0.2.1>");
        assert!(
            model
                .receive_invite(&request(&contact), offer(), clock.now())
                .is_ok()
        );
        model.check();
    }

    /// Once an accept is under way, nothing else picks the final: neither the
    /// decision deadline, nor the drop of a forged authority, nor a reject.
    /// After the core has the 2xx, the same holds.
    #[test]
    fn uas_final_response_is_selected_once() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        assert_eq!(finals(model.take_effects()), [(exchange, 200)]);

        let start = clock.now();
        let effects = advance_to(&mut model, &mut clock, start + DECISION);
        model.abandon(exchange);
        let rejected = model
            .try_submit(Command::Reject {
                authority: Authority { exchange },
                status: StatusCode::from_u16(486).unwrap(),
            })
            .unwrap();
        model.run_commands();

        assert!(effects.is_empty());
        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation: rejected }],
        );
        model.final_committed(exchange, clock.now());
        model.take_effects();
        model.abandon(exchange);
        assert!(model.take_effects().is_empty());
        model.check();
    }

    /// The 2xx goes out again at T1, 2 T1 later, then 4 T1, capped at T2,
    /// and the ACK deadline stays at 64 T1 after the first transmission
    /// however many copies went out (RFC 3261 section 13.3.1.4).
    #[test]
    fn uas_ack_deadline_does_not_slide_on_each_retransmission() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let first = clock.now();
        let (exchange, replay, usage) = accepted(&mut model, &clock);
        let deadline = first + T1 * 64;
        assert_eq!(
            model
                .replays
                .get(replay)
                .unwrap()
                .retransmission
                .unwrap()
                .deadline,
            deadline,
        );

        let mut copies = Vec::new();
        while let Some(next) =
            model.next_deadline().filter(|&at| at < deadline)
        {
            let effects = advance_to(&mut model, &mut clock, next);
            assert_eq!(effects, [Effect::Resend2xx { exchange }]);
            copies.push(next - first);
        }

        let millis: Vec<u128> =
            copies.iter().map(|elapsed| elapsed.as_millis()).collect();
        assert_eq!(
            millis,
            [500, 1500, 3500, 7500, 11500, 15500, 19500, 23500, 27500, 31500],
        );
        assert_eq!(model.next_deadline(), Some(deadline));
        let effects = advance_to(
            &mut model,
            &mut clock,
            deadline - Duration::from_millis(1),
        );
        assert!(effects.is_empty(), "nothing before the deadline");
        let effects = advance_to(&mut model, &mut clock, deadline);
        assert!(notices(&effects).contains(&Event::AckTimeout { usage }));
    }

    /// Without an ACK by the deadline, the retransmissions stop, the
    /// application is told why, and the usage ends with its dialog. Nothing
    /// of the exchange is left.
    #[test]
    fn no_ack_triggers_explicit_termination_policy() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let (exchange, replay, usage) = accepted(&mut model, &clock);
        let deadline = clock.now() + T1 * 64;

        let effects = advance_to(&mut model, &mut clock, deadline);

        let notified = notices(&effects);
        assert_eq!(
            notified,
            [Event::AckTimeout { usage }, Event::UsageEnded { usage }],
        );
        assert!(
            effects.contains(&Effect::Released(Released::Exchange(exchange)))
        );
        assert!(effects.contains(&Effect::Released(Released::Replay(replay))));
        assert!(model.exchanges.get(exchange).is_none());
        assert_eq!(model.usages.len(), 0);
        assert_eq!(model.dialogs.len(), 0);
        assert_eq!(model.next_deadline(), None);
    }

    /// An ACK after the deadline finds nothing. It brings back neither the
    /// usage nor the retransmissions.
    #[test]
    fn late_ack_does_not_revive_terminated_usage() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);
        let deadline = clock.now() + T1 * 64;
        advance_to(&mut model, &mut clock, deadline);

        model.receive_ack(&uas_dialog(), 314159, false);
        model.check();

        assert!(model.take_effects().is_empty());
        assert_eq!(model.usage_state(usage), None);
        assert_eq!(model.replays.len(), 0);
        assert_eq!(model.next_deadline(), None);
    }

    /// An ACK with the 2xx's dialog and CSeq stops the retransmissions. One
    /// with another CSeq does not.
    #[test]
    fn a_matching_ack_stops_the_retransmissions() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let (exchange, _, _) = accepted(&mut model, &clock);

        model.receive_ack(&uas_dialog(), 314158, false);
        let next = model.next_deadline().unwrap();
        let effects = advance_to(&mut model, &mut clock, next);
        assert_eq!(effects, [Effect::Resend2xx { exchange }]);

        model.receive_ack(&uas_dialog(), 314159, false);
        model.check();
        assert_eq!(model.next_deadline(), None);
        assert!(model.exchanges.get(exchange).is_none());
    }

    /// An INVITE the application has not decided by the deadline gets a 500.
    /// The application's later accept loses to it.
    #[test]
    fn an_undecided_invite_gets_a_500_at_its_deadline() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        let due = clock.now() + DECISION;

        assert!(
            advance_to(&mut model, &mut clock, due - Duration::from_millis(1))
                .is_empty()
        );
        let effects = advance_to(&mut model, &mut clock, due);
        assert_eq!(finals(effects), [(exchange, 500)]);

        let late = model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation: late }],
        );
        assert_eq!(
            model.take_outcome(late),
            Some(Err(Error::AlreadyFinalized)),
        );
        model.final_committed(exchange, clock.now());
        model.check();
        assert!(model.exchanges.get(exchange).is_none());
    }

    /// A provisional the application chose goes out again every minute,
    /// with the same To tag, until a final is under way. The UA picks none
    /// of its own. The application rings for longer than the default
    /// decision timeout here, as one that lets a phone ring would.
    #[test]
    fn a_chosen_provisional_is_sent_again_every_minute() {
        let mut clock = Clock(Instant::now());
        let decision_timeout = Duration::from_secs(600);
        let mut model = model(Limits { decision_timeout, ..limits() });
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        let tag: Tag = "0000000000000001".parse().unwrap();
        let minute = Duration::from_secs(60);
        let start = clock.now();
        assert!(advance_to(&mut model, &mut clock, start + minute).is_empty());

        let ringing = StatusCode::from_u16(180).unwrap();
        let operation = model
            .try_submit(Command::Provisional { exchange, status: ringing })
            .unwrap();
        model.run_commands();
        assert_eq!(
            model.take_effects(),
            [Effect::SubmitProvisional {
                exchange,
                status: ringing,
                to_tag: tag.clone(),
                operation: Some(operation),
            }],
        );
        model.provisional_done(
            exchange,
            ringing,
            Some(operation),
            Ok(()),
            clock.now(),
        );
        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation }],
        );
        assert_eq!(model.take_outcome(operation), Some(Ok(Completion::Done)));
        model.check();

        let sent = clock.now();
        for minutes in 1..=3 {
            let effects =
                advance_to(&mut model, &mut clock, sent + minute * minutes);
            assert_eq!(
                effects,
                [Effect::SubmitProvisional {
                    exchange,
                    status: ringing,
                    to_tag: tag.clone(),
                    operation: None,
                }],
            );
        }

        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.take_effects();
        model.check();
        let later = clock.now() + minute * 2;
        let effects = advance_to(&mut model, &mut clock, later);
        assert!(effects.iter().all(|effect| {
            !matches!(effect, Effect::SubmitProvisional { .. })
        }));
    }

    /// A provisional needs a status from 101 to 199, and an exchange whose
    /// final is not under way.
    #[test]
    fn a_provisional_after_the_final_is_refused() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        let trying = model
            .try_submit(Command::Provisional {
                exchange,
                status: StatusCode::from_u16(100).unwrap(),
            })
            .unwrap();
        model.run_commands();
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        let late = model
            .try_submit(Command::Provisional {
                exchange,
                status: StatusCode::from_u16(180).unwrap(),
            })
            .unwrap();
        model.run_commands();

        assert_eq!(model.take_outcome(trying), Some(Err(Error::InvalidInput)));
        assert_eq!(
            model.take_outcome(late),
            Some(Err(Error::AlreadyFinalized)),
        );
    }

    /// An INVITE with the From tag, Call-ID and CSeq of one the UAS is
    /// handling came by another path, and gets a 482 (RFC 3261 section
    /// 8.2.2.2). Once the first exchange is done with, the identity is free.
    #[test]
    fn a_merged_invite_gets_a_482() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let merged = INVITE.replace("z9hG4bK776asdhds", "z9hG4bKother");
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;

        let refusal = model
            .receive_invite(&request(&merged), offer(), clock.now())
            .unwrap_err();
        assert_eq!(refusal, Refusal::Merged);
        assert_eq!(refusal.status().as_u16(), 482);
        let next_cseq = merged.replace("314159 INVITE", "314160 INVITE");
        assert!(
            model
                .receive_invite(&request(&next_cseq), offer(), clock.now())
                .is_ok()
        );

        model
            .try_submit(Command::Reject {
                authority,
                status: StatusCode::from_u16(486).unwrap(),
            })
            .unwrap();
        model.run_commands();
        model.final_committed(exchange, clock.now());
        model.check();
        assert!(
            model
                .receive_invite(&request(&merged), offer(), clock.now())
                .is_ok()
        );
    }

    /// An INVITE that requires an extension gets a 420, since this UA
    /// supports none (RFC 3261 section 8.2.2.3). A malformed Require is a
    /// 400.
    #[test]
    fn a_required_extension_gets_a_420() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let required = INVITE.replace(
            "Max-Forwards: 70\n",
            "Max-Forwards: 70\nRequire: 100rel\n",
        );
        let malformed = INVITE.replace(
            "Max-Forwards: 70\n",
            "Max-Forwards: 70\nRequire: 100rel;x\n",
        );

        let refusal = model
            .receive_invite(&request(&required), offer(), clock.now())
            .unwrap_err();
        assert_eq!(refusal, Refusal::BadExtension);
        assert_eq!(refusal.status().as_u16(), 420);
        assert_eq!(
            model.receive_invite(&request(&malformed), offer(), clock.now()),
            Err(Refusal::Malformed(Field::Require)),
        );
        assert_eq!(model.exchanges.len(), 0);
    }

    /// A driver that runs a retransmission late sends one copy, and the next
    /// is an interval after that, not a burst to catch up.
    #[test]
    fn a_late_retransmission_sends_one_copy() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let first = clock.now();
        let (exchange, _, _) = accepted(&mut model, &clock);

        let late = first + Duration::from_secs(10);
        let effects = advance_to(&mut model, &mut clock, late);

        assert_eq!(effects, [Effect::Resend2xx { exchange }]);
        assert_eq!(model.next_deadline(), Some(late + T1 * 2));
    }

    /// A decision timeout too long to add to the clock sets no deadline,
    /// rather than overflow.
    #[test]
    fn a_decision_timeout_past_the_clock_sets_no_deadline() {
        let clock = Clock(Instant::now());
        let decision_timeout = Duration::MAX;
        let mut model = model(Limits { decision_timeout, ..limits() });

        model.receive_invite(&request(INVITE), offer(), clock.now()).unwrap();
        model.check();

        assert_eq!(model.next_deadline(), None);
    }

    /// Returns what an attempt came to so far, and whether its set of
    /// responses is complete.
    fn progress(
        model: &Model<Counter>,
        attempt: AttemptKey,
    ) -> Option<(Option<AttemptResult>, bool)> {
        let state = model.attempt_state(attempt)?;
        Some((state.result, state.complete))
    }

    /// Returns what `effects` say an attempt came to at its end.
    fn ended(effects: &[Effect]) -> (AttemptResult, bool) {
        effects
            .iter()
            .find_map(|effect| match effect {
                Effect::AttemptEnded { result, complete, .. } => {
                    Some((*result, *complete))
                }
                _ => None,
            })
            .unwrap()
    }

    /// A response the core matched to the INVITE by its Via, but with
    /// another Call-ID, From tag or CSeq, is not taken for a dialog of the
    /// INVITE, and gets no ACK.
    #[test]
    fn a_response_with_another_identity_forms_no_dialog() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        for (from, to) in [
            ("a84b4c76e66710@pc33", "other@pc33"),
            ("tag=1928301774", "tag=other"),
            ("314159 INVITE", "314158 INVITE"),
        ] {
            assert_eq!(
                model.receive_2xx(
                    attempt,
                    &callee_with(from, to),
                    Some(answer())
                ),
                Err(Error::InvalidInput),
                "{from}",
            );
        }
        model.check();

        assert!(model.take_effects().is_empty());
        assert_eq!(model.dialogs.len(), 0);
        assert_eq!(progress(&model, attempt), Some((None, false)));
    }

    /// A 2xx the UA cannot keep, here one without a Contact, still answered
    /// the INVITE. The attempt reports it, and does not report its set of
    /// responses as complete, since that 2xx is no session.
    #[test]
    fn an_unusable_2xx_leaves_the_attempt_incomplete() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let text = String::from_utf8(callee().to_bytes().to_vec()).unwrap();
        let no_contact = response(
            &text
                .replace("\r\n", "\n")
                .replace("Contact: <sip:bob@192.0.2.4>\n", ""),
        );

        assert_eq!(
            model.receive_2xx(attempt, &no_contact, Some(answer())),
            Err(Error::InvalidInput),
        );
        model.check();
        assert_eq!(
            progress(&model, attempt),
            Some((Some(AttemptResult::Answered), false)),
        );

        model.response_collection_finished(attempt);
        assert_eq!(
            ended(&model.take_effects()),
            (AttemptResult::Answered, false)
        );
    }

    /// The ACK of a 2xx takes the INVITE's CSeq number, and takes no new
    /// number from the dialog, whose next request still gets the one after
    /// the INVITE's (RFC 3261 section 13.2.2.4).
    #[test]
    fn uac_ack_uses_invite_cseq_without_increment() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        let (dialog, _) = confirmed(&model.take_effects());
        let replay = model.replays.iter().next().unwrap().0;

        let ack = model.ack_request(replay).unwrap();
        let again = model.ack_request(replay).unwrap();
        let next = model
            .dialogs
            .get_mut(dialog)
            .unwrap()
            .request(Method::BYE, Sequence::Next { seed: 0 })
            .unwrap();

        assert_eq!(ack.request.headers().get("CSeq").unwrap(), "314159 ACK");
        assert_eq!(again.request.headers().get("CSeq").unwrap(), "314159 ACK");
        assert_eq!(next.request.headers().get("CSeq").unwrap(), "314160 BYE");
    }

    /// The first final response or failure decides what an attempt came to.
    /// A non-2xx final and a failure of the transport are told apart, and a
    /// failure after a 2xx does not undo it.
    #[test]
    fn the_first_failure_decides_the_attempt() {
        let mut model = model(limits());
        let busy = StatusCode::from_u16(486).unwrap();
        let rejected = model.start_attempt(&request(INVITE), true).unwrap();
        let lost =
            model.start_attempt(&invite("lost@example.com"), true).unwrap();
        let answered = model
            .start_attempt(&invite("answered@example.com"), true)
            .unwrap();
        let answer_ok = callee_with(
            "a84b4c76e66710@pc33.atlanta.example.com",
            "answered@example.com",
        );

        model.attempt_failed(rejected, Error::RemoteFailure(busy));
        model.attempt_failed(rejected, Error::TransportFailure);
        model.attempt_failed(lost, Error::TransportFailure);
        model.receive_2xx(answered, &answer_ok, Some(answer())).unwrap();
        model.attempt_failed(answered, Error::TransportFailure);
        model.check();

        let failed = Some(AttemptResult::Failed(Error::RemoteFailure(busy)));
        assert_eq!(progress(&model, rejected), Some((failed, true)));
        let lost_state = Some(AttemptResult::Failed(Error::TransportFailure));
        assert_eq!(progress(&model, lost), Some((lost_state, true)));
        assert_eq!(
            progress(&model, answered),
            Some((Some(AttemptResult::Answered), true)),
        );
        let notified: Vec<Event> = notices(&model.take_effects())
            .into_iter()
            .filter(|event| matches!(event, Event::AttemptFailed { .. }))
            .collect();
        assert_eq!(
            notified,
            [
                Event::AttemptFailed {
                    attempt: rejected,
                    error: Error::RemoteFailure(busy),
                },
                Event::AttemptFailed {
                    attempt: lost,
                    error: Error::TransportFailure,
                },
            ],
        );
    }

    /// Once the core dropped responses, the attempt's set of responses is
    /// not complete, and its end says so. Without a final response before
    /// the loss, it ends as `ObservationIncomplete`, not as a success or a
    /// plain stop.
    #[test]
    fn responses_overflow_marks_response_set_incomplete() {
        let mut model = model(limits());
        let answered = model.start_attempt(&request(INVITE), true).unwrap();
        let unknown =
            model.start_attempt(&invite("unknown@example.com"), true).unwrap();
        let stopped =
            model.start_attempt(&invite("stopped@example.com"), true).unwrap();
        model.receive_2xx(answered, &callee(), Some(answer())).unwrap();
        model.take_effects();

        model.responses_lost(answered);
        model.responses_lost(unknown);
        assert_eq!(
            progress(&model, answered),
            Some((Some(AttemptResult::Answered), false)),
        );

        model.response_collection_finished(answered);
        assert_eq!(
            ended(&model.take_effects()),
            (AttemptResult::Answered, false),
        );
        model.response_collection_finished(unknown);
        assert_eq!(
            ended(&model.take_effects()),
            (AttemptResult::Failed(Error::ObservationIncomplete), false),
        );
        model.response_collection_finished(stopped);
        assert_eq!(
            ended(&model.take_effects()),
            (AttemptResult::Failed(Error::DriverStopped), true),
        );
        assert_eq!(progress(&model, answered), None);
        model.check();
    }

    /// A 2xx without the answer the INVITE's offer is owed confirms the
    /// dialog, and gets its ACK, but leaves the offer outstanding rather than
    /// report a completed negotiation. The answer of a 2xx that has one is
    /// kept for the session.
    #[test]
    fn a_2xx_without_its_answer_leaves_the_offer_outstanding() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        model.receive_2xx(attempt, &callee(), None).unwrap();

        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        assert!(!negotiated(&effects));
        assert!(effects.iter().any(|e| matches!(e, Effect::SendAck { .. })));
        assert_eq!(
            model.usage_state(usage),
            Some((
                UsagePhase::Established,
                Negotiation::LocalOfferOutstanding,
                None,
            )),
        );
    }

    /// When the core stops collecting responses, an early dialog no 2xx
    /// confirmed cannot be confirmed any more, and ends.
    #[test]
    fn the_end_of_the_responses_ends_unconfirmed_early_dialogs() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model
            .receive_provisional(
                attempt,
                &reply("180 Ringing", "early", "sip:bob@192.0.2.4", ""),
            )
            .unwrap();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        let effects = model.take_effects();
        let (_, kept) = confirmed(&effects);

        model.response_collection_finished(attempt);
        model.check();

        let ended: Vec<Event> = notices(&model.take_effects());
        assert_eq!(ended.len(), 1);
        assert!(
            matches!(ended[0], Event::UsageEnded { usage } if usage != kept)
        );
        assert!(model.usage_state(kept).is_some());
    }

    /// Returns the replay contexts whose ACK `effects` send, in order.
    fn acks(effects: &[Effect]) -> Vec<ReplayKey> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::SendAck { replay } => Some(*replay),
                _ => None,
            })
            .collect()
    }

    /// Returns the cleanups whose BYE `effects` send, in order.
    fn byes(effects: &[Effect]) -> Vec<ReplayKey> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::SendBye { replay } => Some(*replay),
                _ => None,
            })
            .collect()
    }

    /// Returns the sessions whose dialogs `effects` confirm, in order.
    fn confirmations(effects: &[Effect]) -> Vec<UsageKey> {
        notices(effects)
            .into_iter()
            .filter_map(|event| match event {
                Event::DialogConfirmed { usage, .. } => Some(usage),
                _ => None,
            })
            .collect()
    }

    /// The 2xx of the fork whose tag is `tag`, at `contact`.
    fn fork(tag: &str, contact: &str) -> Response<Bytes> {
        reply("200 OK", tag, contact, "")
    }

    /// A session description that differs from others by `text`.
    fn description(text: &'static str) -> Description {
        Description::new(
            signa_core::HeaderValue::from_static("application/sdp"),
            Bytes::from_static(text.as_bytes()),
        )
    }

    /// A forking proxy has two callees answer the INVITE. Each 2xx forms a
    /// confirmed dialog and a session of its own, and gets an ACK of its own,
    /// sent to its own Contact with its own To tag and the INVITE's CSeq
    /// number (RFC 3261 section 13.2.2.4). The attempt lists both sessions.
    #[test]
    fn two_successful_forks_create_two_dialogs_and_two_acks() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        model
            .receive_2xx(attempt, &fork("bob", "sip:bob@192.0.2.4"), offer())
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("carol", "sip:carol@192.0.2.5"),
                offer(),
            )
            .unwrap();
        model.check();

        let effects = model.take_effects();
        let sessions = confirmations(&effects);
        assert_eq!(sessions.len(), 2);
        assert_ne!(sessions[0], sessions[1]);
        assert_eq!(model.dialogs.len(), 2);
        let sent: Vec<(String, String, String)> = acks(&effects)
            .into_iter()
            .map(|replay| {
                let ack = model.ack_request(replay).unwrap().request;
                let header = |name| ack.headers().get(name).unwrap().as_str();
                (
                    ack.uri().as_str().to_owned(),
                    header("To").to_owned(),
                    header("CSeq").to_owned(),
                )
            })
            .collect();
        assert_eq!(
            sent,
            [
                (
                    "sip:bob@192.0.2.4".to_owned(),
                    "<sip:bob@biloxi.example.com>;tag=bob".to_owned(),
                    "314159 ACK".to_owned(),
                ),
                (
                    "sip:carol@192.0.2.5".to_owned(),
                    "<sip:bob@biloxi.example.com>;tag=carol".to_owned(),
                    "314159 ACK".to_owned(),
                ),
            ],
        );
        let state = model.attempt_state(attempt).unwrap();
        assert_eq!(state.sessions, sessions);
        assert!(state.complete);
    }

    /// A copy of a 2xx asks nothing of the application again. Neither the
    /// copy of a session's 2xx nor that of a fork the UA ends confirms a
    /// dialog, completes a negotiation or forms a session. Each gets its ACK
    /// again, and the fork no second BYE.
    #[test]
    fn same_branch_duplicate_does_not_repeat_application_acceptance() {
        let mut model = model(Limits { forks: 1, ..limits() });
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let ringing = reply("180 Ringing", "kept", "sip:bob@192.0.2.4", "");
        let (kept, ended) = (
            fork("kept", "sip:bob@192.0.2.4"),
            fork("ended", "sip:carol@192.0.2.5"),
        );
        model.receive_provisional(attempt, &ringing).unwrap();
        model.receive_2xx(attempt, &kept, offer()).unwrap();
        let effects = model.take_effects();
        let (session, first) = (confirmations(&effects), acks(&effects));
        assert!(negotiated(&effects));
        assert_eq!(
            model.receive_2xx(attempt, &ended, offer()),
            Err(Error::CapacityExceeded),
        );
        let cleanup = acks(&model.take_effects())[0];
        model.ack_written(cleanup, true);
        assert_eq!(byes(&model.take_effects()), [cleanup]);

        model.receive_2xx(attempt, &kept, offer()).unwrap();
        model.receive_2xx(attempt, &ended, offer()).unwrap();
        model.ack_written(cleanup, true);
        model.check();

        assert_eq!(
            model.take_effects(),
            [
                Effect::ResendAck { replay: first[0] },
                Effect::ResendAck { replay: cleanup },
            ],
        );
        assert_eq!(model.usages.len(), 1);
        assert_eq!(model.attempt_state(attempt).unwrap().sessions, session);
    }

    /// Once the application gives an attempt up, a 2xx that comes later,
    /// for an early dialog or a new fork, forms no session. Each gets its
    /// ACK, and a BYE after it built from its dialog, which is the request
    /// after the INVITE (RFC 3261 section 13.2.2.4). A session formed before
    /// is left alone, and so is the attempt's set of responses, since giving
    /// up was the application's choice.
    #[test]
    fn late_2xx_after_attempt_abandon_is_cleaned_up() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let early = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        model.receive_provisional(attempt, &early).unwrap();
        model
            .receive_2xx(attempt, &fork("kept", "sip:dan@192.0.2.6"), offer())
            .unwrap();
        let kept = confirmations(&model.take_effects())[0];

        model.abandon_attempt(attempt);
        model
            .receive_2xx(attempt, &fork("early", "sip:bob@192.0.2.4"), offer())
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("late", "sip:carol@192.0.2.5"),
                offer(),
            )
            .unwrap();
        let after = reply("180 Ringing", "after", "sip:eve@192.0.2.7", "");
        model.receive_provisional(attempt, &after).unwrap();
        model.check();

        let effects = model.take_effects();
        assert!(confirmations(&effects).is_empty());
        let early_usage = notices(&effects)
            .into_iter()
            .find_map(|event| match event {
                Event::UsageEnded { usage } => Some(usage),
                _ => None,
            })
            .unwrap();
        assert_ne!(early_usage, kept);
        let cleanups = acks(&effects);
        assert_eq!(cleanups.len(), 2);
        for &cleanup in &cleanups {
            model.ack_written(cleanup, true);
        }
        assert_eq!(byes(&model.take_effects()), cleanups);
        let bye = model.bye_request(cleanups[1]).unwrap().request;
        assert_eq!(bye.method(), &Method::BYE);
        assert_eq!(bye.uri().as_str(), "sip:carol@192.0.2.5");
        assert_eq!(bye.headers().get("CSeq").unwrap(), "314160 BYE");
        assert_eq!(
            bye.headers().get("To").unwrap(),
            "<sip:bob@biloxi.example.com>;tag=late",
        );
        assert!(model.bye_request(cleanups[1]).is_none(), "built once");

        let state = model.attempt_state(attempt).unwrap();
        assert_eq!(state.sessions, [kept]);
        assert!(state.complete && !state.degraded);
        assert_eq!(model.dialogs.len(), 1);
    }

    /// Each fork negotiates on its own. One 2xx carries an answer and
    /// settles its session, another carries none and leaves its own offer
    /// outstanding, and each session keeps the description its peer sent.
    #[test]
    fn fork_sdp_state_is_not_shared() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let (bob, carol) =
            (description("v=0 bob\r\n"), description("v=0 carol\r\n"));

        model
            .receive_2xx(
                attempt,
                &fork("bob", "sip:bob@192.0.2.4"),
                Some(bob.clone()),
            )
            .unwrap();
        model
            .receive_2xx(attempt, &fork("dan", "sip:dan@192.0.2.6"), None)
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("carol", "sip:carol@192.0.2.5"),
                Some(carol.clone()),
            )
            .unwrap();
        model.check();

        let effects = model.take_effects();
        let sessions = confirmations(&effects);
        let completed: Vec<UsageKey> = notices(&effects)
            .into_iter()
            .filter_map(|event| match event {
                Event::NegotiationCompleted { usage } => Some(usage),
                _ => None,
            })
            .collect();
        assert_eq!(completed, [sessions[0], sessions[2]]);
        let state = |usage| {
            let (_, negotiation, remote) = model.usage_state(usage).unwrap();
            (negotiation, remote)
        };
        assert_eq!(state(sessions[0]), (Negotiation::Stable, Some(bob)));
        assert_eq!(
            state(sessions[1]),
            (Negotiation::LocalOfferOutstanding, None),
        );
        assert_eq!(state(sessions[2]), (Negotiation::Stable, Some(carol)));
    }

    /// What copies of a 2xx need stays until the core stops collecting the
    /// attempt's responses, whatever happens to the session first. A session
    /// that ended, as with a BYE, leaves its dialog to go at once, so the
    /// retained context holds nothing up. A cleanup whose BYE went stays as
    /// long, and one whose BYE is still owed at the end stays until it goes.
    #[test]
    fn replay_cleanup_waits_for_required_response_collection() {
        let mut model = model(Limits { forks: 1, ..limits() });
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let (kept, ended) = (
            fork("kept", "sip:bob@192.0.2.4"),
            fork("ended", "sip:carol@192.0.2.5"),
        );
        model.receive_2xx(attempt, &kept, offer()).unwrap();
        let effects = model.take_effects();
        let (session, replay) =
            (confirmations(&effects)[0], acks(&effects)[0]);
        let _ = model.receive_2xx(attempt, &ended, offer());
        let cleanup = acks(&model.take_effects())[0];
        model.ack_written(replay, true);
        model.ack_written(cleanup, true);
        model.take_effects();

        model.end_usage(session);
        model.bye_done(cleanup);
        model.check();
        assert_eq!(
            model.take_effects(),
            [Effect::Notify(Event::UsageEnded { usage: session })],
        );
        assert_eq!(model.dialogs.len(), 0, "an ended session holds no dialog");
        assert!(model.has_replay(replay) && model.has_replay(cleanup));
        model.receive_2xx(attempt, &kept, offer()).unwrap();
        model.receive_2xx(attempt, &ended, offer()).unwrap();
        assert_eq!(
            model.take_effects(),
            [
                Effect::ResendAck { replay },
                Effect::ResendAck { replay: cleanup },
            ],
        );

        model.response_collection_finished(attempt);
        model.check();
        let effects = model.take_effects();
        assert!(!model.has_replay(replay) && !model.has_replay(cleanup));
        assert_eq!(
            effects.last(),
            Some(&Effect::AttemptEnded {
                attempt,
                result: AttemptResult::Answered,
                complete: false,
                degraded: false,
                sessions: vec![],
            }),
        );

        // A cleanup whose ACK has not had its try when the responses end
        // stays until its BYE goes.
        let late =
            model.start_attempt(&invite("late@example.com"), true).unwrap();
        let late_fork = |tag, contact| {
            let text =
                String::from_utf8(fork(tag, contact).to_bytes().to_vec())
                    .unwrap()
                    .replace("\r\n", "\n")
                    .replace(
                        "a84b4c76e66710@pc33.atlanta.example.com",
                        "late@example.com",
                    );
            response(&text)
        };
        model
            .receive_2xx(
                late,
                &late_fork("kept", "sip:bob@192.0.2.4"),
                offer(),
            )
            .unwrap();
        model.take_effects();
        let _ = model.receive_2xx(
            late,
            &late_fork("ended", "sip:carol@192.0.2.5"),
            offer(),
        );
        let cleanup = acks(&model.take_effects())[0];

        model.response_collection_finished(late);
        model.check();
        model.take_effects();
        assert!(model.has_replay(cleanup), "its BYE is still owed");
        model.ack_written(cleanup, false);
        assert_eq!(byes(&model.take_effects()), [cleanup]);
        model.bye_done(cleanup);
        model.check();
        assert!(!model.has_replay(cleanup));
    }

    /// A UA whose tables are full turns a fork away from a session, not from
    /// its ACK. A 2xx for a new tag beyond the dialog table, and one for an
    /// early dialog without room for its replay context, get their ACK and
    /// a BYE. The early session ends.
    #[test]
    fn a_fork_beyond_the_tables_is_cleaned_up() {
        let mut model = model(Limits { dialogs: 2, replays: 1, ..limits() });
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        for tag in ["first", "second"] {
            let ringing = reply("180 Ringing", tag, "sip:bob@192.0.2.4", "");
            model.receive_provisional(attempt, &ringing).unwrap();
        }
        let second = match notices(&model.take_effects())[..] {
            [_, Event::EarlyDialog { usage, .. }] => usage,
            ref other => panic!("not two early dialogs: {other:?}"),
        };

        model
            .receive_2xx(attempt, &fork("first", "sip:bob@192.0.2.4"), offer())
            .unwrap();
        let confirmed = model.take_effects();
        assert_eq!(
            model.receive_2xx(
                attempt,
                &fork("second", "sip:bob@192.0.2.4"),
                offer()
            ),
            Err(Error::CapacityExceeded),
        );
        let early_end = model.take_effects();
        assert_eq!(
            model.receive_2xx(
                attempt,
                &fork("third", "sip:carol@192.0.2.5"),
                offer()
            ),
            Err(Error::CapacityExceeded),
        );
        let beyond = model.take_effects();
        model.check();

        assert_eq!(acks(&confirmed).len(), 1);
        assert_eq!(confirmations(&early_end), []);
        assert_eq!(notices(&early_end), [Event::UsageEnded { usage: second }]);
        assert_eq!(acks(&early_end).len(), 1);
        assert_eq!(acks(&beyond).len(), 1);
        assert_eq!(model.cleanups, 2);
        let state = model.attempt_state(attempt).unwrap();
        assert!(!state.complete && !state.degraded);
        assert_eq!(state.sessions.len(), 1);
    }

    /// A forking proxy that floods an attempt with 2xx responses from new
    /// tags gets no more sessions than the attempt's fork limit, and no more
    /// cleanups than their own limit. A 2xx beyond both gets nothing, and
    /// the attempt reports that it is incomplete and degraded rather than
    /// a success. An early dialog beyond the limit is not formed either.
    #[test]
    fn fork_flood_remains_bounded_and_reports_degradation() {
        let mut model = model(Limits { forks: 2, cleanups: 2, ..limits() });
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        let results: Vec<Result<(), Error>> = (0..6)
            .map(|n| {
                let tag = format!("fork{n}");
                let ok =
                    fork(&tag, &format!("sip:fork{n}@192.0.2.{}", n + 10));
                model.receive_2xx(attempt, &ok, offer())
            })
            .collect();
        let ringing = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        let early = model.receive_provisional(attempt, &ringing);
        model.check();

        assert_eq!(
            results,
            [
                Ok(()),
                Ok(()),
                Err(Error::CapacityExceeded),
                Err(Error::CapacityExceeded),
                Err(Error::CapacityExceeded),
                Err(Error::CapacityExceeded),
            ],
        );
        assert_eq!(early, Err(Error::CapacityExceeded));
        let effects = model.take_effects();
        let sessions = confirmations(&effects);
        assert_eq!(sessions.len(), 2);
        let sent = acks(&effects);
        assert_eq!(sent.len(), 4, "two sessions and two cleanups");
        assert_eq!((model.dialogs.len(), model.usages.len()), (2, 2));
        assert_eq!((model.replays.len(), model.cleanups), (4, 2));
        let state = model.attempt_state(attempt).unwrap();
        assert!(!state.complete && state.degraded);

        for &replay in &sent {
            model.ack_written(replay, true);
        }
        for cleanup in byes(&model.take_effects()) {
            model.bye_done(cleanup);
        }
        model.response_collection_finished(attempt);
        model.check();
        let effects = model.take_effects();
        assert_eq!(
            effects.last(),
            Some(&Effect::AttemptEnded {
                attempt,
                result: AttemptResult::Answered,
                complete: false,
                degraded: true,
                sessions: sessions.clone(),
            }),
        );
        assert_eq!((model.replays.len(), model.cleanups), (0, 0));
    }

    /// A provisional response that comes late for a tag whose 2xx is in
    /// forms no early dialog (RFC 3261 section 13.2.2.1), whether that 2xx
    /// is a session that ended, a fork the UA ended for want of room, or a
    /// 2xx of an attempt given up. It counts against no limit and leaves the
    /// attempt as it was.
    #[test]
    fn a_late_provisional_forms_no_dialog_for_an_answered_tag() {
        let mut model = model(Limits { forks: 2, ..limits() });
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let late = |model: &mut Model<Counter>, tag| {
            let late =
                reply("183 Session Progress", tag, "sip:x@192.0.2.9", "");
            model.receive_provisional(attempt, &late)
        };
        model
            .receive_2xx(attempt, &fork("ended", "sip:bob@192.0.2.4"), offer())
            .unwrap();
        let session = confirmations(&model.take_effects())[0];
        model.end_usage(session);
        model
            .receive_2xx(attempt, &fork("kept", "sip:dan@192.0.2.6"), offer())
            .unwrap();
        let _ = model.receive_2xx(
            attempt,
            &fork("beyond", "sip:carol@192.0.2.5"),
            offer(),
        );
        model.take_effects();
        let before = model.attempt_state(attempt).unwrap();

        assert_eq!(late(&mut model, "ended"), Ok(()));
        assert_eq!(late(&mut model, "beyond"), Ok(()));
        model.abandon_attempt(attempt);
        model
            .receive_2xx(attempt, &fork("given", "sip:eve@192.0.2.7"), offer())
            .unwrap();
        model.take_effects();
        assert_eq!(late(&mut model, "given"), Ok(()));
        model.check();

        assert!(model.take_effects().is_empty());
        assert_eq!(model.attempt_state(attempt).unwrap(), before);
        assert_eq!(model.attempts.get(attempt).unwrap().forks.len(), 2);
        assert_eq!(model.dialogs.len(), 1);
    }

    /// A 2xx for an early dialog that finds room neither for its session's
    /// replay context nor for a cleanup changes nothing but the attempt,
    /// which is degraded. The early session stays as it was, so that a copy
    /// of the 2xx can try again.
    #[test]
    fn an_early_dialog_without_any_room_stays_early() {
        let mut model = model(Limits { replays: 1, cleanups: 1, ..limits() });
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        for tag in ["first", "second", "third"] {
            let ringing = reply("180 Ringing", tag, "sip:bob@192.0.2.4", "");
            model.receive_provisional(attempt, &ringing).unwrap();
        }
        let third = match notices(&model.take_effects())[..] {
            [_, _, Event::EarlyDialog { usage, .. }] => usage,
            ref other => panic!("not three early dialogs: {other:?}"),
        };
        model
            .receive_2xx(attempt, &fork("first", "sip:bob@192.0.2.4"), offer())
            .unwrap();
        let _ = model.receive_2xx(
            attempt,
            &fork("second", "sip:bob@192.0.2.4"),
            offer(),
        );
        model.take_effects();

        for _ in 0..2 {
            assert_eq!(
                model.receive_2xx(
                    attempt,
                    &fork("third", "sip:carol@192.0.2.5"),
                    offer()
                ),
                Err(Error::CapacityExceeded),
            );
        }
        model.check();

        assert!(model.take_effects().is_empty());
        let (phase, _, _) = model.usage_state(third).unwrap();
        assert_eq!(phase, UsagePhase::Establishing);
        let state = model.attempt_state(attempt).unwrap();
        assert!(state.degraded && !state.complete);
        assert!(state.sessions.contains(&third));
    }
}
